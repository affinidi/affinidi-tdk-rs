/*!
Handles Secrets - mainly used for internal representation and for saving to files (should always be encrypted)

*/

use crate::{
    errors::{Result, SecretsResolverError},
    multicodec::{
        ED25519_PRIV, ED25519_PUB, MultiEncoded, MultiEncodedBuf, P256_PRIV, P256_PUB, P384_PRIV,
        P384_PUB, P521_PRIV, SECP256K1_PRIV, SECP256K1_PUB, X25519_PRIV, X25519_PUB,
    },
};
pub use affinidi_crypto::KeyType;
use affinidi_crypto::{JWK, Params};
use base58::ToBase58;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use multihash::Multihash;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::warn;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A Shadow inner struct that helps with deserializing
/// Allows for post-processing of the JWK material
#[derive(Deserialize)]
struct SecretShadow {
    id: String,
    #[serde(rename = "type")]
    type_: SecretType,
    #[serde(flatten)]
    secret_material: SecretMaterial,
}

/// Public Structure that manages everything to do with Keys and Secrets
#[derive(Debug, Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(try_from = "SecretShadow")]
pub struct Secret {
    /// A key ID identifying a secret (private key).
    pub id: String,

    /// Must have the same semantics as type ('type' field) of the corresponding method in DID Doc containing a public key.
    #[serde(rename = "type")]
    pub type_: SecretType,

    /// Value of the secret (private key)
    #[serde(flatten)]
    pub secret_material: SecretMaterial,

    /// Performance cheat to hold private key material in a single field
    #[serde(skip)]
    pub(crate) private_bytes: Vec<u8>,

    /// Performance cheat to hold public key material in a single field
    #[serde(skip)]
    pub(crate) public_bytes: Vec<u8>,

    /// What crypto type is this secret
    #[serde(skip)]
    pub(crate) key_type: KeyType,
}

/// Converts the inner Secret Shadow to a public Shadow Struct
/// Handles post-deserializing crypto functions to populate a full Secret Struct
impl TryFrom<SecretShadow> for Secret {
    type Error = SecretsResolverError;

    fn try_from(shadow: SecretShadow) -> Result<Self> {
        match shadow.secret_material {
            SecretMaterial::JWK(jwk) => {
                let mut secret = Secret::from_jwk(&jwk)?;
                secret.id = shadow.id;
                secret.type_ = shadow.type_;
                Ok(secret)
            }
            SecretMaterial::Multibase {
                private_key_multibase,
            } => Secret::from_multibase(&private_key_multibase, Some(&shadow.id)),
            _ => Err(SecretsResolverError::KeyError(
                "Unsupported secret material type".into(),
            )),
        }
    }
}

impl Secret {
    /// Helper function to get raw bytes
    fn convert_to_raw(input: &str) -> Result<Vec<u8>> {
        BASE64_URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|e| SecretsResolverError::KeyError(format!("Failed to decode base64url: {e}")))
    }

    /// Converts a JWK to a Secret
    pub fn from_jwk(jwk: &JWK) -> Result<Self> {
        match &jwk.params {
            Params::EC(params) => {
                let mut x = Secret::convert_to_raw(&params.x)?;
                let mut y = Secret::convert_to_raw(&params.y)?;

                x.append(&mut y);
                Ok(Secret {
                    id: jwk.key_id.as_ref().unwrap_or(&"".to_string()).to_string(),
                    type_: SecretType::JsonWebKey2020,
                    secret_material: SecretMaterial::JWK(jwk.to_owned()),
                    private_bytes: Secret::convert_to_raw(params.d.as_ref().ok_or(
                        SecretsResolverError::KeyError(
                            "Must have secret key available".to_string(),
                        ),
                    )?)?,
                    public_bytes: x,
                    key_type: KeyType::try_from(params.curve.as_str())?,
                })
            }
            Params::OKP(params) => Ok(Secret {
                id: jwk.key_id.as_ref().unwrap_or(&"".to_string()).to_string(),
                type_: SecretType::JsonWebKey2020,
                secret_material: SecretMaterial::JWK(jwk.to_owned()),
                private_bytes: Secret::convert_to_raw(params.d.as_ref().ok_or(
                    SecretsResolverError::KeyError("Must have secret key available".to_string()),
                )?)?,
                public_bytes: Secret::convert_to_raw(&params.x)?,
                key_type: KeyType::try_from(params.curve.as_str())?,
            }),
        }
    }

    /// Helper functions for converting between different types.
    /// Create a new Secret from a JWK JSON string
    /// Example:
    /// ```ignore
    /// use affinidi_secrets_resolver::secrets::{Secret, SecretMaterial, SecretType};
    ///
    ///
    /// let key_id = "did:example:123#key-1";
    /// let key_str = r#"{
    ///    "crv": "Ed25519",
    ///    "d": "LLWCf...dGpIqSFw",
    ///    "kty": "OKP",
    ///    "x": "Hn8T...ZExwQo"
    ///  }"#;
    ///
    /// let secret = Secret::from_str(key_id, key_str)?;
    /// ```
    pub fn from_str(key_id: &str, jwk: &Value) -> Result<Self> {
        let mut jwk: JWK = serde_json::from_value(jwk.to_owned())
            .map_err(|e| SecretsResolverError::KeyError(format!("Failed to parse JWK: {e}")))?;

        jwk.key_id = Some(key_id.to_string());
        Self::from_jwk(&jwk)
    }

    /// Creates a secret from a multibase encoded key
    /// Inputs:
    /// private: multi-encoded private key string
    /// specified)
    /// kid: Optional Key ID (or random if not provided)
    ///
    pub fn from_multibase(private: &str, kid: Option<&str>) -> Result<Self> {
        let private_bytes = multibase::decode(private).map_err(|e| {
            SecretsResolverError::KeyError(format!("Failed to decode private key: {e}"))
        })?;

        let private_bytes = MultiEncoded::new(private_bytes.1.as_slice())?;

        match private_bytes.codec() {
            ED25519_PRIV => {
                if private_bytes.data().len() != 32 {
                    return Err(SecretsResolverError::KeyError(
                        "Invalid ED25519 private key length".into(),
                    ));
                }
                let mut pb: [u8; 32] = [0; 32];
                pb.copy_from_slice(private_bytes.data());

                let secret = Secret::generate_ed25519(kid, Some(&pb));
                pb.zeroize();
                Ok(secret)
            }
            X25519_PRIV => {
                if private_bytes.data().len() != 32 {
                    return Err(SecretsResolverError::KeyError(
                        "Invalid X25519 private key length".into(),
                    ));
                }
                let mut pb: [u8; 32] = [0; 32];
                pb.copy_from_slice(private_bytes.data());

                let secret = Secret::generate_x25519(kid, Some(&pb));
                pb.zeroize();
                secret
            }
            P256_PRIV => {
                if private_bytes.data().len() != 32 {
                    return Err(SecretsResolverError::KeyError(
                        "Invalid P256 private key length".into(),
                    ));
                }

                Secret::generate_p256(kid, Some(private_bytes.data()))
            }
            P384_PRIV => Secret::generate_p384(kid, Some(private_bytes.data())),
            SECP256K1_PRIV => Secret::generate_secp256k1(kid, Some(private_bytes.data())),
            _ => Err(SecretsResolverError::KeyError(
                "Unsupported key type in from_multibase".into(),
            )),
        }
    }

    /// Decodes a multikey to raw bytes
    pub fn decode_multikey(key: &str) -> Result<Vec<u8>> {
        let bytes = multibase::decode(key).map_err(|e| {
            SecretsResolverError::KeyError(format!("Failed to multibase.decode key: {e}"))
        })?;
        let bytes = MultiEncoded::new(bytes.1.as_slice()).map_err(|e| {
            SecretsResolverError::KeyError(format!("Failed to load decoded key: {e}"))
        })?;
        Ok(bytes.data().to_vec())
    }

    /// Get the multibase (Base58btc) encoded public key
    pub fn get_public_keymultibase(&self) -> Result<String> {
        let encoded = match self.key_type {
            KeyType::Ed25519 => MultiEncodedBuf::encode_bytes(ED25519_PUB, &self.public_bytes),
            KeyType::X25519 => MultiEncodedBuf::encode_bytes(X25519_PUB, &self.public_bytes),
            KeyType::P256 => {
                let parity: u8 = if self.public_bytes[64].is_multiple_of(2) {
                    0x02
                } else {
                    0x03
                };
                let mut compressed: [u8; 33] = [0; 33];
                compressed[0] = parity;
                for x in self.public_bytes[1..33].iter().enumerate() {
                    compressed[x.0 + 1] = *x.1;
                }
                MultiEncodedBuf::encode_bytes(P256_PUB, &compressed)
            }
            KeyType::P384 => {
                let parity: u8 = if self.public_bytes[96].is_multiple_of(2) {
                    0x02
                } else {
                    0x03
                };
                let mut compressed: [u8; 49] = [0; 49];
                compressed[0] = parity;
                for x in self.public_bytes[1..49].iter().enumerate() {
                    compressed[x.0 + 1] = *x.1;
                }
                MultiEncodedBuf::encode_bytes(P384_PUB, &compressed)
            }
            KeyType::P521 => {
                return Err(SecretsResolverError::KeyError(
                    "P-521 is not supported".to_string(),
                ));
            }
            KeyType::Secp256k1 => {
                let parity: u8 = if self.public_bytes[64].is_multiple_of(2) {
                    0x02
                } else {
                    0x03
                };
                let mut compressed: [u8; 33] = [0; 33];
                compressed[0] = parity;
                for x in self.public_bytes[1..33].iter().enumerate() {
                    compressed[x.0 + 1] = *x.1;
                }
                MultiEncodedBuf::encode_bytes(SECP256K1_PUB, &compressed)
            }
            _ => {
                return Err(SecretsResolverError::KeyError(
                    "Unsupported key type".into(),
                ));
            }
        };
        Ok(multibase::encode(
            multibase::Base::Base58Btc,
            encoded.into_bytes(),
        ))
    }

    /// Generates a hash of the multikey - useful where you want to pre-rotate keys
    /// but not disclose the actual public key itself!
    pub fn get_public_keymultibase_hash(&self) -> Result<String> {
        let key = self.get_public_keymultibase()?;

        Secret::base58_hash_string(&key)
    }

    /// Will convert a string to a base58btc encoded multihash (SHA256) representation
    /// base58<multihash<multikey>>
    pub fn base58_hash_string(key: &str) -> Result<String> {
        let hash = Sha256::digest(key.as_bytes());
        // SHA_256 code = 0x12
        #[allow(deprecated)]
        let hash_encoded = Multihash::<32>::wrap(0x12, hash.as_slice()).map_err(|e| {
            SecretsResolverError::KeyError(format!(
                "Couldn't create multihash encoding for Public Key. Reason: {e}",
            ))
        })?;
        Ok(hash_encoded.to_bytes().to_base58())
    }

    /// Get the multibase (Base58btc) encoded private key
    pub fn get_private_keymultibase(&self) -> Result<String> {
        let encoded = match self.key_type {
            KeyType::Ed25519 => MultiEncodedBuf::encode_bytes(ED25519_PRIV, &self.private_bytes),
            KeyType::X25519 => MultiEncodedBuf::encode_bytes(X25519_PRIV, &self.private_bytes),
            KeyType::P256 => MultiEncodedBuf::encode_bytes(P256_PRIV, &self.private_bytes),
            KeyType::P384 => MultiEncodedBuf::encode_bytes(P384_PRIV, &self.private_bytes),
            KeyType::P521 => MultiEncodedBuf::encode_bytes(P521_PRIV, &self.private_bytes),
            KeyType::Secp256k1 => {
                MultiEncodedBuf::encode_bytes(SECP256K1_PRIV, &self.private_bytes)
            }
            _ => {
                return Err(SecretsResolverError::KeyError(
                    "Unsupported key type".into(),
                ));
            }
        };
        Ok(multibase::encode(
            multibase::Base::Base58Btc,
            encoded.into_bytes(),
        ))
    }

    /// Get the public key bytes
    pub fn get_public_bytes(&self) -> &[u8] {
        self.public_bytes.as_slice()
    }

    /// Get the private key bytes
    pub fn get_private_bytes(&self) -> &[u8] {
        self.private_bytes.as_slice()
    }

    /// What crypto type is this secret
    pub fn get_key_type(&self) -> KeyType {
        self.key_type
    }

    pub fn to_x25519(&self) -> Result<Secret> {
        if self.key_type != KeyType::Ed25519 {
            warn!(
                "Can only convert ED25519 to X25519! Current key type is {:#?}",
                self.key_type
            );
            Err(SecretsResolverError::KeyError(format!(
                "Can only convert ED25519 to X25519! Current key type is {:#?}",
                self.key_type
            )))
        } else {
            // Convert to X25519 Secret bytes
            let x25519_secret = affinidi_crypto::ed25519::ed25519_private_to_x25519(
                self.private_bytes.first_chunk::<32>().unwrap(),
            );

            let x25519_sk = StaticSecret::from(x25519_secret);
            let x25519_pk = PublicKey::from(&x25519_sk);

            let secret = BASE64_URL_SAFE_NO_PAD.encode(x25519_sk.as_bytes());
            let public = BASE64_URL_SAFE_NO_PAD.encode(x25519_pk.as_bytes());

            let jwk = json!({
                "crv": "X25519",
                "d": secret,
                "kty": "OKP",
                "x": public
            });

            Secret::from_str(&self.id, &jwk)
        }
    }
}

/// Must have the same semantics as type ('type' field) of the corresponding method in DID Doc containing a public key.
#[derive(Debug, Clone, Deserialize, Serialize, Zeroize)]
pub enum SecretType {
    JsonWebKey2020,
    X25519KeyAgreementKey2019,
    X25519KeyAgreementKey2020,
    Ed25519VerificationKey2018,
    Ed25519VerificationKey2020,
    EcdsaSecp256k1VerificationKey2019,
    Other,
}

// KeyType is re-exported from affinidi_crypto

/// Represents secret crypto material.
#[derive(Debug, Clone, Deserialize, Serialize, Zeroize)]
pub enum SecretMaterial {
    #[serde(rename = "privateKeyJwk", rename_all = "camelCase")]
    JWK(JWK),

    #[serde(rename_all = "camelCase")]
    Multibase { private_key_multibase: String },

    #[serde(rename_all = "camelCase")]
    Base58 { private_key_base58: String },
}

#[cfg(test)]
mod tests {
    use super::Secret;
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
    use serde_json::json;

    #[test]
    fn check_hash() {
        let input = "z6MkgfFvvWA7sw8WkNWyK3y74kwNVvWc7Qrs5tWnsnqMfLD3";
        let output = Secret::base58_hash_string(input).expect("Hash of input");
        assert_eq!(&output, "QmY1kaguPMgjndEh1sdDZ8kdjX4Uc1SW4vziMfgWC6ndnJ")
    }

    #[test]
    fn check_hash_bad() {
        let input = "z6MkgfFvvWA7sw8WkNWyK3y74kwNVvWc7Qrs5tWnsnqMfLD4";
        let output = Secret::base58_hash_string(input).expect("Hash of input");
        assert_ne!(&output, "QmY1kaguPMgjndEh1sdDZ8kdjX4Uc1SW4vziMfgWC6ndnJ")
    }

    #[test]
    fn check_x25519() {
        // ED25519 Secret Key
        // https://docs.rs/ed25519_to_curve25519/latest/ed25519_to_curve25519/fn.ed25519_sk_to_curve25519.html
        /* let ed25519_sk_bytes: [u8; 32] = [
            202, 104, 239, 81, 53, 110, 80, 252, 198, 23, 155, 162, 215, 98, 223, 173, 227, 188,
            110, 54, 127, 45, 185, 206, 174, 29, 44, 147, 76, 66, 196, 195,
        ]; */

        let x25519_sk_bytes: [u8; 32] = [
            200, 255, 64, 61, 17, 52, 112, 33, 205, 71, 186, 13, 131, 12, 241, 136, 223, 5, 152,
            40, 95, 187, 83, 168, 142, 10, 234, 215, 70, 210, 148, 104,
        ];

        // The following JWK is created from the ed25519 secret key above
        let jwk = json!({
        "crv": "Ed25519",
        "d": "ymjvUTVuUPzGF5ui12LfreO8bjZ_LbnOrh0sk0xCxMM",
        "kty": "OKP",
        "x": "d17TbZmkoYHZUQpzJTcuOtq0tjWYm8CKvKGYHDW6ZaE"
        });

        let ed25519 = Secret::from_str("test", &jwk).unwrap();

        let x25519 = ed25519
            .to_x25519()
            .expect("Couldn't convert ed25519 to x25519");

        assert_eq!(x25519.private_bytes.as_slice(), x25519_sk_bytes);
    }

    #[test]
    fn check_secret_deserialize() {
        let txt = r#"{
        "id": "did:web:localhost%3A7037:mediator:v1:.well-known#key-2",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "crv": "secp256k1",
            "d": "Cs5xn7WCkUWEua5vGxjP9_wBzIzMtEwjQ4KWKHHQR14",
            "kty": "EC",
            "x": "Lk1FY8MmyLjBswU4KbLoBQ_1THZJBMx2n6aIBXt1uXo",
            "y": "tEv7EQHj4g4njOfrsjjDJBPKOI9RGWWMS8NYClo2cqo"
        }
    }"#;

        let secret = serde_json::from_str::<Secret>(txt);

        assert!(secret.is_ok());
    }

    #[test]
    fn from_multiencode_ed25519() {
        let seed = BASE64_URL_SAFE_NO_PAD
            .decode("oihAhqs-h9V9rq6KYEhiEWwdBDpTI7xL0EEiwC9heFg")
            .expect("Couldn't decode ed25519 BASE64 encoding");

        let public_bytes = BASE64_URL_SAFE_NO_PAD
            .decode("eC1vNebw6IJ8SJ4Tg9g2Q9W-Zy8xIS80byxTZXlPaHk")
            .expect("Couldn't BASE64 decode ed25519 public bytes");

        assert_eq!(seed.len(), 32);
        let mut private_bytes: [u8; 32] = [0; 32];
        private_bytes.copy_from_slice(seed.as_slice());

        let secret = Secret::generate_ed25519(None, Some(&private_bytes));

        assert_eq!(
            secret.get_private_keymultibase().unwrap(),
            "z3u2c8oS2oKgATvakQzVF66EAcZWJqPUzGQzWMUTKnFkv5DR"
        );
        assert_eq!(secret.get_public_bytes(), public_bytes.as_slice());
        assert_eq!(secret.get_private_bytes(), private_bytes.as_slice());

        let secret2 =
            Secret::from_multibase("z3u2c8oS2oKgATvakQzVF66EAcZWJqPUzGQzWMUTKnFkv5DR", None)
                .expect("Failed to transform ed25519 to secret");

        assert_eq!(
            secret2.get_public_keymultibase().unwrap(),
            secret.get_public_keymultibase().unwrap()
        );
        assert_eq!(secret2.get_public_bytes(), secret.get_public_bytes());
        assert_eq!(secret2.get_private_bytes(), secret.get_private_bytes());

        assert_eq!(
            secret2.get_private_keymultibase().unwrap(),
            secret.get_private_keymultibase().unwrap()
        );
    }

    #[test]
    fn from_multiencode_x25519() {
        let seed = BASE64_URL_SAFE_NO_PAD
            .decode("eYN37ZX0ij4TYdklZax2jiRiyHYMNOzwW2bvNauAzKk")
            .expect("Couldn't decode x25519 BASE64 encoding");

        let public_bytes = BASE64_URL_SAFE_NO_PAD
            .decode("Ephwf5xVmhVnDj2KtIPDKcGYBG9CQR_mZKlRqETZ62U")
            .expect("Couldn't BASE64 decode x25519 public bytes");

        assert_eq!(seed.len(), 32);
        let mut private_bytes: [u8; 32] = [0; 32];
        private_bytes.copy_from_slice(seed.as_slice());

        let secret = Secret::generate_x25519(None, Some(&private_bytes))
            .expect("x25519 generate secret failed");

        assert_eq!(
            secret.get_private_keymultibase().unwrap(),
            "z3weexK9erGUKF41d3tJoDu2Fetx1xnsC7WhFWnjuCJXJGxp"
        );
        assert_eq!(secret.get_public_bytes(), public_bytes.as_slice());
        assert_eq!(secret.get_private_bytes(), private_bytes.as_slice());

        let secret2 =
            Secret::from_multibase("z3weexK9erGUKF41d3tJoDu2Fetx1xnsC7WhFWnjuCJXJGxp", None)
                .expect("Failed to transform x25519 to secret");

        assert_eq!(
            secret2.get_public_keymultibase().unwrap(),
            secret.get_public_keymultibase().unwrap()
        );
        assert_eq!(secret2.get_public_bytes(), secret.get_public_bytes());
        assert_eq!(secret2.get_private_bytes(), secret.get_private_bytes());

        assert_eq!(
            secret2.get_private_keymultibase().unwrap(),
            secret.get_private_keymultibase().unwrap()
        );
    }

    #[test]
    fn from_multiencode_p256() {
        let seed = BASE64_URL_SAFE_NO_PAD
            .decode("B5ZIiXYkpEPczVbyWP85H75wrBifiRcFgtqYvI5I9AI")
            .expect("Couldn't decode P-256 BASE64 encoding");

        let pub_x = BASE64_URL_SAFE_NO_PAD
            .decode("Iy3cHBWCRhcjohhS-iSucYMUNjH77DIQRSdn-NylcCw")
            .expect("Couldn't BASE64 decode P-256 X public bytes");

        let pub_y = BASE64_URL_SAFE_NO_PAD
            .decode("p9MikGh-O3nbLWA-6tP4Oanch5AF3ZhRD907tQojH3k")
            .expect("Couldn't BASE64 decode P-256 Y public bytes");

        let public_bytes = [vec![4], pub_x, pub_y].concat();

        assert_eq!(seed.len(), 32);
        let mut private_bytes: [u8; 32] = [0; 32];
        private_bytes.copy_from_slice(seed.as_slice());

        let secret =
            Secret::generate_p256(None, Some(&private_bytes)).expect("P256 secret generate failed");

        assert_eq!(
            secret.get_private_keymultibase().unwrap(),
            "z42tiPvqM1uFz2QxbF7wTsQkfAf3hCsq1Uf9JbUMRaRiV1yb"
        );
        assert_eq!(secret.get_public_bytes(), public_bytes.as_slice());
        assert_eq!(secret.get_private_bytes(), private_bytes.as_slice());

        let secret2 =
            Secret::from_multibase("z42tiPvqM1uFz2QxbF7wTsQkfAf3hCsq1Uf9JbUMRaRiV1yb", None)
                .expect("Failed to transform P256 to secret");

        assert_eq!(
            secret2.get_public_keymultibase().unwrap(),
            secret.get_public_keymultibase().unwrap()
        );
        assert_eq!(secret2.get_public_bytes(), secret.get_public_bytes());
        assert_eq!(secret2.get_private_bytes(), secret.get_private_bytes());

        assert_eq!(
            secret2.get_private_keymultibase().unwrap(),
            secret.get_private_keymultibase().unwrap()
        );
    }

    #[test]
    fn from_multiencode_p384() {
        let seed = BASE64_URL_SAFE_NO_PAD
            .decode("nka5zKVpVpOdCKdZZgnZ-VaSXk6V_ovYibzr2nf-mKAgct6wBdvWCXWLaNr80zY0")
            .expect("Couldn't decode P-384 BASE64 encoding");

        let pub_x = BASE64_URL_SAFE_NO_PAD
            .decode("uitQkpTA3Vw8t_qOGrdLlbIzdzF0K9NsScgsVgmpQdQJgshCifOCUehxeazzL-Ow")
            .expect("Couldn't BASE64 decode P-384 X public bytes");

        let pub_y = BASE64_URL_SAFE_NO_PAD
            .decode("4BIcrueQfhxfnrqToZEOujOfJOmwEsWJAdFNZ9dksIBCnWiCLBEn2HnR7ikyyPMJ")
            .expect("Couldn't BASE64 decode P-384 Y public bytes");

        let public_bytes = [vec![4], pub_x, pub_y].concat();

        assert_eq!(seed.len(), 48);
        let mut private_bytes: [u8; 48] = [0; 48];
        private_bytes.copy_from_slice(seed.as_slice());

        let secret =
            Secret::generate_p384(None, Some(&private_bytes)).expect("P384 secret generate failed");

        assert_eq!(
            secret.get_private_keymultibase().unwrap(),
            "z2fapqKp6mPoQCwkQzvL9Ns35Y57R4LRRfVwbXoSTQjTHdjD4MqFZnw5PueieuTWG4pN5q"
        );
        assert_eq!(secret.get_public_bytes(), public_bytes.as_slice());
        assert_eq!(secret.get_private_bytes(), private_bytes.as_slice());

        let secret2 = Secret::from_multibase(
            "z2fapqKp6mPoQCwkQzvL9Ns35Y57R4LRRfVwbXoSTQjTHdjD4MqFZnw5PueieuTWG4pN5q",
            None,
        )
        .expect("Failed to transform P384 to secret");

        assert_eq!(
            secret2.get_public_keymultibase().unwrap(),
            secret.get_public_keymultibase().unwrap()
        );
        assert_eq!(secret2.get_public_bytes(), secret.get_public_bytes());
        assert_eq!(secret2.get_private_bytes(), secret.get_private_bytes());

        assert_eq!(
            secret2.get_private_keymultibase().unwrap(),
            secret.get_private_keymultibase().unwrap()
        );
    }

    #[test]
    fn from_multiencode_secp256k1() {
        let seed = BASE64_URL_SAFE_NO_PAD
            .decode("CzR8XKYmrxbeEeUKojSgXUskLmGjbLXFf4CoJd6he6A")
            .expect("Couldn't decode secp256k1 BASE64 encoding");

        let pub_x = BASE64_URL_SAFE_NO_PAD
            .decode("jcGMDsxKBME8GmaN_-XTaAEKk2ET6ajWe_8-2RsU-is")
            .expect("Couldn't BASE64 decode secp256k1 X public bytes");

        let pub_y = BASE64_URL_SAFE_NO_PAD
            .decode("9ECTinCwW9bA36fmUBg0_iu0oyLR-Tn54guX8exrUjM")
            .expect("Couldn't BASE64 decode secp256k1 Y public bytes");

        let public_bytes = [vec![4], pub_x, pub_y].concat();

        assert_eq!(seed.len(), 32);
        let mut private_bytes: [u8; 32] = [0; 32];
        private_bytes.copy_from_slice(seed.as_slice());

        let secret = Secret::generate_secp256k1(None, Some(&private_bytes))
            .expect("secp256k1 secret generate failed");

        assert_eq!(
            secret.get_private_keymultibase().unwrap(),
            "z3vLUkda21MTbdECEEyjUWEQmJ8r1CKekvRLqQbZXxfLieL7"
        );
        assert_eq!(secret.get_public_bytes(), public_bytes.as_slice());
        assert_eq!(secret.get_private_bytes(), private_bytes.as_slice());

        let secret2 =
            Secret::from_multibase("z3vLUkda21MTbdECEEyjUWEQmJ8r1CKekvRLqQbZXxfLieL7", None)
                .expect("Failed to transform secp256k1 to secret");

        assert_eq!(
            secret2.get_public_keymultibase().unwrap(),
            secret.get_public_keymultibase().unwrap()
        );
        assert_eq!(secret2.get_public_bytes(), secret.get_public_bytes());
        assert_eq!(secret2.get_private_bytes(), secret.get_private_bytes());

        assert_eq!(
            secret2.get_private_keymultibase().unwrap(),
            secret.get_private_keymultibase().unwrap()
        );
    }
}
