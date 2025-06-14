/*!
Handles Secrets - mainly used for internal representation and for saving to files (should always be encrypted)

*/
use crate::errors::{Result, SecretsResolverError};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use multihash::Multihash;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ssi::{
    JWK,
    jwk::{Base64urlUInt, Params},
    multicodec::{
        ED25519_PRIV, ED25519_PUB, MultiEncoded, MultiEncodedBuf, P256_PRIV, P256_PUB, P384_PRIV,
        P384_PUB, P521_PRIV, P521_PUB, SECP256K1_PRIV, SECP256K1_PUB,
    },
};

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
#[derive(Debug, Clone, Deserialize, Serialize)]
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
    private_bytes: Vec<u8>,

    /// Performance cheat to hold public key material in a single field
    #[serde(skip)]
    public_bytes: Vec<u8>,

    /// What crypto type is this secret
    #[serde(skip)]
    key_type: KeyType,
}

/// Converts the inner Secret Shadow to a public Shadow Struct
/// Handles post-deserializing crypto functions to populate a full Secret Struct
impl TryFrom<SecretShadow> for Secret {
    type Error = SecretsResolverError;

    fn try_from(shadow: SecretShadow) -> Result<Self> {
        match shadow.secret_material {
            SecretMaterial::JWK { private_key_jwk } => {
                let jwk: JWK = serde_json::from_value(private_key_jwk).map_err(|e| {
                    SecretsResolverError::KeyError(format!("Failed to parse JWK: {}", e))
                })?;
                let mut secret = Secret::from_jwk(&jwk)?;
                secret.id = shadow.id;
                secret.type_ = shadow.type_;
                Ok(secret)
            }
            _ => Err(SecretsResolverError::KeyError(
                "Unsupported secret material type".into(),
            )),
        }
    }
}

impl Secret {
    /// Helper function to get raw bytes
    fn convert_to_raw(input: Option<Base64urlUInt>) -> Result<Vec<u8>> {
        if let Some(a) = input {
            Ok(a.0)
        } else {
            Err(SecretsResolverError::KeyError(
                "Failed to convert key to raw bytes".into(),
            ))
        }
    }

    /// Converts a JWK to a Secret
    pub fn from_jwk(jwk: &JWK) -> Result<Self> {
        match &jwk.params {
            Params::EC(params) => {
                if let Some(curve) = &params.curve {
                    let mut x = Secret::convert_to_raw(params.x_coordinate.clone())?;
                    let mut y = Secret::convert_to_raw(params.y_coordinate.clone())?;

                    x.append(&mut y);
                    Ok(Secret {
                        id: jwk.key_id.as_ref().unwrap_or(&"".to_string()).to_string(),
                        type_: SecretType::JsonWebKey2020,
                        secret_material: SecretMaterial::JWK {
                            private_key_jwk: json!({
                                "crv": curve,
                                "d":  params.ecc_private_key,
                                "kty": "EC",
                                "x": params.x_coordinate,
                                "y": params.y_coordinate
                            }),
                        },
                        private_bytes: Secret::convert_to_raw(params.ecc_private_key.clone())?,
                        public_bytes: x,
                        key_type: KeyType::try_from(curve.as_str())?,
                    })
                } else {
                    Err(SecretsResolverError::KeyError(
                        "EC Curve not defined".into(),
                    ))
                }
            }
            Params::OKP(params) => Ok(Secret {
                id: jwk.key_id.as_ref().unwrap_or(&"".to_string()).to_string(),
                type_: SecretType::JsonWebKey2020,
                secret_material: SecretMaterial::JWK {
                    private_key_jwk: json!({
                        "crv": params.curve,
                        "d":  params.private_key,
                        "kty": "OKP",
                        "x": params.public_key
                    }),
                },
                private_bytes: Secret::convert_to_raw(params.private_key.clone())?,
                public_bytes: Secret::convert_to_raw(Some(params.public_key.clone()))?,
                key_type: KeyType::try_from(params.curve.as_str())?,
            }),
            _ => Err(SecretsResolverError::KeyError(format!(
                "Unsupported key type: {:?}",
                jwk.params
            ))),
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
            .map_err(|e| SecretsResolverError::KeyError(format!("Failed to parse JWK: {}", e)))?;

        jwk.key_id = Some(key_id.to_string());
        Self::from_jwk(&jwk)
    }

    /// Creates a secret from a multibase encoded key
    /// Requires a key ID, public key, and private key
    pub fn from_multibase(key_id: &str, public: &str, private: &str) -> Result<Self> {
        let public_bytes = multibase::decode(public).map_err(|e| {
            SecretsResolverError::KeyError(format!("Failed to decode public key: {}", e))
        })?;
        let private_bytes = multibase::decode(private).map_err(|e| {
            SecretsResolverError::KeyError(format!("Failed to decode private key: {}", e))
        })?;

        let public_bytes = MultiEncoded::new(public_bytes.1.as_slice()).map_err(|e| {
            SecretsResolverError::KeyError(format!("Failed to decode public key: {}", e))
        })?;
        let private_bytes = MultiEncoded::new(private_bytes.1.as_slice()).map_err(|e| {
            SecretsResolverError::KeyError(format!("Failed to decode private key: {}", e))
        })?;

        let jwk = match (public_bytes.codec(), private_bytes.codec()) {
            (ED25519_PUB, ED25519_PRIV) => {
                json!({"crv": "Ed25519", "kty": "OKP", "d": BASE64_URL_SAFE_NO_PAD.encode(private_bytes.data()), "x": BASE64_URL_SAFE_NO_PAD.encode(public_bytes.data())})
            }
            (P256_PUB, P256_PRIV) => {
                if let Some((x, y)) = public_bytes.data().split_at_checked(32) {
                    json!({"crv": "P-256", "kty": "EC", "d": BASE64_URL_SAFE_NO_PAD.encode(private_bytes.data()), "x": BASE64_URL_SAFE_NO_PAD.encode(x), "y": BASE64_URL_SAFE_NO_PAD.encode(y)})
                } else {
                    return Err(SecretsResolverError::KeyError(
                        "Failed to split public key".into(),
                    ));
                }
            }
            (P384_PUB, P384_PRIV) => {
                if let Some((x, y)) = public_bytes.data().split_at_checked(32) {
                    json!({"crv": "P-384", "kty": "EC", "d": BASE64_URL_SAFE_NO_PAD.encode(private_bytes.data()), "x": BASE64_URL_SAFE_NO_PAD.encode(x), "y": BASE64_URL_SAFE_NO_PAD.encode(y)})
                } else {
                    return Err(SecretsResolverError::KeyError(
                        "Failed to split public key".into(),
                    ));
                }
            }
            (P521_PUB, P521_PRIV) => {
                if let Some((x, y)) = public_bytes.data().split_at_checked(32) {
                    json!({"crv": "P-521", "kty": "EC", "d": BASE64_URL_SAFE_NO_PAD.encode(private_bytes.data()), "x": BASE64_URL_SAFE_NO_PAD.encode(x), "y": BASE64_URL_SAFE_NO_PAD.encode(y)})
                } else {
                    return Err(SecretsResolverError::KeyError(
                        "Failed to split public key".into(),
                    ));
                }
            }
            _ => {
                return Err(SecretsResolverError::KeyError(
                    "Unsupported key type".into(),
                ));
            }
        };
        Secret::from_str(key_id, &jwk)
    }

    /// Decodes a multikey to raw bytes
    pub fn decode_multikey(key: &str) -> Result<Vec<u8>> {
        let bytes = multibase::decode(key).map_err(|e| {
            SecretsResolverError::KeyError(format!("Failed to multibase.decode key: {}", e))
        })?;
        let bytes = MultiEncoded::new(bytes.1.as_slice()).map_err(|e| {
            SecretsResolverError::KeyError(format!("Failed to load decoded key: {}", e))
        })?;
        Ok(bytes.data().to_vec())
    }

    /// Get the multibase (Base58btc) encoded public key
    pub fn get_public_keymultibase(&self) -> Result<String> {
        let encoded = match self.key_type {
            KeyType::Ed25519 => MultiEncodedBuf::encode_bytes(ED25519_PUB, &self.public_bytes),
            KeyType::P256 => MultiEncodedBuf::encode_bytes(P256_PUB, &self.public_bytes),
            KeyType::P384 => MultiEncodedBuf::encode_bytes(P384_PUB, &self.public_bytes),
            KeyType::P521 => MultiEncodedBuf::encode_bytes(P521_PUB, &self.public_bytes),
            KeyType::Secp256k1 => MultiEncodedBuf::encode_bytes(SECP256K1_PUB, &self.public_bytes),
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

        Secret::hash_string(&key)
    }

    /// Will convert a string to a base58btc encoded multihash (SHA256) representation
    pub fn hash_string(key: &str) -> Result<String> {
        let hash = Sha256::digest(key.as_bytes());
        // SHA_256 code = 0x12
        let hash_encoded = Multihash::<32>::wrap(0x12, hash.as_slice()).map_err(|e| {
            SecretsResolverError::KeyError(format!(
                "Couldn't create multihash encoding for Public Key. Reason: {}",
                e
            ))
        })?;
        Ok(multibase::encode(
            multibase::Base::Base58Btc,
            hash_encoded.to_bytes(),
        ))
    }

    /// Get the multibase (Base58btc) encoded private key
    pub fn get_private_keymultibase(&self) -> Result<String> {
        let encoded = match self.key_type {
            KeyType::Ed25519 => MultiEncodedBuf::encode_bytes(ED25519_PRIV, &self.private_bytes),
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
}

/// Must have the same semantics as type ('type' field) of the corresponding method in DID Doc containing a public key.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum SecretType {
    JsonWebKey2020,
    X25519KeyAgreementKey2019,
    X25519KeyAgreementKey2020,
    Ed25519VerificationKey2018,
    Ed25519VerificationKey2020,
    EcdsaSecp256k1VerificationKey2019,
    Other,
}

/// Known Crypto types
#[derive(Debug, Default, Clone, Copy, Deserialize, Serialize)]
pub enum KeyType {
    Ed25519,
    P256,
    P384,
    P521,
    Secp256k1,
    #[default]
    Unknown,
}

impl TryFrom<&str> for KeyType {
    type Error = SecretsResolverError;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "Ed25519" => Ok(KeyType::Ed25519),
            "P-256" => Ok(KeyType::P256),
            "P-384" => Ok(KeyType::P384),
            "P-521" => Ok(KeyType::P521),
            "secp256k1" => Ok(KeyType::Secp256k1),
            _ => Err(SecretsResolverError::KeyError(format!(
                "Unknown key type: {}",
                value
            ))),
        }
    }
}

/// Represents secret crypto material.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SecretMaterial {
    #[serde(rename_all = "camelCase")]
    JWK { private_key_jwk: Value },

    #[serde(rename_all = "camelCase")]
    Multibase { private_key_multibase: String },

    #[serde(rename_all = "camelCase")]
    Base58 { private_key_base58: String },
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn check_hash() {
        let input = "z6MkgfFvvWA7sw8WkNWyK3y74kwNVvWc7Qrs5tWnsnqMfLD3";
        let output = Secret::hash_string(input).expect("Hash of input");
        assert_eq!(&output, "zQmY1kaguPMgjndEh1sdDZ8kdjX4Uc1SW4vziMfgWC6ndnJ")
    }
    #[test]
    fn check_hash_bad() {
        let input = "z6MkgfFvvWA7sw8WkNWyK3y74kwNVvWc7Qrs5tWnsnqMfLD4";
        let output = Secret::hash_string(input).expect("Hash of input");
        assert_ne!(&output, "zQmY1kaguPMgjndEh1sdDZ8kdjX4Uc1SW4vziMfgWC6ndnJ")
    }
}
