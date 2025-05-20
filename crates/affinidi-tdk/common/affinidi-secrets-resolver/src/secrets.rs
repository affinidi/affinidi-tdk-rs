/*!
Handles Secrets - mainly used for internal representation and for saving to files (should always be encrypted)

*/
use crate::errors::{Result, SecretsResolverError};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ssi::{
    JWK,
    jwk::{Base64urlUInt, Params},
    multicodec::{
        ED25519_PRIV, ED25519_PUB, MultiEncoded, P256_PRIV, P256_PUB, P384_PRIV, P384_PUB,
        P521_PRIV, P521_PUB,
    },
};

#[derive(Debug, Clone, Deserialize, Serialize)]
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
