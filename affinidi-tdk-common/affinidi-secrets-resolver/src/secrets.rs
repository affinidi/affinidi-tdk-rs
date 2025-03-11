/*!
Handles Secrets - mainly used for internal representation and for saving to files (should always be encrypted)

*/
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ssi::{JWK, jwk::Params};

use crate::errors::{Result, SecretsResolverError};
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
}

impl Secret {
    pub fn from_jwk(jwk: &JWK) -> Result<Self> {
        match &jwk.params {
            Params::EC(params) => {
                if let Some(curve) = &params.curve {
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
    pub fn from_str(key_id: &str, jwk: &Value) -> Secret {
        Secret {
            id: key_id.to_string(),
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK {
                private_key_jwk: jwk.clone(),
            },
        }
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
