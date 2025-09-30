/*!
*   Handles JWK (JSON Web Key) operations such as parsing, serialization, and key extraction.
*/

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[cfg(feature = "ed25519")]
use crate::multicodec::X25519_PUB;
#[cfg(feature = "p256")]
use crate::secrets::Secret;
use crate::{
    errors::SecretsResolverError,
    multicodec::{ED25519_PUB, MultiEncoded, P256_PUB, P384_PUB, SECP256K1_PUB},
    secrets::KeyType,
};

/// RFC 7517 JWK Struct
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JWK {
    #[serde(rename = "kid")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(flatten)]
    pub params: Params,
}

impl JWK {
    /// Returns the KeyType for a JWK
    pub fn get_key_type(&self) -> KeyType {
        match &self.params {
            Params::EC(params) => {
                if params.curve == "P-256" {
                    KeyType::P256
                } else if params.curve == "secp256k1" {
                    KeyType::Secp256k1
                } else if params.curve == "P-384" {
                    KeyType::P384
                } else {
                    KeyType::Unknown
                }
            }
            Params::OKP(params) => {
                if params.curve == "Ed25519" {
                    KeyType::Ed25519
                } else if params.curve == "X25519" {
                    KeyType::X25519
                } else {
                    KeyType::Unknown
                }
            }
        }
    }
}

/// JWK Key Types and associated Parameters
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "kty")]
pub enum Params {
    EC(ECParams),
    OKP(OctectParams),
}

#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, PartialEq)]
pub struct ECParams {
    // Public key co-ordinates
    #[serde(rename = "crv")]
    pub curve: String,
    pub x: String,
    pub y: String,

    // Private key cordinate
    pub d: Option<String>,
}

impl Drop for ECParams {
    fn drop(&mut self) {
        // Zeroize private key
        self.d.zeroize();
    }
}

// Ensure we are cleaning up any private key data
#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, PartialEq)]
pub struct OctectParams {
    // Public key co-ordinates
    #[serde(rename = "crv")]
    pub curve: String,
    pub x: String,

    // Private key cordinate
    pub d: Option<String>,
}

impl Drop for OctectParams {
    fn drop(&mut self) {
        // Zeroize private key
        self.d.zeroize();
    }
}

impl JWK {
    /// Converts a multikey string into a JWK struct
    pub fn from_multikey(key: &str) -> Result<Self, SecretsResolverError> {
        // decode multibase
        let decoded = match multibase::decode(key) {
            Ok((_, data)) => data,
            Err(_) => {
                return Err(SecretsResolverError::Decoding(
                    "Failed to decode multibase".to_string(),
                ));
            }
        };

        // decode multiencode
        let decoded = MultiEncoded::new(&decoded)?;

        match decoded.codec() {
            #[cfg(feature = "p256")]
            P256_PUB => Secret::p256_public_jwk(decoded.data()),
            #[cfg(feature = "p384")]
            P384_PUB => Secret::p384_public_jwk(decoded.data()),
            #[cfg(feature = "k256")]
            SECP256K1_PUB => Secret::secp256k1_public_jwk(decoded.data()),
            #[cfg(feature = "ed25519")]
            ED25519_PUB => Secret::ed25519_public_jwk(decoded.data()),
            #[cfg(feature = "ed25519")]
            X25519_PUB => Secret::x25519_public_jwk(decoded.data()),
            _ => Err(SecretsResolverError::UnsupportedKeyType(format!(
                "Unsupported key type codec ({})",
                decoded.codec()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::jwk::{ECParams, JWK, OctectParams, Params};

    #[test]
    fn deserialize_okp_public_jwk() {
        let raw = r#"{
            "crv": "Ed25519",
            "d": "jybTAuX6NlN7cJLWNCSOLUnJpblpsGr05TTp7scjSvE",
            "kty": "OKP",
            "x": "Xx4_L89E6RsyvDTzN9wuN3cDwgifPkXMgFJv_HMIxdk"
        }"#;

        let jwk: JWK = serde_json::from_str(raw).expect("Couldn't deserialize JWK String");

        assert_eq!(
            jwk.params,
            Params::OKP(OctectParams {
                curve: "Ed25519".to_string(),
                x: "Xx4_L89E6RsyvDTzN9wuN3cDwgifPkXMgFJv_HMIxdk".to_string(),
                d: Some("jybTAuX6NlN7cJLWNCSOLUnJpblpsGr05TTp7scjSvE".to_string())
            })
        );
    }

    #[test]
    fn deserialize_ec_public_jwk() {
        let raw = r#"{
            "crv": "P-256",
            "d": "kQrTUKhBU-6bHbCdiY0dIfg3knd5U2-1FlLGGHSbF6U",
            "kty": "EC",
            "x": "sl56LMzaiR5efwwWU1jzC_dfbxQ8gzyLj_N1q2cJmkE",
            "y": "UnAimUtlHMPj_T_wIDVPoJAolKHy8DoXXTb8wch4hgU"
        }"#;

        let jwk: JWK = serde_json::from_str(raw).expect("Couldn't deserialize JWK String");

        assert_eq!(
            jwk.params,
            Params::EC(ECParams {
                curve: "P-256".to_string(),
                x: "sl56LMzaiR5efwwWU1jzC_dfbxQ8gzyLj_N1q2cJmkE".to_string(),
                y: "UnAimUtlHMPj_T_wIDVPoJAolKHy8DoXXTb8wch4hgU".to_string(),
                d: Some("kQrTUKhBU-6bHbCdiY0dIfg3knd5U2-1FlLGGHSbF6U".to_string())
            })
        );
    }
}
