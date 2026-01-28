//! Key material for did:key and related cryptographic operations
//!
//! This module contains types for managing cryptographic key material
//! associated with DIDs, including generation, serialization, and encoding.

use affinidi_crypto::{JWK, KeyType, Params};
use affinidi_encoding::{
    ED25519_PRIV, ED25519_PUB, P256_PRIV, P256_PUB, P384_PRIV, P384_PUB,
    SECP256K1_PRIV, SECP256K1_PUB, X25519_PRIV, X25519_PUB,
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors related to key material operations
#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Key error: {0}")]
    Key(String),

    #[error("Unsupported key type: {0}")]
    UnsupportedKeyType(String),

    #[error("Encoding error: {0}")]
    Encoding(#[from] affinidi_encoding::EncodingError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] affinidi_crypto::CryptoError),
}

/// Type of key material for DID Document verification methods
#[derive(Debug, Clone, Deserialize, Serialize, Zeroize, PartialEq, Eq)]
pub enum KeyMaterialType {
    JsonWebKey2020,
    Multikey,
    X25519KeyAgreementKey2019,
    X25519KeyAgreementKey2020,
    Ed25519VerificationKey2018,
    Ed25519VerificationKey2020,
    EcdsaSecp256k1VerificationKey2019,
    Other,
}

/// Serialization format for key material
#[derive(Debug, Clone, Deserialize, Serialize, Zeroize)]
pub enum KeyMaterialFormat {
    #[serde(rename = "privateKeyJwk", rename_all = "camelCase")]
    JWK(JWK),

    #[serde(rename_all = "camelCase")]
    Multibase { private_key_multibase: String },

    #[serde(rename_all = "camelCase")]
    Base58 { private_key_base58: String },
}

/// Shadow struct for deserialization
#[derive(Deserialize)]
struct KeyMaterialShadow {
    id: String,
    #[serde(rename = "type")]
    type_: KeyMaterialType,
    #[serde(flatten)]
    format: KeyMaterialFormat,
}

/// Key material associated with a DID
///
/// Contains both public and private key bytes along with metadata.
/// This type securely manages cryptographic key material and supports
/// various serialization formats (JWK, multibase).
#[derive(Debug, Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(try_from = "KeyMaterialShadow")]
pub struct KeyMaterial {
    /// Key ID (typically a DID URL like `did:key:z6Mk...#z6Mk...`)
    pub id: String,

    /// Type for DID Document verification methods
    #[serde(rename = "type")]
    pub type_: KeyMaterialType,

    /// Serialized form of the key
    #[serde(flatten)]
    pub format: KeyMaterialFormat,

    /// Raw private key bytes
    #[serde(skip)]
    pub(crate) private_bytes: Vec<u8>,

    /// Raw public key bytes
    #[serde(skip)]
    pub(crate) public_bytes: Vec<u8>,

    /// Cryptographic algorithm
    #[serde(skip)]
    pub(crate) key_type: KeyType,
}

impl TryFrom<KeyMaterialShadow> for KeyMaterial {
    type Error = KeyError;

    fn try_from(shadow: KeyMaterialShadow) -> Result<Self, Self::Error> {
        match shadow.format {
            KeyMaterialFormat::JWK(jwk) => {
                let mut key = KeyMaterial::from_jwk(&jwk)?;
                key.id = shadow.id;
                key.type_ = shadow.type_;
                Ok(key)
            }
            _ => Err(KeyError::Key("Unsupported key material format".into())),
        }
    }
}

impl KeyMaterial {
    // ========== Generation Methods ==========

    /// Generate a new key pair of the specified type
    pub fn generate(key_type: KeyType) -> Result<Self, KeyError> {
        match key_type {
            KeyType::Ed25519 => Ok(Self::generate_ed25519(None)),
            KeyType::X25519 => Self::generate_x25519(None),
            KeyType::P256 => Self::generate_p256(None),
            KeyType::P384 => Self::generate_p384(None),
            KeyType::Secp256k1 => Self::generate_secp256k1(None),
            _ => Err(KeyError::UnsupportedKeyType(format!("{key_type:?}"))),
        }
    }

    /// Generate a random Ed25519 signing key pair
    #[cfg(feature = "ed25519")]
    pub fn generate_ed25519(seed: Option<&[u8; 32]>) -> Self {
        let kp = affinidi_crypto::ed25519::generate(seed);
        Self::from_parts(kp.key_type, kp.private_bytes, kp.public_bytes, kp.jwk)
    }

    /// Generate a random X25519 key agreement key pair
    #[cfg(feature = "ed25519")]
    pub fn generate_x25519(seed: Option<&[u8; 32]>) -> Result<Self, KeyError> {
        let kp = affinidi_crypto::ed25519::generate_x25519(seed);
        Ok(Self::from_parts(kp.key_type, kp.private_bytes, kp.public_bytes, kp.jwk))
    }

    /// Generate a random P-256 key pair
    #[cfg(feature = "p256")]
    pub fn generate_p256(seed: Option<&[u8]>) -> Result<Self, KeyError> {
        let kp = affinidi_crypto::p256::generate(seed)?;
        Ok(Self::from_parts(kp.key_type, kp.private_bytes, kp.public_bytes, kp.jwk))
    }

    /// Generate a random P-384 key pair
    #[cfg(feature = "p384")]
    pub fn generate_p384(seed: Option<&[u8]>) -> Result<Self, KeyError> {
        let kp = affinidi_crypto::p384::generate(seed)?;
        Ok(Self::from_parts(kp.key_type, kp.private_bytes, kp.public_bytes, kp.jwk))
    }

    /// Generate a random secp256k1 key pair
    #[cfg(feature = "k256")]
    pub fn generate_secp256k1(seed: Option<&[u8]>) -> Result<Self, KeyError> {
        let kp = affinidi_crypto::secp256k1::generate(seed)?;
        Ok(Self::from_parts(kp.key_type, kp.private_bytes, kp.public_bytes, kp.jwk))
    }

    /// Create KeyMaterial from raw key parts
    fn from_parts(key_type: KeyType, private_bytes: Vec<u8>, public_bytes: Vec<u8>, jwk: JWK) -> Self {
        KeyMaterial {
            id: String::new(),
            type_: KeyMaterialType::JsonWebKey2020,
            format: KeyMaterialFormat::JWK(jwk),
            private_bytes,
            public_bytes,
            key_type,
        }
    }

    // ========== Conversion Methods ==========

    /// Helper function to decode base64url to raw bytes
    fn decode_base64url(input: &str) -> Result<Vec<u8>, KeyError> {
        BASE64_URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|e| KeyError::Key(format!("Failed to decode base64url: {e}")))
    }

    /// Creates KeyMaterial from a JWK
    pub fn from_jwk(jwk: &JWK) -> Result<Self, KeyError> {
        match &jwk.params {
            Params::EC(params) => {
                let mut x = Self::decode_base64url(&params.x)?;
                let mut y = Self::decode_base64url(&params.y)?;
                x.append(&mut y);

                Ok(KeyMaterial {
                    id: jwk.key_id.as_ref().unwrap_or(&String::new()).clone(),
                    type_: KeyMaterialType::JsonWebKey2020,
                    format: KeyMaterialFormat::JWK(jwk.clone()),
                    private_bytes: Self::decode_base64url(
                        params
                            .d
                            .as_ref()
                            .ok_or_else(|| KeyError::Key("Missing private key".into()))?,
                    )?,
                    public_bytes: x,
                    key_type: KeyType::try_from(params.curve.as_str())?,
                })
            }
            Params::OKP(params) => Ok(KeyMaterial {
                id: jwk.key_id.as_ref().unwrap_or(&String::new()).clone(),
                type_: KeyMaterialType::JsonWebKey2020,
                format: KeyMaterialFormat::JWK(jwk.clone()),
                private_bytes: Self::decode_base64url(
                    params
                        .d
                        .as_ref()
                        .ok_or_else(|| KeyError::Key("Missing private key".into()))?,
                )?,
                public_bytes: Self::decode_base64url(&params.x)?,
                key_type: KeyType::try_from(params.curve.as_str())?,
            }),
        }
    }

    /// Creates KeyMaterial from a JWK JSON value
    pub fn from_jwk_value(key_id: &str, jwk: &Value) -> Result<Self, KeyError> {
        let mut jwk: JWK = serde_json::from_value(jwk.clone())
            .map_err(|e| KeyError::Key(format!("Failed to parse JWK: {e}")))?;
        jwk.key_id = Some(key_id.to_string());
        Self::from_jwk(&jwk)
    }

    /// Get the public key as multibase (Base58btc) encoded string
    pub fn public_multibase(&self) -> Result<String, KeyError> {
        let codec = Self::public_codec(self.key_type);
        let bytes = self.compress_public_key()?;
        Ok(affinidi_encoding::encode_multikey(codec, &bytes))
    }

    /// Get the private key as multibase (Base58btc) encoded string
    pub fn private_multibase(&self) -> Result<String, KeyError> {
        let codec = Self::private_codec(self.key_type);
        Ok(affinidi_encoding::encode_multikey(codec, &self.private_bytes))
    }

    /// Map KeyType to public key codec
    fn public_codec(key_type: KeyType) -> u64 {
        match key_type {
            KeyType::Ed25519 => ED25519_PUB,
            KeyType::X25519 => X25519_PUB,
            KeyType::P256 => P256_PUB,
            KeyType::P384 => P384_PUB,
            KeyType::Secp256k1 => SECP256K1_PUB,
            _ => 0,
        }
    }

    /// Map KeyType to private key codec
    fn private_codec(key_type: KeyType) -> u64 {
        match key_type {
            KeyType::Ed25519 => ED25519_PRIV,
            KeyType::X25519 => X25519_PRIV,
            KeyType::P256 => P256_PRIV,
            KeyType::P384 => P384_PRIV,
            KeyType::Secp256k1 => SECP256K1_PRIV,
            _ => 0,
        }
    }

    /// Compress public key for EC curves (returns as-is for OKP)
    fn compress_public_key(&self) -> Result<Vec<u8>, KeyError> {
        match self.key_type {
            KeyType::Ed25519 | KeyType::X25519 => Ok(self.public_bytes.clone()),
            KeyType::P256 | KeyType::Secp256k1 => {
                if self.public_bytes.len() < 65 {
                    return Err(KeyError::Key("Invalid public key length".into()));
                }
                let parity: u8 = if self.public_bytes[64].is_multiple_of(2) {
                    0x02
                } else {
                    0x03
                };
                let mut compressed = vec![parity];
                compressed.extend_from_slice(&self.public_bytes[1..33]);
                Ok(compressed)
            }
            KeyType::P384 => {
                if self.public_bytes.len() < 97 {
                    return Err(KeyError::Key("Invalid public key length".into()));
                }
                let parity: u8 = if self.public_bytes[96].is_multiple_of(2) {
                    0x02
                } else {
                    0x03
                };
                let mut compressed = vec![parity];
                compressed.extend_from_slice(&self.public_bytes[1..49]);
                Ok(compressed)
            }
            _ => Err(KeyError::UnsupportedKeyType(format!("{:?}", self.key_type))),
        }
    }

    /// Get raw public key bytes
    pub fn public_bytes(&self) -> &[u8] {
        &self.public_bytes
    }

    /// Get raw private key bytes
    pub fn private_bytes(&self) -> &[u8] {
        &self.private_bytes
    }

    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Convert Ed25519 key to X25519 for key agreement
    pub fn to_x25519(&self) -> Result<Self, KeyError> {
        if self.key_type != KeyType::Ed25519 {
            return Err(KeyError::Key(format!(
                "Can only convert Ed25519 to X25519, got {:?}",
                self.key_type
            )));
        }

        let x25519_private = affinidi_crypto::ed25519::ed25519_private_to_x25519(
            self.private_bytes
                .first_chunk::<32>()
                .ok_or_else(|| KeyError::Key("Invalid Ed25519 private key length".into()))?,
        );

        let x25519_sk = x25519_dalek::StaticSecret::from(x25519_private);
        let x25519_pk = x25519_dalek::PublicKey::from(&x25519_sk);

        let jwk = JWK {
            key_id: None,
            params: Params::OKP(affinidi_crypto::OctectParams {
                curve: "X25519".to_string(),
                x: BASE64_URL_SAFE_NO_PAD.encode(x25519_pk.as_bytes()),
                d: Some(BASE64_URL_SAFE_NO_PAD.encode(x25519_sk.as_bytes())),
            }),
        };

        let mut key = Self::from_jwk(&jwk)?;
        key.id = self.id.clone();
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_from_jwk_ed25519() {
        let jwk = json!({
            "crv": "Ed25519",
            "d": "ymjvUTVuUPzGF5ui12LfreO8bjZ_LbnOrh0sk0xCxMM",
            "kty": "OKP",
            "x": "d17TbZmkoYHZUQpzJTcuOtq0tjWYm8CKvKGYHDW6ZaE"
        });

        let key = KeyMaterial::from_jwk_value("test", &jwk).expect("Failed to parse JWK");
        assert_eq!(key.key_type, KeyType::Ed25519);
        assert!(!key.private_bytes.is_empty());
        assert!(!key.public_bytes.is_empty());
    }

    #[test]
    fn test_to_x25519() {
        let jwk = json!({
            "crv": "Ed25519",
            "d": "ymjvUTVuUPzGF5ui12LfreO8bjZ_LbnOrh0sk0xCxMM",
            "kty": "OKP",
            "x": "d17TbZmkoYHZUQpzJTcuOtq0tjWYm8CKvKGYHDW6ZaE"
        });

        let ed25519 = KeyMaterial::from_jwk_value("test", &jwk).expect("Failed to parse JWK");
        let x25519 = ed25519.to_x25519().expect("Failed to convert to X25519");

        assert_eq!(x25519.key_type, KeyType::X25519);
    }
}
