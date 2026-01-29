//! JWK (JSON Web Key) types per RFC 7517

use affinidi_encoding::{ED25519_PUB, MultiEncoded, P256_PUB, P384_PUB, SECP256K1_PUB, X25519_PUB};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, KeyType};

/// RFC 7517 JWK Struct
#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct JWK {
    #[serde(rename = "kid")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(flatten)]
    pub params: Params,
}

impl JWK {
    /// Returns the KeyType for a JWK
    pub fn key_type(&self) -> KeyType {
        match &self.params {
            Params::EC(params) => match params.curve.as_str() {
                "P-256" => KeyType::P256,
                "secp256k1" => KeyType::Secp256k1,
                "P-384" => KeyType::P384,
                _ => KeyType::Unknown,
            },
            Params::OKP(params) => match params.curve.as_str() {
                "Ed25519" => KeyType::Ed25519,
                "X25519" => KeyType::X25519,
                _ => KeyType::Unknown,
            },
        }
    }

    /// Converts a multikey string into a JWK struct
    pub fn from_multikey(key: &str) -> Result<Self, CryptoError> {
        // decode multibase
        let (_, data) = multibase::decode(key)
            .map_err(|e| CryptoError::Decoding(format!("Failed to decode multibase: {e}")))?;

        // decode multicodec
        let decoded = MultiEncoded::new(&data)?;

        match decoded.codec() {
            #[cfg(feature = "p256")]
            P256_PUB => crate::p256::public_jwk(decoded.data()),
            #[cfg(feature = "p384")]
            P384_PUB => crate::p384::public_jwk(decoded.data()),
            #[cfg(feature = "k256")]
            SECP256K1_PUB => crate::secp256k1::public_jwk(decoded.data()),
            #[cfg(feature = "ed25519")]
            ED25519_PUB => crate::ed25519::public_jwk(decoded.data()),
            #[cfg(feature = "ed25519")]
            X25519_PUB => crate::ed25519::x25519_public_jwk(decoded.data()),
            codec => Err(CryptoError::UnsupportedKeyType(format!(
                "Unsupported key type codec (0x{codec:x})"
            ))),
        }
    }
}

/// JWK Key Types and associated Parameters
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "kty")]
pub enum Params {
    EC(ECParams),
    OKP(OctectParams),
}

/// Elliptic Curve parameters (P-256, P-384, secp256k1)
#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, PartialEq, ZeroizeOnDrop)]
pub struct ECParams {
    #[serde(rename = "crv")]
    pub curve: String,
    pub x: String,
    pub y: String,
    pub d: Option<String>,
}

/// Octet Key Pair parameters (Ed25519, X25519)
#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, PartialEq, ZeroizeOnDrop)]
pub struct OctectParams {
    #[serde(rename = "crv")]
    pub curve: String,
    pub x: String,
    pub d: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_okp_jwk() {
        let raw = r#"{
            "crv": "Ed25519",
            "d": "jybTAuX6NlN7cJLWNCSOLUnJpblpsGr05TTp7scjSvE",
            "kty": "OKP",
            "x": "Xx4_L89E6RsyvDTzN9wuN3cDwgifPkXMgFJv_HMIxdk"
        }"#;

        let jwk: JWK = serde_json::from_str(raw).expect("Couldn't deserialize JWK");

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
    fn deserialize_ec_jwk() {
        let raw = r#"{
            "crv": "P-256",
            "d": "kQrTUKhBU-6bHbCdiY0dIfg3knd5U2-1FlLGGHSbF6U",
            "kty": "EC",
            "x": "sl56LMzaiR5efwwWU1jzC_dfbxQ8gzyLj_N1q2cJmkE",
            "y": "UnAimUtlHMPj_T_wIDVPoJAolKHy8DoXXTb8wch4hgU"
        }"#;

        let jwk: JWK = serde_json::from_str(raw).expect("Couldn't deserialize JWK");

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

    #[test]
    fn from_multikey_secp256k1() {
        assert!(JWK::from_multikey("zQ3shT2ynSjzY5XoTxhWHvYVZ6GiLWhBVincVekcEpZDRCBHV").is_ok());
    }

    #[test]
    fn from_multikey_p256() {
        assert!(JWK::from_multikey("zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169").is_ok());
    }

    #[test]
    fn from_multikey_p384() {
        assert!(
            JWK::from_multikey(
                "z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9"
            )
            .is_ok()
        );
    }

    #[test]
    fn from_multikey_ed25519() {
        assert!(JWK::from_multikey("z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp").is_ok());
    }
}
