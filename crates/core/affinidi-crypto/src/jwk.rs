//! JWK (JSON Web Key) types per RFC 7517

#[allow(unused_imports)] // `Codec` is only matched on when a curve feature is enabled.
use affinidi_encoding::{Codec, decode_multikey_checked};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, KeyType, error::key_decoding_error};

/// RFC 7517 JWK Struct
///
/// `#[non_exhaustive]`: construct via [`JWK::new`] (or deserialization) rather
/// than a struct literal, so new fields are not a breaking change. Fields stay
/// public for reads.
#[derive(Debug, Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct JWK {
    #[serde(rename = "kid")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(flatten)]
    pub params: Params,
}

/// An empty public JWK, left behind in a key pair whose JWK has been moved
/// out by `into_parts()` (the key pair is consumed, so it is never read).
#[allow(dead_code)]
pub(crate) fn placeholder_jwk() -> JWK {
    JWK {
        key_id: None,
        params: Params::OKP(OctectParams {
            curve: String::new(),
            x: String::new(),
            d: None,
        }),
    }
}

impl JWK {
    /// Construct a JWK from an optional key id and its parameters.
    pub fn new(key_id: Option<String>, params: Params) -> Self {
        Self { key_id, params }
    }

    /// Returns the KeyType for a JWK
    pub fn key_type(&self) -> KeyType {
        match &self.params {
            Params::EC(params) => match params.curve.as_str() {
                "P-256" => KeyType::P256,
                "secp256k1" => KeyType::Secp256k1,
                "P-384" => KeyType::P384,
                "P-521" => KeyType::P521,
                _ => KeyType::Unknown,
            },
            Params::OKP(params) => match params.curve.as_str() {
                "Ed25519" => KeyType::Ed25519,
                "X25519" => KeyType::X25519,
                _ => KeyType::Unknown,
            },
        }
    }

    /// Converts a multikey string into a public JWK.
    ///
    /// The multikey must be base58btc (`z` prefix) and carry exactly the key
    /// length its codec requires; EC keys are in compressed SEC1 form, as
    /// the Multikey format specifies.
    pub fn from_multikey(key: &str) -> Result<Self, CryptoError> {
        let (codec, data) = decode_multikey_checked(key).map_err(key_decoding_error)?;

        match codec {
            #[cfg(feature = "p256")]
            Codec::P256Pub => crate::p256::public_jwk(&data),
            #[cfg(feature = "p384")]
            Codec::P384Pub => crate::p384::public_jwk(&data),
            #[cfg(feature = "p521")]
            Codec::P521Pub => crate::p521::public_jwk(&data),
            #[cfg(feature = "k256")]
            Codec::Secp256k1Pub => crate::secp256k1::public_jwk(&data),
            #[cfg(feature = "ed25519")]
            Codec::Ed25519Pub => crate::ed25519::public_jwk(&data),
            #[cfg(feature = "ed25519")]
            Codec::X25519Pub => crate::ed25519::x25519_public_jwk(&data),
            codec => Err(CryptoError::UnsupportedKeyType(format!(
                "Unsupported key type codec (0x{:x}, {} key bytes)",
                codec.to_u64(),
                data.len()
            ))),
        }
    }
}

/// JWK Key Types and associated Parameters
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "kty")]
#[non_exhaustive]
pub enum Params {
    EC(ECParams),
    OKP(OctectParams),
}

/// Elliptic Curve parameters (P-256, P-384, secp256k1)
///
/// `#[non_exhaustive]`: construct via [`ECParams::new`] rather than a struct
/// literal. Fields stay public for reads.
#[derive(Serialize, Deserialize, Clone, Zeroize, PartialEq, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct ECParams {
    #[serde(rename = "crv")]
    pub curve: String,
    pub x: String,
    pub y: String,
    /// The private scalar. Omitted from the serialized form when `None`, so a
    /// public JWK carries no `d` member at all (never `"d": null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

impl ECParams {
    /// Construct EC parameters (`d` is the private scalar, `None` for a public
    /// key).
    pub fn new(curve: String, x: String, y: String, d: Option<String>) -> Self {
        Self { curve, x, y, d }
    }
}

impl std::fmt::Debug for ECParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ECParams")
            .field("curve", &self.curve)
            .field("x", &self.x)
            .field("y", &self.y)
            .field("d", &self.d.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Octet Key Pair parameters (Ed25519, X25519)
///
/// `#[non_exhaustive]`: construct via [`OctectParams::new`] rather than a struct
/// literal. Fields stay public for reads.
#[derive(Serialize, Deserialize, Clone, Zeroize, PartialEq, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct OctectParams {
    #[serde(rename = "crv")]
    pub curve: String,
    pub x: String,
    /// The private key. Omitted from the serialized form when `None`, so a
    /// public JWK carries no `d` member at all (never `"d": null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

impl OctectParams {
    /// Construct octet key-pair parameters (`d` is the private key, `None` for
    /// a public key).
    pub fn new(curve: String, x: String, d: Option<String>) -> Self {
        Self { curve, x, d }
    }
}

impl std::fmt::Debug for OctectParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OctectParams")
            .field("curve", &self.curve)
            .field("x", &self.x)
            .field("d", &self.d.as_ref().map(|_| "<redacted>"))
            .finish()
    }
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
    fn debug_redacts_private_d() {
        let okp = OctectParams {
            curve: "Ed25519".to_string(),
            x: "Xx4_L89E6RsyvDTzN9wuN3cDwgifPkXMgFJv_HMIxdk".to_string(),
            d: Some("jybTAuX6NlN7cJLWNCSOLUnJpblpsGr05TTp7scjSvE".to_string()),
        };
        let dbg = format!("{okp:?}");
        assert!(!dbg.contains("jybTAuX6NlN7cJLWNCSOLUnJpblpsGr05TTp7scjSvE"));
        assert!(dbg.contains("<redacted>"));

        let ec = ECParams {
            curve: "P-256".to_string(),
            x: "sl56LMzaiR5efwwWU1jzC_dfbxQ8gzyLj_N1q2cJmkE".to_string(),
            y: "UnAimUtlHMPj_T_wIDVPoJAolKHy8DoXXTb8wch4hgU".to_string(),
            d: Some("kQrTUKhBU-6bHbCdiY0dIfg3knd5U2-1FlLGGHSbF6U".to_string()),
        };
        let dbg = format!("{ec:?}");
        assert!(!dbg.contains("kQrTUKhBU-6bHbCdiY0dIfg3knd5U2-1FlLGGHSbF6U"));
        assert!(dbg.contains("<redacted>"));
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

    /// A public JWK has no `d` member: not `"d": null` (#1054).
    #[test]
    fn public_jwk_serializes_without_d() {
        for key in [
            "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
            "zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
            "zQ3shT2ynSjzY5XoTxhWHvYVZ6GiLWhBVincVekcEpZDRCBHV",
        ] {
            let jwk = JWK::from_multikey(key).unwrap();
            let value = serde_json::to_value(&jwk).unwrap();
            let obj = value.as_object().unwrap();
            assert!(!obj.contains_key("d"), "{key}: {value}");
            let text = serde_json::to_string(&jwk).unwrap();
            assert!(!text.contains("\"d\""), "{key}: {text}");
        }
    }

    /// A private JWK keeps `d`, and a JWK with `"d": null` still parses.
    #[test]
    fn private_jwk_keeps_d_and_null_d_parses() {
        let jwk = crate::ed25519::generate(None).into_parts().jwk;
        let value = serde_json::to_value(&jwk).unwrap();
        assert!(value.get("d").is_some_and(|d| d.is_string()));

        let raw = r#"{"kty":"OKP","crv":"Ed25519","x":"Xx4_L89E6RsyvDTzN9wuN3cDwgifPkXMgFJv_HMIxdk","d":null}"#;
        let parsed: JWK = serde_json::from_str(raw).unwrap();
        match &parsed.params {
            Params::OKP(p) => assert!(p.d.is_none()),
            other => panic!("unexpected params {other:?}"),
        }
        let raw = r#"{"kty":"EC","crv":"P-256","x":"sl56LMzaiR5efwwWU1jzC_dfbxQ8gzyLj_N1q2cJmkE","y":"UnAimUtlHMPj_T_wIDVPoJAolKHy8DoXXTb8wch4hgU"}"#;
        let parsed: JWK = serde_json::from_str(raw).unwrap();
        assert!(!serde_json::to_string(&parsed).unwrap().contains("\"d\""));
    }

    /// A truncated multikey is refused rather than turned into a JWK with a
    /// short `x` (#1056).
    #[test]
    fn from_multikey_refuses_wrong_length() {
        let short = affinidi_encoding::encode_multikey(affinidi_encoding::ED25519_PUB, &[1u8; 31]);
        assert!(matches!(
            JWK::from_multikey(&short),
            Err(CryptoError::KeyError(_))
        ));
        let short = affinidi_encoding::encode_multikey(affinidi_encoding::X25519_PUB, &[1u8; 16]);
        assert!(matches!(
            JWK::from_multikey(&short),
            Err(CryptoError::KeyError(_))
        ));
    }

    #[test]
    fn from_multikey_refuses_unknown_codec() {
        let key = affinidi_encoding::encode_multikey(0x55, &[1u8; 32]);
        assert!(matches!(
            JWK::from_multikey(&key),
            Err(CryptoError::UnsupportedKeyType(_))
        ));
    }
}
