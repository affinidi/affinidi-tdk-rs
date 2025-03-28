use askar_crypto::sign::SignatureType;
use serde::{Deserialize, Serialize};
use serde_enum_str::{Deserialize_enum_str, Serialize_enum_str};

use crate::error::{ErrorKind, Result, err_msg};

/// Subset of JWS in generic json serialization used for signed message type.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Jws {
    /// Array of signatures
    pub signatures: Vec<Signature>,

    /// BASE64URL(JWS Payload)
    pub payload: String,
}

/// Represents a signature or MAC over the JWS Payload and
/// the JWS Protected Header.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// JWS unprotected header
    /// Note it isn't serialized and not integrity protected
    pub header: Header,

    /// BASE64URL(UTF8(JWS Protected Header))
    pub protected: String,

    /// BASE64URL(JWS signature)
    /// Note JWS signature input is ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)).
    pub signature: String,
}

/// JWS protected header.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProtectedHeader {
    /// Must be `application/didcomm-signed+json` or `didcomm-signed+json` for now.
    /// Something like `application/didcomm-signed+cbor` can be introduced in the
    /// future.
    pub typ: String,

    /// Cryptographic algorithm used to produce signature.
    pub alg: Algorithm,
}

/// JWS unprotected header.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// KID used to produce signature as DID URL.
    pub kid: String,
}

/// Header of compactly serialized JWS.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub(crate) struct CompactHeader {
    /// Media type of this complete JWS.
    pub typ: String,

    /// Cryptographic algorithm used to produce signature.
    pub alg: Algorithm,

    /// KID used to produce signature as DID URL.
    pub kid: String,
}

/// Represents possible values for `alg` header.
/// Cryptographic algorithm used to produce signature over JWS payload.
#[derive(Deserialize_enum_str, Serialize_enum_str, Debug, Clone, Eq, PartialEq)]
pub enum Algorithm {
    #[serde(rename = "EdDSA")]
    EdDSA,

    #[serde(rename = "ES256")]
    Es256,

    #[serde(rename = "ES256K")]
    Es256K,

    #[serde(other)]
    Other(String),
}

impl Algorithm {
    pub(crate) fn sig_type(&self) -> Result<SignatureType> {
        let sig_type = match self {
            Algorithm::EdDSA => SignatureType::EdDSA,
            Algorithm::Es256 => SignatureType::ES256,
            Algorithm::Es256K => SignatureType::ES256K,
            Algorithm::Other(_) => Err(err_msg(
                ErrorKind::Unsupported,
                "Unsupported signature type",
            ))?,
        };

        Ok(sig_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_serialize_works() {
        let alg = Algorithm::EdDSA;
        let alg = serde_json::to_string(&alg).expect("Unable serialize");
        assert_eq!(alg, "\"EdDSA\"");

        let alg = Algorithm::Es256;
        let alg = serde_json::to_string(&alg).expect("Unable serialize");
        assert_eq!(alg, "\"ES256\"");

        let alg = Algorithm::Es256K;
        let alg = serde_json::to_string(&alg).expect("Unable serialize");
        assert_eq!(alg, "\"ES256K\"");

        let alg = Algorithm::Other("Unknown".into());
        let alg = serde_json::to_string(&alg).expect("Unable serialize");
        assert_eq!(alg, "\"Unknown\"");

        let alg = Algorithm::Other("Unknown 2".into());
        let alg = serde_json::to_string(&alg).expect("Unable serialize");
        assert_eq!(alg, "\"Unknown 2\"");
    }

    #[test]
    fn algorithm_deserialize_works() {
        let alg: Algorithm = serde_json::from_str("\"EdDSA\"").expect("Unable deserialize");

        assert_eq!(alg, Algorithm::EdDSA);

        let alg: Algorithm = serde_json::from_str("\"ES256\"").expect("Unable deserialize");

        assert_eq!(alg, Algorithm::Es256);

        let alg: Algorithm = serde_json::from_str("\"ES256K\"").expect("Unable deserialize");

        assert_eq!(alg, Algorithm::Es256K);

        let alg: Algorithm = serde_json::from_str("\"Unknown\"").expect("Unable deserialize");
        assert_eq!(alg, Algorithm::Other("Unknown".into()));

        let alg: Algorithm = serde_json::from_str("\"Unknown 2\"").expect("Unable deserialize");
        assert_eq!(alg, Algorithm::Other("Unknown 2".into()));
    }
}
