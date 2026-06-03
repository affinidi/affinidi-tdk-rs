/*!
 * Shared JWT (JSON Web Token) infrastructure for OID4VC protocols.
 *
 * Provides compact JWS encoding/decoding and pluggable signer/verifier traits
 * used by SIOPv2, OpenID4VCI, and OpenID4VP.
 */

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A JWT `aud` (audience) claim, which RFC 7519 §4.1.3 allows to be **either**
/// a single string or an array of strings. Deserialising into this type accepts
/// both wire shapes so consumers don't each re-implement the string-or-array
/// dance (and don't silently mishandle the array form).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// A single audience value.
    One(String),
    /// Multiple audience values.
    Many(Vec<String>),
}

impl Audience {
    /// Whether `value` is one of the audiences.
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Self::One(a) => a == value,
            Self::Many(a) => a.iter().any(|v| v == value),
        }
    }

    /// Iterate the audience values.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        // Box to unify the two arm types behind one iterator.
        let items: Box<dyn Iterator<Item = &str>> = match self {
            Self::One(a) => Box::new(std::iter::once(a.as_str())),
            Self::Many(a) => Box::new(a.iter().map(String::as_str)),
        };
        items
    }
}

/// Error type for JWT operations.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    /// The JWT format is invalid (not 3 dot-separated parts).
    #[error("Invalid JWT format: {0}")]
    InvalidFormat(String),

    /// Signing failed.
    #[error("Signing error: {0}")]
    Signing(String),

    /// Verification failed.
    #[error("Verification error: {0}")]
    Verification(String),

    /// JSON error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64 decoding error.
    #[error("Base64 error: {0}")]
    Base64(String),
}

/// Trait for signing JWT payloads.
///
/// Implementations produce a compact JWS (header.payload.signature).
/// Used across SIOPv2 (ID Tokens), OpenID4VCI (key proofs),
/// and OpenID4VP (request objects).
pub trait JwtSigner: Send + Sync {
    /// The JWS algorithm name for the JWT header `alg` field (e.g., "ES256", "EdDSA").
    fn algorithm(&self) -> &str;

    /// Optional key ID for the JWT header `kid` field.
    fn key_id(&self) -> Option<&str> {
        None
    }

    /// Sign the data and return raw signature bytes.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, JwtError>;
}

/// Trait for verifying JWT signatures.
pub trait JwtVerifier: Send + Sync {
    /// Verify the signature over the data. Returns `Ok(())` if valid.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), JwtError>;
}

/// Encode a JWT header and payload into a compact JWS string.
///
/// Uses the provided signer to create the signature.
pub fn encode_compact_jws(
    header: &Value,
    payload: &Value,
    signer: &dyn JwtSigner,
) -> Result<String, JwtError> {
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(header)?.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(payload)?.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signer.sign(signing_input.as_bytes())?;
    let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);
    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Decode a compact JWS string into header and payload without verifying.
pub fn decode_compact_jws_unverified(jws: &str) -> Result<(Value, Value), JwtError> {
    let parts: Vec<&str> = jws.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(JwtError::InvalidFormat(
            "expected 3 dot-separated parts".into(),
        ));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| JwtError::Base64(format!("header: {e}")))?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| JwtError::Base64(format!("payload: {e}")))?;

    let header: Value = serde_json::from_slice(&header_bytes)?;
    let payload: Value = serde_json::from_slice(&payload_bytes)?;

    Ok((header, payload))
}

/// Decode and verify a compact JWS string.
///
/// Returns the header and payload if the signature is valid.
pub fn decode_compact_jws_verified(
    jws: &str,
    verifier: &dyn JwtVerifier,
) -> Result<(Value, Value), JwtError> {
    let parts: Vec<&str> = jws.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(JwtError::InvalidFormat(
            "expected 3 dot-separated parts".into(),
        ));
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| JwtError::Base64(format!("header: {e}")))?;
    let header: Value = serde_json::from_slice(&header_bytes)?;

    // RFC 7515/7519: an Unsecured JWS (`alg: none`, empty signature) must
    // never satisfy a verified decode. Don't rely on every JwtVerifier impl
    // happening to reject a zero-length signature.
    match header.get("alg").and_then(Value::as_str) {
        Some(alg) if alg.eq_ignore_ascii_case("none") => {
            return Err(JwtError::Verification("alg=none is not permitted".into()));
        }
        Some(_) => {}
        None => {
            return Err(JwtError::Verification("missing alg in JWS header".into()));
        }
    }
    if parts[2].is_empty() {
        return Err(JwtError::Verification("empty JWS signature".into()));
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| JwtError::Base64(format!("signature: {e}")))?;

    verifier.verify(signing_input.as_bytes(), &signature)?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| JwtError::Base64(format!("payload: {e}")))?;
    let payload: Value = serde_json::from_slice(&payload_bytes)?;

    Ok((header, payload))
}

/// Extract the payload from a compact JWS without verification.
pub fn extract_payload(jws: &str) -> Result<Value, JwtError> {
    let (_, payload) = decode_compact_jws_unverified(jws)?;
    Ok(payload)
}

/// Extract the header from a compact JWS without verification.
pub fn extract_header(jws: &str) -> Result<Value, JwtError> {
    let (header, _) = decode_compact_jws_unverified(jws)?;
    Ok(header)
}

/// HMAC-SHA256 test signer/verifier (NOT for production use).
#[cfg(any(test, feature = "_test-utils"))]
pub mod test_utils {
    use super::*;
    use sha2::{Digest, Sha256};

    /// A simple HMAC-SHA256 signer for unit tests.
    ///
    /// **WARNING:** Not constant-time. For testing only.
    pub struct HmacTestSigner {
        key: Vec<u8>,
    }

    impl HmacTestSigner {
        pub fn new(key: &[u8]) -> Self {
            Self { key: key.to_vec() }
        }

        fn hmac(&self, data: &[u8]) -> Vec<u8> {
            let mut key_block = [0u8; 64];
            if self.key.len() <= 64 {
                key_block[..self.key.len()].copy_from_slice(&self.key);
            } else {
                let hash = Sha256::digest(&self.key);
                key_block[..32].copy_from_slice(&hash);
            }

            let mut ipad = [0x36u8; 64];
            let mut opad = [0x5cu8; 64];
            for i in 0..64 {
                ipad[i] ^= key_block[i];
                opad[i] ^= key_block[i];
            }

            let inner = Sha256::new()
                .chain_update(ipad)
                .chain_update(data)
                .finalize();
            Sha256::new()
                .chain_update(opad)
                .chain_update(inner)
                .finalize()
                .to_vec()
        }
    }

    impl JwtSigner for HmacTestSigner {
        fn algorithm(&self) -> &str {
            "HS256"
        }

        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, JwtError> {
            Ok(self.hmac(data))
        }
    }

    /// A simple HMAC-SHA256 verifier for unit tests.
    pub struct HmacTestVerifier {
        signer: HmacTestSigner,
    }

    impl HmacTestVerifier {
        pub fn new(key: &[u8]) -> Self {
            Self {
                signer: HmacTestSigner::new(key),
            }
        }
    }

    impl JwtVerifier for HmacTestVerifier {
        fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), JwtError> {
            let expected = self.signer.hmac(data);
            if expected != signature {
                return Err(JwtError::Verification("signature mismatch".into()));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use test_utils::{HmacTestSigner, HmacTestVerifier};

    #[test]
    fn encode_decode_roundtrip() {
        let signer = HmacTestSigner::new(b"test-key-for-jwt-roundtrip!!!!!");
        let verifier = HmacTestVerifier::new(b"test-key-for-jwt-roundtrip!!!!!");

        let header = json!({"alg": "HS256", "typ": "JWT"});
        let payload = json!({"sub": "user123", "name": "Alice"});

        let jws = encode_compact_jws(&header, &payload, &signer).unwrap();
        assert_eq!(jws.split('.').count(), 3);

        let (decoded_header, decoded_payload) =
            decode_compact_jws_verified(&jws, &verifier).unwrap();
        assert_eq!(decoded_header["alg"], "HS256");
        assert_eq!(decoded_payload["sub"], "user123");
    }

    #[test]
    fn decode_unverified() {
        let signer = HmacTestSigner::new(b"key");
        let jws = encode_compact_jws(&json!({"alg": "HS256"}), &json!({"data": "test"}), &signer)
            .unwrap();

        let (_, payload) = decode_compact_jws_unverified(&jws).unwrap();
        assert_eq!(payload["data"], "test");
    }

    #[test]
    fn verify_wrong_key_fails() {
        let signer = HmacTestSigner::new(b"correct-key");
        let wrong_verifier = HmacTestVerifier::new(b"wrong-key!!");

        let jws = encode_compact_jws(&json!({"alg": "HS256"}), &json!({"x": 1}), &signer).unwrap();

        assert!(decode_compact_jws_verified(&jws, &wrong_verifier).is_err());
    }

    #[test]
    fn rejects_alg_none() {
        let verifier = HmacTestVerifier::new(b"k");
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"x"}"#);
        let jws = format!("{header}.{payload}.");
        let err = decode_compact_jws_verified(&jws, &verifier).unwrap_err();
        assert!(matches!(err, JwtError::Verification(_)), "got {err:?}");
    }

    #[test]
    fn invalid_jwt_format() {
        assert!(decode_compact_jws_unverified("not.a.valid.jwt.too.many.parts").is_err());
        assert!(decode_compact_jws_unverified("only-one-part").is_err());
    }

    #[test]
    fn audience_accepts_string_or_array() {
        let one: Audience = serde_json::from_value(json!("a")).unwrap();
        assert!(one.contains("a") && !one.contains("b"));
        assert_eq!(one.iter().collect::<Vec<_>>(), vec!["a"]);

        let many: Audience = serde_json::from_value(json!(["a", "b"])).unwrap();
        assert!(many.contains("a") && many.contains("b") && !many.contains("c"));
        assert_eq!(many.iter().collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn extract_payload_and_header() {
        let signer = HmacTestSigner::new(b"k");
        let jws = encode_compact_jws(
            &json!({"alg": "HS256", "typ": "JWT"}),
            &json!({"iss": "test"}),
            &signer,
        )
        .unwrap();

        let header = extract_header(&jws).unwrap();
        assert_eq!(header["typ"], "JWT");

        let payload = extract_payload(&jws).unwrap();
        assert_eq!(payload["iss"], "test");
    }
}
