/*!
 * SD-JWT Disclosure: the atomic unit of selective disclosure.
 *
 * A disclosure is a base64url-encoded JSON array:
 * - Object claim: `[salt, claim_name, claim_value]`
 * - Array element: `[salt, claim_value]`
 *
 * The digest of the base64url string is placed in the JWT payload's `_sd` array
 * or as `{"...": digest}` for array elements.
 */

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use serde_json::Value;

use crate::error::{Result, SdJwtError};
use crate::hasher::SdHasher;

/// Claim names reserved by the SD-JWT specification (RFC 9901 §5.2.1).
/// These MUST NOT be used as selectively disclosable claim names.
pub const RESERVED_CLAIM_NAMES: &[&str] = &["_sd", "_sd_alg", "..."];

/// A single selective disclosure.
#[derive(Debug, Clone, PartialEq)]
pub struct Disclosure {
    /// Random salt (base64url-encoded).
    pub salt: String,
    /// Claim name (`None` for array element disclosures).
    pub claim_name: Option<String>,
    /// The disclosed value.
    pub claim_value: Value,
    /// The base64url-encoded serialized form: `base64url([salt, name?, value])`.
    pub serialized: String,
    /// The digest: `hash(serialized)`.
    pub digest: String,
}

impl Disclosure {
    /// Create a new disclosure for an object claim.
    pub fn new_claim(claim_name: &str, claim_value: Value, hasher: &dyn SdHasher) -> Result<Self> {
        let salt = generate_salt();
        Self::build(salt, Some(claim_name.to_string()), claim_value, hasher)
    }

    /// Create a new disclosure for an array element.
    pub fn new_array_element(claim_value: Value, hasher: &dyn SdHasher) -> Result<Self> {
        let salt = generate_salt();
        Self::build(salt, None, claim_value, hasher)
    }

    /// Create a disclosure with a specific salt.
    ///
    /// Intended for reproducing spec test vectors. In production, use
    /// [`new_claim`](Self::new_claim) which generates a random salt.
    pub fn new_claim_with_salt(
        salt: &str,
        claim_name: &str,
        claim_value: Value,
        hasher: &dyn SdHasher,
    ) -> Result<Self> {
        Self::build(
            salt.to_string(),
            Some(claim_name.to_string()),
            claim_value,
            hasher,
        )
    }

    /// Create an array element disclosure with a specific salt.
    ///
    /// Intended for reproducing spec test vectors. In production, use
    /// [`new_array_element`](Self::new_array_element) which generates a random salt.
    pub fn new_array_element_with_salt(
        salt: &str,
        claim_value: Value,
        hasher: &dyn SdHasher,
    ) -> Result<Self> {
        Self::build(salt.to_string(), None, claim_value, hasher)
    }

    /// Parse a disclosure from its base64url-encoded form.
    ///
    /// The digest is recomputed from the serialized bytes using the provided hasher.
    pub fn parse(serialized: &str, hasher: &dyn SdHasher) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD
            .decode(serialized)
            .map_err(|e| SdJwtError::InvalidDisclosure(format!("base64 decode failed: {e}")))?;
        let json_str = String::from_utf8(bytes)
            .map_err(|e| SdJwtError::InvalidDisclosure(format!("invalid UTF-8: {e}")))?;
        let arr: Vec<Value> = serde_json::from_str(&json_str)?;

        let digest = hasher.hash_b64(serialized.as_bytes());

        match arr.len() {
            3 => {
                let salt = arr[0]
                    .as_str()
                    .ok_or_else(|| SdJwtError::InvalidDisclosure("salt must be a string".into()))?
                    .to_string();
                let claim_name = arr[1]
                    .as_str()
                    .ok_or_else(|| {
                        SdJwtError::InvalidDisclosure("claim name must be a string".into())
                    })?
                    .to_string();
                let claim_value = arr[2].clone();

                Ok(Disclosure {
                    salt,
                    claim_name: Some(claim_name),
                    claim_value,
                    serialized: serialized.to_string(),
                    digest,
                })
            }
            2 => {
                let salt = arr[0]
                    .as_str()
                    .ok_or_else(|| SdJwtError::InvalidDisclosure("salt must be a string".into()))?
                    .to_string();
                let claim_value = arr[1].clone();

                Ok(Disclosure {
                    salt,
                    claim_name: None,
                    claim_value,
                    serialized: serialized.to_string(),
                    digest,
                })
            }
            n => Err(SdJwtError::InvalidDisclosure(format!(
                "expected 2 or 3 elements, got {n}"
            ))),
        }
    }

    /// Internal builder shared by all constructors.
    fn build(
        salt: String,
        claim_name: Option<String>,
        claim_value: Value,
        hasher: &dyn SdHasher,
    ) -> Result<Self> {
        let mut arr = vec![Value::String(salt.clone())];
        if let Some(ref name) = claim_name {
            arr.push(Value::String(name.clone()));
        }
        arr.push(claim_value.clone());

        let json_str = serde_json::to_string(&Value::Array(arr))?;
        let serialized = URL_SAFE_NO_PAD.encode(json_str.as_bytes());
        let digest = hasher.hash_b64(serialized.as_bytes());

        Ok(Disclosure {
            salt,
            claim_name,
            claim_value,
            serialized,
            digest,
        })
    }
}

/// Generate a cryptographically random 128-bit salt, base64url-encoded.
///
/// Uses `rand::rng()` which defaults to the OS CSPRNG via `OsRng`.
fn generate_salt() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate a decoy digest using the given hasher.
///
/// The decoy is indistinguishable from a real disclosure digest, hiding
/// the true number of selectively disclosable claims.
pub fn generate_decoy_digest(hasher: &dyn SdHasher) -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    let fake_disclosure = URL_SAFE_NO_PAD.encode(bytes);
    hasher.hash_b64(fake_disclosure.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::Sha256Hasher;

    #[test]
    fn roundtrip_object_claim() {
        let hasher = Sha256Hasher;
        let d = Disclosure::new_claim("name", Value::String("Alice".into()), &hasher).unwrap();

        assert_eq!(d.claim_name.as_deref(), Some("name"));
        assert_eq!(d.claim_value, Value::String("Alice".into()));

        let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn roundtrip_array_element() {
        let hasher = Sha256Hasher;
        let d = Disclosure::new_array_element(Value::String("item".into()), &hasher).unwrap();

        assert!(d.claim_name.is_none());
        let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn known_salt_produces_deterministic_output() {
        let hasher = Sha256Hasher;
        let d1 = Disclosure::new_claim_with_salt(
            "2GLC42sKQveCfGfryNRN9w",
            "given_name",
            Value::String("John".into()),
            &hasher,
        )
        .unwrap();
        let d2 = Disclosure::new_claim_with_salt(
            "2GLC42sKQveCfGfryNRN9w",
            "given_name",
            Value::String("John".into()),
            &hasher,
        )
        .unwrap();

        assert_eq!(d1, d2);
    }

    #[test]
    fn parse_invalid_base64_fails() {
        let hasher = Sha256Hasher;
        assert!(Disclosure::parse("!!!invalid!!!", &hasher).is_err());
    }

    #[test]
    fn parse_invalid_json_fails() {
        let hasher = Sha256Hasher;
        let encoded = URL_SAFE_NO_PAD.encode(b"not json");
        assert!(Disclosure::parse(&encoded, &hasher).is_err());
    }

    #[test]
    fn parse_wrong_element_count_fails() {
        let hasher = Sha256Hasher;
        let encoded = URL_SAFE_NO_PAD.encode(b"[\"salt\"]");
        assert!(Disclosure::parse(&encoded, &hasher).is_err());
        let encoded = URL_SAFE_NO_PAD.encode(b"[\"s\",\"n\",\"v\",\"x\"]");
        assert!(Disclosure::parse(&encoded, &hasher).is_err());
    }

    #[test]
    fn parse_non_string_salt_fails() {
        let hasher = Sha256Hasher;
        let encoded = URL_SAFE_NO_PAD.encode(b"[123,\"name\",\"value\"]");
        let err = Disclosure::parse(&encoded, &hasher).unwrap_err();
        assert!(err.to_string().contains("salt must be a string"));
    }

    #[test]
    fn parse_non_string_claim_name_fails() {
        let hasher = Sha256Hasher;
        let encoded = URL_SAFE_NO_PAD.encode(b"[\"salt\",123,\"value\"]");
        let err = Disclosure::parse(&encoded, &hasher).unwrap_err();
        assert!(err.to_string().contains("claim name must be a string"));
    }

    #[test]
    fn decoy_digest_is_unique() {
        let hasher = Sha256Hasher;
        let d1 = generate_decoy_digest(&hasher);
        let d2 = generate_decoy_digest(&hasher);
        assert_ne!(d1, d2);
    }

    #[test]
    fn complex_claim_value() {
        let hasher = Sha256Hasher;
        let value = serde_json::json!({
            "street": "123 Main St",
            "city": "Anytown"
        });
        let d = Disclosure::new_claim("address", value.clone(), &hasher).unwrap();
        let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
        assert_eq!(parsed.claim_value, value);
    }
}
