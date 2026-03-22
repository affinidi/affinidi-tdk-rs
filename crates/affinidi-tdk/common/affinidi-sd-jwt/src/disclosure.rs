/*!
 * SD-JWT Disclosure: the atomic unit of selective disclosure.
 *
 * A disclosure is a base64url-encoded JSON array:
 * - Object claim: `[salt, claim_name, claim_value]`
 * - Array element: `[salt, claim_value]`
 *
 * The digest of the base64url string is placed in the JWT payload.
 */

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use serde_json::Value;

use crate::error::{Result, SdJwtError};
use crate::hasher::SdHasher;

/// A single selective disclosure.
#[derive(Debug, Clone)]
pub struct Disclosure {
    /// Random salt (base64url-encoded)
    pub salt: String,
    /// Claim name (None for array element disclosures)
    pub claim_name: Option<String>,
    /// The disclosed value
    pub claim_value: Value,
    /// The base64url-encoded serialized form: base64url([salt, name?, value])
    pub serialized: String,
    /// The digest: hash(serialized)
    pub digest: String,
}

impl Disclosure {
    /// Create a new disclosure for an object claim.
    pub fn new_claim(claim_name: &str, claim_value: Value, hasher: &dyn SdHasher) -> Result<Self> {
        let salt = generate_salt();
        let arr = Value::Array(vec![
            Value::String(salt.clone()),
            Value::String(claim_name.to_string()),
            claim_value.clone(),
        ]);
        let json_str = serde_json::to_string(&arr)?;
        let serialized = URL_SAFE_NO_PAD.encode(json_str.as_bytes());
        let digest = hasher.hash_b64(serialized.as_bytes());

        Ok(Disclosure {
            salt,
            claim_name: Some(claim_name.to_string()),
            claim_value,
            serialized,
            digest,
        })
    }

    /// Create a new disclosure for an array element.
    pub fn new_array_element(claim_value: Value, hasher: &dyn SdHasher) -> Result<Self> {
        let salt = generate_salt();
        let arr = Value::Array(vec![Value::String(salt.clone()), claim_value.clone()]);
        let json_str = serde_json::to_string(&arr)?;
        let serialized = URL_SAFE_NO_PAD.encode(json_str.as_bytes());
        let digest = hasher.hash_b64(serialized.as_bytes());

        Ok(Disclosure {
            salt,
            claim_name: None,
            claim_value,
            serialized,
            digest,
        })
    }

    /// Create a disclosure with a specific salt (for test vectors).
    pub fn new_claim_with_salt(
        salt: &str,
        claim_name: &str,
        claim_value: Value,
        hasher: &dyn SdHasher,
    ) -> Result<Self> {
        let arr = Value::Array(vec![
            Value::String(salt.to_string()),
            Value::String(claim_name.to_string()),
            claim_value.clone(),
        ]);
        let json_str = serde_json::to_string(&arr)?;
        let serialized = URL_SAFE_NO_PAD.encode(json_str.as_bytes());
        let digest = hasher.hash_b64(serialized.as_bytes());

        Ok(Disclosure {
            salt: salt.to_string(),
            claim_name: Some(claim_name.to_string()),
            claim_value,
            serialized,
            digest,
        })
    }

    /// Create an array element disclosure with a specific salt (for test vectors).
    pub fn new_array_element_with_salt(
        salt: &str,
        claim_value: Value,
        hasher: &dyn SdHasher,
    ) -> Result<Self> {
        let arr = Value::Array(vec![Value::String(salt.to_string()), claim_value.clone()]);
        let json_str = serde_json::to_string(&arr)?;
        let serialized = URL_SAFE_NO_PAD.encode(json_str.as_bytes());
        let digest = hasher.hash_b64(serialized.as_bytes());

        Ok(Disclosure {
            salt: salt.to_string(),
            claim_name: None,
            claim_value,
            serialized,
            digest,
        })
    }

    /// Parse a disclosure from its base64url-encoded form.
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
                // Object claim: [salt, name, value]
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
                // Array element: [salt, value]
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
}

/// Generate a random 128-bit salt, base64url-encoded.
fn generate_salt() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate a decoy digest using the given hasher.
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
        assert!(!d.serialized.is_empty());
        assert!(!d.digest.is_empty());

        // Parse back
        let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
        assert_eq!(parsed.claim_name, d.claim_name);
        assert_eq!(parsed.claim_value, d.claim_value);
        assert_eq!(parsed.digest, d.digest);
    }

    #[test]
    fn roundtrip_array_element() {
        let hasher = Sha256Hasher;
        let d = Disclosure::new_array_element(Value::String("item".into()), &hasher).unwrap();

        assert!(d.claim_name.is_none());
        assert_eq!(d.claim_value, Value::String("item".into()));

        let parsed = Disclosure::parse(&d.serialized, &hasher).unwrap();
        assert!(parsed.claim_name.is_none());
        assert_eq!(parsed.claim_value, d.claim_value);
        assert_eq!(parsed.digest, d.digest);
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

        assert_eq!(d1.serialized, d2.serialized);
        assert_eq!(d1.digest, d2.digest);
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
        // 1 element
        let encoded = URL_SAFE_NO_PAD.encode(b"[\"salt\"]");
        assert!(Disclosure::parse(&encoded, &hasher).is_err());
        // 4 elements
        let encoded = URL_SAFE_NO_PAD.encode(b"[\"s\",\"n\",\"v\",\"x\"]");
        assert!(Disclosure::parse(&encoded, &hasher).is_err());
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
