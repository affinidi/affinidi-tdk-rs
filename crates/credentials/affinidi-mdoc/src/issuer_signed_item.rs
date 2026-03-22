/*!
 * IssuerSignedItem — the atomic data element in an mdoc.
 *
 * Per ISO 18013-5 §9.1.2.4, each attribute is encoded as:
 *
 * ```text
 * IssuerSignedItem = {
 *   "digestID": uint,
 *   "random": bstr,
 *   "elementIdentifier": tstr,
 *   "elementValue": DataElementValue
 * }
 * ```
 *
 * Always wrapped as `IssuerSignedItemBytes = Tag24<IssuerSignedItem>`.
 * The digest in the MSO is `SHA-256(CBOR(Tag24<IssuerSignedItem>))`.
 */

use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::{MdocError, Result};
use crate::tag24::Tag24;

/// Minimum random salt length per ISO 18013-5 (16 bytes).
const MIN_RANDOM_LENGTH: usize = 16;

/// Default random salt length (32 bytes for extra security).
const DEFAULT_RANDOM_LENGTH: usize = 32;

/// An IssuerSignedItem per ISO 18013-5 §9.1.2.4.
///
/// This is the structure that gets CBOR-encoded, wrapped in Tag24,
/// and then hashed to produce the digest in the MSO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerSignedItem {
    /// The digest ID — matches the key in `MSO.valueDigests[namespace]`.
    #[serde(rename = "digestID")]
    pub digest_id: u32,

    /// Random salt bytes (minimum 16 bytes per spec).
    #[serde(with = "serde_bytes")]
    pub random: Vec<u8>,

    /// The attribute identifier (e.g., "family_name").
    #[serde(rename = "elementIdentifier")]
    pub element_identifier: String,

    /// The attribute value (any CBOR type).
    #[serde(rename = "elementValue")]
    pub element_value: ciborium::Value,
}

impl IssuerSignedItem {
    /// Create a new IssuerSignedItem with a random salt.
    pub fn new(
        digest_id: u32,
        element_identifier: impl Into<String>,
        element_value: ciborium::Value,
    ) -> Self {
        let mut rng = rand::rng();
        let mut random = vec![0u8; DEFAULT_RANDOM_LENGTH];
        rng.fill(&mut random[..]);

        Self {
            digest_id,
            random,
            element_identifier: element_identifier.into(),
            element_value,
        }
    }

    /// Create an IssuerSignedItem with a specific salt (for test vectors).
    pub fn with_random(
        digest_id: u32,
        element_identifier: impl Into<String>,
        element_value: ciborium::Value,
        random: Vec<u8>,
    ) -> Result<Self> {
        if random.len() < MIN_RANDOM_LENGTH {
            return Err(MdocError::InvalidMso(format!(
                "random salt must be at least {MIN_RANDOM_LENGTH} bytes, got {}",
                random.len()
            )));
        }

        Ok(Self {
            digest_id,
            random,
            element_identifier: element_identifier.into(),
            element_value,
        })
    }

    /// Wrap this item in Tag24, producing the `IssuerSignedItemBytes`.
    pub fn to_tagged(&self) -> Result<Tag24<IssuerSignedItem>> {
        Tag24::new(self.clone())
    }

    /// Compute the digest of this item as it would appear in the MSO.
    ///
    /// The digest is: `hash(CBOR(Tag24(self)))` — the hash is computed
    /// over the complete Tag24-wrapped CBOR encoding.
    pub fn compute_digest(&self, algorithm: &str) -> Result<Vec<u8>> {
        let tagged = self.to_tagged()?;
        let tagged_bytes = tagged.to_tagged_bytes()?;
        compute_hash(algorithm, &tagged_bytes)
    }
}

/// Compute a hash using the named algorithm.
pub fn compute_hash(algorithm: &str, data: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        "SHA-256" => Ok(Sha256::digest(data).to_vec()),
        "SHA-384" => Ok(Sha384::digest(data).to_vec()),
        "SHA-512" => Ok(Sha512::digest(data).to_vec()),
        _ => Err(MdocError::InvalidMso(format!(
            "unsupported digest algorithm: {algorithm}"
        ))),
    }
}

/// Generate a decoy digest — a random hash that is indistinguishable
/// from real digests to prevent leaking the number of attributes.
pub fn generate_decoy_digest(algorithm: &str) -> Result<Vec<u8>> {
    let mut rng = rand::rng();
    let mut random_data = vec![0u8; 64];
    rng.fill(&mut random_data[..]);
    compute_hash(algorithm, &random_data)
}

/// Convert a `serde_json::Value` to a `ciborium::Value`.
///
/// Used to convert JSON attribute values to CBOR for IssuerSignedItem encoding.
pub fn json_to_cbor(value: &serde_json::Value) -> ciborium::Value {
    match value {
        serde_json::Value::Null => ciborium::Value::Null,
        serde_json::Value::Bool(b) => ciborium::Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                ciborium::Value::Integer(i.into())
            } else if let Some(f) = n.as_f64() {
                ciborium::Value::Float(f)
            } else {
                ciborium::Value::Null
            }
        }
        serde_json::Value::String(s) => ciborium::Value::Text(s.clone()),
        serde_json::Value::Array(arr) => {
            ciborium::Value::Array(arr.iter().map(json_to_cbor).collect())
        }
        serde_json::Value::Object(obj) => {
            let entries = obj
                .iter()
                .map(|(k, v)| (ciborium::Value::Text(k.clone()), json_to_cbor(v)))
                .collect();
            ciborium::Value::Map(entries)
        }
    }
}

/// Convert a `ciborium::Value` to a `serde_json::Value`.
pub fn cbor_to_json(value: &ciborium::Value) -> serde_json::Value {
    match value {
        ciborium::Value::Null => serde_json::Value::Null,
        ciborium::Value::Bool(b) => serde_json::Value::Bool(*b),
        ciborium::Value::Integer(i) => {
            let n: i128 = (*i).into();
            serde_json::json!(n)
        }
        ciborium::Value::Float(f) => serde_json::json!(f),
        ciborium::Value::Text(s) => serde_json::Value::String(s.clone()),
        ciborium::Value::Bytes(b) => serde_json::Value::String(hex::encode(b)),
        ciborium::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(cbor_to_json).collect())
        }
        ciborium::Value::Map(entries) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in entries {
                let key = match k {
                    ciborium::Value::Text(s) => s.clone(),
                    other => format!("{other:?}"),
                };
                obj.insert(key, cbor_to_json(v));
            }
            serde_json::Value::Object(obj)
        }
        ciborium::Value::Tag(_, inner) => cbor_to_json(inner),
        _ => serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_signed_item_cbor_roundtrip() {
        let item = IssuerSignedItem::new(0, "family_name", ciborium::Value::Text("Doe".into()));

        // Encode to CBOR
        let mut buf = Vec::new();
        ciborium::into_writer(&item, &mut buf).unwrap();

        // Decode back
        let decoded: IssuerSignedItem = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded.digest_id, 0);
        assert_eq!(decoded.element_identifier, "family_name");
        assert_eq!(decoded.element_value, ciborium::Value::Text("Doe".into()));
        assert_eq!(decoded.random.len(), DEFAULT_RANDOM_LENGTH);
    }

    #[test]
    fn tag24_wrapped_item() {
        let item = IssuerSignedItem::new(0, "given_name", ciborium::Value::Text("John".into()));
        let tagged = item.to_tagged().unwrap();

        assert_eq!(tagged.inner.element_identifier, "given_name");

        // Serialize the Tag24
        let mut buf = Vec::new();
        ciborium::into_writer(&tagged, &mut buf).unwrap();

        // First byte should indicate Tag 24
        assert_eq!(buf[0], 0xd8);
        assert_eq!(buf[1], 24);
    }

    #[test]
    fn digest_is_deterministic_with_same_salt() {
        let random = vec![0xab; 32];
        let item1 = IssuerSignedItem::with_random(
            0,
            "name",
            ciborium::Value::Text("Alice".into()),
            random.clone(),
        )
        .unwrap();
        let item2 =
            IssuerSignedItem::with_random(0, "name", ciborium::Value::Text("Alice".into()), random)
                .unwrap();

        let d1 = item1.compute_digest("SHA-256").unwrap();
        let d2 = item2.compute_digest("SHA-256").unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn digest_differs_with_different_salt() {
        let item1 = IssuerSignedItem::with_random(
            0,
            "name",
            ciborium::Value::Text("Alice".into()),
            vec![1u8; 32],
        )
        .unwrap();
        let item2 = IssuerSignedItem::with_random(
            0,
            "name",
            ciborium::Value::Text("Alice".into()),
            vec![2u8; 32],
        )
        .unwrap();

        let d1 = item1.compute_digest("SHA-256").unwrap();
        let d2 = item2.compute_digest("SHA-256").unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn digest_differs_with_different_value() {
        let random = vec![0xab; 32];
        let item1 = IssuerSignedItem::with_random(
            0,
            "name",
            ciborium::Value::Text("Alice".into()),
            random.clone(),
        )
        .unwrap();
        let item2 =
            IssuerSignedItem::with_random(0, "name", ciborium::Value::Text("Bob".into()), random)
                .unwrap();

        let d1 = item1.compute_digest("SHA-256").unwrap();
        let d2 = item2.compute_digest("SHA-256").unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn digest_is_32_bytes_sha256() {
        let item = IssuerSignedItem::new(0, "test", ciborium::Value::Text("value".into()));
        let digest = item.compute_digest("SHA-256").unwrap();
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn digest_is_48_bytes_sha384() {
        let item = IssuerSignedItem::new(0, "test", ciborium::Value::Text("value".into()));
        let digest = item.compute_digest("SHA-384").unwrap();
        assert_eq!(digest.len(), 48);
    }

    #[test]
    fn digest_is_64_bytes_sha512() {
        let item = IssuerSignedItem::new(0, "test", ciborium::Value::Text("value".into()));
        let digest = item.compute_digest("SHA-512").unwrap();
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn reject_short_random() {
        let result = IssuerSignedItem::with_random(
            0,
            "test",
            ciborium::Value::Text("value".into()),
            vec![0u8; 8], // Too short
        );
        assert!(result.is_err());
    }

    #[test]
    fn unsupported_algorithm_fails() {
        let item = IssuerSignedItem::new(0, "test", ciborium::Value::Text("value".into()));
        assert!(item.compute_digest("MD5").is_err());
    }

    #[test]
    fn json_to_cbor_string() {
        let json = serde_json::json!("hello");
        let cbor = json_to_cbor(&json);
        assert_eq!(cbor, ciborium::Value::Text("hello".into()));
    }

    #[test]
    fn json_to_cbor_number() {
        let json = serde_json::json!(42);
        let cbor = json_to_cbor(&json);
        assert_eq!(cbor, ciborium::Value::Integer(42.into()));
    }

    #[test]
    fn json_to_cbor_bool() {
        assert_eq!(
            json_to_cbor(&serde_json::json!(true)),
            ciborium::Value::Bool(true)
        );
    }

    #[test]
    fn json_to_cbor_null() {
        assert_eq!(
            json_to_cbor(&serde_json::json!(null)),
            ciborium::Value::Null
        );
    }

    #[test]
    fn json_to_cbor_object() {
        let json = serde_json::json!({"name": "Alice", "age": 30});
        let cbor = json_to_cbor(&json);
        match cbor {
            ciborium::Value::Map(entries) => assert_eq!(entries.len(), 2),
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn cbor_to_json_roundtrip() {
        let json = serde_json::json!({"name": "Alice", "verified": true, "score": 42});
        let cbor = json_to_cbor(&json);
        let back = cbor_to_json(&cbor);
        assert_eq!(back["name"], "Alice");
        assert_eq!(back["verified"], true);
    }

    #[test]
    fn decoy_digest_unique() {
        let d1 = generate_decoy_digest("SHA-256").unwrap();
        let d2 = generate_decoy_digest("SHA-256").unwrap();
        assert_ne!(d1, d2);
        assert_eq!(d1.len(), 32);
    }
}
