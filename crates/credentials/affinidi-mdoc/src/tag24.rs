/*!
 * CBOR Tag 24 (encoded CBOR data item) wrapper.
 *
 * Per RFC 8949 §3.4.5.1, Tag 24 indicates that the enclosed byte string
 * contains a CBOR-encoded data item. ISO 18013-5 uses this extensively:
 *
 * - `IssuerSignedItemBytes = Tag24<IssuerSignedItem>`
 * - `MobileSecurityObjectBytes = Tag24<MobileSecurityObject>`
 * - `DeviceAuthenticationBytes = Tag24<DeviceAuthentication>`
 *
 * The digest of an IssuerSignedItem is computed over the Tag24-wrapped bytes,
 * NOT over a re-serialized form. This module preserves the original bytes
 * during deserialization to ensure digest fidelity.
 */

use serde::{Deserialize, Serialize};

use crate::error::{MdocError, Result};

/// CBOR Tag number 24 (encoded CBOR data item).
pub const TAG_24: u64 = 24;

/// A CBOR Tag 24 wrapper that preserves the original byte encoding.
///
/// When serialized, produces `Tag(24, bstr(CBOR(inner)))`.
/// When deserialized, preserves the original `inner_bytes` for digest computation.
#[derive(Debug, Clone)]
pub struct Tag24<T> {
    /// The deserialized inner value.
    pub inner: T,
    /// The original CBOR-encoded bytes of the inner value.
    /// Used for digest computation to ensure byte-level fidelity.
    pub inner_bytes: Vec<u8>,
}

impl<T: Serialize> Tag24<T> {
    /// Create a new Tag24 by CBOR-encoding the inner value.
    pub fn new(inner: T) -> Result<Self> {
        let mut inner_bytes = Vec::new();
        ciborium::into_writer(&inner, &mut inner_bytes)
            .map_err(|e| MdocError::Cbor(format!("Tag24 encoding: {e}")))?;

        Ok(Tag24 { inner, inner_bytes })
    }
}

impl<T> Tag24<T> {
    /// Get the raw bytes that would be used for digest computation.
    /// This is the CBOR encoding of `Tag(24, bstr(inner_bytes))`.
    pub fn to_tagged_bytes(&self) -> Result<Vec<u8>> {
        // Encode as CBOR: Tag(24, bstr(inner_bytes))
        let tagged = ciborium::Value::Tag(
            TAG_24,
            Box::new(ciborium::Value::Bytes(self.inner_bytes.clone())),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tagged, &mut buf)
            .map_err(|e| MdocError::Cbor(format!("Tag24 tagged encoding: {e}")))?;
        Ok(buf)
    }
}

impl<T: Serialize> Serialize for Tag24<T> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as Tag(24, bstr(inner_bytes))
        let tagged = ciborium::Value::Tag(
            TAG_24,
            Box::new(ciborium::Value::Bytes(self.inner_bytes.clone())),
        );
        tagged.serialize(serializer)
    }
}

impl<'de, T: for<'a> Deserialize<'a>> Deserialize<'de> for Tag24<T> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = ciborium::Value::deserialize(deserializer)?;

        match value {
            ciborium::Value::Tag(TAG_24, inner_val) => {
                let inner_bytes = match *inner_val {
                    ciborium::Value::Bytes(b) => b,
                    other => {
                        return Err(serde::de::Error::custom(format!(
                            "Tag24 inner must be bytes, got: {other:?}"
                        )));
                    }
                };

                let inner: T = ciborium::from_reader(&inner_bytes[..])
                    .map_err(|e| serde::de::Error::custom(format!("Tag24 inner decode: {e}")))?;

                Ok(Tag24 { inner, inner_bytes })
            }
            ciborium::Value::Bytes(inner_bytes) => {
                // Some implementations omit the tag and just use raw bytes
                let inner: T = ciborium::from_reader(&inner_bytes[..])
                    .map_err(|e| serde::de::Error::custom(format!("Tag24 bytes decode: {e}")))?;

                Ok(Tag24 { inner, inner_bytes })
            }
            other => Err(serde::de::Error::custom(format!(
                "expected Tag(24, bstr) or bstr, got: {other:?}"
            ))),
        }
    }
}

impl<T: PartialEq> PartialEq for Tag24<T> {
    fn eq(&self, other: &Self) -> bool {
        self.inner_bytes == other.inner_bytes
    }
}

impl<T: Eq + PartialEq> Eq for Tag24<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag24_roundtrip() {
        let original = ciborium::Value::Text("hello".to_string());
        let tagged = Tag24::new(original.clone()).unwrap();

        // Serialize to CBOR
        let mut buf = Vec::new();
        ciborium::into_writer(&tagged, &mut buf).unwrap();

        // Deserialize back
        let parsed: Tag24<ciborium::Value> = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(parsed.inner, original);
        assert_eq!(parsed.inner_bytes, tagged.inner_bytes);
    }

    #[test]
    fn tag24_preserves_bytes() {
        let value = ciborium::Value::Integer(42.into());
        let t1 = Tag24::new(value.clone()).unwrap();
        let t2 = Tag24::new(value).unwrap();

        // Same value produces same bytes
        assert_eq!(t1.inner_bytes, t2.inner_bytes);
    }

    #[test]
    fn tag24_to_tagged_bytes() {
        let value = ciborium::Value::Text("test".to_string());
        let tagged = Tag24::new(value).unwrap();
        let bytes = tagged.to_tagged_bytes().unwrap();

        // Should start with CBOR tag 24 marker
        // Tag 24 = major type 6 (0xc0) | value 24 = 0xd818
        assert_eq!(bytes[0], 0xd8);
        assert_eq!(bytes[1], 24);
    }

    #[test]
    fn tag24_equality() {
        let t1 = Tag24::new(ciborium::Value::Integer(1.into())).unwrap();
        let t2 = Tag24::new(ciborium::Value::Integer(1.into())).unwrap();
        let t3 = Tag24::new(ciborium::Value::Integer(2.into())).unwrap();

        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
    }
}
