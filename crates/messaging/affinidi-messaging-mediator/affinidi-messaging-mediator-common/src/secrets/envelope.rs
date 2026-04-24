//! Schema-versioned wrapper for every stored entry.
//!
//! Every byte written by a backend is wrapped as
//! `{"version": 1, "kind": "<type>", "data": <inner>}` before it hits the
//! wire. This lets us rename fields, change internal layouts, or switch
//! encodings (JSON → CBOR, say) in future without breaking the cold
//! upgrade path — old entries still parse via the version field and we can
//! migrate them in-place on first read.
//!
//! The `kind` string is compared against what the caller expected; if the
//! stored kind doesn't match, it's an early error rather than a silent
//! shape surprise further in.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::secrets::error::{Result, SecretStoreError};

/// Current envelope schema version. Increment + add a migration in
/// [`Envelope::open`] when the envelope shape itself changes.
pub const ENVELOPE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub version: u32,
    pub kind: String,
    pub data: T,
    /// Unix seconds (UTC) when this envelope was written. Additive
    /// field introduced after the initial schema; envelopes produced
    /// by older writers deserialize as `None` and round-trip without
    /// a stamp. Consumed by the bootstrap-seed sweeper; ignored by
    /// `get` / `put` paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
}

impl<T> Envelope<T> {
    /// Wrap a value as the current envelope version, stamped with the
    /// current wall-clock time.
    pub fn new(kind: impl Into<String>, data: T) -> Self {
        Self::with_created_at(kind, data, Some(now_unix_seconds()))
    }

    /// Construct an envelope with an explicit (or absent) `created_at`.
    /// Useful for tests that need deterministic timestamps and for the
    /// sweeper's index-rewrite path, which preserves the original
    /// timestamp on surviving entries.
    pub fn with_created_at(kind: impl Into<String>, data: T, created_at: Option<u64>) -> Self {
        Self {
            version: ENVELOPE_VERSION,
            kind: kind.into(),
            data,
            created_at,
        }
    }
}

/// Current wall-clock time in Unix seconds. Saturates to `0` on the
/// pathological case of a system clock set before 1970 — envelopes
/// written under those conditions simply look "ancient" to the sweeper
/// and get cleaned up on the next run, which is the right behaviour.
fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl<T> Envelope<T>
where
    T: Serialize,
{
    /// Serialise to bytes (JSON). Fails only on serde errors, which are
    /// bugs by the time we're writing.
    pub fn seal(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }
}

impl<T> Envelope<T>
where
    T: for<'de> Deserialize<'de>,
{
    /// Deserialise from bytes and validate the version + kind. `key` and
    /// `expected_kind` are only used for error reporting.
    pub fn open(bytes: &[u8], key: &str, expected_kind: &'static str) -> Result<T> {
        let envelope: Envelope<T> =
            serde_json::from_slice(bytes).map_err(|e| SecretStoreError::EnvelopeDecode {
                key: key.to_string(),
                reason: e.to_string(),
            })?;
        if envelope.version != ENVELOPE_VERSION {
            return Err(SecretStoreError::EnvelopeUnsupportedVersion {
                key: key.to_string(),
                version: envelope.version,
            });
        }
        if envelope.kind != expected_kind {
            return Err(SecretStoreError::EnvelopeKindMismatch {
                key: key.to_string(),
                expected: expected_kind,
                actual: envelope.kind,
            });
        }
        Ok(envelope.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct Sample {
        name: String,
        value: u32,
    }

    #[test]
    fn roundtrip_happy_path() {
        let original = Sample {
            name: "admin".into(),
            value: 42,
        };
        let env = Envelope::new("sample", original.clone());
        let bytes = env.seal().unwrap();
        let restored: Sample = Envelope::open(&bytes, "test-key", "sample").unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn open_rejects_wrong_kind() {
        let env = Envelope::new(
            "sample",
            Sample {
                name: "x".into(),
                value: 1,
            },
        );
        let bytes = env.seal().unwrap();
        let err = Envelope::<Sample>::open(&bytes, "k", "other-kind").unwrap_err();
        assert!(matches!(err, SecretStoreError::EnvelopeKindMismatch { .. }));
    }

    #[test]
    fn open_rejects_unsupported_version() {
        let bytes = br#"{"version":99,"kind":"sample","data":{"name":"x","value":1}}"#;
        let err = Envelope::<Sample>::open(bytes, "k", "sample").unwrap_err();
        assert!(matches!(
            err,
            SecretStoreError::EnvelopeUnsupportedVersion { .. }
        ));
    }

    #[test]
    fn open_surfaces_malformed_json() {
        let err = Envelope::<Sample>::open(b"not json", "k", "sample").unwrap_err();
        assert!(matches!(err, SecretStoreError::EnvelopeDecode { .. }));
    }

    /// Envelopes written before `created_at` existed on the struct
    /// still round-trip — the field is `#[serde(default)]`, so missing
    /// JSON keys deserialize to `None`. Guards the cold-upgrade path
    /// where a mediator updated to the new envelope shape reads an
    /// entry a pre-update instance wrote.
    #[test]
    fn open_accepts_legacy_envelope_without_created_at() {
        let bytes = br#"{"version":1,"kind":"sample","data":{"name":"x","value":1}}"#;
        let restored: Sample = Envelope::open(bytes, "legacy-key", "sample").unwrap();
        assert_eq!(
            restored,
            Sample {
                name: "x".into(),
                value: 1
            }
        );
    }

    /// Round-trip via `Envelope::new` stamps `created_at` with the
    /// current wall-clock time; the stamped value survives
    /// seal/open when the envelope is parsed back into a full
    /// `Envelope<T>` (rather than just its inner `T`).
    #[test]
    fn new_stamps_created_at_within_a_reasonable_window() {
        let before = now_unix_seconds();
        let env = Envelope::new(
            "sample",
            Sample {
                name: "x".into(),
                value: 1,
            },
        );
        let after = now_unix_seconds();
        let stamped = env.created_at.expect("new() must stamp created_at");
        assert!(
            stamped >= before && stamped <= after,
            "stamp {stamped} outside the [{before}, {after}] window"
        );

        // And the stamp survives a full seal/open when the caller
        // deserializes the whole envelope (not just its inner data).
        let bytes = env.seal().unwrap();
        let parsed: Envelope<Sample> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.created_at, Some(stamped));
    }
}
