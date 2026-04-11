/*!
 * Bitstring Status List implementation per W3C Bitstring Status List v1.0.
 *
 * A status list is a compressed bitstring where each bit represents the status
 * of a single credential. The bit at a given index is 0 (valid) or 1 (revoked/suspended).
 *
 * Privacy features:
 * - Random index assignment prevents correlation
 * - Decoy entries obscure the actual number of issued credentials
 * - Lists should be large enough for herd privacy (minimum 16KB = 131,072 entries)
 *
 * Reference: https://www.w3.org/TR/vc-bitstring-status-list/
 */

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use rand::Rng;
use std::io::{Read, Write};

use crate::error::{Result, StatusListError};

/// Minimum recommended status list size for herd privacy (16KB = 131,072 bits).
pub const MIN_BITSTRING_SIZE: usize = 131_072;

/// Default status list size (16KB).
pub const DEFAULT_BITSTRING_SIZE: usize = MIN_BITSTRING_SIZE;

/// The status purpose of a status list entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StatusPurpose {
    /// The credential has been revoked (permanent).
    Revocation,
    /// The credential has been suspended (temporary, can be reactivated).
    Suspension,
}

impl std::fmt::Display for StatusPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatusPurpose::Revocation => write!(f, "revocation"),
            StatusPurpose::Suspension => write!(f, "suspension"),
        }
    }
}

/// A bitstring status list for tracking credential status.
///
/// Each bit position corresponds to a credential's status:
/// - `0` = valid (not revoked/suspended)
/// - `1` = revoked/suspended
#[derive(Debug, Clone)]
pub struct BitstringStatusList {
    /// The raw bitstring (uncompressed).
    bits: Vec<u8>,
    /// Total number of status entries (bits).
    size: usize,
    /// The purpose of this status list.
    pub purpose: StatusPurpose,
    /// Tracks which indices have been assigned.
    assigned: Vec<bool>,
}

impl BitstringStatusList {
    /// Create a new status list with the given size (number of entries).
    ///
    /// The size should be at least `MIN_BITSTRING_SIZE` (131,072) for herd privacy.
    pub fn new(size: usize, purpose: StatusPurpose) -> Self {
        let byte_len = size.div_ceil(8);
        Self {
            bits: vec![0u8; byte_len],
            size,
            purpose,
            assigned: vec![false; size],
        }
    }

    /// Create a status list with the default size.
    pub fn with_default_size(purpose: StatusPurpose) -> Self {
        Self::new(DEFAULT_BITSTRING_SIZE, purpose)
    }

    /// Get the total number of entries in the status list.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Allocate a random unused index for a new credential.
    ///
    /// Uses a cryptographically secure RNG for index assignment,
    /// preventing correlation between credential issuance order and status list position.
    ///
    /// Returns `None` if the status list is full.
    pub fn allocate_index(&mut self) -> Option<usize> {
        // Count available slots
        let available: Vec<usize> = (0..self.size).filter(|&i| !self.assigned[i]).collect();

        if available.is_empty() {
            return None;
        }

        let mut rng = rand::rng();
        let pick = rng.random_range(0..available.len());
        let index = available[pick];
        self.assigned[index] = true;
        Some(index)
    }

    /// Get the status of a credential at the given index.
    ///
    /// Returns `true` if the credential is revoked/suspended, `false` if valid.
    pub fn get(&self, index: usize) -> Result<bool> {
        if index >= self.size {
            return Err(StatusListError::IndexOutOfBounds {
                index,
                size: self.size,
            });
        }

        let byte_index = index / 8;
        let bit_index = 7 - (index % 8); // MSB first per spec
        Ok((self.bits[byte_index] >> bit_index) & 1 == 1)
    }

    /// Set the status of a credential at the given index.
    ///
    /// `revoked = true` marks the credential as revoked/suspended.
    /// `revoked = false` marks it as valid (only meaningful for suspension lists).
    pub fn set(&mut self, index: usize, revoked: bool) -> Result<()> {
        if index >= self.size {
            return Err(StatusListError::IndexOutOfBounds {
                index,
                size: self.size,
            });
        }

        let byte_index = index / 8;
        let bit_index = 7 - (index % 8);

        if revoked {
            self.bits[byte_index] |= 1 << bit_index;
        } else {
            self.bits[byte_index] &= !(1 << bit_index);
        }

        Ok(())
    }

    /// Add decoy entries (set random unused bits to 1) to obscure the actual
    /// number of revoked/suspended credentials.
    pub fn add_decoys(&mut self, count: usize) {
        let mut rng = rand::rng();
        let mut added = 0;

        while added < count {
            let index = rng.random_range(0..self.size);
            if !self.assigned[index] {
                let byte_index = index / 8;
                let bit_index = 7 - (index % 8);
                self.bits[byte_index] |= 1 << bit_index;
                added += 1;
            }
        }
    }

    /// Encode the status list as a GZIP-compressed, base64url-encoded string.
    ///
    /// This is the format used in the `encodedList` field of a
    /// BitstringStatusListCredential.
    pub fn encode(&self) -> Result<String> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&self.bits)
            .map_err(|e| StatusListError::Compression(e.to_string()))?;
        let compressed = encoder
            .finish()
            .map_err(|e| StatusListError::Compression(e.to_string()))?;
        Ok(URL_SAFE_NO_PAD.encode(&compressed))
    }

    /// Decode a status list from a GZIP-compressed, base64url-encoded string.
    pub fn decode(encoded: &str, size: usize, purpose: StatusPurpose) -> Result<Self> {
        let compressed = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| StatusListError::Encoding(e.to_string()))?;

        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut bits = Vec::new();
        decoder
            .read_to_end(&mut bits)
            .map_err(|e| StatusListError::Compression(e.to_string()))?;

        let expected_bytes = size.div_ceil(8);
        if bits.len() < expected_bytes {
            return Err(StatusListError::Invalid(format!(
                "decoded bitstring too short: {} bytes, expected {}",
                bits.len(),
                expected_bytes
            )));
        }

        // Truncate to expected size (in case of padding)
        bits.truncate(expected_bytes);

        Ok(Self {
            bits,
            size,
            purpose,
            assigned: vec![false; size], // Assignment state not preserved in encoding
        })
    }

    /// Count the number of entries with status = 1 (revoked/suspended).
    pub fn count_set(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }
}

/// A status list entry to embed in a credential.
///
/// This is the data that gets placed in the credential's `credentialStatus` field.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StatusListEntry {
    /// Entry identifier (typically `<list_uri>#<index>`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Always "BitstringStatusListEntry".
    #[serde(rename = "type")]
    pub entry_type: String,

    /// The purpose: "revocation" or "suspension".
    #[serde(rename = "statusPurpose")]
    pub status_purpose: StatusPurpose,

    /// The URI of the status list credential.
    #[serde(rename = "statusListCredential")]
    pub status_list_credential: String,

    /// The index in the status list bitstring.
    #[serde(rename = "statusListIndex")]
    pub status_list_index: String,
}

impl StatusListEntry {
    /// Create a new status list entry.
    pub fn new(
        status_list_credential: impl Into<String>,
        index: usize,
        purpose: StatusPurpose,
    ) -> Self {
        let credential_uri = status_list_credential.into();
        Self {
            id: Some(format!("{credential_uri}#{index}")),
            entry_type: "BitstringStatusListEntry".to_string(),
            status_purpose: purpose,
            status_list_credential: credential_uri,
            status_list_index: index.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_list_all_valid() {
        let list = BitstringStatusList::new(1000, StatusPurpose::Revocation);
        assert_eq!(list.size(), 1000);
        assert_eq!(list.count_set(), 0);

        for i in 0..1000 {
            assert!(!list.get(i).unwrap());
        }
    }

    #[test]
    fn set_and_get() {
        let mut list = BitstringStatusList::new(100, StatusPurpose::Revocation);

        list.set(42, true).unwrap();
        assert!(list.get(42).unwrap());
        assert!(!list.get(41).unwrap());
        assert!(!list.get(43).unwrap());

        // Unset
        list.set(42, false).unwrap();
        assert!(!list.get(42).unwrap());
    }

    #[test]
    fn set_multiple() {
        let mut list = BitstringStatusList::new(256, StatusPurpose::Suspension);

        list.set(0, true).unwrap();
        list.set(7, true).unwrap();
        list.set(8, true).unwrap();
        list.set(255, true).unwrap();

        assert!(list.get(0).unwrap());
        assert!(list.get(7).unwrap());
        assert!(list.get(8).unwrap());
        assert!(list.get(255).unwrap());
        assert!(!list.get(1).unwrap());
        assert_eq!(list.count_set(), 4);
    }

    #[test]
    fn out_of_bounds() {
        let list = BitstringStatusList::new(100, StatusPurpose::Revocation);
        assert!(list.get(100).is_err());
        assert!(list.get(999).is_err());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut list = BitstringStatusList::new(1000, StatusPurpose::Revocation);
        list.set(42, true).unwrap();
        list.set(500, true).unwrap();
        list.set(999, true).unwrap();

        let encoded = list.encode().unwrap();

        let decoded =
            BitstringStatusList::decode(&encoded, 1000, StatusPurpose::Revocation).unwrap();
        assert!(decoded.get(42).unwrap());
        assert!(decoded.get(500).unwrap());
        assert!(decoded.get(999).unwrap());
        assert!(!decoded.get(0).unwrap());
        assert_eq!(decoded.count_set(), 3);
    }

    #[test]
    fn encode_is_compressed() {
        let list = BitstringStatusList::new(DEFAULT_BITSTRING_SIZE, StatusPurpose::Revocation);
        let encoded = list.encode().unwrap();

        // 16KB of zeros should compress very well
        // Uncompressed base64 would be ~21K chars, compressed should be much less
        assert!(encoded.len() < 1000);
    }

    #[test]
    fn allocate_random_index() {
        let mut list = BitstringStatusList::new(100, StatusPurpose::Revocation);

        let idx1 = list.allocate_index().unwrap();
        let idx2 = list.allocate_index().unwrap();

        assert_ne!(idx1, idx2);
        assert!(idx1 < 100);
        assert!(idx2 < 100);
    }

    #[test]
    fn allocate_exhausts_list() {
        let mut list = BitstringStatusList::new(3, StatusPurpose::Revocation);

        assert!(list.allocate_index().is_some());
        assert!(list.allocate_index().is_some());
        assert!(list.allocate_index().is_some());
        assert!(list.allocate_index().is_none()); // Full
    }

    #[test]
    fn decoy_entries() {
        let mut list = BitstringStatusList::new(1000, StatusPurpose::Revocation);
        list.set(42, true).unwrap();
        list.add_decoys(10);

        // Should have 11 bits set (1 real + 10 decoy)
        assert_eq!(list.count_set(), 11);
        // Original revocation still present
        assert!(list.get(42).unwrap());
    }

    #[test]
    fn status_list_entry_creation() {
        let entry = StatusListEntry::new(
            "https://example.com/status/1",
            42,
            StatusPurpose::Revocation,
        );

        assert_eq!(entry.entry_type, "BitstringStatusListEntry");
        assert_eq!(entry.status_purpose, StatusPurpose::Revocation);
        assert_eq!(entry.status_list_index, "42");
        assert_eq!(entry.status_list_credential, "https://example.com/status/1");
        assert_eq!(entry.id.as_deref(), Some("https://example.com/status/1#42"));
    }

    #[test]
    fn entry_serialization() {
        let entry = StatusListEntry::new(
            "https://example.com/status/1",
            42,
            StatusPurpose::Revocation,
        );
        let json = serde_json::to_string(&entry).unwrap();

        assert!(json.contains("BitstringStatusListEntry"));
        assert!(json.contains("revocation"));
        assert!(json.contains("\"42\""));

        let parsed: StatusListEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status_list_index, "42");
    }

    #[test]
    fn suspension_can_be_reversed() {
        let mut list = BitstringStatusList::new(100, StatusPurpose::Suspension);

        list.set(50, true).unwrap();
        assert!(list.get(50).unwrap());

        // Unsuspend
        list.set(50, false).unwrap();
        assert!(!list.get(50).unwrap());
    }

    #[test]
    fn msb_first_bit_ordering() {
        let mut list = BitstringStatusList::new(16, StatusPurpose::Revocation);

        // Set bit 0 (MSB of first byte)
        list.set(0, true).unwrap();
        assert_eq!(list.bits[0], 0b1000_0000);

        // Set bit 7 (LSB of first byte)
        list.set(7, true).unwrap();
        assert_eq!(list.bits[0], 0b1000_0001);

        // Set bit 8 (MSB of second byte)
        list.set(8, true).unwrap();
        assert_eq!(list.bits[1], 0b1000_0000);
    }

    #[test]
    fn purpose_display() {
        assert_eq!(StatusPurpose::Revocation.to_string(), "revocation");
        assert_eq!(StatusPurpose::Suspension.to_string(), "suspension");
    }
}
