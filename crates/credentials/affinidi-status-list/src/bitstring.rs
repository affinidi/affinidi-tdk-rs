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
use rand::RngExt;
use std::io::{Read, Write};

use crate::error::{Result, StatusListError};

/// Minimum recommended status list size for herd privacy (16KB = 131,072 bits).
pub const MIN_BITSTRING_SIZE: usize = 131_072;

/// Default status list size (16KB).
pub const DEFAULT_BITSTRING_SIZE: usize = MIN_BITSTRING_SIZE;

/// The multibase prefix of base64url (no padding), which W3C Bitstring
/// Status List v1.0 requires on `encodedList`.
pub const MULTIBASE_BASE64URL_PREFIX: char = 'u';

/// The status purpose of a status list entry (`statusPurpose`).
///
/// W3C Bitstring Status List v1.0 defines `revocation`, `suspension`,
/// `refresh` and `message`; any other string deserialises to
/// [`StatusPurpose::Other`] rather than failing, so an entry with an
/// unfamiliar purpose still parses and the caller decides what to do with it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StatusPurpose {
    /// The credential has been revoked (permanent).
    Revocation,
    /// The credential has been suspended (temporary, can be reactivated).
    Suspension,
    /// A refreshed version of the credential is available.
    Refresh,
    /// The status carries a message (`statusMessages`, multi-bit entries).
    Message,
    /// A purpose this crate does not know, kept verbatim.
    Other(String),
}

impl StatusPurpose {
    /// The wire value (`"revocation"`, `"suspension"`, ...).
    pub fn as_str(&self) -> &str {
        match self {
            StatusPurpose::Revocation => "revocation",
            StatusPurpose::Suspension => "suspension",
            StatusPurpose::Refresh => "refresh",
            StatusPurpose::Message => "message",
            StatusPurpose::Other(other) => other,
        }
    }
}

impl From<&str> for StatusPurpose {
    fn from(value: &str) -> Self {
        match value {
            "revocation" => StatusPurpose::Revocation,
            "suspension" => StatusPurpose::Suspension,
            "refresh" => StatusPurpose::Refresh,
            "message" => StatusPurpose::Message,
            other => StatusPurpose::Other(other.to_string()),
        }
    }
}

impl From<String> for StatusPurpose {
    fn from(value: String) -> Self {
        match StatusPurpose::from(value.as_str()) {
            StatusPurpose::Other(_) => StatusPurpose::Other(value),
            known => known,
        }
    }
}

impl std::str::FromStr for StatusPurpose {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(StatusPurpose::from(s))
    }
}

impl std::fmt::Display for StatusPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for StatusPurpose {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for StatusPurpose {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(StatusPurpose::from)
    }
}

/// A bitstring status list: the bits a status list credential publishes.
///
/// Each bit position corresponds to a credential's status:
/// - `0` = valid (not revoked/suspended)
/// - `1` = revoked/suspended
///
/// This is the list as verifiers see it and as [`encode`](Self::encode) /
/// [`decode`](Self::decode) round-trip it. It does **not** know which
/// indices an issuer has handed out: a `0` bit is the same whether the index
/// is free or belongs to a valid credential. Issuers track that in a
/// [`StatusListAllocator`], which they persist alongside the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitstringStatusList {
    /// The raw bitstring (uncompressed).
    bits: Vec<u8>,
    /// Total number of status entries (bits).
    size: usize,
    /// The purpose of this status list.
    pub purpose: StatusPurpose,
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
    ///
    /// This changes the published bit only. Index assignment is tracked by a
    /// [`StatusListAllocator`]; use [`StatusListAllocator::reserve`] to record
    /// an index that was not handed out by that allocator.
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

    /// Encode the status list for the `encodedList` field of a
    /// BitstringStatusListCredential: GZIP-compressed, base64url (no padding),
    /// with the multibase `u` prefix W3C Bitstring Status List v1.0 requires.
    pub fn encode(&self) -> Result<String> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&self.bits)
            .map_err(|e| StatusListError::Compression(e.to_string()))?;
        let compressed = encoder
            .finish()
            .map_err(|e| StatusListError::Compression(e.to_string()))?;
        let mut encoded = String::with_capacity(1 + compressed.len().div_ceil(3) * 4);
        encoded.push(MULTIBASE_BASE64URL_PREFIX);
        URL_SAFE_NO_PAD.encode_string(&compressed, &mut encoded);
        Ok(encoded)
    }

    /// Decode an `encodedList` value: multibase base64url (`u` prefix) of a
    /// GZIP-compressed bitstring.
    ///
    /// For lists written by this crate before 0.2, bare base64url (no
    /// multibase prefix) is also accepted. The two cannot be confused: base64url
    /// of a GZIP stream always starts with `H` (the `1f 8b` magic), never `u`.
    /// Any other multibase prefix is refused with a clear error.
    pub fn decode(encoded: &str, size: usize, purpose: StatusPurpose) -> Result<Self> {
        let b64 = match encoded.strip_prefix(MULTIBASE_BASE64URL_PREFIX) {
            Some(rest) => rest,
            None if encoded.is_empty() || encoded.starts_with('H') => encoded,
            None => {
                return Err(StatusListError::Encoding(format!(
                    "encodedList must be multibase base64url (prefix `{MULTIBASE_BASE64URL_PREFIX}`), \
                     found prefix {:?}",
                    encoded.chars().next().unwrap_or_default()
                )));
            }
        };
        let compressed = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| StatusListError::Encoding(e.to_string()))?;

        let expected_bytes = size.div_ceil(8);
        // Cap inflation at the size we actually need (plus one byte so we can
        // tell "exactly right" from "still more coming"). A hostile issuer
        // could otherwise hand us a few KB of gzip that expands to gigabytes.
        let limit = (expected_bytes as u64).saturating_add(1);
        let mut decoder = GzDecoder::new(&compressed[..]).take(limit);
        let mut bits = Vec::with_capacity(expected_bytes);
        decoder
            .read_to_end(&mut bits)
            .map_err(|e| StatusListError::Compression(e.to_string()))?;

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
        })
    }

    /// Count the number of entries with status = 1 (revoked/suspended).
    pub fn count_set(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }
}

/// [`StatusListAllocator`] picks by rejection sampling while at least
/// `1 / REJECTION_SAMPLING_FREE_DIVISOR` of the list is free (at most that
/// many draws on average); below it, a uniform pick over the free slots by
/// scanning.
const REJECTION_SAMPLING_FREE_DIVISOR: usize = 4;

/// Upper bound on rejection-sampling draws before falling back to the scan.
const REJECTION_SAMPLING_MAX_DRAWS: usize = 64;

/// Issuer-side index assignment for a [`BitstringStatusList`].
///
/// A `0` bit in the published list is indistinguishable between "free" and
/// "issued to a valid credential", so the list alone cannot say which indices
/// are safe to hand out. This allocator is that record: a bitset of assigned
/// indices plus a free count. It is `Serialize`/`Deserialize` and **must be
/// persisted with the list** — an issuer that reloads only the encoded list
/// and allocates from a fresh allocator can hand out an index that already
/// belongs to a still-valid credential, and revoking either then revokes both.
///
/// Serialised form: `{ "size": <entries>, "assigned": "<base64url of the
/// bitset, MSB first, same layout as the list>" }`. The free count is
/// recomputed (and the bitset validated) on deserialisation.
///
/// [`from_list`](Self::from_list) recovers what can be recovered from a list
/// alone (every set bit is reserved); indices of valid credentials cannot be.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "AllocatorRepr", into = "AllocatorRepr")]
pub struct StatusListAllocator {
    /// Assigned indices, MSB-first within each byte (the list's layout).
    assigned: Vec<u8>,
    size: usize,
    free_count: usize,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AllocatorRepr {
    size: usize,
    assigned: String,
}

impl From<StatusListAllocator> for AllocatorRepr {
    fn from(value: StatusListAllocator) -> Self {
        Self {
            size: value.size,
            assigned: URL_SAFE_NO_PAD.encode(&value.assigned),
        }
    }
}

impl TryFrom<AllocatorRepr> for StatusListAllocator {
    type Error = StatusListError;

    fn try_from(value: AllocatorRepr) -> Result<Self> {
        let assigned = URL_SAFE_NO_PAD
            .decode(&value.assigned)
            .map_err(|e| StatusListError::Encoding(format!("allocator bitset: {e}")))?;
        if assigned.len() != value.size.div_ceil(8) {
            return Err(StatusListError::Invalid(format!(
                "allocator bitset is {} bytes, size {} needs {}",
                assigned.len(),
                value.size,
                value.size.div_ceil(8)
            )));
        }
        let tail_bits = value.size % 8;
        if tail_bits != 0 {
            let padding_mask = 0xffu8 >> tail_bits;
            if assigned.last().is_some_and(|b| b & padding_mask != 0) {
                return Err(StatusListError::Invalid(
                    "allocator bitset has bits set past its size".into(),
                ));
            }
        }
        let used = count_ones(&assigned);
        Ok(Self {
            assigned,
            size: value.size,
            free_count: value.size - used,
        })
    }
}

fn count_ones(bytes: &[u8]) -> usize {
    bytes.iter().map(|b| b.count_ones() as usize).sum()
}

impl StatusListAllocator {
    /// An allocator for a list of `size` entries with nothing assigned.
    pub fn new(size: usize) -> Self {
        Self {
            assigned: vec![0u8; size.div_ceil(8)],
            size,
            free_count: size,
        }
    }

    /// An allocator that reserves every index whose bit is set in `list`.
    ///
    /// This is the best that can be rebuilt from a published list: revoked
    /// entries and decoys are reserved, but an index issued to a credential
    /// that is still valid has a `0` bit and is **not** — prefer persisting
    /// the allocator itself.
    pub fn from_list(list: &BitstringStatusList) -> Self {
        let mut assigned = list.bits.clone();
        // Bits past `size` in the last byte are padding, never entries.
        let tail_bits = list.size % 8;
        if tail_bits != 0
            && let Some(last) = assigned.last_mut()
        {
            *last &= !(0xffu8 >> tail_bits);
        }
        let used = count_ones(&assigned);
        Self {
            assigned,
            size: list.size,
            free_count: list.size - used,
        }
    }

    /// The number of entries this allocator covers.
    pub fn size(&self) -> usize {
        self.size
    }

    /// The number of indices not yet assigned.
    pub fn free_count(&self) -> usize {
        self.free_count
    }

    /// Whether `index` has been assigned. Out-of-range indices are not.
    pub fn is_assigned(&self, index: usize) -> bool {
        index < self.size && self.assigned[index / 8] & (0x80 >> (index % 8)) != 0
    }

    /// Mark `index` as assigned (for an index not handed out by
    /// [`allocate_index`](Self::allocate_index), e.g. one chosen by hand).
    /// Returns `Ok(true)` if it was free, `Ok(false)` if already assigned.
    pub fn reserve(&mut self, index: usize) -> Result<bool> {
        if index >= self.size {
            return Err(StatusListError::IndexOutOfBounds {
                index,
                size: self.size,
            });
        }
        Ok(self.mark(index))
    }

    /// Mark an in-range index; `true` if it was free.
    fn mark(&mut self, index: usize) -> bool {
        let mask = 0x80u8 >> (index % 8);
        let byte = &mut self.assigned[index / 8];
        if *byte & mask != 0 {
            return false;
        }
        *byte |= mask;
        self.free_count -= 1;
        true
    }

    /// Allocate a uniformly random unused index for a new credential.
    ///
    /// Uses a cryptographically secure RNG, so the index carries no
    /// information about issuance order. While at least a quarter of the list
    /// is free this is rejection sampling (O(1) expected); otherwise, or if
    /// sampling keeps missing, it picks the k-th free index by scanning the
    /// bitset (O(size / 8), no allocation).
    ///
    /// Returns `None` if every index is assigned.
    pub fn allocate_index(&mut self) -> Option<usize> {
        if self.free_count == 0 {
            return None;
        }
        let mut rng = rand::rng();
        if self
            .free_count
            .saturating_mul(REJECTION_SAMPLING_FREE_DIVISOR)
            >= self.size
        {
            for _ in 0..REJECTION_SAMPLING_MAX_DRAWS {
                let index = rng.random_range(0..self.size);
                if self.mark(index) {
                    return Some(index);
                }
            }
        }
        let k = rng.random_range(0..self.free_count);
        let index = self.nth_free(k)?;
        self.mark(index);
        Some(index)
    }

    /// The index of the `k`-th (0-based) unassigned entry, by scanning.
    fn nth_free(&self, mut k: usize) -> Option<usize> {
        for (byte_index, &byte) in self.assigned.iter().enumerate() {
            let base = byte_index * 8;
            let width = (self.size - base).min(8);
            // Mask of the in-range bit positions of this byte (MSB first).
            let in_range = !(0xffu8.checked_shr(width as u32).unwrap_or(0));
            let free = !byte & in_range;
            let free_here = free.count_ones() as usize;
            if k >= free_here {
                k -= free_here;
                continue;
            }
            for bit in 0..width {
                if free & (0x80 >> bit) != 0 {
                    if k == 0 {
                        return Some(base + bit);
                    }
                    k -= 1;
                }
            }
        }
        None
    }

    /// Add decoy entries: assign up to `count` random unused indices and set
    /// their bits in `list`, obscuring the number of revoked/suspended
    /// credentials.
    ///
    /// Decoys are capped at [`free_count`](Self::free_count) and the number
    /// actually added is returned, so this always terminates (and adds
    /// nothing to an empty or full list). Errors if `list` is not the size
    /// this allocator covers.
    pub fn add_decoys(&mut self, list: &mut BitstringStatusList, count: usize) -> Result<usize> {
        if list.size != self.size {
            return Err(StatusListError::Invalid(format!(
                "allocator covers {} entries but the list has {}",
                self.size, list.size
            )));
        }
        let count = count.min(self.free_count);
        for added in 0..count {
            let Some(index) = self.allocate_index() else {
                return Ok(added);
            };
            list.set(index, true)?;
        }
        Ok(count)
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

    /// The purpose (`revocation`, `suspension`, `refresh`, `message`, ...).
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
        let mut alloc = StatusListAllocator::new(100);

        let idx1 = alloc.allocate_index().unwrap();
        let idx2 = alloc.allocate_index().unwrap();

        assert_ne!(idx1, idx2);
        assert!(idx1 < 100);
        assert!(idx2 < 100);
        assert_eq!(alloc.free_count(), 98);
    }

    #[test]
    fn allocate_exhausts_list() {
        let mut alloc = StatusListAllocator::new(3);

        assert!(alloc.allocate_index().is_some());
        assert!(alloc.allocate_index().is_some());
        assert!(alloc.allocate_index().is_some());
        assert!(alloc.allocate_index().is_none()); // Full
        assert_eq!(alloc.free_count(), 0);
    }

    #[test]
    fn allocate_every_index_exactly_once() {
        // Crosses from rejection sampling to the scan fallback; every index of
        // an odd-sized list (padding bits in the last byte) comes out once.
        let size = 1_003;
        let mut alloc = StatusListAllocator::new(size);
        let mut seen = vec![false; size];
        for _ in 0..size {
            let index = alloc.allocate_index().unwrap();
            assert!(!seen[index], "index {index} allocated twice");
            seen[index] = true;
        }
        assert!(alloc.allocate_index().is_none());
        assert!(seen.iter().all(|&s| s));
    }

    #[test]
    fn allocate_on_empty_list_is_none() {
        let mut alloc = StatusListAllocator::new(0);
        assert_eq!(alloc.allocate_index(), None);
    }

    #[test]
    fn decoy_entries() {
        let mut list = BitstringStatusList::new(1000, StatusPurpose::Revocation);
        let mut alloc = StatusListAllocator::new(1000);
        alloc.reserve(42).unwrap();
        list.set(42, true).unwrap();
        assert_eq!(alloc.add_decoys(&mut list, 10).unwrap(), 10);

        // Should have 11 bits set (1 real + 10 decoy)
        assert_eq!(list.count_set(), 11);
        // Original revocation still present
        assert!(list.get(42).unwrap());
        assert_eq!(alloc.free_count(), 1000 - 11);
    }

    #[test]
    fn decoys_are_always_distinct() {
        // Regression for the decoy-collision flake: `add_decoys(N)` must set
        // exactly N new distinct bits, never colliding with each other or with
        // a real entry. Run many rounds so a reintroduced collision can't hide.
        for _ in 0..500 {
            let mut list = BitstringStatusList::new(1000, StatusPurpose::Revocation);
            let mut alloc = StatusListAllocator::new(1000);
            alloc.reserve(42).unwrap();
            list.set(42, true).unwrap();
            alloc.add_decoys(&mut list, 10).unwrap();
            assert_eq!(list.count_set(), 11);
            assert!(list.get(42).unwrap());
        }
    }

    #[test]
    fn decoys_cap_at_free_count_and_terminate() {
        // Used to loop forever when `count` exceeded the free slots.
        let mut list = BitstringStatusList::new(10, StatusPurpose::Revocation);
        let mut alloc = StatusListAllocator::new(10);
        for _ in 0..7 {
            alloc.allocate_index().unwrap();
        }
        assert_eq!(alloc.add_decoys(&mut list, 1_000).unwrap(), 3);
        assert_eq!(alloc.free_count(), 0);
        assert_eq!(alloc.add_decoys(&mut list, 5).unwrap(), 0);
    }

    #[test]
    fn decoys_on_empty_list_do_not_panic() {
        // Used to panic in `random_range(0..0)`.
        let mut list = BitstringStatusList::new(0, StatusPurpose::Revocation);
        let mut alloc = StatusListAllocator::new(0);
        assert_eq!(alloc.add_decoys(&mut list, 3).unwrap(), 0);
    }

    #[test]
    fn decoys_refuse_a_list_of_another_size() {
        let mut list = BitstringStatusList::new(10, StatusPurpose::Revocation);
        let mut alloc = StatusListAllocator::new(11);
        assert!(alloc.add_decoys(&mut list, 1).is_err());
    }

    #[test]
    fn allocator_survives_a_restart() {
        // The issuer persists the allocator next to the list; after a reload no
        // index already handed out is handed out again, even though its bit
        // in the list is 0 (a valid credential).
        let size = 64;
        let mut alloc = StatusListAllocator::new(size);
        let issued: Vec<usize> = (0..60).map(|_| alloc.allocate_index().unwrap()).collect();

        let saved = serde_json::to_string(&alloc).unwrap();
        let mut reloaded: StatusListAllocator = serde_json::from_str(&saved).unwrap();
        assert_eq!(reloaded, alloc);
        assert_eq!(reloaded.free_count(), 4);

        for _ in 0..4 {
            let index = reloaded.allocate_index().unwrap();
            assert!(!issued.contains(&index), "reissued {index}");
        }
        assert!(reloaded.allocate_index().is_none());
    }

    #[test]
    fn allocator_deserialisation_is_validated() {
        let bad_len = serde_json::json!({ "size": 16, "assigned": "AA" });
        assert!(serde_json::from_value::<StatusListAllocator>(bad_len).is_err());
        // size 4 → one byte whose low four bits are padding; 0x0f sets them.
        let padding_set = serde_json::json!({ "size": 4, "assigned": "Dw" });
        assert!(serde_json::from_value::<StatusListAllocator>(padding_set).is_err());
        let ok = serde_json::json!({ "size": 4, "assigned": "wA" }); // 0xc0
        let alloc: StatusListAllocator = serde_json::from_value(ok).unwrap();
        assert_eq!(alloc.free_count(), 2);
        assert!(alloc.is_assigned(0) && alloc.is_assigned(1) && !alloc.is_assigned(2));
    }

    #[test]
    fn allocator_from_list_reserves_set_bits() {
        let mut list = BitstringStatusList::new(12, StatusPurpose::Revocation);
        list.set(3, true).unwrap();
        list.set(11, true).unwrap();
        let alloc = StatusListAllocator::from_list(&list);
        assert_eq!(alloc.free_count(), 10);
        assert!(alloc.is_assigned(3) && alloc.is_assigned(11));
        assert!(!alloc.is_assigned(4));
    }

    #[test]
    fn reserve_reports_prior_state_and_bounds() {
        let mut alloc = StatusListAllocator::new(8);
        assert!(alloc.reserve(5).unwrap());
        assert!(!alloc.reserve(5).unwrap());
        assert!(alloc.reserve(8).is_err());
        assert_eq!(alloc.free_count(), 7);
    }

    #[test]
    fn encode_has_multibase_prefix() {
        let list = BitstringStatusList::new(1000, StatusPurpose::Revocation);
        let encoded = list.encode().unwrap();
        // W3C Bitstring Status List v1.0: multibase base64url of a GZIP stream.
        assert!(encoded.starts_with("uH4sI"), "{encoded}");
    }

    #[test]
    fn decode_accepts_bare_base64url_from_older_versions() {
        let mut list = BitstringStatusList::new(1000, StatusPurpose::Revocation);
        list.set(7, true).unwrap();
        let encoded = list.encode().unwrap();
        let bare = encoded.strip_prefix('u').unwrap();
        let decoded = BitstringStatusList::decode(bare, 1000, StatusPurpose::Revocation).unwrap();
        assert_eq!(decoded, list);
    }

    #[test]
    fn decode_refuses_other_multibase_prefixes() {
        let err = BitstringStatusList::decode("zabc", 8, StatusPurpose::Revocation).unwrap_err();
        assert!(err.to_string().contains("multibase"), "{err}");
    }

    #[test]
    fn decode_spec_style_list() {
        // A conformant issuer's empty 131,072-entry list, as the spec's
        // examples write it (`u` + base64url of the GZIP stream).
        let list = BitstringStatusList::with_default_size(StatusPurpose::Revocation);
        let encoded = list.encode().unwrap();
        let decoded = BitstringStatusList::decode(
            &encoded,
            DEFAULT_BITSTRING_SIZE,
            StatusPurpose::Revocation,
        )
        .unwrap();
        assert_eq!(decoded.count_set(), 0);
    }

    #[test]
    fn status_purposes_round_trip() {
        for (purpose, wire) in [
            (StatusPurpose::Revocation, "revocation"),
            (StatusPurpose::Suspension, "suspension"),
            (StatusPurpose::Refresh, "refresh"),
            (StatusPurpose::Message, "message"),
            (StatusPurpose::Other("custom".into()), "custom"),
        ] {
            assert_eq!(serde_json::to_value(&purpose).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<StatusPurpose>(wire.into()).unwrap(),
                purpose
            );
            assert_eq!(purpose.to_string(), wire);
        }
    }

    #[test]
    fn entry_with_refresh_purpose_parses() {
        let entry: StatusListEntry = serde_json::from_value(serde_json::json!({
            "id": "https://example.com/status/3#94567",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "refresh",
            "statusListIndex": "94567",
            "statusListCredential": "https://example.com/status/3"
        }))
        .unwrap();
        assert_eq!(entry.status_purpose, StatusPurpose::Refresh);
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
