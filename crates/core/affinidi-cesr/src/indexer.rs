//! Indexer: CESR indexed signature codes (index + ondex + raw).

use crate::codec;
use crate::error::CesrError;
use crate::matter::count_to_b64;
use crate::tables::{hardage, indexer_sizage};

/// An indexed CESR signature primitive.
///
/// Indexed signatures include:
/// - A code identifying the signature algorithm
/// - An index (key position in current signing key set)
/// - An optional ondex (key position in prior key set, for rotation)
/// - The raw signature bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Indexer {
    /// The indexer code (e.g., "A" for Ed25519 current-only)
    code: String,
    /// Index into current signing keys
    index: usize,
    /// Index into prior next keys (only used for "both" codes)
    ondex: Option<usize>,
    /// Raw signature bytes
    raw: Vec<u8>,
}

impl Indexer {
    /// Create a new Indexer.
    ///
    /// For "current only" codes (A, C, E), ondex is ignored (same as index).
    /// For "both" codes (B, D, F), ondex specifies the prior key position.
    pub fn new(
        code: &str,
        index: usize,
        ondex: Option<usize>,
        raw: Vec<u8>,
    ) -> Result<Self, CesrError> {
        let _sizage =
            indexer_sizage(code).ok_or_else(|| CesrError::UnknownCode(code.to_string()))?;

        // Validate raw size
        let expected_raw = Self::raw_size_from_code(code)?;
        if raw.len() != expected_raw {
            return Err(CesrError::InvalidRawSize {
                expected: expected_raw,
                got: raw.len(),
            });
        }

        // For "current only" codes, ondex defaults to index
        let effective_ondex = if Self::is_current_only(code) {
            None
        } else {
            ondex
        };

        Ok(Self {
            code: code.to_string(),
            index,
            ondex: effective_ondex,
            raw,
        })
    }

    /// Parse an Indexer from a qb64 string.
    pub fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
        if qb64.is_empty() {
            return Err(CesrError::EmptyInput);
        }

        let first_char = qb64.chars().next().ok_or(CesrError::EmptyInput)?;
        let hs = hardage(first_char).ok_or(CesrError::UnknownCode(first_char.to_string()))?;

        if qb64.len() < hs {
            return Err(CesrError::UnexpectedEnd);
        }

        // For indexer codes, we need to check the indexer_sizage table
        // Small codes (hs=1): code is 1 char, but we need to check if it's an indexer
        let code = &qb64[..hs];
        let sizage =
            indexer_sizage(code).ok_or_else(|| CesrError::UnknownCode(code.to_string()))?;

        if qb64.len() < sizage.fs {
            return Err(CesrError::UnexpectedEnd);
        }

        // Parse index from soft portion
        let ss = sizage.ss;
        let idx_str = &qb64[hs..hs + ss];
        let index = b64_to_count(idx_str)?;

        // For big indexed codes, parse ondex too
        let ondex = if sizage.hs >= 2 && !Self::is_current_only(code) {
            // Big codes with "both" variant: ondex is in second half of soft
            let half = ss / 2;
            let index_val = b64_to_count(&qb64[hs..hs + half])?;
            let ondex_val = b64_to_count(&qb64[hs + half..hs + ss])?;
            // Re-derive index from first half
            return Self::from_qb64_big(code, &sizage, qb64, index_val, ondex_val);
        } else if !Self::is_current_only(code) {
            Some(index) // for small "both" codes, ondex == index
        } else {
            None
        };

        // Extract raw bytes
        let raw = Self::extract_raw(qb64, &sizage)?;

        Ok(Self {
            code: code.to_string(),
            index,
            ondex,
            raw,
        })
    }

    /// Helper for big indexed codes.
    fn from_qb64_big(
        code: &str,
        sizage: &crate::tables::Sizage,
        qb64: &str,
        index: usize,
        ondex: usize,
    ) -> Result<Self, CesrError> {
        let raw = Self::extract_raw(qb64, sizage)?;
        Ok(Self {
            code: code.to_string(),
            index,
            ondex: Some(ondex),
            raw,
        })
    }

    /// Encode this Indexer to qb64.
    pub fn qb64(&self) -> Result<String, CesrError> {
        let sizage =
            indexer_sizage(&self.code).ok_or_else(|| CesrError::UnknownCode(self.code.clone()))?;

        // Encode index into soft portion
        let ss = sizage.ss;
        let index_b64 = if sizage.hs >= 2 && self.ondex.is_some() {
            // Big code with both: split soft between index and ondex
            let half = ss / 2;
            let idx_str = count_to_b64(self.index, half)?;
            let ondex_str = count_to_b64(self.ondex.unwrap_or(self.index), half)?;
            format!("{idx_str}{ondex_str}")
        } else {
            count_to_b64(self.index, ss)?
        };

        // Encode raw bytes
        let lead = codec::lead_bytes(self.raw.len());
        let mut padded = vec![0u8; lead];
        padded.extend_from_slice(&self.raw);
        let encoded = codec::b64_encode(&padded);

        let raw_chars = sizage.fs - sizage.hs - sizage.ss;
        if encoded.len() < raw_chars {
            return Err(CesrError::InvalidRawSize {
                expected: raw_chars,
                got: encoded.len(),
            });
        }
        let raw_b64 = &encoded[encoded.len() - raw_chars..];

        Ok(format!("{}{}{}", self.code, index_b64, raw_b64))
    }

    /// The indexer code.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The index (key position in current signing set).
    pub fn index(&self) -> usize {
        self.index
    }

    /// The ondex (key position in prior key set), if applicable.
    pub fn ondex(&self) -> Option<usize> {
        self.ondex
    }

    /// The raw signature bytes.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Whether this code is "current only" (ondex == index).
    fn is_current_only(code: &str) -> bool {
        matches!(code, "A" | "C" | "E" | "2A" | "2C" | "2E" | "3A")
    }

    /// Get the raw signature size for a given indexer code.
    fn raw_size_from_code(code: &str) -> Result<usize, CesrError> {
        match code {
            "A" | "B" | "C" | "D" | "E" | "F" => Ok(64),       // 64-byte signatures
            "2A" | "2B" | "2C" | "2D" | "2E" | "2F" => Ok(64), // big variants, same sig size
            "3A" | "3B" => Ok(114),                              // Ed448 signatures
            _ => Err(CesrError::UnknownCode(code.to_string())),
        }
    }

    /// Extract raw bytes from qb64.
    fn extract_raw(
        qb64: &str,
        sizage: &crate::tables::Sizage,
    ) -> Result<Vec<u8>, CesrError> {
        let full = &qb64[..sizage.fs];
        let all_bytes = codec::b64_decode(full)?;

        // Use the known raw sizes for each code
        let raw_size = Self::raw_size_from_code(
            &qb64[..sizage.hs],
        )?;

        if all_bytes.len() < raw_size {
            return Err(CesrError::InvalidRawSize {
                expected: raw_size,
                got: all_bytes.len(),
            });
        }

        Ok(all_bytes[all_bytes.len() - raw_size..].to_vec())
    }
}

/// Convert a Base64url string to a count value.
fn b64_to_count(s: &str) -> Result<usize, CesrError> {
    let mut count = 0usize;
    for c in s.bytes() {
        let val = codec::b64_char_to_index(c)? as usize;
        count = count * 64 + val;
    }
    Ok(count)
}

impl std::fmt::Display for Indexer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.qb64() {
            Ok(s) => write!(f, "{s}"),
            Err(e) => write!(f, "<Indexer error: {e}>"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indexer_new_ed25519() {
        let raw = vec![0xAAu8; 64];
        let idx = Indexer::new("A", 0, None, raw.clone()).unwrap();
        assert_eq!(idx.code(), "A");
        assert_eq!(idx.index(), 0);
        assert_eq!(idx.ondex(), None); // current-only
        assert_eq!(idx.raw(), raw.as_slice());
    }

    #[test]
    fn test_indexer_qb64_roundtrip() {
        let raw = vec![0x42u8; 64];
        let idx = Indexer::new("A", 0, None, raw.clone()).unwrap();
        let qb64 = idx.qb64().unwrap();

        assert_eq!(qb64.len(), 88);
        assert!(qb64.starts_with('A'));

        let idx2 = Indexer::from_qb64(&qb64).unwrap();
        assert_eq!(idx2.code(), "A");
        assert_eq!(idx2.index(), 0);
        assert_eq!(idx2.raw(), raw.as_slice());
    }

    #[test]
    fn test_indexer_with_index() {
        let raw = vec![0x55u8; 64];
        let idx = Indexer::new("A", 3, None, raw).unwrap();
        let qb64 = idx.qb64().unwrap();

        let idx2 = Indexer::from_qb64(&qb64).unwrap();
        assert_eq!(idx2.index(), 3);
    }

    #[test]
    fn test_indexer_both_code() {
        let raw = vec![0x77u8; 64];
        let idx = Indexer::new("B", 1, Some(2), raw.clone()).unwrap();
        assert_eq!(idx.code(), "B");
        assert_eq!(idx.index(), 1);
        assert_eq!(idx.ondex(), Some(2));
    }

    #[test]
    fn test_indexer_invalid_raw_size() {
        assert!(Indexer::new("A", 0, None, vec![0u8; 32]).is_err());
    }
}
