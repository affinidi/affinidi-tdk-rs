//! Indexer: CESR indexed signature codes (index + ondex + raw).
//!
//! Follows keripy's `Indexer` (`keri/core/indexing.py`, b70986f): its code
//! table, its code sizes, and its rules for the `ondex`.

use crate::codec;
use crate::error::CesrError;
use crate::matter::count_to_b64;
use crate::tables::{indexer_hardage, indexer_is_current_only, indexer_other_size, indexer_sizage};

/// An indexed CESR signature primitive.
///
/// An indexed signature carries:
/// - a code naming the signature algorithm, and whether the signing key is in
///   both key lists or the current one only;
/// - an `index`: the signing key's position in the current key list;
/// - an `ondex`: its position in the prior next-key list, for a key in both
///   lists; `None` for a current-only code;
/// - the raw signature.
///
/// | | both lists | current only |
/// |---|---|---|
/// | Ed25519 | `A`, big `2A` | `B`, big `2B` |
/// | ECDSA secp256k1 | `C`, big `2C` | `D`, big `2D` |
/// | ECDSA secp256r1 | `E`, big `2E` | `F`, big `2F` |
/// | Ed448 | `0A`, big `3A` | `0B`, big `3B` |
///
/// A small both-lists code (`A`, `C`, `E`) has no room for an ondex of its
/// own: the key is at the same position in both lists. A key at different
/// positions needs a big code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Indexer {
    /// The indexer code.
    code: String,
    /// The signing key's position in the current key list.
    index: usize,
    /// Its position in the prior next-key list; `None` for a current-only code.
    ondex: Option<usize>,
    /// Raw signature bytes.
    raw: Vec<u8>,
}

impl Indexer {
    /// Create a new Indexer.
    ///
    /// For a both-lists code, `ondex` defaults to `index`, and a code with no
    /// room for an ondex of its own (`A`, `C`, `E`) refuses one that differs.
    /// A current-only code carries no ondex: one given is dropped, as before
    /// 0.1.4, so callers built against the older reading keep working.
    ///
    /// # Errors
    /// [`CesrError::UnknownCode`] for an unknown code,
    /// [`CesrError::InvalidRawSize`] for a signature of the wrong size, and
    /// [`CesrError::InvalidIndex`] for an index or ondex the code cannot carry.
    pub fn new(
        code: &str,
        index: usize,
        ondex: Option<usize>,
        raw: Vec<u8>,
    ) -> Result<Self, CesrError> {
        let sizage =
            indexer_sizage(code).ok_or_else(|| CesrError::UnknownCode(code.to_string()))?;
        let os = indexer_other_size(code).unwrap_or(0);
        let ms = sizage.ss - os;

        let expected_raw = Self::raw_size_from_code(code)?;
        if raw.len() != expected_raw {
            return Err(CesrError::InvalidRawSize {
                expected: expected_raw,
                got: raw.len(),
            });
        }

        if index >= 64usize.pow(ms as u32) {
            return Err(CesrError::InvalidIndex(format!(
                "index {index} does not fit code {code}"
            )));
        }
        let ondex = if indexer_is_current_only(code) {
            None
        } else {
            let o = ondex.unwrap_or(index);
            if os == 0 && o != index {
                return Err(CesrError::InvalidIndex(format!(
                    "code {code} puts the key at the same position in both lists, but \
                     index {index} and ondex {o} differ: use a big code"
                )));
            }
            if os > 0 && o >= 64usize.pow(os as u32) {
                return Err(CesrError::InvalidIndex(format!(
                    "ondex {o} does not fit code {code}"
                )));
            }
            Some(o)
        };

        Ok(Self {
            code: code.to_string(),
            index,
            ondex,
            raw,
        })
    }

    /// Parse an Indexer from a qb64 string.
    ///
    /// # Errors
    /// As [`Indexer::new`], plus [`CesrError::UnexpectedEnd`] for truncated
    /// input and [`CesrError::InvalidIndex`] for a current-only code whose
    /// ondex characters are not zero.
    pub fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
        if qb64.is_empty() {
            return Err(CesrError::EmptyInput);
        }
        codec::ensure_ascii(qb64)?;

        let first_char = qb64.chars().next().ok_or(CesrError::EmptyInput)?;
        let hs = indexer_hardage(first_char)
            .ok_or_else(|| CesrError::UnknownCode(first_char.to_string()))?;
        if qb64.len() < hs {
            return Err(CesrError::UnexpectedEnd);
        }
        let code = &qb64[..hs];
        let sizage =
            indexer_sizage(code).ok_or_else(|| CesrError::UnknownCode(code.to_string()))?;
        if qb64.len() < sizage.fs {
            return Err(CesrError::UnexpectedEnd);
        }
        let os = indexer_other_size(code).unwrap_or(0);
        let ms = sizage.ss - os;

        let index = b64_to_count(&qb64[hs..hs + ms])?;
        let ondex_chars = &qb64[hs + ms..hs + sizage.ss];
        let ondex = if indexer_is_current_only(code) {
            // keripy: a current-only code's ondex characters must be zero.
            if os > 0 && b64_to_count(ondex_chars)? != 0 {
                return Err(CesrError::InvalidIndex(format!(
                    "current-only code {code} carries a non-zero ondex"
                )));
            }
            None
        } else if os > 0 {
            Some(b64_to_count(ondex_chars)?)
        } else {
            Some(index)
        };

        let raw = Self::extract_raw(qb64, code, &sizage)?;
        Self::new(code, index, ondex, raw)
    }

    /// Encode this Indexer to qb64.
    ///
    /// # Errors
    /// Returns [`CesrError`] if the code is unknown or the material does not
    /// fit it.
    pub fn qb64(&self) -> Result<String, CesrError> {
        let sizage =
            indexer_sizage(&self.code).ok_or_else(|| CesrError::UnknownCode(self.code.clone()))?;
        let os = indexer_other_size(&self.code).unwrap_or(0);
        let ms = sizage.ss - os;

        let mut soft = count_to_b64(self.index, ms)?;
        if os > 0 {
            // A current-only code writes zeros where the ondex would be.
            soft.push_str(&count_to_b64(self.ondex.unwrap_or(0), os)?);
        }

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

        Ok(format!("{}{}{}", self.code, soft, raw_b64))
    }

    /// The indexer code.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The signing key's position in the current key list.
    pub fn index(&self) -> usize {
        self.index
    }

    /// The signing key's position in the prior next-key list; `None` for a
    /// current-only code.
    pub fn ondex(&self) -> Option<usize> {
        self.ondex
    }

    /// Whether the code is current-only: the key is not in the prior next-key
    /// list, so the signature counts towards no prior next threshold.
    pub fn is_current_only(&self) -> bool {
        indexer_is_current_only(&self.code)
    }

    /// The raw signature bytes.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The raw signature size for an indexer code.
    fn raw_size_from_code(code: &str) -> Result<usize, CesrError> {
        match code {
            "A" | "B" | "C" | "D" | "E" | "F" => Ok(64),
            "2A" | "2B" | "2C" | "2D" | "2E" | "2F" => Ok(64),
            "0A" | "0B" | "3A" | "3B" => Ok(114), // Ed448
            _ => Err(CesrError::UnknownCode(code.to_string())),
        }
    }

    /// Extract the raw signature from qb64: decode with the code and index
    /// characters zeroed, and keep the trailing raw bytes. The bytes in front
    /// of the raw signature then hold only pad bits, which CESR requires to be
    /// zero.
    fn extract_raw(
        qb64: &str,
        code: &str,
        sizage: &crate::tables::Sizage,
    ) -> Result<Vec<u8>, CesrError> {
        let cs = sizage.hs + sizage.ss;
        let zeroed = format!("{}{}", "A".repeat(cs), &qb64[cs..sizage.fs]);
        let all_bytes = codec::b64_decode(&zeroed)?;
        let raw_size = Self::raw_size_from_code(code)?;
        if all_bytes.len() < raw_size {
            return Err(CesrError::InvalidRawSize {
                expected: raw_size,
                got: all_bytes.len(),
            });
        }
        let (pad, raw) = all_bytes.split_at(all_bytes.len() - raw_size);
        if pad.iter().any(|&byte| byte != 0) {
            return Err(CesrError::NonCanonical(format!(
                "pad bits after code {code} are not zero"
            )));
        }
        Ok(raw.to_vec())
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

    /// keripy b70986f, `Siger(raw=bytes(range(64)), code, index, ondex).qb64`.
    const RAW: [u8; 64] = {
        let mut r = [0u8; 64];
        let mut i = 0;
        while i < 64 {
            r[i] = i as u8;
            i += 1;
        }
        r
    };

    #[test]
    fn from_qb64_rejects_non_ascii_without_panicking() {
        assert!(matches!(
            Indexer::from_qb64("0\u{FFFD}"),
            Err(CesrError::InvalidCharacter { .. })
        ));
    }

    #[test]
    fn a_is_both_lists_at_the_same_position() {
        let idx = Indexer::new("A", 3, None, RAW.to_vec()).unwrap();
        assert_eq!(idx.ondex(), Some(3));
        assert!(!idx.is_current_only());
        let back = Indexer::from_qb64(&idx.qb64().unwrap()).unwrap();
        assert_eq!((back.index(), back.ondex()), (3, Some(3)));
        assert_eq!(back.raw(), RAW);
        // No room for a different ondex.
        assert!(Indexer::new("A", 1, Some(2), RAW.to_vec()).is_err());
    }

    #[test]
    fn b_is_current_only() {
        let idx = Indexer::new("B", 1, None, RAW.to_vec()).unwrap();
        assert_eq!(idx.ondex(), None);
        assert!(idx.is_current_only());
        let back = Indexer::from_qb64(&idx.qb64().unwrap()).unwrap();
        assert_eq!((back.code(), back.index(), back.ondex()), ("B", 1, None));
        // An ondex given for a current-only code is dropped.
        let given = Indexer::new("B", 1, Some(1), RAW.to_vec()).unwrap();
        assert_eq!(given.ondex(), None);
    }

    #[test]
    fn a_big_both_code_carries_its_own_ondex() {
        let idx = Indexer::new("2A", 0, Some(1), RAW.to_vec()).unwrap();
        let qb64 = idx.qb64().unwrap();
        assert_eq!(qb64.len(), 92);
        assert!(qb64.starts_with("2AAAAB"), "{qb64}");
        let back = Indexer::from_qb64(&qb64).unwrap();
        assert_eq!(
            (back.code(), back.index(), back.ondex()),
            ("2A", 0, Some(1))
        );
        assert_eq!(back.raw(), RAW);
    }

    #[test]
    fn a_big_current_only_code_writes_a_zero_ondex_and_refuses_another() {
        let idx = Indexer::new("2B", 70, None, RAW.to_vec()).unwrap();
        let qb64 = idx.qb64().unwrap();
        assert!(qb64.starts_with("2BBGAA"), "{qb64}");
        let back = Indexer::from_qb64(&qb64).unwrap();
        assert_eq!((back.index(), back.ondex()), (70, None));
        let tampered = format!("2BBGAB{}", &qb64[6..]);
        assert!(Indexer::from_qb64(&tampered).is_err());
    }

    #[test]
    fn matches_keripys_encoding() {
        // keripy: Siger(raw=bytes(range(64)), code=…, index=…, ondex=…).qb64[:8]
        for (code, index, ondex, prefix) in [
            ("A", 0, None, "AAAAAQID"),
            ("B", 2, None, "BCAAAQID"),
            ("2A", 0, Some(1), "2AAAABAA"),
            ("2A", 1, Some(0), "2AABAAAA"),
        ] {
            let qb64 = Indexer::new(code, index, ondex, RAW.to_vec())
                .unwrap()
                .qb64()
                .unwrap();
            assert_eq!(&qb64[..8], prefix, "{code} {index} {ondex:?}");
        }
    }

    /// The bits between the code and index characters and the signature are
    /// zero in CESR. Setting any of them leaves the signature bytes the same,
    /// so such a text is refused.
    #[test]
    fn non_zero_pad_bits_are_refused() {
        for (code, index, ondex, position) in
            [("A", 0, None, 2), ("B", 2, None, 2), ("2A", 0, Some(1), 6)]
        {
            let canonical = Indexer::new(code, index, ondex, RAW.to_vec())
                .unwrap()
                .qb64()
                .unwrap();
            assert_eq!(
                Indexer::from_qb64(&canonical).unwrap().qb64().unwrap(),
                canonical
            );
            for bit in [0b10_0000u8, 0b01_0000, 0b00_1000, 0b00_0100] {
                let mut text = canonical.as_bytes().to_vec();
                let value = codec::b64_char_to_index(text[position]).unwrap() | bit;
                text[position] = codec::index_to_b64_char(value).unwrap();
                let altered = String::from_utf8(text).unwrap();
                assert!(
                    matches!(
                        Indexer::from_qb64(&altered),
                        Err(CesrError::NonCanonical(_))
                    ),
                    "{code} {altered}"
                );
            }
        }
    }

    #[test]
    fn indexer_codes_have_their_own_code_lengths() {
        use crate::tables::{hardage, indexer_hardage};
        assert_eq!(indexer_hardage('2'), Some(2));
        assert_eq!(indexer_hardage('3'), Some(2));
        assert_eq!(hardage('2'), Some(4), "the primitive table differs");
    }

    #[test]
    fn test_indexer_invalid_raw_size() {
        assert!(Indexer::new("A", 0, None, vec![0u8; 32]).is_err());
    }
}
