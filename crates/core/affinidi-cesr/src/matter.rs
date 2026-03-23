//! Matter: CESR primitive type (code + raw bytes) with qb64/qb2 encode/decode.

use crate::codec;
use crate::error::CesrError;
use crate::tables::{Sizage, hardage, matter_sizage};

/// A CESR primitive: a typed code with raw bytes payload.
///
/// Matter represents the fundamental CESR encoding unit. Each Matter has:
/// - A code string identifying the type and size
/// - Raw bytes containing the actual data (key, digest, etc.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matter {
    /// The CESR type code (e.g., "B" for Ed25519 non-transferable prefix)
    code: String,
    /// The raw bytes payload
    raw: Vec<u8>,
    /// Cached sizage for this code
    sizage: Sizage,
}

impl Matter {
    /// Create a new Matter from a code and raw bytes.
    pub fn new(code: &str, raw: Vec<u8>) -> Result<Self, CesrError> {
        let sizage = matter_sizage(code).ok_or_else(|| CesrError::UnknownCode(code.to_string()))?;

        // Validate raw size for fixed-length codes
        if sizage.fs > 0 {
            let expected_raw = Self::raw_size_from_sizage(&sizage);
            if raw.len() != expected_raw {
                return Err(CesrError::InvalidRawSize {
                    expected: expected_raw,
                    got: raw.len(),
                });
            }
        }

        Ok(Self {
            code: code.to_string(),
            raw,
            sizage,
        })
    }

    /// Parse a Matter from a qb64 (text domain) string.
    pub fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
        if qb64.is_empty() {
            return Err(CesrError::EmptyInput);
        }

        // Determine hard size from first character
        let first_char = qb64.chars().next().ok_or(CesrError::EmptyInput)?;
        let hs = hardage(first_char).ok_or(CesrError::UnknownCode(first_char.to_string()))?;

        if qb64.len() < hs {
            return Err(CesrError::UnexpectedEnd);
        }

        let code = &qb64[..hs];
        let sizage =
            matter_sizage(code).ok_or_else(|| CesrError::UnknownCode(code.to_string()))?;

        let fs = if sizage.fs > 0 {
            sizage.fs
        } else {
            // Variable-length: read soft size
            let ss_str = &qb64[hs..hs + sizage.ss];
            let count = b64_to_count(ss_str)?;
            // fs = hs + ss + count * 4 (each group is 4 chars)
            sizage.hs + sizage.ss + count * 4
        };

        if qb64.len() < fs {
            return Err(CesrError::UnexpectedEnd);
        }

        let raw = Self::extract_raw(qb64, &sizage, fs)?;

        Ok(Self {
            code: code.to_string(),
            raw,
            sizage,
        })
    }

    /// Parse a Matter from qb2 (binary domain) bytes.
    pub fn from_qb2(qb2: &[u8]) -> Result<Self, CesrError> {
        if qb2.is_empty() {
            return Err(CesrError::EmptyInput);
        }

        // Convert enough bytes to text to sniff the code
        // We need at least 3 bytes to get 4 base64 chars
        let sniff_len = std::cmp::min(qb2.len(), 6);
        if sniff_len < 3 {
            return Err(CesrError::UnexpectedEnd);
        }

        // Align to multiple of 3 for base64 conversion
        let aligned = (sniff_len / 3) * 3;
        let sniff_b64 = codec::b64_encode(&qb2[..aligned]);

        // Now use text-domain parsing logic to get the code
        let first_char = sniff_b64.chars().next().ok_or(CesrError::EmptyInput)?;
        let hs = hardage(first_char).ok_or(CesrError::UnknownCode(first_char.to_string()))?;

        if sniff_b64.len() < hs {
            return Err(CesrError::UnexpectedEnd);
        }

        let code = &sniff_b64[..hs];
        let sizage =
            matter_sizage(code).ok_or_else(|| CesrError::UnknownCode(code.to_string()))?;

        let fs = if sizage.fs > 0 {
            sizage.fs
        } else {
            return Err(CesrError::Conversion(
                "variable-length qb2 not yet supported".into(),
            ));
        };

        // Binary size = fs * 3 / 4
        let bs = fs * 3 / 4;
        if qb2.len() < bs {
            return Err(CesrError::UnexpectedEnd);
        }

        // Convert the full binary to text and extract raw
        let qb64 = codec::b64_encode(&qb2[..bs]);
        let raw = Self::extract_raw(&qb64, &sizage, fs)?;

        Ok(Self {
            code: code.to_string(),
            raw,
            sizage,
        })
    }

    /// Encode this Matter to qb64 (text domain).
    pub fn qb64(&self) -> Result<String, CesrError> {
        let fs = if self.sizage.fs > 0 {
            self.sizage.fs
        } else {
            return Err(CesrError::Conversion(
                "variable-length qb64 encoding not yet supported".into(),
            ));
        };

        let hs = self.sizage.hs;
        let cs = fs - hs; // chars for raw portion

        // Compute lead bytes
        let ls = self.compute_lead();

        // Prepend lead zero bytes
        let mut padded = vec![0u8; ls];
        padded.extend_from_slice(&self.raw);

        let encoded = codec::b64_encode(&padded);

        // Take the last `cs` characters
        if encoded.len() < cs {
            return Err(CesrError::InvalidRawSize {
                expected: cs,
                got: encoded.len(),
            });
        }
        let raw_b64 = &encoded[encoded.len() - cs..];

        let mut result = String::with_capacity(fs);
        result.push_str(&self.code);
        result.push_str(raw_b64);
        Ok(result)
    }

    /// Encode this Matter to qb2 (binary domain).
    pub fn qb2(&self) -> Result<Vec<u8>, CesrError> {
        let qb64 = self.qb64()?;
        codec::qb64_to_qb2(&qb64)
    }

    /// The CESR code string.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The raw bytes payload.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The sizage information.
    pub fn sizage(&self) -> &Sizage {
        &self.sizage
    }

    /// The full size in qb64 characters.
    pub fn full_size(&self) -> usize {
        self.sizage.fs
    }

    /// Compute lead bytes for the current raw size.
    fn compute_lead(&self) -> usize {
        codec::lead_bytes(self.raw.len())
    }

    /// Compute the expected raw byte size from a sizage.
    fn raw_size_from_sizage(sizage: &Sizage) -> usize {
        if sizage.fs == 0 {
            return 0;
        }
        // Total encoded bytes = fs * 3 / 4
        // Code bytes = hs * 3 / 4 (approximately, but codes are always aligned)
        // Raw bytes = total - lead
        let total_bytes = sizage.fs * 3 / 4;
        // For 1-char codes, the lead is absorbed differently
        // The raw size = (fs - hs) * 3/4 - lead_adjustment
        // Simpler: total_bytes - hs (since hs chars encode the code)
        // Actually in CESR: raw_size = (fs * 3 / 4) - lead_bytes
        // where lead depends on the code

        // For common cases:
        match sizage.hs {
            1 => {
                // 1-char code: code takes 6 bits from first triplet
                // fs=44 -> 33 bytes total, raw = 32 (1 lead byte used for code alignment)
                total_bytes - 1
            }
            2 => {
                // 2-char code: code takes 12 bits from first triplet
                // fs=88 -> 66 bytes total, raw = 64 (2 lead bytes for code alignment)
                total_bytes - 2
            }
            4 => {
                // 4-char code: code takes 24 bits = 3 bytes (perfectly aligned)
                // fs=48 -> 36 bytes total, code = 3 bytes, raw = 33
                total_bytes - 3
            }
            _ => total_bytes,
        }
    }

    /// Extract raw bytes from a qb64 string given sizage and full size.
    fn extract_raw(qb64: &str, sizage: &Sizage, fs: usize) -> Result<Vec<u8>, CesrError> {
        // Decode the entire qb64 to bytes
        let full_qb64 = &qb64[..fs];
        let all_bytes = codec::b64_decode(full_qb64)?;

        // Extract based on code size
        let lead = match sizage.hs {
            1 => 1usize,
            2 => 2,
            4 => 3,
            _ => 0,
        };

        if all_bytes.len() <= lead {
            return Err(CesrError::InvalidRawSize {
                expected: lead + 1,
                got: all_bytes.len(),
            });
        }

        // Raw bytes start after the lead bytes
        let raw = all_bytes[lead..].to_vec();
        Ok(raw)
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

/// Convert a count value to a Base64url string of given length.
pub fn count_to_b64(count: usize, length: usize) -> Result<String, CesrError> {
    let mut result = vec![0u8; length];
    let mut remaining = count;
    for i in (0..length).rev() {
        let val = (remaining % 64) as u8;
        result[i] = codec::index_to_b64_char(val)?;
        remaining /= 64;
    }
    if remaining > 0 {
        return Err(CesrError::Conversion(format!(
            "count {count} too large for {length} base64 chars"
        )));
    }
    String::from_utf8(result).map_err(|e| CesrError::Conversion(e.to_string()))
}

impl std::fmt::Display for Matter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.qb64() {
            Ok(s) => write!(f, "{s}"),
            Err(e) => write!(f, "<Matter error: {e}>"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matter_raw_size() {
        // Ed25519 key: code "B", fs=44, raw should be 32 bytes
        let sizage = matter_sizage("B").unwrap();
        let raw_size = Matter::raw_size_from_sizage(&sizage);
        assert_eq!(raw_size, 32);

        // Ed25519 sig: code "0B", fs=88, raw should be 64 bytes
        let sizage = matter_sizage("0B").unwrap();
        let raw_size = Matter::raw_size_from_sizage(&sizage);
        assert_eq!(raw_size, 64);

        // secp256k1 key: code "1AAB", fs=48, raw should be 33 bytes
        let sizage = matter_sizage("1AAB").unwrap();
        let raw_size = Matter::raw_size_from_sizage(&sizage);
        assert_eq!(raw_size, 33);
    }

    #[test]
    fn test_matter_new_ed25519() {
        let raw = vec![0u8; 32]; // dummy 32-byte key
        let m = Matter::new("B", raw.clone()).unwrap();
        assert_eq!(m.code(), "B");
        assert_eq!(m.raw(), raw.as_slice());
    }

    #[test]
    fn test_matter_qb64_roundtrip() {
        let raw = vec![42u8; 32];
        let m = Matter::new("B", raw.clone()).unwrap();
        let qb64 = m.qb64().unwrap();

        assert_eq!(qb64.len(), 44);
        assert!(qb64.starts_with('B'));

        let m2 = Matter::from_qb64(&qb64).unwrap();
        assert_eq!(m2.code(), "B");
        assert_eq!(m2.raw(), raw.as_slice());
    }

    #[test]
    fn test_matter_qb2_roundtrip() {
        let raw = vec![7u8; 32];
        let m = Matter::new("D", raw.clone()).unwrap();
        let qb2 = m.qb2().unwrap();

        let m2 = Matter::from_qb2(&qb2).unwrap();
        assert_eq!(m2.code(), "D");
        assert_eq!(m2.raw(), raw.as_slice());
    }

    #[test]
    fn test_matter_ed25519_sig() {
        let raw = vec![0xABu8; 64];
        let m = Matter::new("0B", raw.clone()).unwrap();
        let qb64 = m.qb64().unwrap();

        assert_eq!(qb64.len(), 88);
        assert!(qb64.starts_with("0B"));

        let m2 = Matter::from_qb64(&qb64).unwrap();
        assert_eq!(m2.code(), "0B");
        assert_eq!(m2.raw(), raw.as_slice());
    }

    #[test]
    fn test_matter_secp256k1_key() {
        let raw = vec![0x02u8; 33]; // compressed pubkey size
        let m = Matter::new("1AAB", raw.clone()).unwrap();
        let qb64 = m.qb64().unwrap();

        assert_eq!(qb64.len(), 48);
        assert!(qb64.starts_with("1AAB"));

        let m2 = Matter::from_qb64(&qb64).unwrap();
        assert_eq!(m2.code(), "1AAB");
        assert_eq!(m2.raw(), raw.as_slice());
    }

    #[test]
    fn test_count_to_b64() {
        assert_eq!(count_to_b64(0, 2).unwrap(), "AA");
        assert_eq!(count_to_b64(1, 2).unwrap(), "AB");
        assert_eq!(count_to_b64(63, 2).unwrap(), "A_");
        assert_eq!(count_to_b64(64, 2).unwrap(), "BA");
    }

    #[test]
    fn test_matter_display() {
        let raw = vec![0u8; 32];
        let m = Matter::new("B", raw).unwrap();
        let display = format!("{m}");
        assert_eq!(display.len(), 44);
    }

    #[test]
    fn test_invalid_code() {
        assert!(Matter::new("ZZ", vec![0u8; 32]).is_err());
    }

    #[test]
    fn test_invalid_raw_size() {
        assert!(Matter::new("B", vec![0u8; 16]).is_err());
    }
}
