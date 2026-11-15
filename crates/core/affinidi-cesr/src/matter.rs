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
    ///
    /// For a variable-length code the code names a family (`4A`/`5A`/`6A`,
    /// `4B`/`5B`/`6B` and their `7AAx`/`8AAx`/`9AAx` big forms), and the
    /// member is chosen from the raw size, as keripy does: the lead size
    /// (`0`, `1` or `2` zero bytes to reach whole triplets) picks `4`/`5`/`6`
    /// (or `7`/`8`/`9`), and a value too long for a two-character count uses
    /// the big form. So `Matter::new("4B", 2 bytes)` has code `6B`; see
    /// [`Matter::code`].
    pub fn new(code: &str, raw: Vec<u8>) -> Result<Self, CesrError> {
        let sizage = matter_sizage(code).ok_or_else(|| CesrError::UnknownCode(code.to_string()))?;

        if sizage.fs == 0 {
            let code = variable_code_for(code, &sizage, raw.len())?;
            let sizage =
                matter_sizage(&code).ok_or_else(|| CesrError::UnknownCode(code.clone()))?;
            return Ok(Self { code, raw, sizage });
        }

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
        codec::ensure_ascii(qb64)?;

        // Determine hard size from first character
        let first_char = qb64.chars().next().ok_or(CesrError::EmptyInput)?;
        let hs = hardage(first_char).ok_or(CesrError::UnknownCode(first_char.to_string()))?;

        if qb64.len() < hs {
            return Err(CesrError::UnexpectedEnd);
        }

        let code = &qb64[..hs];
        let sizage = matter_sizage(code).ok_or_else(|| CesrError::UnknownCode(code.to_string()))?;

        if sizage.fs > 0 {
            // Fixed-length
            if qb64.len() < sizage.fs {
                return Err(CesrError::UnexpectedEnd);
            }
            let raw = Self::extract_raw(qb64, &sizage, sizage.fs)?;
            Ok(Self {
                code: code.to_string(),
                raw,
                sizage,
            })
        } else {
            // Variable-length: read soft size (count of 4-char groups)
            if qb64.len() < hs + sizage.ss {
                return Err(CesrError::UnexpectedEnd);
            }
            let ss_str = &qb64[hs..hs + sizage.ss];
            let count = b64_to_count(ss_str)?;
            let data_chars = count * 4;
            let fs = hs + sizage.ss + data_chars;

            if qb64.len() < fs {
                return Err(CesrError::UnexpectedEnd);
            }

            // Decode just the data portion (after code + count)
            let data_b64 = &qb64[hs + sizage.ss..fs];
            let all_bytes = codec::b64_decode(data_b64)?;
            let raw = strip_lead(code, &all_bytes, sizage.ls)?;

            Ok(Self {
                code: code.to_string(),
                raw,
                sizage,
            })
        }
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
        let sizage = matter_sizage(code).ok_or_else(|| CesrError::UnknownCode(code.to_string()))?;

        if sizage.fs > 0 {
            // Fixed-length: binary size = fs * 3 / 4
            let bs = sizage.fs * 3 / 4;
            if qb2.len() < bs {
                return Err(CesrError::UnexpectedEnd);
            }

            // Convert the full binary to text and extract raw
            let qb64 = codec::b64_encode(&qb2[..bs]);
            let raw = Self::extract_raw(&qb64, &sizage, sizage.fs)?;

            Ok(Self {
                code: code.to_string(),
                raw,
                sizage,
            })
        } else {
            // Variable-length: need enough bytes to read the soft (count) portion.
            // In qb64: code is hs chars, count is ss chars → (hs+ss) chars total header.
            // In qb2: (hs+ss) chars → (hs+ss)*3/4 bytes. (hs+ss) is always a multiple of 4
            // for the variable-length codes we support (hs=2,ss=2 → 4 chars → 3 bytes).
            let header_chars = sizage.hs + sizage.ss;
            let header_bytes = header_chars * 3 / 4;
            if qb2.len() < header_bytes {
                return Err(CesrError::UnexpectedEnd);
            }

            // Convert the header portion to qb64 to read the count
            let header_b64 = codec::b64_encode(&qb2[..header_bytes]);
            let count_str = &header_b64[sizage.hs..sizage.hs + sizage.ss];
            let count = b64_to_count(count_str)?;

            // Total qb64 size and binary size
            let fs = header_chars + count * 4;
            let bs = fs * 3 / 4;
            if qb2.len() < bs {
                return Err(CesrError::UnexpectedEnd);
            }

            // Convert the full primitive to qb64 and use text-domain parsing
            let full_b64 = codec::b64_encode(&qb2[..bs]);
            let data_b64 = &full_b64[header_chars..fs];
            let all_bytes = codec::b64_decode(data_b64)?;
            let raw = strip_lead(code, &all_bytes, sizage.ls)?;

            Ok(Self {
                code: code.to_string(),
                raw,
                sizage,
            })
        }
    }

    /// Encode this Matter to qb64 (text domain).
    pub fn qb64(&self) -> Result<String, CesrError> {
        if self.sizage.fs > 0 {
            // Fixed-length encoding
            let fs = self.sizage.fs;
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
        } else {
            // Variable-length encoding: code (hs chars) + count (ss chars) + data (count * 4 chars)
            // The raw bytes are prefixed with the code's `ls` zero bytes to a
            // multiple of 3, then base64-encoded. The count is the number of
            // 4-char base64 groups in the data portion.
            let ls = self.sizage.ls;
            if !(ls + self.raw.len()).is_multiple_of(3) {
                return Err(CesrError::Conversion(format!(
                    "{} bytes with lead size {ls} under code {} are not whole triplets",
                    self.raw.len(),
                    self.code
                )));
            }
            let mut padded = vec![0u8; ls];
            padded.extend_from_slice(&self.raw);

            let encoded = codec::b64_encode(&padded);
            let num_groups = encoded.len() / 4;
            if !encoded.len().is_multiple_of(4) {
                return Err(CesrError::Conversion(
                    "padded raw bytes did not produce aligned base64".into(),
                ));
            }

            let count_b64 = count_to_b64(num_groups, self.sizage.ss)?;

            let mut result = String::with_capacity(self.sizage.hs + self.sizage.ss + encoded.len());
            result.push_str(&self.code);
            result.push_str(&count_b64);
            result.push_str(&encoded);
            Ok(result)
        }
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
    ///
    /// For fixed-length codes this is the static `fs` from the sizage table.
    /// For variable-length codes it is computed from the raw data length.
    pub fn full_size(&self) -> usize {
        if self.sizage.fs > 0 {
            self.sizage.fs
        } else {
            let ls = self.compute_lead();
            let padded = ls + self.raw.len();
            let num_groups = padded / 3;
            self.sizage.hs + self.sizage.ss + num_groups * 4
        }
    }

    /// The full size in qb2 (binary) bytes.
    pub fn full_size_qb2(&self) -> usize {
        self.full_size() * 3 / 4
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
    ///
    /// The code characters are decoded as zeros (`A`), as keripy does, so the
    /// bytes in front of the raw material hold only the pad bits. CESR
    /// requires those to be zero; anything else is a second spelling of the
    /// same primitive and is refused with [`CesrError::NonCanonical`].
    fn extract_raw(qb64: &str, sizage: &Sizage, fs: usize) -> Result<Vec<u8>, CesrError> {
        let mut zeroed = "A".repeat(sizage.hs);
        zeroed.push_str(&qb64[sizage.hs..fs]);
        let all_bytes = codec::b64_decode(&zeroed)?;

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

        let (pad, raw) = all_bytes.split_at(lead);
        if pad.iter().any(|&byte| byte != 0) {
            return Err(CesrError::NonCanonical(format!(
                "pad bits after code {} are not zero",
                &qb64[..sizage.hs]
            )));
        }
        Ok(raw.to_vec())
    }
}

/// The member of a variable-length code family that fits `raw_len` bytes.
///
/// The family is the code's second character (`A`, `B`, ...) for a small
/// code and its last three characters for a big one. The lead size picks the
/// first character (`4`/`5`/`6` small, `7`/`8`/`9` big), and a value whose
/// quadlet count does not fit a small code's two count characters is moved
/// to the big form, as keripy does.
fn variable_code_for(code: &str, sizage: &Sizage, raw_len: usize) -> Result<String, CesrError> {
    let ls = codec::lead_bytes(raw_len);
    let quadlets = (raw_len + ls) / 3;
    let small_max = 64usize.pow(2) - 1;
    let big_max = 64usize.pow(4) - 1;
    const SMALL: [char; 3] = ['4', '5', '6'];
    const BIG: [char; 3] = ['7', '8', '9'];
    let code = if sizage.hs == 2 {
        let family = &code[1..2];
        if quadlets <= small_max {
            format!("{}{family}", SMALL[ls])
        } else if quadlets <= big_max {
            format!("{}AA{family}", BIG[ls])
        } else {
            return Err(CesrError::InvalidRawSize {
                expected: big_max * 3,
                got: raw_len,
            });
        }
    } else {
        if quadlets > big_max {
            return Err(CesrError::InvalidRawSize {
                expected: big_max * 3,
                got: raw_len,
            });
        }
        format!("{}{}", BIG[ls], &code[1..])
    };
    Ok(code)
}

/// Remove the code's `ls` lead bytes from the decoded data of a
/// variable-length primitive. They must be zero: anything else is refused
/// with [`CesrError::NonCanonical`], as keripy does ("Nonzero midpad bytes").
/// Raw data that itself begins with zero bytes is kept intact.
fn strip_lead(code: &str, data: &[u8], ls: usize) -> Result<Vec<u8>, CesrError> {
    if data.len() < ls {
        return Err(CesrError::InvalidRawSize {
            expected: ls,
            got: data.len(),
        });
    }
    let (lead, raw) = data.split_at(ls);
    if lead.iter().any(|&b| b != 0) {
        return Err(CesrError::NonCanonical(format!(
            "lead bytes of variable-length code {code} are not zero"
        )));
    }
    Ok(raw.to_vec())
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
    fn from_qb64_rejects_non_ascii_without_panicking() {
        // Each of these would previously panic on a char-boundary slice
        // because the byte offset lands inside the multi-byte U+FFFD.
        assert!(matches!(
            Matter::from_qb64("-\u{FFFD}"),
            Err(CesrError::InvalidCharacter { .. })
        ));
        assert!(matches!(
            Matter::from_qb64(&format!("B{}\u{FFFD}", "A".repeat(41))),
            Err(CesrError::InvalidCharacter { .. })
        ));
        // ASCII input still parses or returns a normal (non-panicking) error.
        let _ = Matter::from_qb64(&"B".repeat(44));
    }

    /// Every fixed-size code in the table.
    const FIXED_CODES: &[&str] = &[
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "0A", "0B", "0C", "0D", "0E",
        "0F", "0G", "0I", "1AAA", "1AAB", "1AAC", "1AAD", "1AAE", "1AAF", "1AAG", "1AAH", "1AAI",
        "1AAJ", "1AAK", "1AAL", "1AAM",
    ];

    /// Set `bits` in the 6-bit value of the Base64 character at `position`.
    fn with_bits_set(qb64: &str, position: usize, bits: u8) -> String {
        let mut text = qb64.as_bytes().to_vec();
        let value = codec::b64_char_to_index(text[position]).unwrap() | bits;
        text[position] = codec::index_to_b64_char(value).unwrap();
        String::from_utf8(text).unwrap()
    }

    /// Parsing the encoding of a fixed-size primitive gives the primitive
    /// back, and encoding that gives the same text, in both domains.
    #[test]
    fn fixed_size_encodings_round_trip_to_the_same_text() {
        for &code in FIXED_CODES {
            let size = Matter::raw_size_from_sizage(&matter_sizage(code).unwrap());
            for fill in [0x00u8, 0xff, 0x5a] {
                let matter = Matter::new(code, vec![fill; size]).unwrap();
                let qb64 = matter.qb64().unwrap();
                let parsed = Matter::from_qb64(&qb64).unwrap();
                assert_eq!(parsed, matter, "{code}");
                assert_eq!(parsed.qb64().unwrap(), qb64, "{code}");
                let from_qb2 = Matter::from_qb2(&matter.qb2().unwrap()).unwrap();
                assert_eq!(from_qb2, matter, "{code}");
            }
        }
    }

    /// CESR fills the bits between a one- or two-character code and the raw
    /// bytes with zeros (2 bits after a one-character code, 4 after a
    /// two-character code). A text with any of them set decodes to the same
    /// raw bytes, so it is refused rather than accepted as a second spelling.
    #[test]
    fn non_zero_pad_bits_are_refused() {
        let one_char_pad: &[u8] = &[0b10_0000, 0b01_0000];
        let two_char_pad: &[u8] = &[0b10_0000, 0b01_0000, 0b00_1000, 0b00_0100];
        for (code, position, pad_bits) in [
            ("B", 1, one_char_pad),
            ("D", 1, one_char_pad),
            ("E", 1, one_char_pad),
            ("J", 1, one_char_pad),
            ("0A", 2, two_char_pad),
            ("0B", 2, two_char_pad),
        ] {
            let size = Matter::raw_size_from_sizage(&matter_sizage(code).unwrap());
            let canonical = Matter::new(code, vec![0xff; size]).unwrap().qb64().unwrap();
            for &bit in pad_bits {
                let altered = with_bits_set(&canonical, position, bit);
                assert_ne!(altered, canonical);
                assert!(
                    matches!(Matter::from_qb64(&altered), Err(CesrError::NonCanonical(_))),
                    "{code} {altered}"
                );
                let qb2 = codec::qb64_to_qb2(&altered).unwrap();
                assert!(
                    matches!(Matter::from_qb2(&qb2), Err(CesrError::NonCanonical(_))),
                    "{code} {altered}"
                );
            }
        }
    }

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

    #[test]
    fn test_variable_length_qb64_roundtrip() {
        // 17 bytes need one lead byte, so the `4B` family member is `5B`.
        let raw = b"did:example:alice".to_vec();
        let m = Matter::new("4B", raw.clone()).unwrap();
        assert_eq!(m.code(), "5B");
        let qb64 = m.qb64().unwrap();

        // Code "5B" (2 chars) + count (2 chars) + data
        assert!(qb64.starts_with("5B"));

        let m2 = Matter::from_qb64(&qb64).unwrap();
        assert_eq!(m2, m);
        assert_eq!(m2.raw(), raw.as_slice());
    }

    #[test]
    fn test_variable_length_qb2_roundtrip() {
        let raw = b"did:example:bob".to_vec();
        let m = Matter::new("4B", raw.clone()).unwrap();
        let qb2 = m.qb2().unwrap();

        let m2 = Matter::from_qb2(&qb2).unwrap();
        // 15 bytes are whole triplets: lead size 0, code stays `4B`.
        assert_eq!(m2.code(), "4B");
        assert_eq!(m2.raw(), raw.as_slice());
    }

    #[test]
    fn test_variable_length_full_size() {
        // 17 bytes raw → lead = (3 - 17%3)%3 = (3-2)%3 = 1, padded = 18, groups = 6
        // fs = 2 + 2 + 6*4 = 28 chars, bs = 28*3/4 = 21 bytes
        let raw = b"did:example:alice".to_vec(); // 17 bytes
        let m = Matter::new("4B", raw).unwrap();
        assert_eq!(m.full_size(), 28);
        assert_eq!(m.full_size_qb2(), 21);
    }

    #[test]
    fn test_variable_length_multiple_of_3() {
        // Raw data length is exactly a multiple of 3 (no lead bytes needed)
        let raw = b"abcdef".to_vec(); // 6 bytes, lead = 0
        let m = Matter::new("4B", raw.clone()).unwrap();
        let qb64 = m.qb64().unwrap();
        let m2 = Matter::from_qb64(&qb64).unwrap();
        assert_eq!(m2.raw(), raw.as_slice());

        let qb2 = m.qb2().unwrap();
        let m3 = Matter::from_qb2(&qb2).unwrap();
        assert_eq!(m3.raw(), raw.as_slice());
    }

    #[test]
    fn test_variable_length_string_code() {
        // "4A" is for string variable-length
        // 11 bytes need one lead byte: `4A` becomes `5A`.
        let raw = b"hello world".to_vec();
        let m = Matter::new("4A", raw.clone()).unwrap();
        assert_eq!(m.code(), "5A");
        let qb64 = m.qb64().unwrap();
        let m2 = Matter::from_qb64(&qb64).unwrap();
        assert_eq!(m2.code(), "5A");
        assert_eq!(m2.raw(), raw.as_slice());
    }

    /// Vectors from keripy's `test_matter` (`tests/core/test_coring.py`):
    /// `Bytes_L1` of `b'abcde'` is `5BACAGFiY2Rl` / `e4 10 02 00 'abcde'`.
    /// The `Bytes_L0` and `Bytes_L2` values follow the same layout.
    #[test]
    fn keripy_variable_size_vectors() {
        let cases: &[(&str, &[u8], &str, &str)] = &[
            ("4B", b"abcde", "5B", "5BACAGFiY2Rl"),
            ("4B", b"abcdef", "4B", "4BACYWJjZGVm"),
            ("4B", b"abcd", "6B", "6BACAABhYmNk"),
            ("6B", b"abcde", "5B", "5BACAGFiY2Rl"),
        ];
        for &(given, raw, code, qb64) in cases {
            let m = Matter::new(given, raw.to_vec()).unwrap();
            assert_eq!(m.code(), code, "{given} {raw:?}");
            assert_eq!(m.qb64().unwrap(), qb64);
            let parsed = Matter::from_qb64(qb64).unwrap();
            assert_eq!(parsed, m);
            assert_eq!(Matter::from_qb2(&m.qb2().unwrap()).unwrap(), m);
        }
        let m = Matter::new("5B", b"abcde".to_vec()).unwrap();
        assert_eq!(m.qb2().unwrap(), b"\xe4\x10\x02\x00abcde");
        assert_eq!(m.full_size(), 12);
    }

    /// A raw value that starts with zero bytes keeps them: only the code's
    /// lead bytes are removed.
    #[test]
    fn variable_size_raw_starting_with_zero_bytes_round_trips() {
        for raw in [
            vec![0u8],
            vec![0u8, 0],
            vec![0u8, 0, 0],
            vec![0u8, 1],
            vec![0u8, 0, 7, 8],
            vec![0u8; 5],
            vec![0u8, 0, 0, 0, 0, 9],
            vec![],
        ] {
            for family in ["4A", "4B", "7AAB"] {
                let m = Matter::new(family, raw.clone()).unwrap();
                assert_eq!(m.sizage().ls, codec::lead_bytes(raw.len()));
                let qb64 = m.qb64().unwrap();
                assert_eq!(qb64.len(), m.full_size());
                let parsed = Matter::from_qb64(&qb64).unwrap();
                assert_eq!(parsed.raw(), raw.as_slice(), "{family} {raw:?} {qb64}");
                assert_eq!(parsed.code(), m.code());
                let from_qb2 = Matter::from_qb2(&m.qb2().unwrap()).unwrap();
                assert_eq!(from_qb2.raw(), raw.as_slice(), "{family} {raw:?}");
            }
        }
        // Explicit: one zero data byte under 6B is `6BAB` + `AAAA`.
        let m = Matter::new("4B", vec![0u8]).unwrap();
        assert_eq!(m.qb64().unwrap(), "6BABAAAA");
        assert_eq!(Matter::from_qb64("6BABAAAA").unwrap().raw(), &[0u8]);
        // The same text under 4B is three zero data bytes.
        assert_eq!(Matter::from_qb64("4BABAAAA").unwrap().raw(), &[0u8; 3]);
    }

    /// keripy refuses non-zero lead bytes ("Nonzero midpad bytes").
    #[test]
    fn variable_size_non_zero_lead_bytes_are_refused() {
        for bad in ["5BAC_2FiY2Rl", "6BAC__9hYmNk", "6BACAP9hYmNk"] {
            assert!(
                matches!(Matter::from_qb64(bad), Err(CesrError::NonCanonical(_))),
                "{bad}"
            );
            let qb2 = codec::qb64_to_qb2(bad).unwrap();
            assert!(
                matches!(Matter::from_qb2(&qb2), Err(CesrError::NonCanonical(_))),
                "{bad}"
            );
        }
    }

    /// The lead size is part of the code, in the table and in big forms.
    #[test]
    fn variable_size_lead_sizes_come_from_the_code() {
        for (code, ls) in [
            ("4A", 0),
            ("5A", 1),
            ("6A", 2),
            ("4B", 0),
            ("5B", 1),
            ("6B", 2),
            ("7AAA", 0),
            ("8AAA", 1),
            ("9AAA", 2),
            ("7AAB", 0),
            ("8AAB", 1),
            ("9AAB", 2),
        ] {
            assert_eq!(matter_sizage(code).unwrap().ls, ls, "{code}");
        }
        // Big family members are chosen by lead size too.
        assert_eq!(Matter::new("7AAB", vec![1u8; 2]).unwrap().code(), "8AAB");
        assert_eq!(Matter::new("9AAA", vec![1u8; 3]).unwrap().code(), "7AAA");
    }

    /// A value too long for a two-character count moves to the big form.
    #[test]
    fn variable_size_promotes_to_big_form() {
        let raw = vec![0x41u8; 4096 * 3];
        let m = Matter::new("4B", raw.clone()).unwrap();
        assert_eq!(m.code(), "7AAB");
        let qb64 = m.qb64().unwrap();
        assert!(qb64.starts_with("7AABABAA"), "{}", &qb64[..8]);
        assert_eq!(Matter::from_qb64(&qb64).unwrap(), m);

        let m = Matter::new("4A", vec![0x41u8; 4095 * 3 + 1]).unwrap();
        assert_eq!(m.code(), "9AAA");
        assert_eq!(Matter::from_qb64(&m.qb64().unwrap()).unwrap(), m);
    }
}
