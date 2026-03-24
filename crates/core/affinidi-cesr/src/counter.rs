//! Counter: CESR framing/counting codes for attached material groups.

use crate::codec;
use crate::error::CesrError;
use crate::matter::count_to_b64;
use crate::tables::counter_sizage;

/// A CESR counter code: identifies and counts attached material groups.
///
/// Counters have a code and a count, encoded together in qb64 format.
/// For example, `-AAB` means counter code `-A` with count 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counter {
    /// The counter code (e.g., "-A", "-B")
    code: String,
    /// The count value
    count: usize,
}

impl Counter {
    /// Create a new Counter with the given code and count.
    pub fn new(code: &str, count: usize) -> Result<Self, CesrError> {
        let _sizage =
            counter_sizage(code).ok_or_else(|| CesrError::UnknownCode(code.to_string()))?;
        Ok(Self {
            code: code.to_string(),
            count,
        })
    }

    /// Parse a Counter from a qb64 string.
    pub fn from_qb64(qb64: &str) -> Result<Self, CesrError> {
        if qb64.is_empty() {
            return Err(CesrError::EmptyInput);
        }

        let first_char = qb64.chars().next().ok_or(CesrError::EmptyInput)?;
        if first_char != '-' {
            return Err(CesrError::UnknownCode(format!(
                "counter must start with '-', got '{first_char}'"
            )));
        }

        // Check if this is a big counter (3-char code like "-0A")
        // or a small counter (2-char code like "-A")
        if qb64.len() < 2 {
            return Err(CesrError::UnexpectedEnd);
        }

        let second_char = qb64.as_bytes()[1];
        let (code, ss_start) = if second_char == b'0' {
            // Big counter: 3-char code
            if qb64.len() < 3 {
                return Err(CesrError::UnexpectedEnd);
            }
            let code = &qb64[..3];
            (code.to_string(), 3usize)
        } else {
            // Small counter: 2-char code
            let code = &qb64[..2];
            (code.to_string(), 2usize)
        };

        let sizage = counter_sizage(&code).ok_or_else(|| CesrError::UnknownCode(code.clone()))?;

        if qb64.len() < sizage.fs {
            return Err(CesrError::UnexpectedEnd);
        }

        // Parse count from the soft portion
        let count_str = &qb64[ss_start..sizage.fs];
        let count = b64_to_count(count_str)?;

        Ok(Self { code, count })
    }

    /// Encode this Counter to qb64.
    pub fn qb64(&self) -> Result<String, CesrError> {
        let sizage =
            counter_sizage(&self.code).ok_or_else(|| CesrError::UnknownCode(self.code.clone()))?;
        let ss = sizage.ss;
        let count_b64 = count_to_b64(self.count, ss)?;
        Ok(format!("{}{}", self.code, count_b64))
    }

    /// The counter code.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The count value.
    pub fn count(&self) -> usize {
        self.count
    }

    /// The full size in qb64 characters.
    pub fn full_size(&self) -> usize {
        let sizage = counter_sizage(&self.code).unwrap();
        sizage.fs
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

impl std::fmt::Display for Counter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.qb64() {
            Ok(s) => write!(f, "{s}"),
            Err(e) => write!(f, "<Counter error: {e}>"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_new() {
        let c = Counter::new("-A", 1).unwrap();
        assert_eq!(c.code(), "-A");
        assert_eq!(c.count(), 1);
    }

    #[test]
    fn test_counter_qb64_roundtrip() {
        let c = Counter::new("-A", 1).unwrap();
        let qb64 = c.qb64().unwrap();
        assert_eq!(qb64, "-AAB");
        assert_eq!(qb64.len(), 4);

        let c2 = Counter::from_qb64(&qb64).unwrap();
        assert_eq!(c2.code(), "-A");
        assert_eq!(c2.count(), 1);
    }

    #[test]
    fn test_counter_zero_count() {
        let c = Counter::new("-B", 0).unwrap();
        let qb64 = c.qb64().unwrap();
        assert_eq!(qb64, "-BAA");

        let c2 = Counter::from_qb64(&qb64).unwrap();
        assert_eq!(c2.count(), 0);
    }

    #[test]
    fn test_counter_large_count() {
        let c = Counter::new("-A", 63).unwrap();
        let qb64 = c.qb64().unwrap();

        let c2 = Counter::from_qb64(&qb64).unwrap();
        assert_eq!(c2.count(), 63);
    }

    #[test]
    fn test_counter_big_code() {
        let c = Counter::new("-0A", 1).unwrap();
        let qb64 = c.qb64().unwrap();
        assert_eq!(qb64.len(), 8);
        assert!(qb64.starts_with("-0A"));

        let c2 = Counter::from_qb64(&qb64).unwrap();
        assert_eq!(c2.code(), "-0A");
        assert_eq!(c2.count(), 1);
    }

    #[test]
    fn test_counter_controller_sigs() {
        // -B with count 2: two controller indexed signatures follow
        let c = Counter::new("-B", 2).unwrap();
        let qb64 = c.qb64().unwrap();
        assert_eq!(qb64, "-BAC");
    }

    #[test]
    fn test_invalid_counter_code() {
        assert!(Counter::new("-Z", 1).is_err());
    }

    #[test]
    fn test_counter_display() {
        let c = Counter::new("-A", 5).unwrap();
        let display = format!("{c}");
        assert_eq!(display.len(), 4);
    }
}
