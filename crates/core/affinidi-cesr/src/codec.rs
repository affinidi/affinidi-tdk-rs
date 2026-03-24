//! Base64url encoding/decoding and qb64/qb2 conversion utilities.

use crate::error::CesrError;

/// URL-safe Base64 alphabet (RFC 4648 §5) without padding.
const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Decode table: ASCII byte -> 6-bit value (255 = invalid).
const B64_DECODE: [u8; 128] = {
    let mut table = [255u8; 128];
    let mut i = 0usize;
    while i < 64 {
        table[B64_CHARS[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// Encode raw bytes to URL-safe Base64 (no padding).
pub fn b64_encode(data: &[u8]) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::encode_string(data)
}

/// Decode URL-safe Base64 (no padding) to bytes.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, CesrError> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(s).map_err(|e| CesrError::Base64Decode(e.to_string()))
}

/// Returns true if the character is a valid Base64url character.
pub fn is_b64_char(c: u8) -> bool {
    c < 128 && B64_DECODE[c as usize] != 255
}

/// Convert a single Base64url character to its 6-bit value.
pub fn b64_char_to_index(c: u8) -> Result<u8, CesrError> {
    if c >= 128 || B64_DECODE[c as usize] == 255 {
        return Err(CesrError::InvalidCharacter {
            position: 0,
            ch: c as char,
        });
    }
    Ok(B64_DECODE[c as usize])
}

/// Convert a 6-bit value to its Base64url character.
pub fn index_to_b64_char(idx: u8) -> Result<u8, CesrError> {
    if idx >= 64 {
        return Err(CesrError::Conversion(format!(
            "index {idx} out of range for base64"
        )));
    }
    Ok(B64_CHARS[idx as usize])
}

/// Compute the number of lead bytes (zero-padding) from the code.
/// Lead bytes = (3 - (raw_size % 3)) % 3
pub fn lead_bytes(raw_size: usize) -> usize {
    (3 - (raw_size % 3)) % 3
}

/// Compute pad size (number of Base64 `=` padding characters that would be needed).
/// pad_size = (3 - (raw_size % 3)) % 3
pub fn pad_size(raw_size: usize) -> usize {
    (3 - (raw_size % 3)) % 3
}

/// Convert qb64 text to qb2 binary.
///
/// The qb64 string is decoded from Base64url to produce the full binary
/// representation including the code prefix bytes.
pub fn qb64_to_qb2(qb64: &str) -> Result<Vec<u8>, CesrError> {
    // qb64 length must be multiple of 4
    if !qb64.len().is_multiple_of(4) {
        return Err(CesrError::InvalidCodeSize {
            expected: qb64.len().div_ceil(4) * 4,
            got: qb64.len(),
        });
    }
    b64_decode(qb64)
}

/// Convert qb2 binary to qb64 text.
///
/// The qb2 bytes are encoded to Base64url to produce the text representation.
pub fn qb2_to_qb64(qb2: &[u8]) -> Result<String, CesrError> {
    // qb2 length must be multiple of 3
    if !qb2.len().is_multiple_of(3) {
        return Err(CesrError::InvalidRawSize {
            expected: qb2.len().div_ceil(3) * 3,
            got: qb2.len(),
        });
    }
    Ok(b64_encode(qb2))
}

/// Encode a code string and raw bytes into qb64 format.
///
/// The code characters occupy the "hard" portion of the output,
/// and the raw bytes (with leading zero padding) fill the rest.
pub fn encode_qb64(code: &str, raw: &[u8], fs: usize) -> Result<String, CesrError> {
    let hs = code.len();
    let cs = fs - hs; // number of Base64 chars for the raw portion
    let lead = lead_bytes(raw.len());

    // Prepend lead zero bytes to raw
    let mut padded = vec![0u8; lead];
    padded.extend_from_slice(raw);

    // Encode the padded raw bytes
    let encoded = b64_encode(&padded);

    // Take only the last `cs` characters (lead bytes absorbed into the code portion)
    if encoded.len() < cs {
        return Err(CesrError::InvalidRawSize {
            expected: cs,
            got: encoded.len(),
        });
    }
    let raw_b64 = &encoded[encoded.len() - cs..];

    let mut result = String::with_capacity(fs);
    result.push_str(code);
    result.push_str(raw_b64);
    Ok(result)
}

/// Decode a qb64 string into (code, raw_bytes) given code size `hs` and full size `fs`.
pub fn decode_qb64(qb64: &str, hs: usize, fs: usize, ls: usize) -> Result<Vec<u8>, CesrError> {
    if qb64.len() < fs {
        return Err(CesrError::UnexpectedEnd);
    }

    let raw_b64 = &qb64[hs..fs];

    // Decode the raw portion
    // We need to handle the lead bytes: prepend 'A' chars to make a valid Base64 chunk
    let lead_chars = ls; // number of lead pad characters
    let mut full_b64 = String::with_capacity(lead_chars + raw_b64.len());
    for _ in 0..lead_chars {
        full_b64.push('A');
    }
    full_b64.push_str(raw_b64);

    // Decode full base64
    let decoded = b64_decode(&full_b64)?;

    // Strip lead zero bytes
    if decoded.len() < ls {
        return Err(CesrError::InvalidRawSize {
            expected: ls,
            got: decoded.len(),
        });
    }
    let raw = decoded[ls..].to_vec();

    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_b64_roundtrip() {
        let data = b"Hello, KERI!";
        let encoded = b64_encode(data);
        let decoded = b64_decode(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_qb2_qb64_roundtrip() {
        // 6 bytes -> 8 base64 chars
        let data = b"abcdef";
        let qb64 = qb2_to_qb64(data).unwrap();
        let qb2 = qb64_to_qb2(&qb64).unwrap();
        assert_eq!(data.as_slice(), qb2.as_slice());
    }

    #[test]
    fn test_lead_bytes() {
        assert_eq!(lead_bytes(32), 1); // Ed25519 pubkey: 32 bytes -> 1 lead
        assert_eq!(lead_bytes(33), 0); // secp256k1 compressed: 33 bytes -> 0 lead
        assert_eq!(lead_bytes(64), 2); // Ed25519 sig: 64 bytes -> 2 lead
    }

    #[test]
    fn test_pad_size() {
        assert_eq!(pad_size(32), 1);
        assert_eq!(pad_size(33), 0);
        assert_eq!(pad_size(64), 2);
    }
}
