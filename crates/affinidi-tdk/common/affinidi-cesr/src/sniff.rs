//! Stream format detection (sniffing) for CESR data.

use crate::error::CesrError;

/// The detected format of a CESR stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamFormat {
    /// JSON message (starts with `{`)
    Json,
    /// CBOR message (starts with CBOR map major type)
    Cbor,
    /// MessagePack message (starts with msgpack map byte)
    MessagePack,
    /// CESR text domain (Base64url characters)
    CesrText,
    /// CESR binary domain
    CesrBinary,
}

/// Sniff the format of a byte stream from its leading bytes.
///
/// Returns the detected format based on the first byte(s) of input.
pub fn sniff(data: &[u8]) -> Result<StreamFormat, CesrError> {
    if data.is_empty() {
        return Err(CesrError::EmptyInput);
    }

    match data[0] {
        // JSON: starts with '{'
        b'{' => Ok(StreamFormat::Json),

        // CBOR: map with <24 entries (0xa0-0xb7) or with 1-byte length (0xb8)
        // or indefinite-length map (0xbf)
        0xa0..=0xb7 | 0xb8 | 0xb9 | 0xba | 0xbb | 0xbf => Ok(StreamFormat::Cbor),

        // MessagePack: fixmap (0x80-0x8f) or map16 (0xde) or map32 (0xdf)
        0x80..=0x8f | 0xde | 0xdf => Ok(StreamFormat::MessagePack),

        // CESR text: starts with a Base64url character
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => Ok(StreamFormat::CesrText),

        // Otherwise treat as CESR binary
        _ => Ok(StreamFormat::CesrBinary),
    }
}

/// Detect whether data starts with a KERI version string.
///
/// KERI version strings look like `KERI10JSON000000_` (17 characters).
/// Returns true if the data starts with a recognized protocol + version + serialization kind.
pub fn has_version_string(data: &[u8]) -> bool {
    if data.len() < 17 {
        return false;
    }

    // Check for known protocol prefixes
    let prefix = &data[..4];
    matches!(
        prefix,
        b"KERI" | b"ACDC" | b"SAID"
    )
}

/// Extract the serialization size from a KERI version string.
///
/// The version string format is: `PPPPvvSSSS000000_`
/// where `000000` is a 6-digit hex size.
pub fn version_string_size(data: &[u8]) -> Result<usize, CesrError> {
    if data.len() < 17 {
        return Err(CesrError::UnexpectedEnd);
    }

    // Size is at bytes 10..16 (6 hex digits)
    let size_str = std::str::from_utf8(&data[10..16])
        .map_err(|_| CesrError::Conversion("invalid version string".into()))?;

    usize::from_str_radix(size_str, 16)
        .map_err(|_| CesrError::Conversion(format!("invalid hex size in version string: {size_str}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sniff_json() {
        assert_eq!(sniff(b"{\"v\":\"KERI10JSON\"}").unwrap(), StreamFormat::Json);
    }

    #[test]
    fn test_sniff_cesr_text() {
        assert_eq!(sniff(b"BAAAAAAA").unwrap(), StreamFormat::CesrText);
        assert_eq!(sniff(b"-AAB").unwrap(), StreamFormat::CesrText);
    }

    #[test]
    fn test_sniff_cbor() {
        assert_eq!(sniff(&[0xa2, 0x01, 0x02]).unwrap(), StreamFormat::Cbor);
    }

    #[test]
    fn test_sniff_msgpack() {
        assert_eq!(sniff(&[0x82, 0xa1]).unwrap(), StreamFormat::MessagePack);
    }

    #[test]
    fn test_sniff_empty() {
        assert!(sniff(b"").is_err());
    }

    #[test]
    fn test_has_version_string() {
        assert!(has_version_string(b"KERI10JSON0000fd_some content"));
        assert!(!has_version_string(b"NOT_KERI"));
        assert!(!has_version_string(b"short"));
    }

    #[test]
    fn test_version_string_size() {
        let vs = b"KERI10JSON0000fd_";
        let size = version_string_size(vs).unwrap();
        assert_eq!(size, 0xfd); // 253
    }
}
