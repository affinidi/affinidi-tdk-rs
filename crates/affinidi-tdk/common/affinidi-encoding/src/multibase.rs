//! Multibase encoding/decoding utilities
//!
//! Multibase is a protocol for self-describing base encodings.
//! The first character indicates the encoding used.
//!
//! See: <https://github.com/multiformats/multibase>

use crate::EncodingError;
use crate::multicodec::MultiEncoded;

/// Multibase prefix for base58btc (Bitcoin alphabet)
pub const BASE58BTC_PREFIX: char = 'z';

/// Decode a base58btc multibase string (must start with 'z')
///
/// Returns the decoded bytes without the prefix.
pub fn decode_base58btc(s: &str) -> Result<Vec<u8>, EncodingError> {
    let Some(encoded) = s.strip_prefix(BASE58BTC_PREFIX) else {
        let prefix = s.chars().next().unwrap_or('\0');
        return Err(EncodingError::InvalidMultibasePrefix(prefix));
    };

    bs58::decode(encoded)
        .into_vec()
        .map_err(|e| EncodingError::InvalidBase58(e.to_string()))
}

/// Encode bytes as base58btc with multibase prefix 'z'
pub fn encode_base58btc(bytes: &[u8]) -> String {
    format!("{}{}", BASE58BTC_PREFIX, bs58::encode(bytes).into_string())
}

/// Validate that a string is valid base58btc multibase (starts with 'z' and decodes correctly)
pub fn validate_base58btc(s: &str) -> Result<(), EncodingError> {
    decode_base58btc(s)?;
    Ok(())
}

/// Decode a multikey string (multibase + multicodec encoded)
///
/// Returns just the key bytes without the multicodec prefix.
/// This is the inverse of how keys are encoded in DID documents (publicKeyMultibase).
pub fn decode_multikey(key: &str) -> Result<Vec<u8>, EncodingError> {
    let bytes = decode_base58btc(key)?;
    let multi_encoded = MultiEncoded::new(&bytes)?;
    Ok(multi_encoded.data().to_vec())
}

/// Decode a multikey string and return both codec and key bytes
pub fn decode_multikey_with_codec(key: &str) -> Result<(u64, Vec<u8>), EncodingError> {
    let bytes = decode_base58btc(key)?;
    let multi_encoded = MultiEncoded::new(&bytes)?;
    Ok((multi_encoded.codec(), multi_encoded.data().to_vec()))
}

/// Encode key bytes with a multicodec prefix as a multibase (base58btc) string
///
/// This is the inverse of `decode_multikey`. The result is suitable for
/// use as a DID key identifier or publicKeyMultibase value.
pub fn encode_multikey(codec: u64, key_bytes: &[u8]) -> String {
    let encoded = crate::multicodec::MultiEncodedBuf::encode_bytes(codec, key_bytes);
    encode_base58btc(encoded.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_base58btc() {
        // "z" + base58btc("hello") = "zCn8eVZg"
        let result = decode_base58btc("zCn8eVZg").unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_encode_base58btc() {
        let encoded = encode_base58btc(b"hello");
        assert_eq!(encoded, "zCn8eVZg");
    }

    #[test]
    fn test_roundtrip() {
        let original = b"test data for encoding";
        let encoded = encode_base58btc(original);
        let decoded = decode_base58btc(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_invalid_prefix() {
        let result = decode_base58btc("fABCDEF"); // 'f' is hex, not base58btc
        assert!(matches!(
            result.unwrap_err(),
            EncodingError::InvalidMultibasePrefix('f')
        ));
    }

    #[test]
    fn test_invalid_base58() {
        // '0', 'O', 'I', 'l' are not valid base58 characters
        let result = decode_base58btc("z0OIl");
        assert!(matches!(
            result.unwrap_err(),
            EncodingError::InvalidBase58(_)
        ));
    }

    #[test]
    fn test_did_key_identifier() {
        // Real did:key identifier (ed25519)
        let id = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let result = decode_base58btc(id);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        // First byte should be 0xed (ed25519 multicodec prefix)
        assert_eq!(bytes[0], 0xed);
    }
}
