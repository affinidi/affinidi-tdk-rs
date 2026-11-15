//! Multibase encoding/decoding utilities
//!
//! Multibase is a protocol for self-describing base encodings.
//! The first character indicates the encoding used.
//!
//! See: <https://github.com/multiformats/multibase>

use crate::EncodingError;
use crate::multicodec::{Codec, MultiEncoded};

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

/// Decode a multikey string, returning its codec and key bytes, and enforce
/// the codec's key length.
///
/// This is the validating counterpart of [`decode_multikey_with_codec`]: the
/// string must be base58btc (`z` prefix), carry a well-formed multicodec
/// prefix, and — for every codec with a known
/// [`Codec::expected_key_length`] — exactly that many key bytes. A codec this
/// crate does not know is returned as [`Codec::Unknown`] without a length
/// check; the caller decides whether to accept it.
///
/// EC public keys are expected in compressed SEC1 form (33 bytes for P-256
/// and secp256k1, 49 for P-384, 67 for P-521), as the Multikey format
/// requires.
pub fn decode_multikey_checked(key: &str) -> Result<(Codec, Vec<u8>), EncodingError> {
    let bytes = decode_base58btc(key)?;
    let multi_encoded = MultiEncoded::new(&bytes)?;
    let codec = multi_encoded.codec_type();
    let data = multi_encoded.data();
    check_key_length(codec, data)?;
    Ok((codec, data.to_vec()))
}

/// Decode a multikey string that must carry the `expected` codec, returning
/// its key bytes with the codec's key length enforced.
///
/// Fails with [`EncodingError::UnexpectedCodec`] for any other codec, and
/// with [`EncodingError::InvalidKeyLength`] for a key of the wrong length.
pub fn decode_multikey_expecting(key: &str, expected: Codec) -> Result<Vec<u8>, EncodingError> {
    let bytes = decode_base58btc(key)?;
    let multi_encoded = MultiEncoded::new(&bytes)?;
    let codec = multi_encoded.codec_type();
    if codec != expected {
        return Err(EncodingError::UnexpectedCodec {
            expected: expected.to_u64(),
            actual: codec.to_u64(),
        });
    }
    let data = multi_encoded.data();
    check_key_length(codec, data)?;
    Ok(data.to_vec())
}

/// Refuse key bytes whose length differs from the codec's expected length.
fn check_key_length(codec: Codec, data: &[u8]) -> Result<(), EncodingError> {
    match codec.expected_key_length() {
        Some(expected) if data.len() != expected => Err(EncodingError::InvalidKeyLength {
            codec: codec.to_u64(),
            expected,
            actual: data.len(),
        }),
        _ => Ok(()),
    }
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
    fn decode_multikey_checked_accepts_a_well_formed_key() {
        let key = encode_multikey(crate::ED25519_PUB, &[7u8; 32]);
        let (codec, bytes) = decode_multikey_checked(&key).unwrap();
        assert_eq!(codec, Codec::Ed25519Pub);
        assert_eq!(bytes, [7u8; 32]);
    }

    #[test]
    fn decode_multikey_checked_refuses_a_truncated_key() {
        let key = encode_multikey(crate::ED25519_PUB, &[7u8; 31]);
        assert!(matches!(
            decode_multikey_checked(&key).unwrap_err(),
            EncodingError::InvalidKeyLength {
                codec: crate::ED25519_PUB,
                expected: 32,
                actual: 31
            }
        ));
        // An uncompressed P-256 point is not a Multikey.
        let key = encode_multikey(crate::P256_PUB, &[4u8; 65]);
        assert!(matches!(
            decode_multikey_checked(&key).unwrap_err(),
            EncodingError::InvalidKeyLength { expected: 33, .. }
        ));
    }

    #[test]
    fn decode_multikey_checked_passes_unknown_codecs_through() {
        let key = encode_multikey(0x55, &[1, 2, 3]);
        let (codec, bytes) = decode_multikey_checked(&key).unwrap();
        assert_eq!(codec, Codec::Unknown(0x55));
        assert_eq!(bytes, [1, 2, 3]);
    }

    #[test]
    fn decode_multikey_checked_refuses_non_base58btc() {
        assert!(matches!(
            decode_multikey_checked("fed01").unwrap_err(),
            EncodingError::InvalidMultibasePrefix('f')
        ));
    }

    #[test]
    fn decode_multikey_expecting_checks_codec_then_length() {
        let key = encode_multikey(crate::X25519_PUB, &[0u8; 32]);
        assert!(matches!(
            decode_multikey_expecting(&key, Codec::Ed25519Pub).unwrap_err(),
            EncodingError::UnexpectedCodec {
                expected: crate::ED25519_PUB,
                actual: crate::X25519_PUB
            }
        ));
        assert_eq!(
            decode_multikey_expecting(&key, Codec::X25519Pub).unwrap(),
            [0u8; 32]
        );
        let short = encode_multikey(crate::X25519_PUB, &[0u8; 16]);
        assert!(matches!(
            decode_multikey_expecting(&short, Codec::X25519Pub).unwrap_err(),
            EncodingError::InvalidKeyLength { .. }
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
