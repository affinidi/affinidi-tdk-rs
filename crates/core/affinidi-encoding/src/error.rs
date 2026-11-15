//! Encoding errors

use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum EncodingError {
    #[error("Invalid multibase prefix: expected 'z' (base58btc), got '{0}'")]
    InvalidMultibasePrefix(char),

    #[error("Invalid base58 encoding: {0}")]
    InvalidBase58(String),

    #[error("Invalid multicodec: {0}")]
    InvalidMulticodec(String),

    #[error("Unknown codec: 0x{0:x}")]
    UnknownCodec(u64),

    #[error("Decoding error: {0}")]
    Decoding(String),

    /// The key bytes under a known multicodec are not the length that codec
    /// requires (see [`crate::Codec::expected_key_length`]).
    #[error("Invalid key length for codec 0x{codec:x}: expected {expected} bytes, got {actual}")]
    InvalidKeyLength {
        codec: u64,
        expected: usize,
        actual: usize,
    },

    /// A multikey carried a different multicodec from the one required.
    #[error("Unexpected codec: expected 0x{expected:x}, got 0x{actual:x}")]
    UnexpectedCodec { expected: u64, actual: u64 },

    /// The string is not a `did:key` DID.
    #[error("Invalid did:key: {0}")]
    InvalidDidKey(String),
}
