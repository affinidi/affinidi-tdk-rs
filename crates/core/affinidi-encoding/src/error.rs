//! Encoding errors

use thiserror::Error;

#[derive(Error, Debug)]
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
}
