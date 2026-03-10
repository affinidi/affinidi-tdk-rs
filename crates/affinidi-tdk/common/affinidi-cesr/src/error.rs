use thiserror::Error;

#[derive(Debug, Error)]
pub enum CesrError {
    #[error("unknown code: {0}")]
    UnknownCode(String),

    #[error("invalid code size: expected {expected}, got {got}")]
    InvalidCodeSize { expected: usize, got: usize },

    #[error("invalid raw size: expected {expected}, got {got}")]
    InvalidRawSize { expected: usize, got: usize },

    #[error("base64 decode error: {0}")]
    Base64Decode(String),

    #[error("unexpected end of input")]
    UnexpectedEnd,

    #[error("invalid character at position {position}: {ch}")]
    InvalidCharacter { position: usize, ch: char },

    #[error("invalid lead byte count: {0}")]
    InvalidLeadBytes(usize),

    #[error("conversion error: {0}")]
    Conversion(String),

    #[error("empty input")]
    EmptyInput,

    #[error("unknown format")]
    UnknownFormat,
}
