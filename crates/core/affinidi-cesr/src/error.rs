use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
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

    /// An indexed signature's index or ondex is one its code cannot carry.
    #[error("invalid index: {0}")]
    InvalidIndex(String),

    /// The text is not the canonical encoding of the primitive: the pad bits
    /// between the code and the raw bytes are not zero.
    #[error("non-canonical encoding: {0}")]
    NonCanonical(String),
}
