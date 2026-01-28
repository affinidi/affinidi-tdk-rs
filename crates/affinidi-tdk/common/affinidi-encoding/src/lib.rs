//! Multibase and multicodec encoding utilities for Affinidi TDK
//!
//! This crate provides encoding primitives used across the TDK:
//! - Multibase encoding/decoding (base58btc, etc.)
//! - Multicodec varint prefixes and codec constants
//! - Utilities for encoding/decoding DID keys

pub mod multibase;
pub mod multicodec;

pub use multibase::{
    BASE58BTC_PREFIX, decode_base58btc, decode_multikey, decode_multikey_with_codec,
    encode_base58btc, encode_multikey, validate_base58btc,
};
pub use multicodec::{
    Codec, ED25519_PRIV, ED25519_PUB, MultiEncoded, MultiEncodedBuf, P256_PRIV, P256_PUB,
    P384_PRIV, P384_PUB, P521_PRIV, P521_PUB, SECP256K1_PRIV, SECP256K1_PUB, X25519_PRIV,
    X25519_PUB,
};

mod error;
pub use error::EncodingError;
