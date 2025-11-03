//! Generic Multicodec encoding/decoding

use crate::errors::SecretsResolverError;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ****************************************************************************
// Codec Magic Numbers
// ****************************************************************************
pub const ED25519_PUB: u64 = 0xed;
pub const ED25519_PRIV: u64 = 0x1300;
pub const X25519_PUB: u64 = 0xec;
pub const X25519_PRIV: u64 = 0x1302;
pub const SECP256K1_PUB: u64 = 0xe7;
pub const SECP256K1_PRIV: u64 = 0x1301;
pub const P256_PUB: u64 = 0x1200;
pub const P256_PRIV: u64 = 0x1306;
pub const P384_PUB: u64 = 0x1201;
pub const P384_PRIV: u64 = 0x1307;
pub const P521_PUB: u64 = 0x1202;
pub const P521_PRIV: u64 = 0x1308;

// multi-encoded byte array
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MultiEncoded([u8]);

impl MultiEncoded {
    /// Create a new multiencoded byte slice
    /// Does check the codec encoding
    pub fn new(bytes: &[u8]) -> Result<&Self, SecretsResolverError> {
        unsigned_varint::decode::u64(bytes)
            .map_err(|e| SecretsResolverError::Decoding(format!("unsigned_varint: {e}")))?;

        Ok(unsafe { &*(bytes as *const [u8] as *const MultiEncoded) })
    }

    /// Size of the byte array
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Seperates the codec and the data
    pub fn parts(&self) -> (u64, &[u8]) {
        unsigned_varint::decode::u64(&self.0).unwrap()
    }

    /// Codec value
    pub fn codec(&self) -> u64 {
        self.parts().0
    }

    /// Data value
    pub fn data(&self) -> &[u8] {
        self.parts().1
    }

    /// Returns the raw bytes, including the codec prefix
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MultiEncodedBuf(Vec<u8>);

impl MultiEncodedBuf {
    /// Creates a new multiencoded slice
    pub fn new(bytes: Vec<u8>) -> Result<Self, SecretsResolverError> {
        unsigned_varint::decode::u64(&bytes)
            .map_err(|e| SecretsResolverError::Decoding(format!("unsigned_varint: {e}")))?;
        Ok(Self(bytes))
    }

    /// Encode bytes with the given codec
    pub fn encode_bytes(codec: u64, bytes: &[u8]) -> Self {
        let mut codec_buffer = [0u8; 10];
        let encoded_codec = unsigned_varint::encode::u64(codec, &mut codec_buffer);
        let mut result = Vec::with_capacity(encoded_codec.len() + bytes.len());
        result.extend(encoded_codec);
        result.extend(bytes);
        Self(result)
    }

    /// Returns the raw bytes, including the codec prefix.
    #[inline(always)]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.clone()
    }
}
