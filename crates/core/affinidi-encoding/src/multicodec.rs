//! Multicodec encoding/decoding
//!
//! Multicodec is a self-describing format that prefixes data with a varint
//! indicating the type of data that follows.
//!
//! See: <https://github.com/multiformats/multicodec>

use crate::EncodingError;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ****************************************************************************
// Codec Magic Numbers
// See: https://github.com/multiformats/multicodec/blob/master/table.csv
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

// Post-quantum codecs (draft entries in the multicodec table).
// Public: aligns with W3C `di-quantum-safe` cryptosuite multi-byte prefixes.
// Private: draft convention (pub code + 0x20).
pub const ML_DSA_44_PUB: u64 = 0x1210;
pub const ML_DSA_44_PRIV: u64 = 0x1230;
pub const ML_DSA_65_PUB: u64 = 0x1211;
pub const ML_DSA_65_PRIV: u64 = 0x1231;
pub const ML_DSA_87_PUB: u64 = 0x1212;
pub const ML_DSA_87_PRIV: u64 = 0x1232;
pub const SLH_DSA_SHA2_128S_PUB: u64 = 0x1220;
pub const SLH_DSA_SHA2_128S_PRIV: u64 = 0x1240;

/// Known codec types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Codec {
    Ed25519Pub,
    Ed25519Priv,
    X25519Pub,
    X25519Priv,
    Secp256k1Pub,
    Secp256k1Priv,
    P256Pub,
    P256Priv,
    P384Pub,
    P384Priv,
    P521Pub,
    P521Priv,
    MlDsa44Pub,
    MlDsa44Priv,
    MlDsa65Pub,
    MlDsa65Priv,
    MlDsa87Pub,
    MlDsa87Priv,
    SlhDsaSha2_128sPub,
    SlhDsaSha2_128sPriv,
    Unknown(u64),
}

impl Codec {
    /// Convert a raw codec value to a Codec enum
    pub fn from_u64(value: u64) -> Self {
        match value {
            ED25519_PUB => Codec::Ed25519Pub,
            ED25519_PRIV => Codec::Ed25519Priv,
            X25519_PUB => Codec::X25519Pub,
            X25519_PRIV => Codec::X25519Priv,
            SECP256K1_PUB => Codec::Secp256k1Pub,
            SECP256K1_PRIV => Codec::Secp256k1Priv,
            P256_PUB => Codec::P256Pub,
            P256_PRIV => Codec::P256Priv,
            P384_PUB => Codec::P384Pub,
            P384_PRIV => Codec::P384Priv,
            P521_PUB => Codec::P521Pub,
            P521_PRIV => Codec::P521Priv,
            ML_DSA_44_PUB => Codec::MlDsa44Pub,
            ML_DSA_44_PRIV => Codec::MlDsa44Priv,
            ML_DSA_65_PUB => Codec::MlDsa65Pub,
            ML_DSA_65_PRIV => Codec::MlDsa65Priv,
            ML_DSA_87_PUB => Codec::MlDsa87Pub,
            ML_DSA_87_PRIV => Codec::MlDsa87Priv,
            SLH_DSA_SHA2_128S_PUB => Codec::SlhDsaSha2_128sPub,
            SLH_DSA_SHA2_128S_PRIV => Codec::SlhDsaSha2_128sPriv,
            other => Codec::Unknown(other),
        }
    }

    /// Convert to raw u64 value
    pub fn to_u64(self) -> u64 {
        match self {
            Codec::Ed25519Pub => ED25519_PUB,
            Codec::Ed25519Priv => ED25519_PRIV,
            Codec::X25519Pub => X25519_PUB,
            Codec::X25519Priv => X25519_PRIV,
            Codec::Secp256k1Pub => SECP256K1_PUB,
            Codec::Secp256k1Priv => SECP256K1_PRIV,
            Codec::P256Pub => P256_PUB,
            Codec::P256Priv => P256_PRIV,
            Codec::P384Pub => P384_PUB,
            Codec::P384Priv => P384_PRIV,
            Codec::P521Pub => P521_PUB,
            Codec::P521Priv => P521_PRIV,
            Codec::MlDsa44Pub => ML_DSA_44_PUB,
            Codec::MlDsa44Priv => ML_DSA_44_PRIV,
            Codec::MlDsa65Pub => ML_DSA_65_PUB,
            Codec::MlDsa65Priv => ML_DSA_65_PRIV,
            Codec::MlDsa87Pub => ML_DSA_87_PUB,
            Codec::MlDsa87Priv => ML_DSA_87_PRIV,
            Codec::SlhDsaSha2_128sPub => SLH_DSA_SHA2_128S_PUB,
            Codec::SlhDsaSha2_128sPriv => SLH_DSA_SHA2_128S_PRIV,
            Codec::Unknown(v) => v,
        }
    }

    /// Returns true if this is a public key codec
    pub fn is_public(&self) -> bool {
        matches!(
            self,
            Codec::Ed25519Pub
                | Codec::X25519Pub
                | Codec::Secp256k1Pub
                | Codec::P256Pub
                | Codec::P384Pub
                | Codec::P521Pub
                | Codec::MlDsa44Pub
                | Codec::MlDsa65Pub
                | Codec::MlDsa87Pub
                | Codec::SlhDsaSha2_128sPub
        )
    }

    /// Returns the expected key length for this codec, if known
    pub fn expected_key_length(&self) -> Option<usize> {
        match self {
            Codec::Ed25519Pub | Codec::Ed25519Priv => Some(32),
            Codec::X25519Pub | Codec::X25519Priv => Some(32),
            Codec::Secp256k1Pub => Some(33), // compressed
            Codec::P256Pub => Some(33),      // compressed
            Codec::P384Pub => Some(49),      // compressed
            Codec::P521Pub => Some(67),      // compressed
            // ML-DSA public keys: FIPS 204 fixed sizes
            Codec::MlDsa44Pub => Some(1312),
            Codec::MlDsa65Pub => Some(1952),
            Codec::MlDsa87Pub => Some(2592),
            // ML-DSA private representation: 32-byte seed (xi) per FIPS 204
            Codec::MlDsa44Priv | Codec::MlDsa65Priv | Codec::MlDsa87Priv => Some(32),
            // SLH-DSA-SHA2-128s: FIPS 205 sizes (PK = 32, SK = 64)
            Codec::SlhDsaSha2_128sPub => Some(32),
            Codec::SlhDsaSha2_128sPriv => Some(64),
            _ => None,
        }
    }
}

/// A multicodec-encoded byte slice (borrowed)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MultiEncoded([u8]);

impl MultiEncoded {
    /// Create a new multiencoded byte slice
    /// Validates the codec encoding
    pub fn new(bytes: &[u8]) -> Result<&Self, EncodingError> {
        unsigned_varint::decode::u64(bytes)
            .map_err(|e| EncodingError::InvalidMulticodec(format!("varint decode: {e}")))?;

        Ok(unsafe { &*(bytes as *const [u8] as *const MultiEncoded) })
    }

    /// Size of the byte array (including codec prefix)
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Separates the codec and the data
    pub fn parts(&self) -> (u64, &[u8]) {
        unsigned_varint::decode::u64(&self.0).unwrap()
    }

    /// Raw codec value (u64)
    pub fn codec(&self) -> u64 {
        self.parts().0
    }

    /// Codec as typed enum
    pub fn codec_type(&self) -> Codec {
        Codec::from_u64(self.codec())
    }

    /// Data bytes (without codec prefix)
    pub fn data(&self) -> &[u8] {
        self.parts().1
    }

    /// Returns the raw bytes, including the codec prefix
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A multicodec-encoded byte buffer (owned)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MultiEncodedBuf(Vec<u8>);

impl MultiEncodedBuf {
    /// Parse an existing multicodec-encoded buffer
    pub fn new(bytes: Vec<u8>) -> Result<Self, EncodingError> {
        unsigned_varint::decode::u64(&bytes)
            .map_err(|e| EncodingError::InvalidMulticodec(format!("varint decode: {e}")))?;
        Ok(Self(bytes))
    }

    /// Encode bytes with the given codec
    pub fn encode(codec: Codec, bytes: &[u8]) -> Self {
        Self::encode_raw(codec.to_u64(), bytes)
    }

    /// Encode bytes with a raw codec value (backwards-compatible alias)
    pub fn encode_bytes(codec: u64, bytes: &[u8]) -> Self {
        Self::encode_raw(codec, bytes)
    }

    /// Encode bytes with a raw codec value
    pub fn encode_raw(codec: u64, bytes: &[u8]) -> Self {
        let mut codec_buffer = [0u8; 10];
        let encoded_codec = unsigned_varint::encode::u64(codec, &mut codec_buffer);
        let mut result = Vec::with_capacity(encoded_codec.len() + bytes.len());
        result.extend(encoded_codec);
        result.extend(bytes);
        Self(result)
    }

    /// Returns the raw bytes, including the codec prefix
    /// Note: clones due to ZeroizeOnDrop
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.clone()
    }

    /// Returns a reference to the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Borrow as MultiEncoded slice
    pub fn as_multi_encoded(&self) -> &MultiEncoded {
        unsafe { &*(self.0.as_slice() as *const [u8] as *const MultiEncoded) }
    }
}

impl AsRef<MultiEncoded> for MultiEncodedBuf {
    fn as_ref(&self) -> &MultiEncoded {
        self.as_multi_encoded()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_ed25519() {
        let key_bytes = [0u8; 32];
        let encoded = MultiEncodedBuf::encode(Codec::Ed25519Pub, &key_bytes);

        let decoded = MultiEncoded::new(encoded.as_bytes()).unwrap();
        assert_eq!(decoded.codec(), ED25519_PUB);
        assert_eq!(decoded.codec_type(), Codec::Ed25519Pub);
        assert_eq!(decoded.data(), &key_bytes);
    }

    #[test]
    fn test_codec_roundtrip() {
        for codec in [
            Codec::Ed25519Pub,
            Codec::X25519Pub,
            Codec::P256Pub,
            Codec::P384Pub,
        ] {
            let raw = codec.to_u64();
            assert_eq!(Codec::from_u64(raw), codec);
        }
    }
}
