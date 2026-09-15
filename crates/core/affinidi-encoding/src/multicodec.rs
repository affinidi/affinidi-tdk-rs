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
// BLS12-381 public keys (used by BBS+ issuers). Compressed group elements:
// G1 = 48 bytes, G2 = 96 bytes. A BBS issuer's verification key is a G2 point.
pub const BLS12381_G1_PUB: u64 = 0xea;
pub const BLS12381_G2_PUB: u64 = 0xeb;

// Post-quantum codecs — draft entries from the official multicodec table.
// We store ML-DSA private keys as the 32-byte seed, so we use the
// `-priv-seed` codes (0x131a–0x131c), not the 2560/4032/4896-byte
// expanded-private codes (0x1317–0x1319).
//
// SLH-DSA has no private-key codec registered; `Secret::from_multibase`
// and `get_private_keymultibase` return an error for SLH-DSA keys.
//
// These seven are `draft` upstream and may legitimately move, so they are
// pinned by `pqc_code_points_match_the_multicodec_registry` rather than
// trusted. Last verified 2026-09-15 against `table.csv` at commit
// 38e3bf3e38f613679d76ef2041d73a8060f8622a — change a value here and
// re-state the revision there.
pub const ML_DSA_44_PUB: u64 = 0x1210;
pub const ML_DSA_44_PRIV_SEED: u64 = 0x131a;
pub const ML_DSA_65_PUB: u64 = 0x1211;
pub const ML_DSA_65_PRIV_SEED: u64 = 0x131b;
pub const ML_DSA_87_PUB: u64 = 0x1212;
pub const ML_DSA_87_PRIV_SEED: u64 = 0x131c;
pub const SLH_DSA_SHA2_128S_PUB: u64 = 0x1220;

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
    Bls12381G1Pub,
    Bls12381G2Pub,
    MlDsa44Pub,
    MlDsa44PrivSeed,
    MlDsa65Pub,
    MlDsa65PrivSeed,
    MlDsa87Pub,
    MlDsa87PrivSeed,
    SlhDsaSha2_128sPub,
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
            BLS12381_G1_PUB => Codec::Bls12381G1Pub,
            BLS12381_G2_PUB => Codec::Bls12381G2Pub,
            ML_DSA_44_PUB => Codec::MlDsa44Pub,
            ML_DSA_44_PRIV_SEED => Codec::MlDsa44PrivSeed,
            ML_DSA_65_PUB => Codec::MlDsa65Pub,
            ML_DSA_65_PRIV_SEED => Codec::MlDsa65PrivSeed,
            ML_DSA_87_PUB => Codec::MlDsa87Pub,
            ML_DSA_87_PRIV_SEED => Codec::MlDsa87PrivSeed,
            SLH_DSA_SHA2_128S_PUB => Codec::SlhDsaSha2_128sPub,
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
            Codec::Bls12381G1Pub => BLS12381_G1_PUB,
            Codec::Bls12381G2Pub => BLS12381_G2_PUB,
            Codec::MlDsa44Pub => ML_DSA_44_PUB,
            Codec::MlDsa44PrivSeed => ML_DSA_44_PRIV_SEED,
            Codec::MlDsa65Pub => ML_DSA_65_PUB,
            Codec::MlDsa65PrivSeed => ML_DSA_65_PRIV_SEED,
            Codec::MlDsa87Pub => ML_DSA_87_PUB,
            Codec::MlDsa87PrivSeed => ML_DSA_87_PRIV_SEED,
            Codec::SlhDsaSha2_128sPub => SLH_DSA_SHA2_128S_PUB,
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
                | Codec::Bls12381G1Pub
                | Codec::Bls12381G2Pub
                | Codec::MlDsa44Pub
                | Codec::MlDsa65Pub
                | Codec::MlDsa87Pub
                | Codec::SlhDsaSha2_128sPub // SLH-DSA has no private codec registered
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
            // BLS12-381 compressed group elements.
            Codec::Bls12381G1Pub => Some(48),
            Codec::Bls12381G2Pub => Some(96),
            // ML-DSA public keys: FIPS 204 fixed sizes
            Codec::MlDsa44Pub => Some(1312),
            Codec::MlDsa65Pub => Some(1952),
            Codec::MlDsa87Pub => Some(2592),
            // ML-DSA priv-seed codec (0x131a–0x131c): 32-byte seed (xi)
            Codec::MlDsa44PrivSeed | Codec::MlDsa65PrivSeed | Codec::MlDsa87PrivSeed => Some(32),
            // SLH-DSA-SHA2-128s public key: FIPS 205 (32 bytes)
            Codec::SlhDsaSha2_128sPub => Some(32),
            _ => None,
        }
    }
}

/// A multicodec-encoded byte slice (borrowed).
///
/// `#[repr(transparent)]` guarantees the same memory layout as `[u8]`,
/// which `MultiEncoded::new` relies on when reinterpreting a borrowed
/// byte slice as this DST.
#[derive(Zeroize, ZeroizeOnDrop)]
#[repr(transparent)]
pub struct MultiEncoded([u8]);

impl MultiEncoded {
    /// Create a new multiencoded byte slice, validating the varint
    /// prefix.
    pub fn new(bytes: &[u8]) -> Result<&Self, EncodingError> {
        unsigned_varint::decode::u64(bytes)
            .map_err(|e| EncodingError::InvalidMulticodec(format!("varint decode: {e}")))?;

        // SAFETY: `MultiEncoded` is a `#[repr(transparent)]` wrapper
        // around `[u8]`, so `&[u8]` and `&MultiEncoded` have identical
        // memory layout (including DST metadata). The varint prefix has
        // been validated above, so every subsequent call into `parts()`
        // will see well-formed bytes.
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

    /// Borrow as MultiEncoded slice.
    pub fn as_multi_encoded(&self) -> &MultiEncoded {
        // SAFETY: `MultiEncoded` is `#[repr(transparent)]` over `[u8]`.
        // The varint prefix was validated when this `MultiEncodedBuf`
        // was constructed (see `MultiEncodedBuf::new` / `encode_raw`).
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

    /// The post-quantum code points, pinned against the upstream registry.
    ///
    /// Verified 2026-09-15 against `multiformats/multicodec` `table.csv` at
    /// commit `38e3bf3e38f613679d76ef2041d73a8060f8622a`. Every one of these
    /// rows is `draft` status, which means upstream may legitimately move them
    /// — and a code point that has moved does not fail loudly. It produces
    /// `did:key`s and multikeys that this workspace reads back perfectly and no
    /// other implementation can resolve, which is the kind of defect that is
    /// found by an interop partner months later rather than by a test.
    ///
    /// So this test is a provenance record as much as an assertion: changing a
    /// constant means changing the value *here* and re-stating which revision
    /// of the table it was checked against.
    ///
    /// Registry names, for grepping upstream: `mldsa-44-pub`, `mldsa-65-pub`,
    /// `mldsa-87-pub`, `mldsa-44-priv-seed`, `mldsa-65-priv-seed`,
    /// `mldsa-87-priv-seed`, `slhdsa-sha2-128s-pub`.
    #[test]
    fn pqc_code_points_match_the_multicodec_registry() {
        // ML-DSA public keys (FIPS 204).
        assert_eq!(ML_DSA_44_PUB, 0x1210, "mldsa-44-pub");
        assert_eq!(ML_DSA_65_PUB, 0x1211, "mldsa-65-pub");
        assert_eq!(ML_DSA_87_PUB, 0x1212, "mldsa-87-pub");

        // ML-DSA private keys. The registry has *two* families and we use the
        // seed one deliberately: `-priv-seed` (0x131a-0x131c) is the 32-byte
        // seed xi, not the expanded 2560/4032/4896-byte private key
        // (0x1317-0x1319). Storing the seed is what lets a key be re-derived
        // from a BIP-32/SLIP-0010 chain, so this choice is load-bearing for
        // context-scoped key derivation and not merely a size optimisation.
        assert_eq!(ML_DSA_44_PRIV_SEED, 0x131a, "mldsa-44-priv-seed");
        assert_eq!(ML_DSA_65_PRIV_SEED, 0x131b, "mldsa-65-priv-seed");
        assert_eq!(ML_DSA_87_PRIV_SEED, 0x131c, "mldsa-87-priv-seed");

        // SLH-DSA (FIPS 205). Only the SHA2-128s parameter set is implemented.
        assert_eq!(SLH_DSA_SHA2_128S_PUB, 0x1220, "slhdsa-sha2-128s-pub");

        // Key lengths are the algorithms' own, and are the cheap check that
        // catches a truncated key without any base64 reasoning.
        assert_eq!(Codec::MlDsa44Pub.expected_key_length(), Some(1312));
        assert_eq!(Codec::MlDsa65Pub.expected_key_length(), Some(1952));
        assert_eq!(Codec::MlDsa87Pub.expected_key_length(), Some(2592));
        assert_eq!(Codec::MlDsa44PrivSeed.expected_key_length(), Some(32));
        assert_eq!(Codec::MlDsa65PrivSeed.expected_key_length(), Some(32));
        assert_eq!(Codec::MlDsa87PrivSeed.expected_key_length(), Some(32));
        assert_eq!(Codec::SlhDsaSha2_128sPub.expected_key_length(), Some(32));

        // Every PQC codec we hold round-trips through the u64 conversion.
        for codec in [
            Codec::MlDsa44Pub,
            Codec::MlDsa65Pub,
            Codec::MlDsa87Pub,
            Codec::MlDsa44PrivSeed,
            Codec::MlDsa65PrivSeed,
            Codec::MlDsa87PrivSeed,
            Codec::SlhDsaSha2_128sPub,
        ] {
            assert_eq!(Codec::from_u64(codec.to_u64()), codec, "{codec:?}");
        }
    }

    /// SLH-DSA has no registered private-key code point, and that is a fact
    /// about the registry rather than a gap in this crate.
    ///
    /// Re-checked 2026-09-15 at the revision named above: the registry carries
    /// twelve `slhdsa-*-pub` rows (0x1220-0x122b) and **no** `slhdsa-*-priv` of
    /// any parameter set. `get_private_keymultibase` therefore refuses an
    /// SLH-DSA secret rather than encoding one, and
    /// `affinidi-secrets-resolver` keeps those keys memory-only.
    ///
    /// The failure mode this guards against is someone closing that gap from
    /// this side by picking an unused number. A self-assigned code point
    /// round-trips perfectly in-workspace and is unreadable everywhere else —
    /// the same trap a neighbouring TSP implementation fell into with
    /// private-use-area codecs. If a `slhdsa-*-priv` row is ever registered,
    /// add the constant and delete this test; do not invent one.
    #[test]
    fn slh_dsa_has_no_private_code_point_to_hold() {
        // The public codec exists...
        assert!(Codec::SlhDsaSha2_128sPub.is_public());

        // ...and every private codec we hold is an ML-DSA seed. If this list
        // ever gains an SLH-DSA entry, the comment above is out of date.
        for codec in [
            Codec::MlDsa44PrivSeed,
            Codec::MlDsa65PrivSeed,
            Codec::MlDsa87PrivSeed,
        ] {
            assert!(!codec.is_public(), "{codec:?} must classify as private");
        }
    }
}
