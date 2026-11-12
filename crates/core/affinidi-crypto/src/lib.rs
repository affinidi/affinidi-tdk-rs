//! Cryptographic primitives and JWK types for Affinidi TDK
//!
//! This crate provides:
//! - JWK (JSON Web Key) types per RFC 7517
//! - Key generation for various curves (Ed25519, X25519, P-256, P-384, secp256k1)
//! - Key conversion utilities (e.g., Ed25519 → X25519)
//! - `did:key` encode/decode helpers for raw-bytes APIs (HPKE, ECDH) —
//!   see [`did_key`]
//! - Post-quantum signatures (FIPS 204 ML-DSA, FIPS 205 SLH-DSA) behind
//!   the `post-quantum` feature (off by default; also available
//!   individually as `ml-dsa` / `slh-dsa`)

/// Gives a key-pair struct a `Debug` that leaves `private_bytes` out and a
/// `Zeroize` that wipes the private material. The struct keeps its public
/// fields (and `Clone`), so holders can still move `private_bytes` into their
/// own zeroizing container; anything left in place is wiped by `zeroize()`.
#[allow(unused_macros)]
macro_rules! key_pair_hygiene {
    ($($other_field:ident),*) => {
        impl std::fmt::Debug for KeyPair {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("KeyPair")
                    .field("key_type", &self.key_type)
                    .field("private_bytes", &"<redacted>")
                    .field("public_bytes", &self.public_bytes)
                    $(.field(stringify!($other_field), &self.$other_field))*
                    .finish()
            }
        }

        impl zeroize::Zeroize for KeyPair {
            fn zeroize(&mut self) {
                zeroize::Zeroize::zeroize(&mut self.private_bytes);
                $(zeroize::Zeroize::zeroize(&mut self.$other_field);)*
            }
        }
    };
}

mod error;
mod jwk;
mod key_type;

/// BLS12-381 G2 `did:key` framing (BBS+ issuer keys). Curve-free, so it needs
/// no feature gate.
pub mod bls12381;

#[cfg(feature = "ed25519")]
pub mod did_key;

#[cfg(feature = "ed25519")]
pub mod ed25519;

#[cfg(feature = "p256")]
pub mod p256;

#[cfg(feature = "k256")]
pub mod secp256k1;

#[cfg(feature = "p384")]
pub mod p384;

#[cfg(feature = "p521")]
pub mod p521;

#[cfg(feature = "jose")]
pub mod jose;

#[cfg(feature = "ml-dsa")]
pub mod ml_dsa;

#[cfg(feature = "slh-dsa")]
pub mod slh_dsa;

pub use error::CryptoError;
pub use jwk::{ECParams, JWK, OctectParams, Params};
pub use key_type::KeyType;

#[cfg(feature = "ed25519")]
pub use ed25519::KeyPair as Ed25519KeyPair;
#[cfg(feature = "p256")]
pub use p256::KeyPair as P256KeyPair;
#[cfg(feature = "p384")]
pub use p384::KeyPair as P384KeyPair;
#[cfg(feature = "k256")]
pub use secp256k1::KeyPair as Secp256k1KeyPair;

#[cfg(test)]
#[allow(dead_code)]
pub(crate) mod key_pair_test_support {
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

    /// The `Debug` output of a key pair names the field but shows neither
    /// the raw private bytes nor their base64url (`d`) form.
    pub(crate) fn assert_debug_hides_private(printed: &str, private_bytes: &[u8]) {
        assert!(!private_bytes.is_empty());
        assert!(
            printed.contains("private_bytes: \"<redacted>\""),
            "{printed}"
        );
        assert!(
            !printed.contains(&format!("{private_bytes:?}")),
            "{printed}"
        );
        assert!(
            !printed.contains(&BASE64_URL_SAFE_NO_PAD.encode(private_bytes)),
            "{printed}"
        );
    }

    /// After `zeroize()` the private bytes and the JWK's `d` are gone.
    pub(crate) fn assert_jwk_private_wiped(jwk: &crate::JWK) {
        match &jwk.params {
            crate::Params::EC(params) => assert!(params.d.is_none()),
            crate::Params::OKP(params) => assert!(params.d.is_none()),
        }
    }
}
