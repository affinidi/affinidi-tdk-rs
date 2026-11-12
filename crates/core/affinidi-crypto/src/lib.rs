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

/// Gives a key-pair struct a `Debug` that leaves `private_bytes` out, a
/// `Zeroize` that wipes the private material, and `ZeroizeOnDrop`: the
/// private bytes and the JWK's `d` are wiped when the key pair is dropped.
///
/// Because the key pair has a `Drop`, its fields can be read and borrowed but
/// not moved out. `into_parts()` moves them into a `KeyPairParts` instead,
/// with the private bytes in a `Zeroizing` buffer, so taking ownership never
/// leaves an unwiped copy behind. `into_private_bytes()` (and, where there is
/// a JWK, `into_jwk()`) are shorthands for one part.
///
/// Invoked as `key_pair_hygiene!(jwk)` for key pairs with a JWK, or
/// `key_pair_hygiene!()` for those without.
#[allow(unused_macros)]
macro_rules! key_pair_hygiene {
    (jwk) => {
        key_pair_hygiene!(@common jwk);

        /// The fields of a [`KeyPair`], moved out of it by
        /// [`KeyPair::into_parts`]. `private_bytes` is wiped when it is
        /// dropped, and so is the JWK's `d`. Take the `Vec` itself with
        /// `std::mem::take(&mut *parts.private_bytes)` to hand it to another
        /// container that wipes on drop; the buffer moves, nothing is copied.
        #[non_exhaustive]
        pub struct KeyPairParts {
            pub key_type: crate::KeyType,
            pub private_bytes: zeroize::Zeroizing<Vec<u8>>,
            pub public_bytes: Vec<u8>,
            pub jwk: crate::JWK,
        }

        impl std::fmt::Debug for KeyPairParts {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("KeyPairParts")
                    .field("key_type", &self.key_type)
                    .field("private_bytes", &"<redacted>")
                    .field("public_bytes", &self.public_bytes)
                    .field("jwk", &self.jwk)
                    .finish()
            }
        }

        impl KeyPair {
            /// Moves the key type, the private and public bytes and the JWK
            /// out of the key pair without copying the private key.
            pub fn into_parts(mut self) -> KeyPairParts {
                KeyPairParts {
                    key_type: self.key_type,
                    private_bytes: zeroize::Zeroizing::new(std::mem::take(
                        &mut self.private_bytes,
                    )),
                    public_bytes: std::mem::take(&mut self.public_bytes),
                    jwk: std::mem::replace(&mut self.jwk, crate::jwk::placeholder_jwk()),
                }
            }

            /// Moves the private bytes out; everything else is wiped and
            /// dropped.
            pub fn into_private_bytes(self) -> zeroize::Zeroizing<Vec<u8>> {
                self.into_parts().private_bytes
            }

            /// Moves the JWK (with its `d`) out; the raw private bytes are
            /// wiped and dropped. The JWK wipes `d` when it is dropped.
            pub fn into_jwk(self) -> crate::JWK {
                self.into_parts().jwk
            }
        }
    };
    () => {
        key_pair_hygiene!(@common);

        /// The fields of a [`KeyPair`], moved out of it by
        /// [`KeyPair::into_parts`]. `private_bytes` is wiped when it is
        /// dropped. Take the `Vec` itself with
        /// `std::mem::take(&mut *parts.private_bytes)` to hand it to another
        /// container that wipes on drop; the buffer moves, nothing is copied.
        #[non_exhaustive]
        pub struct KeyPairParts {
            pub key_type: crate::KeyType,
            pub private_bytes: zeroize::Zeroizing<Vec<u8>>,
            pub public_bytes: Vec<u8>,
        }

        impl std::fmt::Debug for KeyPairParts {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("KeyPairParts")
                    .field("key_type", &self.key_type)
                    .field("private_bytes", &"<redacted>")
                    .field("public_bytes", &self.public_bytes)
                    .finish()
            }
        }

        impl KeyPair {
            /// Moves the key type and the private and public bytes out of the
            /// key pair without copying the private key.
            pub fn into_parts(mut self) -> KeyPairParts {
                KeyPairParts {
                    key_type: self.key_type,
                    private_bytes: zeroize::Zeroizing::new(std::mem::take(
                        &mut self.private_bytes,
                    )),
                    public_bytes: std::mem::take(&mut self.public_bytes),
                }
            }

            /// Moves the private bytes out; the rest is dropped.
            pub fn into_private_bytes(self) -> zeroize::Zeroizing<Vec<u8>> {
                self.into_parts().private_bytes
            }
        }
    };
    (@common $($other_field:ident)?) => {
        impl std::fmt::Debug for KeyPair {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("KeyPair")
                    .field("key_type", &self.key_type)
                    .field("private_bytes", &"<redacted>")
                    .field("public_bytes", &self.public_bytes)
                    $(.field(stringify!($other_field), &self.$other_field))?
                    .finish()
            }
        }

        impl zeroize::Zeroize for KeyPair {
            fn zeroize(&mut self) {
                zeroize::Zeroize::zeroize(&mut self.private_bytes);
                $(zeroize::Zeroize::zeroize(&mut self.$other_field);)?
            }
        }

        impl Drop for KeyPair {
            fn drop(&mut self) {
                zeroize::Zeroize::zeroize(self);
            }
        }

        impl zeroize::ZeroizeOnDrop for KeyPair {}
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

    /// Compile-time check that a key pair wipes itself when dropped.
    pub(crate) fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    /// The JWK carries `private_bytes` as its `d`.
    pub(crate) fn assert_jwk_private_is(jwk: &crate::JWK, private_bytes: &[u8]) {
        let d = match &jwk.params {
            crate::Params::EC(params) => params.d.clone(),
            crate::Params::OKP(params) => params.d.clone(),
        };
        assert_eq!(
            d.as_deref(),
            Some(BASE64_URL_SAFE_NO_PAD.encode(private_bytes).as_str())
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
