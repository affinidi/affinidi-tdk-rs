//! Cryptographic operations for TSP.
//!
//! - [`hpke`]: HPKE-Base seal/open over `DHKEM(X25519, HKDF-SHA256)` (RFC 9180)
//! - [`sealed_box`]: the libsodium anonymous sealed box (Rev 3 §8.3)
//! - [`signing`]: Ed25519 outer signatures
//!
//! Behind the `pq` feature, the post-quantum halves of the same two operations
//! (Rev 3 §8.1, §8.2.1). They are separate modules rather than branches inside
//! the classical ones because every size differs — the encapsulated key, both
//! keys, and the signature — and the classical path is verified against
//! published vectors that a rewrite would put at risk for no gain:
//!
//! - [`hpke_pq`]: HPKE-Base over the `MLKEM768-X25519` hybrid KEM
//! - [`ml_dsa`]: ML-DSA-65 outer signatures

pub mod hpke;
#[cfg(feature = "pq")]
pub mod hpke_pq;
#[cfg(feature = "pq")]
pub mod ml_dsa;
pub mod sealed_box;
pub mod signing;
