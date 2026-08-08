//! NaCl primitives that DIDComm v1 is specified in terms of.
//!
//! DIDComm v2.1 is a JOSE protocol: its envelope is a real JWE, its algorithms
//! are registered JWA identifiers (`ECDH-1PU+A256KW`, `A256CBC-HS512`), and
//! this workspace implements them centrally in `affinidi-crypto::jose`.
//!
//! DIDComm v1 only *looks* like JOSE. Aries RFC 0019 borrows the JWE JSON
//! serialization — `protected` / `iv` / `ciphertext` / `tag` — but every
//! algorithm underneath it is a libsodium call, none of which has a JWA
//! registration. There is consequently nothing in `affinidi-crypto::jose` to
//! reuse, and this module exists to supply the missing primitives:
//!
//! | Purpose | v2.1 (JOSE) | v1 (NaCl) |
//! |---|---|---|
//! | Key agreement | ECDH-ES / ECDH-1PU + Concat KDF | `crypto_box` (X25519 + HSalsa20) |
//! | CEK wrapping | A256KW | `crypto_secretbox` (XSalsa20-Poly1305) |
//! | Anonymous CEK wrapping | ECDH-ES+A256KW | `crypto_box_seal` (sealed box) |
//! | Content encryption | A256CBC-HS512 | ChaCha20-Poly1305 IETF |
//! | Curve agility | X25519, P-256, K-256, P-384, P-521 | X25519 only |
//!
//! The last row is the one that most constrains the API: v1 has **no curve
//! agility at all**. Every v1 key is an Ed25519 verkey converted to X25519 for
//! key agreement, so nothing in the v1 surface takes a curve parameter, and
//! the v2 crate's `Curve` / `PrivateKeyAgreement` enums have no counterpart
//! here.
//!
//! # Implementation note
//!
//! [`crypto_box`] re-implements libsodium's `crypto_box_easy` /
//! `crypto_box_seal` rather than using the RustCrypto `crypto_box` crate.
//! That crate would otherwise be a drop-in, but it depends on
//! `curve25519-dalek` 4 while this workspace is uniformly on the 5 line —
//! pulling it in would put two dalek generations in the graph. The
//! construction is small, and every step is covered by a known-answer test
//! against libsodium output (see the `kat` tests in each submodule).

pub mod content;
pub mod crypto_box;
