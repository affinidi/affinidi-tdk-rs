//! Algorithm traits — the open-for-extension seam for JOSE crypto.
//!
//! Per ADR 0001, each JOSE role is a trait; concrete algorithms are
//! implementations keyed by their JOSE `alg`/`enc` identifier. Adding a
//! new curve, AEAD, key-wrap, or signature scheme is then an additive
//! `impl`, not an edit to a closed `match` across the codebase.
//!
//! Security boundary: these traits are *capability*. Deciding which
//! identifiers a given protocol message is *allowed* to use stays an
//! explicit allowlist in the envelope layer (e.g. didcomm) — registering
//! an implementation here never auto-enables it on the wire. The traits
//! take `&[u8]` keys (not fixed-size arrays) so differently-sized
//! algorithms share one interface; each impl length-checks its inputs.

use crate::error::CryptoError;

use super::{aes_kw, concat_kdf, content_encryption, signing};

/// Key-wrapping algorithms (JWE `alg` of the `…+AxxxKW` form).
pub trait KeyWrap {
    /// JOSE key-management algorithm identifier, e.g. `"A256KW"`.
    fn algorithm(&self) -> &'static str;
    /// Wrap `key` (the CEK) under `kek`.
    fn wrap(&self, kek: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// Unwrap a wrapped key under `kek`.
    fn unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// Authenticated content-encryption algorithms (JWE `enc`).
pub trait ContentEncryption {
    /// JOSE content-encryption identifier, e.g. `"A256CBC-HS512"`.
    fn enc(&self) -> &'static str;
    /// Required content-encryption key length in bytes.
    fn cek_len(&self) -> usize;
    /// Required IV length in bytes.
    fn iv_len(&self) -> usize;
    /// Authentication tag length in bytes.
    fn tag_len(&self) -> usize;
    /// Encrypt, returning `(ciphertext, tag)`.
    fn encrypt(
        &self,
        plaintext: &[u8],
        cek: &[u8],
        iv: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;
    /// Verify the tag and decrypt.
    fn decrypt(
        &self,
        ciphertext: &[u8],
        cek: &[u8],
        iv: &[u8],
        aad: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

/// JOSE key-derivation (Concat KDF and future KDFs). `cc_tag` is the
/// ECDH-1PU content-encryption tag; pass an empty slice for ECDH-ES.
pub trait KeyDerivation {
    /// Derive `key_len_bits` of key-encryption key from the raw ECDH
    /// shared secret `z` and the OtherInfo parameters.
    fn derive(
        &self,
        z: &[u8],
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        key_len_bits: u32,
        cc_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

/// JWS signing algorithms (`alg`).
pub trait JwsSigner {
    /// JOSE signature algorithm identifier, e.g. `"EdDSA"`.
    fn algorithm(&self) -> &'static str;
    /// Sign `data` with `private_key`.
    fn sign(&self, data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// JWS verification algorithms (`alg`).
pub trait JwsVerifier {
    /// JOSE signature algorithm identifier, e.g. `"EdDSA"`.
    fn algorithm(&self) -> &'static str;
    /// Verify `signature` over `data` with `public_key`.
    fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), CryptoError>;
}

// ─── Concrete algorithms ────────────────────────────────────────────────────

/// AES-256 Key Wrap (RFC 3394).
#[derive(Debug, Clone, Copy, Default)]
pub struct A256Kw;

impl KeyWrap for A256Kw {
    fn algorithm(&self) -> &'static str {
        "A256KW"
    }

    fn wrap(&self, kek: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let kek: &[u8; 32] = kek
            .try_into()
            .map_err(|_| CryptoError::KeyWrap("A256KW KEK must be 32 bytes".into()))?;
        aes_kw::wrap(kek, key)
    }

    fn unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let kek: &[u8; 32] = kek
            .try_into()
            .map_err(|_| CryptoError::KeyWrap("A256KW KEK must be 32 bytes".into()))?;
        aes_kw::unwrap(kek, wrapped)
    }
}

/// A256CBC-HS512 (AES-256-CBC + HMAC-SHA-512/256).
#[derive(Debug, Clone, Copy, Default)]
pub struct A256CbcHs512;

impl ContentEncryption for A256CbcHs512 {
    fn enc(&self) -> &'static str {
        "A256CBC-HS512"
    }
    fn cek_len(&self) -> usize {
        content_encryption::CEK_SIZE
    }
    fn iv_len(&self) -> usize {
        content_encryption::IV_SIZE
    }
    fn tag_len(&self) -> usize {
        content_encryption::TAG_SIZE
    }

    fn encrypt(
        &self,
        plaintext: &[u8],
        cek: &[u8],
        iv: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let cek: &[u8; content_encryption::CEK_SIZE] = cek
            .try_into()
            .map_err(|_| CryptoError::ContentEncryption("CEK must be 64 bytes".into()))?;
        let iv: &[u8; content_encryption::IV_SIZE] = iv
            .try_into()
            .map_err(|_| CryptoError::ContentEncryption("IV must be 16 bytes".into()))?;
        let (ct, tag) = content_encryption::encrypt(plaintext, cek, iv, aad)?;
        Ok((ct, tag.to_vec()))
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        cek: &[u8],
        iv: &[u8],
        aad: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cek: &[u8; content_encryption::CEK_SIZE] = cek
            .try_into()
            .map_err(|_| CryptoError::ContentEncryption("CEK must be 64 bytes".into()))?;
        let iv: &[u8; content_encryption::IV_SIZE] = iv
            .try_into()
            .map_err(|_| CryptoError::ContentEncryption("IV must be 16 bytes".into()))?;
        let tag: &[u8; content_encryption::TAG_SIZE] = tag
            .try_into()
            .map_err(|_| CryptoError::ContentEncryption("tag must be 32 bytes".into()))?;
        content_encryption::decrypt(ciphertext, cek, iv, aad, tag)
    }
}

/// JOSE Concat KDF (SHA-256), covering both ECDH-ES (empty `cc_tag`) and
/// ECDH-1PU (length-prefixed `cc_tag`, the #322-correct encoding).
#[derive(Debug, Clone, Copy, Default)]
pub struct ConcatKdf;

impl KeyDerivation for ConcatKdf {
    fn derive(
        &self,
        z: &[u8],
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        key_len_bits: u32,
        cc_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if cc_tag.is_empty() {
            concat_kdf::concat_kdf(z, alg, apu, apv, key_len_bits)
        } else {
            concat_kdf::concat_kdf_1pu(z, alg, apu, apv, key_len_bits, cc_tag)
        }
    }
}

/// Ed25519 (EdDSA).
#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519;

impl JwsSigner for Ed25519 {
    fn algorithm(&self) -> &'static str {
        "EdDSA"
    }

    fn sign(&self, data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sk: &[u8; 32] = private_key
            .try_into()
            .map_err(|_| CryptoError::Signing("Ed25519 private key must be 32 bytes".into()))?;
        Ok(signing::sign(data, sk)?.to_vec())
    }
}

impl JwsVerifier for Ed25519 {
    fn algorithm(&self) -> &'static str {
        "EdDSA"
    }

    fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), CryptoError> {
        let sig: &[u8; 64] = signature
            .try_into()
            .map_err(|_| CryptoError::Verification("Ed25519 signature must be 64 bytes".into()))?;
        let pk: &[u8; 32] = public_key
            .try_into()
            .map_err(|_| CryptoError::Verification("Ed25519 public key must be 32 bytes".into()))?;
        signing::verify(data, sig, pk)
    }
}
