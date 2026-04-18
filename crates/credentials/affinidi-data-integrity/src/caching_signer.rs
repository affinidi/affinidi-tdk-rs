//! [`CachingSigner`] — wraps any [`Signer`] and caches the expanded
//! signing key on first use.
//!
//! # When to use
//!
//! For ML-DSA, `<Params as KeyGen>::from_seed` re-expands a NIST lattice
//! matrix on every call (≈ 80–100 µs for ML-DSA-44, more for -65/-87).
//! An issuer signing thousands of credentials with the same key pays
//! that cost for every signature. [`CachingSigner`] amortises it to
//! once per key.
//!
//! For Ed25519 and SLH-DSA, caching does nothing useful — Ed25519
//! sign is already ~30 µs with no expansion step, and SLH-DSA sign is
//! dominated by the hash tree (tens of ms) which the cache can't
//! affect. The wrapper transparently falls through to the inner
//! signer for non-ML-DSA key types.
//!
//! # Thread safety
//!
//! [`CachingSigner`] holds its cached expanded key behind a
//! [`std::sync::OnceLock`] — the first concurrent caller populates
//! it, every other caller blocks briefly on the same init. After
//! first use, access is lock-free.
//!
//! # Clone / sharing
//!
//! `CachingSigner<S>` intentionally does not implement `Clone`.
//! `OnceLock` cannot be cloned (doing so would either duplicate the
//! cached key — defeating the purpose — or require a shared cache
//! with atomic reference counting). To share a signer across tokio
//! tasks, wrap in `Arc<CachingSigner<_>>`.
//!
//! # Zeroize
//!
//! The ml-dsa crate is built with `zeroize` in this workspace, so the
//! internal ExpandedSigningKey wipes its matrix on drop. The enum
//! wrapper this module holds does not add extra copies.

use std::sync::OnceLock;

use affinidi_secrets_resolver::secrets::KeyType;
use async_trait::async_trait;

use crate::DataIntegrityError;
use crate::crypto_suites::CryptoSuite;
use crate::signer::Signer;

/// Wraps an inner [`Signer`] with a lazy ML-DSA expanded-key cache.
pub struct CachingSigner<S: Signer> {
    inner: S,
    #[cfg(feature = "ml-dsa")]
    cached_expanded: OnceLock<affinidi_crypto::ml_dsa::MlDsaExpandedKey>,
    #[cfg(not(feature = "ml-dsa"))]
    _phantom: std::marker::PhantomData<()>,
}

impl<S: Signer> CachingSigner<S> {
    /// Wraps `inner` in a new `CachingSigner`.
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            #[cfg(feature = "ml-dsa")]
            cached_expanded: OnceLock::new(),
            #[cfg(not(feature = "ml-dsa"))]
            _phantom: std::marker::PhantomData,
        }
    }

    /// Returns the wrapped signer.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

#[async_trait]
impl<S> Signer for CachingSigner<S>
where
    S: Signer + GetPrivateBytes,
{
    fn key_type(&self) -> KeyType {
        self.inner.key_type()
    }

    fn verification_method(&self) -> &str {
        self.inner.verification_method()
    }

    fn cryptosuite(&self) -> CryptoSuite {
        self.inner.cryptosuite()
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, DataIntegrityError> {
        #[cfg(feature = "ml-dsa")]
        {
            match self.inner.key_type() {
                KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => {
                    let expanded = self.cached_expanded.get_or_init(|| {
                        // Expand once. Panics only on programmer error
                        // (wrong-length seed) which can't happen here:
                        // we've already matched an ML-DSA key type, and
                        // the secret's private_bytes is always a 32-byte
                        // seed for ML-DSA variants.
                        affinidi_crypto::ml_dsa::MlDsaExpandedKey::from_seed(
                            self.inner.key_type(),
                            self.inner.private_bytes(),
                        )
                        .expect("ML-DSA seed is always 32 bytes for ML-DSA key types")
                    });
                    return Ok(expanded.sign(data));
                }
                _ => {}
            }
        }
        self.inner.sign(data).await
    }
}

/// Private-byte accessor needed for the ML-DSA cache. Callers can
/// implement this alongside [`Signer`] for types that ship raw keys in
/// memory (e.g. `Secret`). Remote signers typically can't expose bytes
/// and so shouldn't be wrapped in [`CachingSigner`] — the wrapper is
/// not useful for remote backends anyway (the cost is at the far end).
pub trait GetPrivateBytes {
    fn private_bytes(&self) -> &[u8];
}

impl GetPrivateBytes for affinidi_secrets_resolver::secrets::Secret {
    fn private_bytes(&self) -> &[u8] {
        self.get_private_bytes()
    }
}

#[cfg(test)]
#[cfg(feature = "ml-dsa")]
mod tests {
    use super::*;
    use crate::{DataIntegrityProof, SignOptions, VerifyOptions};
    use affinidi_secrets_resolver::secrets::Secret;
    use serde_json::json;

    #[tokio::test]
    async fn caching_signer_produces_same_signature_as_plain() {
        // Determinism guarantee: caching must not change the output.
        let secret = Secret::generate_ml_dsa_44(None, Some(&[7u8; 32]));
        let caching = CachingSigner::new(secret.clone());
        let doc = json!({ "cache": "test" });

        let created = chrono::Utc::now();
        let opts = || SignOptions::new().with_created(created);

        let plain_proof = DataIntegrityProof::sign(&doc, &secret, opts())
            .await
            .unwrap();
        let cached_proof = DataIntegrityProof::sign(&doc, &caching, opts())
            .await
            .unwrap();
        assert_eq!(plain_proof.proof_value, cached_proof.proof_value);

        plain_proof
            .verify_with_public_key(&doc, secret.get_public_bytes(), VerifyOptions::new())
            .unwrap();
        cached_proof
            .verify_with_public_key(&doc, secret.get_public_bytes(), VerifyOptions::new())
            .unwrap();
    }

    #[tokio::test]
    async fn caching_signer_second_call_is_faster() {
        // Not a strict benchmark (no criterion), just a sanity check:
        // the cache should make repeated signs cheaper than repeated
        // un-cached signs.
        let secret = Secret::generate_ml_dsa_44(None, Some(&[3u8; 32]));
        let caching = CachingSigner::new(secret.clone());

        // Warm up
        let _ = caching.sign(b"warm").await.unwrap();

        let n = 50;
        let t0 = std::time::Instant::now();
        for _ in 0..n {
            let _ = secret.sign(b"x").await.unwrap();
        }
        let without_cache = t0.elapsed();

        let t0 = std::time::Instant::now();
        for _ in 0..n {
            let _ = caching.sign(b"x").await.unwrap();
        }
        let with_cache = t0.elapsed();

        // Cached path should be at least 15% faster. (Bench showed ~28%
        // improvement in practice; 15% is a generous lower bound that
        // still catches accidental cache misses in CI.)
        assert!(
            with_cache < without_cache.saturating_sub(without_cache / 7),
            "caching did not speed up: without={without_cache:?}, with={with_cache:?}"
        );
    }
}
