//! DID verification-method helpers.
//!
//! A [`VerificationMethodResolver`] takes a verification-method URI
//! (e.g. `did:key:z6Mk...#z6Mk...`) and returns the raw public key bytes
//! plus their [`KeyType`]. The data-integrity verify pipeline uses this
//! to pull keys out of DIDs without entangling this crate with full DID
//! resolution.
//!
//! A [`DidKeyResolver`] is shipped by default — it handles the
//! `did:key:` method purely from the URI, with no network I/O. For
//! `did:web`, `did:webvh`, and friends, provide a custom impl that
//! delegates to your preferred DID resolver (e.g.
//! `affinidi-did-resolver-cache-sdk`) and maps back into this trait.

#[cfg(feature = "slh-dsa")]
use affinidi_secrets_resolver::multicodec::SLH_DSA_SHA2_128S_PUB;
use affinidi_secrets_resolver::multicodec::{
    ED25519_PUB, MultiEncoded, P256_PUB, P384_PUB, P521_PUB, SECP256K1_PUB,
};
#[cfg(feature = "ml-dsa")]
use affinidi_secrets_resolver::multicodec::{ML_DSA_44_PUB, ML_DSA_65_PUB, ML_DSA_87_PUB};
use affinidi_secrets_resolver::secrets::KeyType;
use async_trait::async_trait;

use crate::DataIntegrityError;

/// Decoded public key material from a verification method.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ResolvedKey {
    pub key_type: KeyType,
    pub public_key_bytes: Vec<u8>,
}

/// Resolves a verification-method URI to its public key.
///
/// Implementors may do anything — purely local decoding (did:key),
/// HTTP fetches (did:web), cached DID document lookups, HSM introspection.
/// The method is async because the typical implementation involves I/O.
///
/// A blanket `&T: VerificationMethodResolver` impl means callers can
/// pass a borrow of any resolver without wrapping it.
#[async_trait]
pub trait VerificationMethodResolver: Send + Sync {
    /// Resolve a verification-method URI, returning its key type and raw
    /// public-key bytes.
    async fn resolve_vm(&self, vm: &str) -> Result<ResolvedKey, DataIntegrityError>;
}

/// Resolves `did:key:zXXX#zXXX` verification methods with no I/O.
///
/// Supports every public-key multicodec registered with this build:
/// Ed25519, X25519, P-256, P-384, P-521, secp256k1, and (with features
/// enabled) ML-DSA-{44,65,87} and SLH-DSA-SHA2-128s.
pub struct DidKeyResolver;

#[async_trait]
impl VerificationMethodResolver for DidKeyResolver {
    async fn resolve_vm(&self, vm: &str) -> Result<ResolvedKey, DataIntegrityError> {
        resolve_did_key(vm)
    }
}

/// Synchronous variant of [`DidKeyResolver::resolve_vm`].
///
/// `did:key:` is parseable locally, so callers with a key already in hand
/// can skip the async machinery.
pub fn resolve_did_key(vm: &str) -> Result<ResolvedKey, DataIntegrityError> {
    // Strip the fragment to get the DID; fragment is expected to repeat
    // the multibase key identifier, but we only need the DID body.
    let did = vm.split('#').next().unwrap_or(vm);
    let id = did.strip_prefix("did:key:").ok_or_else(|| {
        DataIntegrityError::Resolver(format!(
            "not a did:key URI (expected did:key:..., got {vm})"
        ))
    })?;

    // id = multibase-encoded multicodec ||  public-key bytes.
    let (_base, raw) = multibase::decode(id).map_err(|e| {
        DataIntegrityError::Resolver(format!("multibase decode of did:key id failed: {e}"))
    })?;
    let mc = MultiEncoded::new(&raw).map_err(|e| {
        DataIntegrityError::Resolver(format!("multicodec decode of did:key failed: {e}"))
    })?;

    let codec = mc.codec();
    let data = mc.data();

    let (key_type, expected_len): (KeyType, usize) = match codec {
        ED25519_PUB => (KeyType::Ed25519, 32),
        SECP256K1_PUB => (KeyType::Secp256k1, 33),
        P256_PUB => (KeyType::P256, 33),
        P384_PUB => (KeyType::P384, 49),
        P521_PUB => (KeyType::P521, 67),
        #[cfg(feature = "ml-dsa")]
        ML_DSA_44_PUB => (KeyType::MlDsa44, 1312),
        #[cfg(feature = "ml-dsa")]
        ML_DSA_65_PUB => (KeyType::MlDsa65, 1952),
        #[cfg(feature = "ml-dsa")]
        ML_DSA_87_PUB => (KeyType::MlDsa87, 2592),
        #[cfg(feature = "slh-dsa")]
        SLH_DSA_SHA2_128S_PUB => (KeyType::SlhDsaSha2_128s, 32),
        other => {
            return Err(DataIntegrityError::InvalidPublicKey {
                codec: Some(other),
                len: data.len(),
                reason: "unknown or unsupported multicodec for did:key".to_string(),
            });
        }
    };

    if data.len() != expected_len {
        return Err(DataIntegrityError::InvalidPublicKey {
            codec: Some(codec),
            len: data.len(),
            reason: format!(
                "did:key public key length {} does not match expected {} for {key_type:?}",
                data.len(),
                expected_len
            ),
        });
    }

    Ok(ResolvedKey {
        key_type,
        public_key_bytes: data.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_secrets_resolver::secrets::Secret;

    #[tokio::test]
    async fn resolve_did_key_ed25519_roundtrip() {
        let secret = Secret::generate_ed25519(None, Some(&[1u8; 32]));
        let pk_mb = secret.get_public_keymultibase().unwrap();
        let vm = format!("did:key:{pk_mb}#{pk_mb}");

        let resolved = DidKeyResolver.resolve_vm(&vm).await.unwrap();
        assert_eq!(resolved.key_type, KeyType::Ed25519);
        assert_eq!(resolved.public_key_bytes, secret.get_public_bytes());
    }

    #[cfg(feature = "ml-dsa")]
    #[tokio::test]
    async fn resolve_did_key_ml_dsa_44_roundtrip() {
        let secret = Secret::generate_ml_dsa_44(None, Some(&[2u8; 32]));
        let pk_mb = secret.get_public_keymultibase().unwrap();
        let vm = format!("did:key:{pk_mb}#{pk_mb}");

        let resolved = DidKeyResolver.resolve_vm(&vm).await.unwrap();
        assert_eq!(resolved.key_type, KeyType::MlDsa44);
        assert_eq!(resolved.public_key_bytes, secret.get_public_bytes());
        assert_eq!(resolved.public_key_bytes.len(), 1312);
    }

    #[cfg(feature = "slh-dsa")]
    #[tokio::test]
    async fn resolve_did_key_slh_dsa_roundtrip() {
        let secret = Secret::generate_slh_dsa_sha2_128s(None);
        let pk_mb = secret.get_public_keymultibase().unwrap();
        let vm = format!("did:key:{pk_mb}#{pk_mb}");

        let resolved = DidKeyResolver.resolve_vm(&vm).await.unwrap();
        assert_eq!(resolved.key_type, KeyType::SlhDsaSha2_128s);
        assert_eq!(resolved.public_key_bytes.len(), 32);
    }

    #[tokio::test]
    async fn resolve_did_key_rejects_non_did_key() {
        let err = DidKeyResolver
            .resolve_vm("did:web:example.com#key-1")
            .await
            .unwrap_err();
        assert!(matches!(err, DataIntegrityError::Resolver(_)));
    }

    #[tokio::test]
    async fn resolve_did_key_rejects_unknown_codec() {
        // multibase-encoded varint 0x9999 (not a registered pubkey codec)
        // followed by 32 zero bytes.
        let bogus = "did:key:z8NGuWZeMJTxQeofMjZPEdN2PC6eaDKhKCbF19UqjpDEwKzYwQnH3YzHK3#x";
        let err = DidKeyResolver.resolve_vm(bogus).await.unwrap_err();
        assert!(
            matches!(
                err,
                DataIntegrityError::Resolver(_) | DataIntegrityError::InvalidPublicKey { .. }
            ),
            "got: {err:?}"
        );
    }
}
