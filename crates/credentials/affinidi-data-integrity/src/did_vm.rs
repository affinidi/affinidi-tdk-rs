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

use affinidi_encoding::{Codec, EncodingError, did_key};
use affinidi_secrets_resolver::secrets::KeyType;
use async_trait::async_trait;

use crate::DataIntegrityError;

/// Decoded public key material from a verification method.
///
/// Construct via [`ResolvedKey::new`] to stay forward-compatible with
/// future fields. Direct struct-literal construction is blocked by
/// `#[non_exhaustive]`.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ResolvedKey {
    pub key_type: KeyType,
    pub public_key_bytes: Vec<u8>,
}

impl ResolvedKey {
    /// Constructs a `ResolvedKey` for custom
    /// [`VerificationMethodResolver`] implementations.
    pub fn new(key_type: KeyType, public_key_bytes: Vec<u8>) -> Self {
        Self {
            key_type,
            public_key_bytes,
        }
    }
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
/// Supports the signing-key multicodecs: Ed25519, P-256, P-384, P-521,
/// secp256k1, and (with features enabled) ML-DSA-{44,65,87} and
/// SLH-DSA-SHA2-128s. Any other multicodec, X25519 included, is refused.
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
///
/// The key comes from the DID. A `#fragment` is ignored and not compared
/// with the DID's key.
pub fn resolve_did_key(vm: &str) -> Result<ResolvedKey, DataIntegrityError> {
    // The key is read from the DID; the fragment is dropped unchecked.
    let did = vm.split('#').next().unwrap_or(vm);
    if !did.starts_with(did_key::DID_KEY_PREFIX) {
        return Err(DataIntegrityError::Resolver(format!(
            "not a did:key URI (expected did:key:..., got {vm})"
        )));
    }

    // did:key = "did:key:" base58btc(multicodec || public-key bytes). The
    // codec's key length is enforced by `affinidi_encoding`.
    let (codec, data) = did_key::decode(did).map_err(|e| match e {
        EncodingError::InvalidKeyLength {
            codec,
            expected,
            actual,
        } => DataIntegrityError::InvalidPublicKey {
            codec: Some(codec),
            len: actual,
            reason: format!(
                "did:key public key length {actual} does not match expected {expected} for {:?}",
                Codec::from_u64(codec)
            ),
        },
        other => DataIntegrityError::Resolver(format!("decoding did:key failed: {other}")),
    })?;

    let key_type = match codec {
        Codec::Ed25519Pub => KeyType::Ed25519,
        Codec::Secp256k1Pub => KeyType::Secp256k1,
        Codec::P256Pub => KeyType::P256,
        Codec::P384Pub => KeyType::P384,
        Codec::P521Pub => KeyType::P521,
        #[cfg(feature = "ml-dsa")]
        Codec::MlDsa44Pub => KeyType::MlDsa44,
        #[cfg(feature = "ml-dsa")]
        Codec::MlDsa65Pub => KeyType::MlDsa65,
        #[cfg(feature = "ml-dsa")]
        Codec::MlDsa87Pub => KeyType::MlDsa87,
        #[cfg(feature = "slh-dsa")]
        Codec::SlhDsaSha2_128sPub => KeyType::SlhDsaSha2_128s,
        other => {
            return Err(DataIntegrityError::InvalidPublicKey {
                codec: Some(other.to_u64()),
                len: data.len(),
                reason: "unknown or unsupported multicodec for did:key".to_string(),
            });
        }
    };

    Ok(ResolvedKey {
        key_type,
        public_key_bytes: data,
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

    #[test]
    fn resolve_did_key_refuses_wrong_length_and_unsupported_codecs() {
        let short = affinidi_encoding::did_key::encode(affinidi_encoding::ED25519_PUB, &[1u8; 31]);
        let err = resolve_did_key(&short).unwrap_err();
        assert!(
            matches!(
                err,
                DataIntegrityError::InvalidPublicKey {
                    codec: Some(0xed),
                    len: 31,
                    ..
                }
            ),
            "got: {err:?}"
        );

        // X25519 is a well-formed did:key but not a signing key.
        let x = affinidi_encoding::did_key::encode(affinidi_encoding::X25519_PUB, &[1u8; 32]);
        let err = resolve_did_key(&format!("{x}#k")).unwrap_err();
        assert!(
            matches!(err, DataIntegrityError::InvalidPublicKey { len: 32, .. }),
            "got: {err:?}"
        );

        // Only base58btc is a did:key.
        let err = resolve_did_key("did:key:uAe0BAQ").unwrap_err();
        assert!(
            matches!(err, DataIntegrityError::Resolver(_)),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn resolve_did_key_p256_roundtrip() {
        let secret = Secret::generate_p256(None, Some(&[3u8; 32])).unwrap();
        let pk_mb = secret.get_public_keymultibase().unwrap();
        let resolved = resolve_did_key(&format!("did:key:{pk_mb}#{pk_mb}")).unwrap();
        assert_eq!(resolved.key_type, KeyType::P256);
        assert_eq!(resolved.public_key_bytes.len(), 33);
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
