/*!
 * Determinism primitives (TI4a): seeded `did:peer` generation.
 *
 * Test identities are random by default (`DID::generate_did_peer` draws from the
 * OS RNG), so a failing CI run can't be reproduced and golden-file assertions
 * are impossible. This module derives the keys from a caller-supplied `seed`
 * instead: **same seed → same DID, same keys, same key ids**, every run.
 *
 * It builds on the seed support that already exists in the crypto stack
 * (`Secret::generate_ed25519(None, Some(seed))` and friends) and assembles the
 * `did:peer:2` with the same `affinidi-did-common` API and default `dm` service
 * that `DID::generate_did_peer` uses — so a seeded identity is byte-for-byte
 * what `TestEnvironment::add_user` would have produced, only reproducible.
 *
 * **TEST-ONLY.** Seeded keys are predictable by construction; never use this on
 * a production key path.
 *
 * ```
 * use affinidi_tdk_test_support::determinism::didcomm_identity_from_seed;
 *
 * let (did_a, secrets_a) = didcomm_identity_from_seed(42, None).unwrap();
 * let (did_b, secrets_b) = didcomm_identity_from_seed(42, None).unwrap();
 * assert_eq!(did_a, did_b); // same seed → same DID
 * assert_eq!(secrets_a[0].id, secrets_b[0].id);
 *
 * let (did_c, _) = didcomm_identity_from_seed(43, None).unwrap();
 * assert_ne!(did_a, did_c); // a different seed → a different DID
 * ```
 */

use affinidi_did_common::{
    DID, PeerCreateKey, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
    one_or_many::OneOrMany,
};
use affinidi_secrets_resolver::errors::SecretsResolverError;

// Re-exported so callers name the key purpose / type / secret from one place.
pub use affinidi_did_common::PeerKeyPurpose;
pub use affinidi_secrets_resolver::secrets::{KeyType, Secret};

/// Errors from seeded identity generation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeterminismError {
    /// Assembling the `did:peer` failed.
    #[error("did:peer: {0}")]
    DidPeer(String),

    /// A seeded key could not be built.
    #[error("secret: {0}")]
    Secret(#[from] SecretsResolverError),

    /// The key type has no 32-byte-seed constructor in this helper.
    #[error("unsupported key type for seeded generation: {0:?}")]
    UnsupportedKeyType(KeyType),
}

/// Build a single deterministic [`Secret`] of `key_type` from a 32-byte `seed`.
///
/// Supports the key types used by `did:peer` DIDComm identities — `Ed25519`,
/// `X25519`, `P256`, `Secp256k1` (all keyed by a 32-byte scalar). Other types
/// (e.g. `P384`, which needs 48 bytes) return [`DeterminismError::UnsupportedKeyType`].
/// The `id` is a throwaway here — [`did_peer_from_seed`] rewrites it to
/// `{did}#key-N` once the DID is known.
pub fn seeded_secret(key_type: KeyType, seed: &[u8; 32]) -> Result<Secret, DeterminismError> {
    Ok(match key_type {
        KeyType::Ed25519 => Secret::generate_ed25519(None, Some(seed)),
        KeyType::X25519 => Secret::generate_x25519(None, Some(seed))?,
        KeyType::P256 => Secret::generate_p256(None, Some(seed))?,
        KeyType::Secp256k1 => Secret::generate_secp256k1(None, Some(seed))?,
        other => return Err(DeterminismError::UnsupportedKeyType(other)),
    })
}

/// Build a deterministic `did:peer:2` from `seed` with an explicit key list
/// (each `(purpose, key_type)` becomes one key). With `didcomm_service_uri`, a
/// single default `dm` DIDComm service is attached — the same service
/// `DID::generate_did_peer` emits.
///
/// Returns the DID and its [`Secret`]s, their ids set to `{did}#key-N`. Same
/// `seed` + same key list → identical DID and secrets across runs.
pub fn did_peer_from_seed(
    seed: u64,
    keys: &[(PeerKeyPurpose, KeyType)],
    didcomm_service_uri: Option<String>,
) -> Result<(String, Vec<Secret>), DeterminismError> {
    // Build one seeded Secret per requested key, with a distinct per-key seed.
    let mut secrets: Vec<Secret> = keys
        .iter()
        .enumerate()
        .map(|(index, (_purpose, key_type))| seeded_secret(*key_type, &key_seed(seed, index)))
        .collect::<Result<_, _>>()?;

    let peer_keys: Vec<PeerCreateKey> = keys
        .iter()
        .zip(secrets.iter())
        .map(|((purpose, _), secret)| {
            Ok(PeerCreateKey::from_multibase(
                *purpose,
                secret.get_public_keymultibase()?,
            ))
        })
        .collect::<Result<_, SecretsResolverError>>()?;

    let services = didcomm_service_uri.map(default_didcomm_services);
    let (peer_did, _created) = DID::generate_peer(&peer_keys, services.as_deref())
        .map_err(|e| DeterminismError::DidPeer(e.to_string()))?;
    let did = peer_did.to_string();

    // Match the secret ids to the freshly-minted DID (`{did}#key-N`), exactly as
    // the facade's `generate_did_peer` does.
    for (index, secret) in secrets.iter_mut().enumerate() {
        secret.id = format!("{did}#key-{}", index + 1);
    }

    Ok((did, secrets))
}

/// Convenience: the default DIDComm identity shape — `Ed25519` verification +
/// `X25519` encryption — that `TestEnvironment::add_user` produces, derived
/// deterministically from `seed`.
pub fn didcomm_identity_from_seed(
    seed: u64,
    didcomm_service_uri: Option<String>,
) -> Result<(String, Vec<Secret>), DeterminismError> {
    did_peer_from_seed(
        seed,
        &[
            (PeerKeyPurpose::Verification, KeyType::Ed25519),
            (PeerKeyPurpose::Encryption, KeyType::X25519),
        ],
        didcomm_service_uri,
    )
}

/// A distinct, fully-determined 32-byte seed per key from `(seed, index)`.
fn key_seed(seed: u64, index: usize) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8] = index as u8;
    bytes
}

/// The default service set `DID::generate_did_peer` attaches: one DIDComm
/// Messaging service (`type: "dm"`) at `service_uri`.
fn default_didcomm_services(service_uri: String) -> Vec<PeerService> {
    vec![PeerService {
        type_: "dm".into(),
        endpoint: PeerServiceEndpoint::Long(OneOrMany::One(PeerServiceEndpointLong {
            uri: service_uri,
            accept: vec!["didcomm/v2".into()],
            routing_keys: vec![],
        })),
        id: None,
    }]
}
