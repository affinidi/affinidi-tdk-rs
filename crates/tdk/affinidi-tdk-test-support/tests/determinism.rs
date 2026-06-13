//! TI4a — seeded `did:peer` generation: same seed → same DID/keys/ids across
//! runs; different seeds diverge; the seeded DID is well-formed and resolves.

use affinidi_did_common::DID;
use affinidi_tdk_test_support::determinism::{
    KeyType, PeerKeyPurpose, did_peer_from_seed, didcomm_identity_from_seed, seeded_secret,
};

/// The core guarantee: the same seed yields an identical DID, the same number of
/// secrets, and the same key ids and public key material every time.
#[test]
fn same_seed_is_reproducible() {
    let (did_a, secrets_a) = didcomm_identity_from_seed(7, None).expect("first");
    let (did_b, secrets_b) = didcomm_identity_from_seed(7, None).expect("second");

    assert_eq!(did_a, did_b, "same seed must yield the same DID");
    assert_eq!(secrets_a.len(), secrets_b.len());
    for (a, b) in secrets_a.iter().zip(&secrets_b) {
        assert_eq!(a.id, b.id, "key ids must match");
        assert_eq!(
            a.get_public_keymultibase().unwrap(),
            b.get_public_keymultibase().unwrap(),
            "public key material must match"
        );
    }
}

/// Different seeds must produce different identities (no accidental collisions).
#[test]
fn different_seeds_diverge() {
    let (did_7, _) = didcomm_identity_from_seed(7, None).expect("seed 7");
    let (did_8, _) = didcomm_identity_from_seed(8, None).expect("seed 8");
    assert_ne!(did_7, did_8, "different seeds must yield different DIDs");
}

/// The default DIDComm shape is a `did:peer:2` with two keys whose ids are bound
/// to the DID, and it resolves locally (no network) like any did:peer.
#[test]
fn default_identity_is_a_resolvable_did_peer() {
    let (did, secrets) =
        didcomm_identity_from_seed(1, Some("https://mediator.example/".to_string()))
            .expect("identity");

    assert!(did.starts_with("did:peer:2"), "got {did}");
    assert_eq!(secrets.len(), 2, "Ed25519 verification + X25519 encryption");
    assert_eq!(secrets[0].id, format!("{did}#key-1"));
    assert_eq!(secrets[0].get_key_type(), KeyType::Ed25519);
    assert_eq!(secrets[1].id, format!("{did}#key-2"));
    assert_eq!(secrets[1].get_key_type(), KeyType::X25519);

    // did:peer resolves locally — confirms the assembled DID is well-formed.
    let parsed: DID = did.parse().expect("parse did:peer");
    let document = parsed.resolve().expect("resolve did:peer");
    assert_eq!(document.id.to_string(), did);
    assert!(!document.verification_method.is_empty());
    assert!(!document.key_agreement.is_empty(), "X25519 key agreement");
}

/// The DIDComm service URI is carried through when supplied, and omitted when
/// not — a seeded identity without a service still resolves.
#[test]
fn service_uri_is_optional() {
    let (did_no_svc, _) = didcomm_identity_from_seed(2, None).expect("no service");
    let parsed: DID = did_no_svc.parse().expect("parse");
    let doc = parsed.resolve().expect("resolve");
    assert!(
        doc.service.is_empty(),
        "no service URI → no service entries"
    );

    let (did_svc, _) =
        didcomm_identity_from_seed(2, Some("https://m.example/".to_string())).expect("service");
    // Same keys (same seed) but the service changes the DID's last segment.
    assert_ne!(did_no_svc, did_svc, "adding a service changes the DID");
    let doc = did_svc.parse::<DID>().unwrap().resolve().unwrap();
    assert!(!doc.service.is_empty(), "service URI → a service entry");
}

/// An explicit key list is honoured (purpose + type), and a single seeded
/// secret of a supported type can be built on its own.
#[test]
fn explicit_keys_and_low_level_secret() {
    let (_did, secrets) = did_peer_from_seed(
        99,
        &[
            (PeerKeyPurpose::Verification, KeyType::Ed25519),
            (PeerKeyPurpose::Verification, KeyType::P256),
            (PeerKeyPurpose::Encryption, KeyType::X25519),
        ],
        None,
    )
    .expect("three-key did:peer");
    assert_eq!(secrets.len(), 3);
    assert_eq!(secrets[0].get_key_type(), KeyType::Ed25519);
    assert_eq!(secrets[1].get_key_type(), KeyType::P256);
    assert_eq!(secrets[2].get_key_type(), KeyType::X25519);

    // The low-level primitive is deterministic for a raw 32-byte seed.
    let seed = [9u8; 32];
    let a = seeded_secret(KeyType::Ed25519, &seed).unwrap();
    let b = seeded_secret(KeyType::Ed25519, &seed).unwrap();
    assert_eq!(
        a.get_public_keymultibase().unwrap(),
        b.get_public_keymultibase().unwrap()
    );
}

/// A key type without a 32-byte-seed constructor here is a clean error, not a
/// panic.
#[test]
fn unsupported_key_type_errors() {
    assert!(seeded_secret(KeyType::P384, &[0u8; 32]).is_err());
}
