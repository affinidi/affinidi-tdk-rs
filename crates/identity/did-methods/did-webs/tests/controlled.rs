//! An identifier whose keys the caller holds, with a recovery key held by a
//! custodian: the method profile's arrangement (`n = [H(R′), H(K)]`,
//! `nt = ["1/2", "1"]`). Every step goes through the resolver.

#![cfg(feature = "create")]

use affinidi_did_webs::create::{CreateConfig, create, create_controlled};
use affinidi_did_webs::update::{
    Change, ControlledUpdate, complete_rotation, prepare_rotation, update_controlled,
};
use affinidi_did_webs::{
    Artifacts, ControlledResult, DesignatedService, DidWebs, KeyAgreementKey, KeyRoles,
    VerificationKey, resolve_from_artifacts,
};
use affinidi_keri::controller::{Inception, KeySigner, NextKey, Rotation};
use affinidi_keri_core::threshold::Threshold;
use affinidi_keri_crypto::{Salter, Signer};
use serde_json::{Value, json};

const HOST: &str = "example.com";

/// Keys from distinct salts, standing in for keys held in different places.
fn key(seed: u8) -> Signer {
    Salter::new("0A", vec![seed; 16])
        .unwrap()
        .signer("A", "0", "low", true)
        .unwrap()
}

fn pk(s: &Signer) -> String {
    s.public_key().unwrap()
}

fn recovery_nt() -> Threshold {
    Threshold::from_json_value(&json!([["1/2", "1"]])).unwrap()
}

fn didcomm() -> DesignatedService {
    DesignatedService::new(
        "#didcomm",
        "DIDCommMessaging",
        json!({ "uri": "did:webvh:QmMediator:mediator.example", "accept": ["didcomm/v2"] }),
    )
}

struct Keys {
    r0: Signer,
    r1: Signer,
    k: Signer,
}

fn keys() -> Keys {
    Keys {
        r0: key(1),
        r1: key(2),
        k: key(3),
    }
}

/// `k = [R0]`, `n = [H(R1), H(K)]`; the custodian supplies only `K`'s digest.
fn created(keys: &Keys) -> ControlledResult {
    let k_digest = NextKey::PublicKey(pk(&keys.k)).digest().unwrap();
    create_controlled(
        CreateConfig::builder(HOST)
            .controlled(Inception::new(
                vec![pk(&keys.r0)],
                Threshold::Simple(1),
                vec![NextKey::PublicKey(pk(&keys.r1)), NextKey::Digest(k_digest)],
                recovery_nt(),
            ))
            .key_roles(
                KeyRoles::new()
                    .with_attestation(VerificationKey::Ed25519([11; 32]))
                    .with_operational(VerificationKey::Ed25519([12; 32]))
                    .with_messaging(KeyAgreementKey::X25519([13; 32])),
            )
            .designated_service(didcomm())
            .build(),
        &[&keys.r0],
    )
    .expect("create")
}

fn resolve(did: &str, artifacts: &Artifacts) -> Value {
    let parsed = DidWebs::parse(did).unwrap();
    let doc = resolve_from_artifacts(&parsed, &artifacts.keri_cesr, Some(&artifacts.did_json))
        .expect("the published artifacts resolve");
    serde_json::to_value(doc).unwrap()
}

fn next_rotation() -> Rotation {
    Rotation::new(
        Threshold::Simple(1),
        vec![
            NextKey::PublicKey(pk(&key(4))),
            NextKey::PublicKey(pk(&key(5))),
        ],
        recovery_nt(),
    )
}

#[test]
fn a_created_identifier_resolves_with_its_role_keys_and_services() {
    let keys = keys();
    let created = created(&keys);
    let doc = resolve(created.did(), created.artifacts());
    assert!(doc["keyRoles"].is_object(), "{doc}");
    assert_eq!(
        doc["service"][0]["type"],
        json!(["DIDCommMessaging"]),
        "{doc}"
    );
    // The key state — R0 — is in no relationship.
    assert!(!doc.to_string().contains(&pk(&keys.r0)[1..]));
    assert_eq!(created.state().keys, vec![pk(&keys.r0)]);
    assert_eq!(created.state().next_digests.len(), 2);
}

#[test]
fn a_designation_change_is_signed_by_the_routine_key_alone() {
    let keys = keys();
    let created = created(&keys);
    let (artifacts, state) = created.clone().into_parts();
    let updated = update_controlled(
        ControlledUpdate::new(
            created.did(),
            artifacts,
            state,
            Change::DesignatedServices(vec![]),
        ),
        &[&keys.r0],
    )
    .expect("update");
    let doc = resolve(updated.did(), updated.artifacts());
    assert!(
        doc.get("service")
            .is_none_or(|s| s.as_array().unwrap().is_empty()),
        "{doc}"
    );
    assert!(updated.state().sn > created.state().sn);
    assert_eq!(updated.state().establishment_sn, 0, "no rotation");
}

#[test]
fn the_routine_successor_alone_cannot_rotate() {
    let keys = keys();
    let created = created(&keys);
    let mut pending = prepare_rotation(
        created.did(),
        created.artifacts(),
        created.state(),
        &[pk(&keys.r1), pk(&keys.k)],
        &next_rotation(),
    )
    .expect("prepare");
    pending.sign_with(&keys.r1).unwrap();
    assert!(complete_rotation(created.did(), created.artifacts(), pending).is_err());
}

#[test]
fn the_custodian_signs_a_rotation_elsewhere_and_it_resolves() {
    let keys = keys();
    let created = created(&keys);
    let pending = prepare_rotation(
        created.did(),
        created.artifacts(),
        created.state(),
        &[pk(&keys.r1), pk(&keys.k)],
        &next_rotation(),
    )
    .expect("prepare");

    // Stored, sent to the custodian, signed there, returned.
    let wire = serde_json::to_string(&pending).unwrap();
    let signature = KeySigner::sign(&keys.k, pending.signing_input()).unwrap();
    let mut pending: affinidi_keri::controller::PendingEvent = serde_json::from_str(&wire).unwrap();
    pending.add_signature(1, signature).unwrap();

    let rotated = complete_rotation(created.did(), created.artifacts(), pending).expect("rotate");
    let doc = resolve(rotated.did(), rotated.artifacts());
    assert!(
        doc["keyRoles"].is_object(),
        "role keys survive the rotation: {doc}"
    );
    assert_eq!(rotated.state().keys, vec![pk(&keys.r1), pk(&keys.k)]);
    assert_eq!(rotated.state().establishment_sn, rotated.state().sn);

    // From here the routine successor alone signs designations.
    let (artifacts, state) = rotated.clone().into_parts();
    let updated = update_controlled(
        ControlledUpdate::new(
            rotated.did(),
            artifacts,
            state,
            Change::DesignatedServices(vec![didcomm()]),
        ),
        &[&keys.r1],
    )
    .expect("R′ signs routine changes under kt \"1\"");
    resolve(updated.did(), updated.artifacts());
}

#[test]
fn a_stale_state_or_a_key_that_is_not_current_is_refused() {
    let keys = keys();
    let created = created(&keys);
    let (artifacts, state) = created.clone().into_parts();
    let updated = update_controlled(
        ControlledUpdate::new(
            created.did(),
            artifacts.clone(),
            state.clone(),
            Change::DesignatedServices(vec![]),
        ),
        &[&keys.r0],
    )
    .unwrap();

    // The state from before that update, against the log after it.
    assert!(
        update_controlled(
            ControlledUpdate::new(
                created.did(),
                updated.artifacts().clone(),
                state.clone(),
                Change::DesignatedServices(vec![didcomm()]),
            ),
            &[&keys.r0],
        )
        .is_err()
    );
    // A successor is not a current key.
    assert!(
        update_controlled(
            ControlledUpdate::new(
                created.did(),
                artifacts.clone(),
                state.clone(),
                Change::DesignatedServices(vec![didcomm()]),
            ),
            &[&keys.r1],
        )
        .is_err()
    );
    // A rotation goes through prepare_rotation.
    assert!(
        update_controlled(
            ControlledUpdate::new(
                created.did(),
                artifacts,
                state,
                Change::Rotate(Default::default()),
            ),
            &[&keys.r0],
        )
        .is_err()
    );
}

#[test]
fn a_controlled_configuration_is_not_created_from_a_salt() {
    let keys = keys();
    let config = CreateConfig::builder(HOST)
        .controlled(Inception::new(
            vec![pk(&keys.r0)],
            Threshold::Simple(1),
            vec![NextKey::PublicKey(pk(&keys.r1))],
            Threshold::Simple(1),
        ))
        .build();
    assert!(create(config).is_err());
}
