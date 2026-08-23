//! Creation must produce artifacts the existing resolver accepts.
//!
//! That is the whole invariant. This crate already had a verifier before it
//! could create anything, and the verifier is the side that decides: if
//! resolution does not return what creation published, creation is wrong.
//! Every path below asserts the round-trip.

#![cfg(feature = "create")]

use std::collections::BTreeMap;

use affinidi_did_webs::create::{CreateConfig, SelfEndpoint, create};
use affinidi_did_webs::update::{Change, UpdateConfig, update};
use affinidi_did_webs::{Artifacts, DidWebs, resolve_from_artifacts};
use affinidi_keri::config::{InceptionConfig, RotationConfig};

const SALT: &[u8] = &[42u8; 16];
const HOST: &str = "example.com";

fn inception() -> InceptionConfig {
    InceptionConfig::builder().salt(SALT.to_vec()).build()
}

fn config() -> CreateConfig {
    CreateConfig::builder(HOST).inception(inception()).build()
}

/// Resolve the artifacts and return the document, failing loudly.
fn resolve(did: &str, artifacts: &Artifacts) -> affinidi_did_common::Document {
    let parsed = DidWebs::parse(did).expect("created DID must parse");
    resolve_from_artifacts(&parsed, &artifacts.keri_cesr, Some(&artifacts.did_json))
        .expect("created artifacts must resolve")
}

#[test]
fn a_created_identifier_resolves() {
    let result = create(config()).expect("create");

    assert!(result.did().starts_with(&format!("did:webs:{HOST}:")));
    let doc = resolve(result.did(), result.artifacts());

    assert_eq!(doc.id.as_str(), result.did());
    assert_eq!(doc.verification_method.len(), 1);
}

#[test]
fn the_published_document_is_what_resolution_returns() {
    // Not merely "it resolves" — the bytes published and the document derived
    // have to be the same document. Anything else means a consumer reading
    // did.json and a consumer resolving it disagree.
    let result = create(config()).expect("create");
    let published: serde_json::Value =
        serde_json::from_slice(&result.artifacts().did_json).expect("did.json is JSON");

    let resolved = resolve(result.did(), result.artifacts());
    let resolved = serde_json::to_value(&resolved).expect("serializes");

    assert_eq!(published, resolved);
}

#[test]
fn the_did_web_twin_is_recorded() {
    let result = create(config()).expect("create");
    let doc = resolve(result.did(), result.artifacts());
    let aid = DidWebs::parse(result.did())
        .expect("parse")
        .aid()
        .to_string();

    assert!(
        doc.also_known_as
            .iter()
            .any(|a| a == &format!("did:web:{HOST}:{aid}")),
        "got {:?}",
        doc.also_known_as,
    );
}

#[test]
fn creation_is_deterministic_for_a_salt() {
    // The AID is the inception event's SAID, so the same salt and config must
    // yield the same identifier. If it did not, a caller could never recreate
    // an identifier from a backed-up salt.
    let a = create(config()).expect("create");
    let b = create(config()).expect("create");
    assert_eq!(a.did(), b.did());
    assert_eq!(a.artifacts(), b.artifacts());
}

#[test]
fn a_rotation_resolves_and_changes_the_key() {
    let created = create(config()).expect("create");
    let before = resolve(created.did(), created.artifacts());

    let updated = update(
        UpdateConfig {
            did: created.did().to_string(),
            prior: created.artifacts().clone(),
            custody: created.custody().clone(),
            change: Change::Rotate(RotationConfig::default()),
        },
        SALT,
    )
    .expect("rotate");

    let after = resolve(updated.did(), updated.artifacts());

    assert_eq!(
        after.id, before.id,
        "rotation does not change the identifier"
    );
    assert_ne!(
        after.verification_method[0].id, before.verification_method[0].id,
        "rotation must install a different key",
    );
}

#[test]
fn several_rotations_resolve() {
    let created = create(config()).expect("create");
    let mut did = created.did().to_string();
    let mut artifacts = created.artifacts().clone();
    let mut custody = created.custody().clone();

    for round in 0..3 {
        let updated = update(
            UpdateConfig {
                did: did.clone(),
                prior: artifacts,
                custody,
                change: Change::Rotate(RotationConfig::default()),
            },
            SALT,
        )
        .unwrap_or_else(|e| panic!("rotation {round} failed: {e}"));

        did = updated.did().to_string();
        artifacts = updated.artifacts().clone();
        custody = updated.custody().clone();

        resolve(&did, &artifacts);
    }
}

#[test]
fn an_interaction_resolves() {
    let created = create(config()).expect("create");
    let anchors = vec![serde_json::json!({"d": "ESomeAnchor"})];

    let updated = update(
        UpdateConfig {
            did: created.did().to_string(),
            prior: created.artifacts().clone(),
            custody: created.custody().clone(),
            change: Change::Interact(anchors),
        },
        SALT,
    )
    .expect("interact");

    resolve(updated.did(), updated.artifacts());
}

fn agent_endpoint() -> SelfEndpoint {
    let mut urls = BTreeMap::new();
    urls.insert("http".to_string(), "https://agent.example".to_string());
    SelfEndpoint {
        role: "agent".to_string(),
        urls,
    }
}

#[test]
fn a_service_designated_at_creation_survives_resolution() {
    // The point of emitting signed replies rather than writing the service into
    // did.json: the resolver verifies them and derives the service back.
    let config = CreateConfig::builder(HOST)
        .inception(inception())
        .service(agent_endpoint())
        .build();

    let result = create(config).expect("create");
    let doc = resolve(result.did(), result.artifacts());

    assert_eq!(doc.service.len(), 1, "got {:?}", doc.service);
    assert_eq!(doc.service[0].type_, vec!["agent".to_string()]);
}

#[test]
fn a_service_added_later_survives_resolution() {
    let created = create(config()).expect("create");
    assert!(
        resolve(created.did(), created.artifacts())
            .service
            .is_empty(),
        "nothing designated yet",
    );

    let updated = update(
        UpdateConfig {
            did: created.did().to_string(),
            prior: created.artifacts().clone(),
            custody: created.custody().clone(),
            change: Change::Services(vec![agent_endpoint()]),
        },
        SALT,
    )
    .expect("designate");

    let doc = resolve(updated.did(), updated.artifacts());
    assert_eq!(doc.service.len(), 1, "got {:?}", doc.service);
}

#[test]
fn a_service_survives_a_later_rotation() {
    // Services are authorised by an establishment event's key state. After a
    // rotation that state is different, so this checks the authorisation is
    // still honoured rather than quietly dropped.
    let config = CreateConfig::builder(HOST)
        .inception(inception())
        .service(agent_endpoint())
        .build();
    let created = create(config).expect("create");

    let updated = update(
        UpdateConfig {
            did: created.did().to_string(),
            prior: created.artifacts().clone(),
            custody: created.custody().clone(),
            change: Change::Rotate(RotationConfig::default()),
        },
        SALT,
    )
    .expect("rotate");

    let doc = resolve(updated.did(), updated.artifacts());
    assert_eq!(
        doc.service.len(),
        1,
        "the service should survive a rotation, got {:?}",
        doc.service,
    );
}

#[test]
fn a_service_with_no_urls_is_refused() {
    let config = CreateConfig::builder(HOST)
        .inception(inception())
        .service(SelfEndpoint {
            role: "agent".to_string(),
            urls: BTreeMap::new(),
        })
        .build();

    assert!(
        create(config).is_err(),
        "an endpoint with nowhere to reach it would be dropped on resolution",
    );
}

#[test]
fn the_wrong_salt_cannot_update() {
    let created = create(config()).expect("create");

    let result = update(
        UpdateConfig {
            did: created.did().to_string(),
            prior: created.artifacts().clone(),
            custody: created.custody().clone(),
            change: Change::Rotate(RotationConfig::default()),
        },
        &[0u8; 16],
    );

    assert!(
        result.is_err(),
        "a rotation signed by keys the log never committed to must not verify",
    );
}

#[test]
fn a_stale_custody_record_is_refused() {
    // Rotating twice from the same custody record would sign from a point the
    // log has already passed. Catching it here beats emitting an event that
    // nothing accepts.
    let created = create(config()).expect("create");
    let stale = created.custody().clone();

    let once = update(
        UpdateConfig {
            did: created.did().to_string(),
            prior: created.artifacts().clone(),
            custody: stale.clone(),
            change: Change::Rotate(RotationConfig::default()),
        },
        SALT,
    )
    .expect("first rotation");

    let err = update(
        UpdateConfig {
            did: once.did().to_string(),
            prior: once.artifacts().clone(),
            custody: stale,
            change: Change::Rotate(RotationConfig::default()),
        },
        SALT,
    )
    .expect_err("a stale custody record must be refused");
    assert!(err.to_string().contains("stale"), "{err}");
}

#[test]
fn a_custody_record_for_another_identifier_is_refused() {
    let a = create(config()).expect("create");
    let b = create(
        CreateConfig::builder(HOST)
            .inception(InceptionConfig::builder().salt(vec![9u8; 16]).build())
            .build(),
    )
    .expect("create");

    assert!(
        update(
            UpdateConfig {
                did: a.did().to_string(),
                prior: a.artifacts().clone(),
                custody: b.custody().clone(),
                change: Change::Rotate(RotationConfig::default()),
            },
            SALT,
        )
        .is_err(),
    );
}
