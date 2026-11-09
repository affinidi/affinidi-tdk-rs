//! Key roles, designated by the AID (a proposed extension; see
//! `affinidi_did_webs::key_roles`).
//!
//! Every test goes through the resolver: what matters is the document a
//! verifier gets, with the published `did.json` cross-checked against it.

#![cfg(feature = "create")]

use affinidi_did_webs::create::{CreateConfig, CreateResult, create};
use affinidi_did_webs::update::{Change, UpdateConfig, UpdateResult, update};
use affinidi_did_webs::{
    Artifacts, DidWebs, Kels, KeyAgreementKey, KeyCustody, KeyRoles, RevokedKey, VerificationKey,
    resolve_from_artifacts,
};
use affinidi_keri::config::{InceptionConfig, RotationConfig};
use serde_json::Value;

const SALT: &[u8] = &[7u8; 16];
const HOST: &str = "example.com";

fn ed(seed: u8) -> VerificationKey {
    VerificationKey::Ed25519([seed; 32])
}

fn x25519(seed: u8) -> KeyAgreementKey {
    KeyAgreementKey::X25519([seed; 32])
}

fn cesr(key: &VerificationKey) -> String {
    key.to_cesr().expect("cesr")
}

fn inception() -> InceptionConfig {
    InceptionConfig::builder().salt(SALT.to_vec()).build()
}

fn roles() -> KeyRoles {
    KeyRoles::new()
        .with_attestation(ed(1))
        .with_operational(ed(2))
        .with_messaging(x25519(3))
}

fn created_with_roles() -> CreateResult {
    create(
        CreateConfig::builder(HOST)
            .inception(inception())
            .key_roles(roles())
            .build(),
    )
    .expect("create")
}

/// The resolved document, as JSON with relative ids, so assertions read like
/// the document.
fn resolve(did: &str, artifacts: &Artifacts) -> Value {
    let parsed = DidWebs::parse(did).expect("parse");
    let doc = resolve_from_artifacts(&parsed, &artifacts.keri_cesr, Some(&artifacts.did_json))
        .expect("the published artifacts resolve");
    let text = serde_json::to_string(&doc)
        .expect("serializes")
        .replace(&format!("{did}#"), "#");
    serde_json::from_str(&text).expect("json")
}

fn apply(did: &str, artifacts: &Artifacts, custody: &KeyCustody, change: Change) -> UpdateResult {
    update(
        UpdateConfig {
            did: did.to_string(),
            prior: artifacts.clone(),
            custody: custody.clone(),
            change,
        },
        SALT,
    )
    .expect("update")
}

fn ids(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().or_else(|| v["id"].as_str()))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

fn method<'a>(doc: &'a Value, id: &str) -> Option<&'a Value> {
    doc["verificationMethod"]
        .as_array()
        .and_then(|ms| ms.iter().find(|m| m["id"] == id))
}

fn kel_keys(did: &str, artifacts: &Artifacts) -> Vec<String> {
    let aid = DidWebs::parse(did).expect("parse").aid().to_string();
    Kels::parse(&artifacts.keri_cesr)
        .expect("parse")
        .key_state(&aid)
        .expect("state")
        .keys
}

#[test]
fn role_keys_are_each_in_their_own_relationship_and_no_kel_key_is_listed() {
    let result = created_with_roles();
    let doc = resolve(result.did(), result.artifacts());

    let attestation = format!("#{}", cesr(&ed(1)));
    let operational = format!("#{}", cesr(&ed(2)));
    let messaging = format!("#{}", x25519(3).to_cesr().expect("cesr"));

    assert_eq!(ids(&doc["assertionMethod"]), vec![attestation.clone()]);
    assert_eq!(ids(&doc["authentication"]), vec![operational.clone()]);
    assert_eq!(ids(&doc["keyAgreement"]), vec![messaging.clone()]);
    assert_eq!(ids(&doc["keyRoles"]["attestation"]), vec![attestation]);
    assert_eq!(ids(&doc["keyRoles"]["operational"]), vec![operational]);
    assert_eq!(ids(&doc["keyRoles"]["messaging"]), vec![messaging]);
    assert!(doc["keyRoles"].get("update").is_none(), "{doc}");

    // The change authority is stated only by the KEL (VTI-KEY-093).
    let text = doc.to_string();
    for key in kel_keys(result.did(), result.artifacts()) {
        assert!(
            !text.contains(&key),
            "KEL key {key} is in the document: {doc}"
        );
    }
    assert!(!text.contains("ConditionalProof2022"), "{doc}");
    assert_eq!(doc["verificationMethod"].as_array().map(Vec::len), Some(3));
}

#[test]
fn a_planned_rotation_removes_the_retired_key() {
    let created = created_with_roles();
    let rotated = apply(
        created.did(),
        created.artifacts(),
        created.custody(),
        Change::KeyRoles(
            KeyRoles::new()
                .with_attestation(ed(4))
                .with_operational(ed(2))
                .with_messaging(x25519(3)),
        ),
    );
    let doc = resolve(rotated.did(), rotated.artifacts());
    let retired = format!("#{}", cesr(&ed(1)));
    let fresh = format!("#{}", cesr(&ed(4)));
    assert!(method(&doc, &retired).is_none(), "{doc}");
    assert_eq!(ids(&doc["assertionMethod"]), vec![fresh.clone()]);
    assert_eq!(ids(&doc["keyRoles"]["attestation"]), vec![fresh]);
}

#[test]
fn a_compromised_key_stays_revoked_out_of_every_relationship_for_good() {
    let created = created_with_roles();
    let compromised = cesr(&ed(2));
    let at = "2026-11-01T00:00:00Z";
    let revoked = apply(
        created.did(),
        created.artifacts(),
        created.custody(),
        Change::RevokeRoleKey(RevokedKey::new(compromised.clone(), at)),
    );

    let check = |doc: &Value| {
        let id = format!("#{compromised}");
        let vm = method(doc, &id).expect("the revoked key stays listed");
        assert_eq!(vm["revoked"], at, "{doc}");
        for relationship in ["authentication", "assertionMethod", "keyAgreement"] {
            assert!(
                !ids(&doc[relationship]).contains(&id),
                "{relationship}: {doc}"
            );
        }
        for (_, refs) in doc["keyRoles"].as_object().expect("keyRoles") {
            assert!(!ids(refs).contains(&id), "{doc}");
        }
    };
    check(&resolve(revoked.did(), revoked.artifacts()));

    // A later designation that does not mention the revocation still carries
    // it (VTI-KEY-127).
    let later = apply(
        revoked.did(),
        revoked.artifacts(),
        revoked.custody(),
        Change::KeyRoles(
            KeyRoles::new()
                .with_attestation(ed(1))
                .with_operational(ed(5))
                .with_messaging(x25519(3)),
        ),
    );
    let doc = resolve(later.did(), later.artifacts());
    check(&doc);
    assert_eq!(
        ids(&doc["authentication"]),
        vec![format!("#{}", cesr(&ed(5)))]
    );
}

#[test]
fn a_revoked_key_cannot_be_bound_again() {
    let created = created_with_roles();
    let compromised = ed(2);
    let revoked = apply(
        created.did(),
        created.artifacts(),
        created.custody(),
        Change::RevokeRoleKey(RevokedKey::new(cesr(&compromised), "2026-11-01T00:00:00Z")),
    );
    let err = update(
        UpdateConfig {
            did: revoked.did().to_string(),
            prior: revoked.artifacts().clone(),
            custody: revoked.custody().clone(),
            change: Change::KeyRoles(KeyRoles::new().with_operational(compromised)),
        },
        SALT,
    )
    .expect_err("a compromised key is never bound again");
    assert!(err.to_string().contains("revoked"), "{err}");
}

#[test]
fn a_key_of_the_key_state_or_under_two_roles_is_refused_at_issuance() {
    let created = created_with_roles();
    let kel_key = VerificationKey::from_cesr(&kel_keys(created.did(), created.artifacts())[0])
        .expect("an Ed25519 key");
    for roles in [
        KeyRoles::new().with_attestation(kel_key),
        KeyRoles::new()
            .with_attestation(ed(6))
            .with_operational(ed(6)),
    ] {
        let attempt = update(
            UpdateConfig {
                did: created.did().to_string(),
                prior: created.artifacts().clone(),
                custody: created.custody().clone(),
                change: Change::KeyRoles(roles),
            },
            SALT,
        );
        assert!(attempt.is_err(), "issued a designation it must refuse");
    }
}

#[test]
fn role_keys_survive_a_rotation_of_the_key_state() {
    let created = created_with_roles();
    let rotated = apply(
        created.did(),
        created.artifacts(),
        created.custody(),
        Change::Rotate(RotationConfig::default()),
    );
    let doc = resolve(rotated.did(), rotated.artifacts());
    assert_eq!(
        ids(&doc["assertionMethod"]),
        vec![format!("#{}", cesr(&ed(1)))]
    );
    let text = doc.to_string();
    for key in kel_keys(rotated.did(), rotated.artifacts()) {
        assert!(!text.contains(&key), "{doc}");
    }
}

#[test]
fn key_agreement_designations_give_way_to_the_messaging_role() {
    let err = create(
        CreateConfig::builder(HOST)
            .inception(inception())
            .key_roles(roles())
            .key_agreement(x25519(9))
            .build(),
    )
    .expect_err("key agreement is the messaging role's");
    assert!(err.to_string().contains("messaging"), "{err}");

    let created = created_with_roles();
    let attempt = update(
        UpdateConfig {
            did: created.did().to_string(),
            prior: created.artifacts().clone(),
            custody: created.custody().clone(),
            change: Change::KeyAgreement(vec![x25519(9)]),
        },
        SALT,
    );
    assert!(attempt.is_err());
}

#[test]
fn a_published_document_without_key_roles_is_refused() {
    let created = created_with_roles();
    let mut published: Value = serde_json::from_slice(&created.artifacts().did_json).expect("json");
    published
        .as_object_mut()
        .expect("object")
        .remove("keyRoles");
    let parsed = DidWebs::parse(created.did()).expect("parse");
    let err = resolve_from_artifacts(
        &parsed,
        &created.artifacts().keri_cesr,
        Some(&serde_json::to_vec(&published).expect("bytes")),
    )
    .expect_err("keyRoles may not be left out");
    assert!(err.to_string().contains("keyRoles"), "{err}");
}
