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
    // The signing key and the X25519 key converted from it.
    assert_eq!(doc.verification_method.len(), 2);
    assert_eq!(doc.key_agreement.len(), 1);
}

#[test]
fn the_published_document_is_what_resolution_returns() {
    // Not merely "it resolves" — the bytes published and the document derived
    // have to be the same document. Anything else means a consumer reading
    // did.json and a consumer resolving it disagree.
    //
    // did.json is the did:web form (§ Transformation to did:web DID document),
    // so it is compared after transforming it back.
    let result = create(config()).expect("create");
    let did = DidWebs::parse(result.did()).expect("parse");
    let published: serde_json::Value =
        serde_json::from_slice(&result.artifacts().did_json).expect("did.json is JSON");
    assert_eq!(
        published["id"],
        did.did_web_twin(),
        "did.json is the did:web document"
    );

    let as_webs = affinidi_did_webs::document::from_did_web(&published, &did, true)
        .expect("the twin is designated");
    // What is published is the specification's derivation; resolution adds
    // only the key agreement keys converted from the key state, which a
    // publisher never publishes (it would bind the encryption key to the
    // change authority for every reader, not only those that choose to).
    assert!(as_webs.get("keyAgreement").is_none(), "{as_webs}");
    let state_keys = affinidi_did_webs::kel::Kels::parse(&result.artifacts().keri_cesr)
        .expect("kel")
        .key_state(did.aid())
        .expect("key state")
        .keys;
    let converted = affinidi_did_webs::key_agreement::converted_key_agreement(&state_keys);
    assert_eq!(converted.len(), 1);
    let as_webs = affinidi_did_webs::document::with_key_agreement(as_webs, &did, &converted)
        .expect("converted keys render");
    let published = affinidi_did_webs::document::into_document(&as_webs, &did).expect("document");

    assert_eq!(published, resolve(result.did(), result.artifacts()));
}

#[test]
fn every_identifier_designates_itself_its_twin_and_its_did_keri() {
    // § Create and § Also Known As: a resolver refuses a did:webs DID no
    // attestation names, the did:web form of the document needs its twin
    // designated, and the did:keri form must be listed.
    let result = create(config()).expect("create");
    let did = DidWebs::parse(result.did()).expect("parse");
    let doc = resolve(result.did(), result.artifacts());
    assert_eq!(doc.also_known_as, vec![did.did_web_twin(), did.did_keri()]);
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
    //
    // The artifacts as a whole are not byte-identical: the designated-aliases
    // attestation every identifier carries is dated when it is issued. What a
    // salt must reproduce is the identifier and its key state.
    let a = create(config()).expect("create");
    let b = create(config()).expect("create");
    assert_eq!(a.did(), b.did());
    let (ca, cb) = (&a.custody().state, &b.custody().state);
    assert_eq!(
        (&ca.prefix, ca.signer_gen, ca.next_gen, ca.key_gen, ca.sn),
        (&cb.prefix, cb.signer_gen, cb.next_gen, cb.key_gen, cb.sn),
    );
    let inception = |r: &affinidi_did_webs::CreateResult| {
        let text = String::from_utf8(r.artifacts().keri_cesr.clone()).expect("ascii");
        text[..text.find("-A").expect("signatures follow the inception")].to_string()
    };
    assert_eq!(inception(&a), inception(&b));
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
    let anchors = vec![affinidi_keri_core::sad!({"d": "ESomeAnchor"})];

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
fn a_multi_key_identifier_signs_its_services_with_enough_keys() {
    // The resolver holds a reply to the key state's signing threshold, so a
    // 2-of-2 identifier has to sign with both keys or its own service would be
    // dropped on the way back.
    let config = CreateConfig::builder(HOST)
        .inception(
            InceptionConfig::builder()
                .salt(SALT.to_vec())
                .count(2)
                .threshold(2)
                .next_count(2)
                .next_threshold(2)
                .build(),
        )
        .service(agent_endpoint())
        .also_known_as(OTHER)
        .build();

    let result = create(config).expect("create");
    let doc = resolve(result.did(), result.artifacts());

    assert_eq!(doc.service.len(), 1, "got {:?}", doc.service);
    assert!(
        doc.also_known_as.iter().any(|a| a == OTHER),
        "the alias attestation must also meet the threshold: {:?}",
        doc.also_known_as,
    );

    // § Thresholds: no single key of a 2-of-2 identifier authenticates; the
    // ConditionalProof2022 over both does.
    let aid = DidWebs::parse(result.did())
        .expect("parse")
        .aid()
        .to_string();
    let condition = doc
        .verification_method
        .iter()
        .find(|vm| vm.type_ == "ConditionalProof2022")
        .expect("a threshold condition");
    assert_eq!(condition.id.as_str(), format!("{}#{aid}", result.did()));
    let auth = serde_json::to_value(&doc.authentication).expect("serializes");
    assert_eq!(auth, serde_json::json!([format!("{}#{aid}", result.did())]));
}

#[test]
fn rotating_to_no_next_keys_deactivates_the_identifier() {
    // § Deactivate: a rotation committing to no next keys renders the AID
    // non-transferable, and resolution reports it.
    let created = create(config()).expect("create");
    let did = DidWebs::parse(created.did()).expect("parse");
    let fresh = affinidi_did_webs::resolve_with_metadata(
        &did,
        &created.artifacts().keri_cesr,
        Some(&created.artifacts().did_json),
    )
    .expect("resolves");
    assert!(!fresh.metadata.deactivated);

    let rotation = RotationConfig {
        next_count: 0,
        next_threshold: 0,
        ..RotationConfig::default()
    };
    let updated = update(
        UpdateConfig {
            did: created.did().to_string(),
            prior: created.artifacts().clone(),
            custody: created.custody().clone(),
            change: Change::Rotate(rotation),
        },
        SALT,
    )
    .expect("rotate to no next keys");

    let resolution = affinidi_did_webs::resolve_with_metadata(
        &did,
        &updated.artifacts().keri_cesr,
        Some(&updated.artifacts().did_json),
    )
    .expect("a deactivated identifier still resolves");
    assert!(resolution.metadata.deactivated);
    assert_eq!(resolution.metadata.to_json()["deactivated"], true);
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

// -- designated aliases --------------------------------------------------

const OTHER: &str = "did:web:elsewhere.example:alice";

#[test]
fn a_designated_alias_survives_resolution() {
    // The whole point: the alias is carried back because the chain verifies,
    // not because did.json said so.
    let config = CreateConfig::builder(HOST)
        .inception(inception())
        .also_known_as(OTHER)
        .build();

    let result = create(config).expect("create");
    let doc = resolve(result.did(), result.artifacts());

    assert!(
        doc.also_known_as.iter().any(|a| a == OTHER),
        "got {:?}",
        doc.also_known_as,
    );
}

#[test]
fn the_did_scid_form_can_be_designated() {
    let config = CreateConfig::builder(HOST)
        .inception(inception())
        .also_known_as_scid(true)
        .build();

    let result = create(config).expect("create");
    let aid = DidWebs::parse(result.did())
        .expect("parse")
        .aid()
        .to_string();
    let doc = resolve(result.did(), result.artifacts());

    assert!(
        doc.also_known_as
            .iter()
            .any(|a| a == &format!("did:scid:ke:1:{aid}?src={HOST}")),
        "got {:?}",
        doc.also_known_as,
    );
}

#[test]
fn aliases_can_be_designated_after_creation() {
    let created = create(config()).expect("create");
    assert_eq!(
        resolve(created.did(), created.artifacts())
            .also_known_as
            .len(),
        2,
        "only the did:web twin and did:keri to begin with",
    );

    let updated = update(
        UpdateConfig {
            did: created.did().to_string(),
            prior: created.artifacts().clone(),
            custody: created.custody().clone(),
            change: Change::AlsoKnownAs(vec![OTHER.to_string()]),
        },
        SALT,
    )
    .expect("designate");

    let doc = resolve(updated.did(), updated.artifacts());
    assert!(
        doc.also_known_as.iter().any(|a| a == OTHER),
        "got {:?}",
        doc.also_known_as
    );
}

#[test]
fn an_alias_survives_a_later_rotation() {
    // The attestation is signed under one key state and read after another.
    let config = CreateConfig::builder(HOST)
        .inception(inception())
        .also_known_as(OTHER)
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
    assert!(
        doc.also_known_as.iter().any(|a| a == OTHER),
        "a rotation must not withdraw a designation, got {:?}",
        doc.also_known_as,
    );
}

#[test]
fn a_replaced_designation_withdraws_the_old_aliases() {
    // `AlsoKnownAs` replaces the designation. A resolver reads every
    // unrevoked attestation, so the old one has to be revoked — by an anchored
    // revocation — or a dropped alias would still be listed.
    let config = CreateConfig::builder(HOST)
        .inception(inception())
        .also_known_as(OTHER)
        .build();
    let created = create(config).expect("create");
    let did = DidWebs::parse(created.did()).expect("parse");

    let updated = update(
        UpdateConfig {
            did: created.did().to_string(),
            prior: created.artifacts().clone(),
            custody: created.custody().clone(),
            change: Change::AlsoKnownAs(vec![]),
        },
        SALT,
    )
    .expect("an empty list leaves the three every identifier designates");

    let doc = resolve(updated.did(), updated.artifacts());
    assert_eq!(doc.also_known_as, vec![did.did_web_twin(), did.did_keri()]);

    // As of the version before the revocation was anchored, the alias stood.
    let resolution = affinidi_did_webs::resolve_with_metadata(
        &did,
        &updated.artifacts().keri_cesr,
        Some(&updated.artifacts().did_json),
    )
    .expect("resolves");
    let before = resolution.metadata.version_id - 3;
    let then = DidWebs::parse(&format!("{}?versionId={before}", did.did())).expect("parse");
    let doc =
        resolve_from_artifacts(&then, &updated.artifacts().keri_cesr, None).expect("resolves");
    assert!(
        doc.also_known_as.iter().any(|a| a == OTHER),
        "got {:?}",
        doc.also_known_as
    );
}

#[test]
fn an_unanchored_attestation_is_not_carried_back() {
    // Strip the interaction events that anchor the registry and the issuance,
    // leaving the credential itself intact and correctly signed. Its aliases
    // must not survive: an attestation that nothing in the key event log
    // authorises is only a document the identifier wrote about itself.
    //
    // The key event log still verifies after the strip — the inception stands
    // alone — so this exercises the anchor check rather than merely breaking
    // the log, which would prove nothing. (`Kels` below confirms it.)
    let config = CreateConfig::builder(HOST)
        .inception(inception())
        .also_known_as(OTHER)
        .build();
    let created = create(config).expect("create");

    let text = String::from_utf8(created.artifacts().keri_cesr.clone()).expect("ascii");
    let stripped = strip_interactions(&text);
    assert!(
        stripped.contains(OTHER),
        "the credential itself must still be present",
    );

    // With its only attestation unanchored, nothing designates the DID, so it
    // does not resolve at all — rather than resolving without the alias. The
    // registry events are in the stream but not in the log, which is itself
    // a fault: the stream is not the log's.
    let kels = affinidi_did_webs::Kels::parse(stripped.as_bytes()).expect("parses");
    let did = DidWebs::parse(created.did()).expect("parse");
    kels.key_state(did.aid())
        .expect("the key event log still verifies");
    let err = resolve_from_artifacts(&did, stripped.as_bytes(), None)
        .expect_err("an unanchored attestation designates nothing");
    assert!(
        matches!(err, affinidi_did_webs::DidWebsError::Registry(_)),
        "{err}"
    );
}

/// Remove every `ixn` message from a CESR stream, leaving the rest.
fn strip_interactions(stream: &str) -> String {
    let mut out = String::new();
    let mut starts: Vec<usize> = stream.match_indices("{\"v\":\"").map(|(i, _)| i).collect();
    starts.push(stream.len());

    for window in starts.windows(2) {
        let segment = &stream[window[0]..window[1]];
        if !segment.contains("\"t\":\"ixn\"") {
            out.push_str(segment);
        }
    }
    out
}

/// The created identifier's did.json in its `did:webs` form, and the keys
/// converted from its key state.
fn published_and_converted(
    result: &affinidi_did_webs::CreateResult,
) -> (DidWebs, serde_json::Value, Vec<String>) {
    let did = DidWebs::parse(result.did()).expect("parse");
    let published: serde_json::Value =
        serde_json::from_slice(&result.artifacts().did_json).expect("did.json is JSON");
    let as_webs = affinidi_did_webs::document::from_did_web(&published, &did, true)
        .expect("the twin is designated");
    let state_keys = affinidi_did_webs::kel::Kels::parse(&result.artifacts().keri_cesr)
        .expect("kel")
        .key_state(did.aid())
        .expect("key state")
        .keys;
    let converted = affinidi_did_webs::key_agreement::converted_key_agreement(&state_keys);
    (did, as_webs, converted)
}

#[test]
fn a_did_json_publishing_the_converted_keys_also_agrees() {
    // Another implementation may publish the keys it converts. That adds
    // nothing the key state does not already imply, so it is not a
    // disagreement.
    let result = create(config()).expect("create");
    let (did, as_webs, converted) = published_and_converted(&result);
    let with = affinidi_did_webs::document::with_key_agreement(as_webs, &did, &converted)
        .expect("converted keys render");
    let did_json = serde_json::to_vec(&affinidi_did_webs::document::to_did_web(&with, &did))
        .expect("did.json");

    let doc = resolve_from_artifacts(&did, &result.artifacts().keri_cesr, Some(&did_json))
        .expect("a did.json with the converted keys resolves");
    assert_eq!(doc, resolve(result.did(), result.artifacts()));
}

#[test]
fn a_did_json_publishing_some_other_key_agreement_key_is_still_refused() {
    let result = create(config()).expect("create");
    let (did, as_webs, _) = published_and_converted(&result);
    let other = affinidi_did_webs::KeyAgreementKey::X25519([5u8; 32])
        .to_cesr()
        .expect("cesr");
    let with =
        affinidi_did_webs::document::with_key_agreement(as_webs, &did, &[other]).expect("renders");
    let did_json = serde_json::to_vec(&affinidi_did_webs::document::to_did_web(&with, &did))
        .expect("did.json");

    assert!(
        resolve_from_artifacts(&did, &result.artifacts().keri_cesr, Some(&did_json)).is_err(),
        "a key agreement key the KEL never authorised is a disagreement",
    );
}
