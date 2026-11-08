//! Key agreement keys and services of any type, designated by the AID.
//!
//! Neither can come from key state alone: the KEL's keys are signing keys, and
//! KERI's endpoint replies carry only KERI roles and `tcp`/`http`/`https` URLs.
//! Both are designations — ACDCs the AID issues to itself, anchored in its KEL
//! — and every test here goes through the same resolver that reads them.

#![cfg(feature = "create")]

use affinidi_did_webs::create::{CreateConfig, CreateResult, SelfEndpoint, create};
use affinidi_did_webs::designated_services::{SERVICE_SCHEMA, SERVICE_SCHEMA_JSON};
use affinidi_did_webs::key_agreement::{KEY_AGREEMENT_SCHEMA, KEY_AGREEMENT_SCHEMA_JSON};
use affinidi_did_webs::update::{Change, UpdateConfig, UpdateResult, update};
use affinidi_did_webs::{
    Artifacts, DesignatedService, DidWebs, KeyAgreementKey, resolve_from_artifacts,
    resolve_with_metadata,
};
use affinidi_keri::config::{InceptionConfig, RotationConfig};
use affinidi_keri_core::said;
use affinidi_keri_core::version::SerializationKind;
use serde_json::{Value, json};

const SALT: &[u8] = &[9u8; 16];
const HOST: &str = "example.com";
const MEDIATOR: &str = "did:webvh:QmMediator:mediator.example";

fn x25519(seed: u8) -> KeyAgreementKey {
    KeyAgreementKey::X25519([seed; 32])
}

fn didcomm() -> DesignatedService {
    DesignatedService::new(
        "#didcomm",
        "DIDCommMessaging",
        json!({"uri": MEDIATOR, "accept": ["didcomm/v2"], "routingKeys": []}),
    )
}

fn tsp() -> DesignatedService {
    DesignatedService::new("#tsp", "TSPTransport", json!(MEDIATOR))
}

fn inception() -> InceptionConfig {
    InceptionConfig::builder().salt(SALT.to_vec()).build()
}

fn created() -> CreateResult {
    create(
        CreateConfig::builder(HOST)
            .inception(inception())
            .key_agreement(x25519(1))
            .designated_service(didcomm())
            .designated_service(tsp())
            .build(),
    )
    .expect("create")
}

fn resolve(did: &str, artifacts: &Artifacts) -> affinidi_did_common::Document {
    let parsed = DidWebs::parse(did).expect("parse");
    resolve_from_artifacts(&parsed, &artifacts.keri_cesr, Some(&artifacts.did_json))
        .expect("the published artifacts resolve")
}

fn apply(
    did: &str,
    artifacts: &Artifacts,
    custody: &affinidi_did_webs::KeyCustody,
    change: Change,
) -> UpdateResult {
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

fn key_agreement_refs(doc: &affinidi_did_common::Document) -> Vec<String> {
    serde_json::to_value(&doc.key_agreement)
        .expect("serializes")
        .as_array()
        .expect("array")
        .iter()
        .map(|v| v.as_str().expect("a reference").to_string())
        .collect()
}

// ── Schemas ────────────────────────────────────────────────────────────────

/// SAIDify a schema as keripy does: every nested `$id` first, then the whole.
fn saidify(value: &mut Value) {
    match value {
        Value::Object(map) => map.values_mut().for_each(saidify),
        Value::Array(items) => items.iter_mut().for_each(saidify),
        _ => {}
    }
    if value.get("$id").is_some() {
        said::compute_said(value, "$id", "E", SerializationKind::Json).expect("said");
    }
}

#[test]
fn the_bundled_schemas_are_what_their_saids_say() {
    for (json, expected) in [
        (KEY_AGREEMENT_SCHEMA_JSON, KEY_AGREEMENT_SCHEMA),
        (SERVICE_SCHEMA_JSON, SERVICE_SCHEMA),
    ] {
        let mut schema: Value = serde_json::from_str(json).expect("json");
        assert_eq!(schema["$id"], expected);
        saidify(&mut schema);
        assert_eq!(
            schema["$id"], expected,
            "the schema changed without its SAID"
        );
    }
}

// ── Round trip ─────────────────────────────────────────────────────────────

#[test]
fn designated_key_agreement_and_services_are_in_the_resolved_document() {
    let result = created();
    let doc = resolve(result.did(), result.artifacts());

    let key = x25519(1).to_cesr().expect("cesr");
    let expected_ref = format!("{}#{key}", result.did());
    assert_eq!(key_agreement_refs(&doc), vec![expected_ref.clone()]);

    let method = doc
        .verification_method
        .iter()
        .find(|vm| vm.id.as_str() == expected_ref)
        .expect("a verification method for the designated key");
    let jwk = method.property_set.get("publicKeyJwk").expect("jwk");
    assert_eq!(jwk["kty"], "OKP");
    assert_eq!(jwk["crv"], "X25519");

    // The key agreement key authenticates and asserts nothing.
    let auth = serde_json::to_value(&doc.authentication).expect("serializes");
    assert!(!auth.to_string().contains(&key), "{auth}");

    let types: Vec<Vec<String>> = doc.service.iter().map(|s| s.type_.clone()).collect();
    assert!(
        types.contains(&vec!["DIDCommMessaging".to_string()]),
        "{types:?}"
    );
    assert!(
        types.contains(&vec!["TSPTransport".to_string()]),
        "{types:?}"
    );
    let didcomm = doc
        .service
        .iter()
        .find(|s| s.type_ == vec!["DIDCommMessaging".to_string()])
        .expect("didcomm");
    assert_eq!(
        didcomm.id.as_ref().map(|u| u.as_str().to_string()),
        Some(format!("{}#didcomm", result.did())),
    );
}

#[test]
fn the_published_did_json_carries_them() {
    // Published, not only derived: a consumer reading did.json — or its did:web
    // twin — sees the same keyAgreement and services.
    let result = created();
    let published: Value = serde_json::from_slice(&result.artifacts().did_json).expect("json");
    let key = x25519(1).to_cesr().expect("cesr");
    assert_eq!(published["keyAgreement"], json!([format!("#{key}")]));
    assert!(
        published["service"]
            .as_array()
            .expect("services")
            .iter()
            .any(|s| s["type"] == "DIDCommMessaging" && s["serviceEndpoint"]["uri"] == MEDIATOR)
    );
}

#[test]
fn a_did_json_leaving_out_the_designated_key_agreement_is_refused() {
    let result = created();
    let mut published: Value = serde_json::from_slice(&result.artifacts().did_json).expect("json");
    published
        .as_object_mut()
        .expect("object")
        .remove("keyAgreement");
    let did = DidWebs::parse(result.did()).expect("parse");
    let bytes = serde_json::to_vec(&published).expect("serializes");
    assert!(resolve_from_artifacts(&did, &result.artifacts().keri_cesr, Some(&bytes)).is_err());
}

#[test]
fn p256_and_secp256k1_keys_can_be_designated() {
    // Compressed points that are on their curves: the generators.
    let p256 = hex("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    let k1 = hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    let result = create(
        CreateConfig::builder(HOST)
            .inception(inception())
            .key_agreement(KeyAgreementKey::P256(p256))
            .key_agreement(KeyAgreementKey::Secp256k1(k1))
            .build(),
    )
    .expect("create");
    let doc = resolve(result.did(), result.artifacts());
    assert_eq!(key_agreement_refs(&doc).len(), 2);
    let curves: Vec<String> = doc
        .verification_method
        .iter()
        .filter_map(|vm| {
            vm.property_set
                .get("publicKeyJwk")?
                .get("crv")?
                .as_str()
                .map(str::to_string)
        })
        .collect();
    assert!(curves.contains(&"P-256".to_string()), "{curves:?}");
    assert!(curves.contains(&"secp256k1".to_string()), "{curves:?}");
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

// ── Lifecycle ──────────────────────────────────────────────────────────────

#[test]
fn an_encryption_key_is_replaced_without_rotating_the_identifier() {
    let result = created();
    let before = resolve(result.did(), result.artifacts());

    let updated = apply(
        result.did(),
        result.artifacts(),
        result.custody(),
        Change::KeyAgreement(vec![x25519(2)]),
    );
    let after = resolve(updated.did(), updated.artifacts());

    let new_key = x25519(2).to_cesr().expect("cesr");
    assert_eq!(
        key_agreement_refs(&after),
        vec![format!("{}#{new_key}", result.did())]
    );
    let old_key = x25519(1).to_cesr().expect("cesr");
    assert!(
        after
            .verification_method
            .iter()
            .all(|vm| !vm.id.as_str().ends_with(&old_key)),
        "the replaced key must be gone",
    );
    // The signing keys — the key state — did not change.
    assert_eq!(
        serde_json::to_value(&before.authentication).expect("serializes"),
        serde_json::to_value(&after.authentication).expect("serializes"),
    );
    // Services are a separate designation, and untouched.
    assert_eq!(before.service, after.service);
}

#[test]
fn an_empty_list_withdraws_key_agreement() {
    let result = created();
    let updated = apply(
        result.did(),
        result.artifacts(),
        result.custody(),
        Change::KeyAgreement(vec![]),
    );
    let doc = resolve(updated.did(), updated.artifacts());
    assert!(doc.key_agreement.is_empty());
    let published: Value = serde_json::from_slice(&updated.artifacts().did_json).expect("json");
    assert!(published.get("keyAgreement").is_none(), "{published}");
}

#[test]
fn services_are_replaced_as_a_set() {
    let result = created();
    let updated = apply(
        result.did(),
        result.artifacts(),
        result.custody(),
        Change::DesignatedServices(vec![tsp()]),
    );
    let doc = resolve(updated.did(), updated.artifacts());
    assert_eq!(doc.service.len(), 1, "{:?}", doc.service);
    assert_eq!(doc.service[0].type_, vec!["TSPTransport".to_string()]);
    // Key agreement is a separate designation, and untouched.
    assert_eq!(key_agreement_refs(&doc).len(), 1);
}

#[test]
fn designations_survive_a_rotation() {
    // Signed under one key state, read under the next.
    let result = created();
    let rotated = apply(
        result.did(),
        result.artifacts(),
        result.custody(),
        Change::Rotate(RotationConfig::default()),
    );
    let doc = resolve(rotated.did(), rotated.artifacts());
    assert_eq!(key_agreement_refs(&doc).len(), 1);
    assert_eq!(doc.service.len(), 2);
}

#[test]
fn a_historical_version_has_what_was_designated_then() {
    // § Support for versionId: designations are anchored in the KEL, so they
    // follow the version asked for.
    let result =
        create(CreateConfig::builder(HOST).inception(inception()).build()).expect("create");
    let updated = apply(
        result.did(),
        result.artifacts(),
        result.custody(),
        Change::KeyAgreement(vec![x25519(3)]),
    );
    let did = DidWebs::parse(updated.did()).expect("parse");
    let latest =
        resolve_with_metadata(&did, &updated.artifacts().keri_cesr, None).expect("resolves");
    assert_eq!(key_agreement_refs(&latest.document).len(), 1);

    let then = DidWebs::parse(&format!("{}?versionId=2", did.did())).expect("parse");
    let doc =
        resolve_from_artifacts(&then, &updated.artifacts().keri_cesr, None).expect("resolves");
    assert!(
        doc.key_agreement.is_empty(),
        "nothing was designated at sn 2"
    );
}

// ── Refusals ───────────────────────────────────────────────────────────────

#[test]
fn a_signing_key_cannot_be_designated_for_key_agreement() {
    // A P-256 identifier, then an attempt to designate its own signing key.
    let result = create(
        CreateConfig::builder(HOST)
            .inception(
                InceptionConfig::builder()
                    .salt(SALT.to_vec())
                    .code("1AAI")
                    .build(),
            )
            .build(),
    )
    .expect("create a P-256 identifier");
    let doc = resolve(result.did(), result.artifacts());
    let signing = doc.verification_method[0]
        .id
        .as_str()
        .rsplit('#')
        .next()
        .expect("key")
        .to_string();
    let raw = affinidi_cesr::Matter::from_qb64(&signing)
        .expect("cesr")
        .raw()
        .to_vec();

    let err = update(
        UpdateConfig {
            did: result.did().to_string(),
            prior: result.artifacts().clone(),
            custody: result.custody().clone(),
            change: Change::KeyAgreement(vec![KeyAgreementKey::P256(raw)]),
        },
        SALT,
    )
    .expect_err("the change authority must not double as an encryption key");
    assert!(err.to_string().contains("key state"), "{err}");
}

#[test]
fn a_service_id_used_twice_is_refused() {
    let err = create(
        CreateConfig::builder(HOST)
            .inception(inception())
            .designated_service(didcomm())
            .designated_service(DesignatedService::new(
                "#didcomm",
                "LinkedDomains",
                json!("https://x"),
            ))
            .build(),
    )
    .expect_err("one id, one service");
    assert!(err.to_string().contains("twice"), "{err}");
}

#[test]
fn a_designated_service_cannot_replace_a_keri_endpoint() {
    // KERI's own endpoint data stands; a designation reusing its id is dropped.
    let partial =
        create(CreateConfig::builder(HOST).inception(inception()).build()).expect("create");
    let aid = DidWebs::parse(partial.did())
        .expect("parse")
        .aid()
        .to_string();

    let mut urls = std::collections::BTreeMap::new();
    urls.insert("https".to_string(), "https://agent.example".to_string());
    let result = create(
        CreateConfig::builder(HOST)
            .inception(inception())
            .service(SelfEndpoint {
                role: "agent".to_string(),
                urls,
            })
            .designated_service(DesignatedService::new(
                format!("#{aid}/agent"),
                "agent",
                json!({"https": "https://attacker.example"}),
            ))
            .build(),
    )
    .expect("create");
    let doc = resolve(result.did(), result.artifacts());
    assert_eq!(doc.service.len(), 1, "{:?}", doc.service);
    assert_eq!(
        serde_json::to_value(&doc.service[0].service_endpoint).expect("serializes")["https"],
        "https://agent.example",
    );
}
