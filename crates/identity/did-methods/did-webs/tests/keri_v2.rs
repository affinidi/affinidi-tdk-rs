//! `did:webs` on KERI 2.0: an identifier written in 2.0 publishes a 2.0 log,
//! 2.x designations in `rip`/`bup` registries, and 2.0 replies; a replaced
//! designation is revoked in its own registry; and a critical designation this
//! resolver does not implement fails resolution (P2, P5, P6 of
//! `did-webs-keri-v2.md` in OpenVTC/verifiable-trust-infrastructure).

#![cfg(feature = "create")]

use std::collections::BTreeMap;

use affinidi_did_webs::create::{CreateConfig, SelfEndpoint, create, create_controlled};
use affinidi_did_webs::update::{
    Change, ControlledUpdate, complete_rotation, prepare_rotation, update_controlled,
};
use affinidi_did_webs::{
    Artifacts, ControlledResult, DesignatedService, DidWebs, DidWebsError, Kels, KeyAgreementKey,
    KeyRoles, VerificationKey, designated_aliases, designated_key_agreement, designated_services,
    resolve_from_artifacts,
};
use affinidi_keri::ProtocolVersion;
use affinidi_keri::config::InceptionConfig;
use affinidi_keri::controller::{ControllerState, Inception, KeySigner, NextKey, Rotation};
use affinidi_keri_core::parser::{ParsedMessage, parse_all};
use affinidi_keri_core::registry::Anchor;
use affinidi_keri_core::registry::write::{
    BlindingUuid, RegistryNonce, RegistryState, TransactionState,
};
use affinidi_keri_core::sad::SadValue;
use affinidi_keri_core::threshold::Threshold;
use affinidi_keri_crypto::{Salter, Signer};
use serde_json::{Value, json};

const HOST: &str = "example.com";
const ALIASES_V2: &str = "EF9Iy-vwD8GRKghnzHHGwAA6sC0VEWNtZ2Sf4tfd4IAA";
const KEY_AGREEMENT_V2: &str = "EIW1ONwnh_dkiDZ3_xmUsBxh7X5u7luVOuCoRdCl3jPZ";
const SERVICE_V2: &str = "EJVZ789syil6R--yix7j8X4g_mHZCDIaSWM15MgkFQgG";
const KEY_ROLE_V2: &str = "EBMCaUhHZqulCtix3fzRRsdW0_gfT3bMLsrp3c3ixpxx";
/// A designation schema this resolver does not implement.
const FOREIGN: &str = "EForeignDesignationSchema000000000000000000";

fn key(seed: u8) -> Signer {
    Salter::new("0A", vec![seed; 16])
        .unwrap()
        .signer("A", "0", "low", true)
        .unwrap()
}

fn pk(s: &Signer) -> String {
    s.public_key().unwrap()
}

fn didcomm() -> DesignatedService {
    DesignatedService::new(
        "#didcomm",
        "DIDCommMessaging",
        json!({ "uri": "did:webvh:QmMediator:mediator.example", "accept": ["didcomm/v2"] }),
    )
}

fn endpoint() -> SelfEndpoint {
    SelfEndpoint {
        role: "controller".into(),
        urls: BTreeMap::from([("https".into(), "https://example.com/".into())]),
    }
}

/// A controlled identifier, 2.0 by default, with key agreement, a service and
/// an endpoint.
fn created(signer: &Signer) -> ControlledResult {
    create_controlled(
        CreateConfig::builder(HOST)
            .controlled(Inception::new(
                vec![pk(signer)],
                Threshold::Simple(1),
                vec![NextKey::PublicKey(pk(&key(2)))],
                Threshold::Simple(1),
            ))
            .key_agreement(KeyAgreementKey::X25519([7; 32]))
            .designated_service(didcomm())
            .service(endpoint())
            .build(),
        &[signer],
    )
    .expect("create")
}

fn resolve(did: &str, artifacts: &Artifacts) -> Result<Value, DidWebsError> {
    let parsed = DidWebs::parse(did).unwrap();
    resolve_from_artifacts(&parsed, &artifacts.keri_cesr, None)
        .map(|doc| serde_json::to_value(doc).unwrap())
}

fn messages(artifacts: &Artifacts) -> Vec<ParsedMessage> {
    parse_all(&artifacts.keri_cesr).expect("the stream parses")
}

fn ilk(m: &ParsedMessage) -> String {
    m.serder.ilk().unwrap_or_default()
}

fn major(m: &ParsedMessage) -> u8 {
    m.serder.version.as_ref().map_or(0, |v| v.major)
}

fn protocol(m: &ParsedMessage) -> String {
    m.serder
        .version
        .as_ref()
        .map_or(String::new(), |v| v.protocol.clone())
}

#[test]
fn a_controlled_identifier_is_written_in_keri_2() {
    let signer = key(1);
    let created = created(&signer);
    assert_eq!(created.state().version, ProtocolVersion::V2);
    assert!(
        created.artifacts().keri_cesr.starts_with(b"-_AAACAA"),
        "a 2.0 stream states its genus first (P1)"
    );

    let all = messages(created.artifacts());
    let ilks: Vec<String> = all.iter().map(ilk).collect();
    for m in &all {
        assert_eq!(major(m), 2, "every message is 2.x: {}", ilk(m));
    }
    for v1 in ["vcp", "iss", "rev"] {
        assert!(
            !ilks.contains(&v1.to_string()),
            "no 1.x TEL event: {ilks:?}"
        );
    }
    // Aliases, key agreement and services: three designations, each in a
    // registry of its own, issued by one update each.
    let count = |t: &str| ilks.iter().filter(|i| *i == t).count();
    assert_eq!(
        (count("rip"), count("acm"), count("bup")),
        (3, 3, 3),
        "{ilks:?}"
    );
    let schemas: Vec<&str> = all
        .iter()
        .filter(|m| ilk(m) == "acm")
        .filter_map(|m| m.serder.sad().get("s").and_then(|s| s.as_str()))
        .collect();
    for schema in [ALIASES_V2, KEY_AGREEMENT_V2, SERVICE_V2] {
        assert!(schemas.contains(&schema), "{schema} in {schemas:?}");
    }
    // Every designation carries the rules section its schema requires.
    for acm in all.iter().filter(|m| ilk(m) == "acm") {
        assert!(acm.serder.sad().get("r").is_some_and(|r| r.is_object()));
    }

    // Replies name their sender (`i`, 2.x only) and are endorsed under the
    // inception, at sequence number 0 — not the log's latest.
    let replies: Vec<&ParsedMessage> = all.iter().filter(|m| ilk(m) == "rpy").collect();
    assert_eq!(replies.len(), 2, "/end/role/add and /loc/scheme");
    for rpy in replies {
        assert_eq!(
            rpy.serder.sad().get("i").and_then(|v| v.as_str()),
            Some(created.state().prefix.as_str())
        );
        let [group] = rpy.trans_idx_sig_groups() else {
            panic!("one endorsement");
        };
        assert_eq!(group.sn, "MAAA", "the inception's sequence number");
        assert_eq!(group.said, created.state().prefix);
    }

    let doc = resolve(created.did(), created.artifacts()).expect("resolves");
    assert_eq!(doc["keyAgreement"].as_array().unwrap().len(), 1, "{doc}");
    assert_eq!(doc["service"].as_array().unwrap().len(), 2, "{doc}");
}

#[test]
fn a_replaced_designation_is_revoked_in_its_own_registry() {
    let signer = key(1);
    let created = created(&signer);
    let (artifacts, state) = created.clone().into_parts();
    let before = messages(&artifacts);
    let old_ka = before
        .iter()
        .find(|m| {
            ilk(m) == "acm"
                && m.serder.sad().get("s").and_then(|s| s.as_str()) == Some(KEY_AGREEMENT_V2)
        })
        .expect("a key agreement designation");
    let old_registry = old_ka.serder.sad()["rd"].as_str().unwrap().to_string();

    let updated = update_controlled(
        ControlledUpdate::new(
            created.did(),
            artifacts,
            state,
            Change::KeyAgreement(vec![KeyAgreementKey::X25519([8; 32])]),
        ),
        &[&signer],
    )
    .expect("update");

    let after = messages(updated.artifacts());
    let updates: Vec<&ParsedMessage> = after
        .iter()
        .filter(|m| {
            ilk(m) == "bup"
                && m.serder.sad().get("rd").and_then(|v| v.as_str()) == Some(&old_registry)
        })
        .collect();
    assert_eq!(updates.len(), 2, "issued, then revoked, in one registry");
    assert_eq!(updates[1].serder.sad()["n"].as_str(), Some("2"));

    let doc = resolve(updated.did(), updated.artifacts()).expect("resolves");
    let ka = doc["keyAgreement"].as_array().unwrap();
    assert_eq!(ka.len(), 1, "only the new key: {doc}");
    let before_doc = resolve(created.did(), created.artifacts()).unwrap();
    assert_ne!(doc["keyAgreement"], before_doc["keyAgreement"]);
}

#[test]
fn key_roles_on_keri_2_are_critical() {
    let signer = key(1);
    let created = create_controlled(
        CreateConfig::builder(HOST)
            .controlled(Inception::new(
                vec![pk(&signer)],
                Threshold::Simple(1),
                vec![NextKey::PublicKey(pk(&key(2)))],
                Threshold::Simple(1),
            ))
            .key_roles(
                KeyRoles::new()
                    .with_attestation(VerificationKey::Ed25519([11; 32]))
                    .with_messaging(KeyAgreementKey::X25519([13; 32])),
            )
            .build(),
        &[&signer],
    )
    .expect("create");
    let roles = messages(created.artifacts())
        .into_iter()
        .find(|m| ilk(m) == "acm" && m.serder.sad()["s"].as_str() == Some(KEY_ROLE_V2))
        .expect("a 2.x key role designation");
    assert_eq!(roles.serder.sad()["a"]["critical"], SadValue::Bool(true));
    let doc = resolve(created.did(), created.artifacts()).expect("resolves");
    assert!(doc["keyRoles"].is_object(), "{doc}");
}

/// Anchor `seals` in an interaction event signed by `signer`, appended to
/// `keri_cesr`, built directly: `update_controlled` would refuse to publish
/// it, since it resolves the result and the stream does not yet carry what the
/// seals name.
fn anchor(
    state: &ControllerState,
    signer: &Signer,
    seals: &[SadValue],
    keri_cesr: &mut Vec<u8>,
) -> (ControllerState, Anchor) {
    let mut pending = state.interact(seals).unwrap();
    pending.sign_with(signer).unwrap();
    let (event, next) = pending.finish().unwrap();
    keri_cesr.extend(event.composed);
    let anchor = Anchor {
        sn: next.sn,
        said: next.last_said.clone(),
    };
    (next, anchor)
}

/// Issue a 2.x designation of `schema` with `attributes` from `created`'s AID
/// and append it to the stream. Returns the artifacts, the controller and
/// registry state after it, and the credential's SAID.
fn designate(
    created: &ControlledResult,
    signer: &Signer,
    schema: &str,
    attributes: Value,
) -> (Artifacts, ControllerState, RegistryState, String) {
    let aid = created.state().prefix.clone();
    let dt = "2026-01-01T00:00:00.000000+00:00";
    let (state, rip) = RegistryState::incept(&aid, &RegistryNonce([9; 16]), dt).unwrap();
    let credential = state
        .designation(schema, &SadValue::from_json_value(&attributes))
        .unwrap();
    let (state, bup) = state
        .update(
            &credential.said,
            TransactionState::Issued,
            &BlindingUuid([1; 32]),
            dt,
        )
        .unwrap();
    let mut keri_cesr = created.artifacts().keri_cesr.clone();
    let (controller, at) = anchor(
        created.state(),
        signer,
        &[rip.seal(), bup.seal()],
        &mut keri_cesr,
    );
    keri_cesr.extend(rip.compose(&at).unwrap());
    keri_cesr.extend(credential.compose().unwrap());
    keri_cesr.extend(bup.compose(&at).unwrap());
    let artifacts = Artifacts {
        keri_cesr,
        did_json: created.artifacts().did_json.clone(),
    };
    (artifacts, controller, state, credential.said)
}

#[test]
fn a_critical_designation_this_resolver_does_not_implement_fails_resolution() {
    let signer = key(1);
    let created = created(&signer);
    let (artifacts, ..) = designate(
        &created,
        &signer,
        FOREIGN,
        json!({ "dt": "2026-01-01T00:00:00.000000+00:00", "critical": true, "x": 1 }),
    );
    let err = resolve(created.did(), &artifacts).expect_err("critical and unknown");
    assert!(
        matches!(&err, DidWebsError::UnsupportedDesignation(s) if s == FOREIGN),
        "{err}"
    );
}

#[test]
fn a_designation_this_resolver_does_not_implement_is_ignored_unless_critical() {
    let signer = key(1);
    let created = created(&signer);
    let (artifacts, ..) = designate(
        &created,
        &signer,
        FOREIGN,
        json!({ "dt": "2026-01-01T00:00:00.000000+00:00", "x": 1 }),
    );
    resolve(created.did(), &artifacts).expect("an additive designation is ignored");
}

#[test]
fn a_revoked_critical_designation_no_longer_restricts() {
    let signer = key(1);
    let created = created(&signer);
    let (artifacts, controller, registry, said) = designate(
        &created,
        &signer,
        FOREIGN,
        json!({ "dt": "2026-01-01T00:00:00.000000+00:00", "critical": true }),
    );
    let issued_at = controller.sn;
    let (_, bup) = registry
        .update(
            &said,
            TransactionState::Revoked,
            &BlindingUuid([2; 32]),
            "2026-01-02T00:00:00.000000+00:00",
        )
        .unwrap();
    let mut keri_cesr = artifacts.keri_cesr.clone();
    let (_, at) = anchor(&controller, &signer, &[bup.seal()], &mut keri_cesr);
    keri_cesr.extend(bup.compose(&at).unwrap());
    let revoked = Artifacts {
        keri_cesr,
        did_json: artifacts.did_json.clone(),
    };
    resolve(created.did(), &revoked).expect("the restriction was withdrawn");

    // As of the event that issued it, it still restricts.
    let then = format!("{}?versionId={issued_at}", created.did());
    let err = resolve(&then, &revoked).expect_err("in force then");
    assert!(
        matches!(err, DidWebsError::UnsupportedDesignation(_)),
        "{err}"
    );
}

#[test]
fn a_salted_identifier_can_be_written_in_keri_2() {
    let created = create(
        CreateConfig::builder(HOST)
            .inception(
                InceptionConfig::builder()
                    .salt(vec![5; 16])
                    .version(ProtocolVersion::V2)
                    .build(),
            )
            .key_agreement(KeyAgreementKey::X25519([7; 32]))
            .service(endpoint())
            .build(),
    )
    .expect("create");
    let all = messages(created.artifacts());
    assert!(all.iter().all(|m| major(m) == 2));
    assert!(all.iter().any(|m| ilk(m) == "rip"));
    assert!(
        all.iter()
            .filter(|m| protocol(m) == "ACDC")
            .all(|m| !ilk(m).is_empty()),
        "no 1.x credential"
    );
    resolve(created.did(), created.artifacts()).expect("resolves");
}

/// `created`'s stream with one signature of the key event at `sn` broken: its
/// last base64 character changed, which changes the signature's value.
fn with_a_broken_signature(created: &ControlledResult, sn: u64) -> Vec<u8> {
    let text = String::from_utf8(created.artifacts().keri_cesr.clone()).unwrap();
    let all = messages(created.artifacts());
    let event = all
        .iter()
        .find(|m| ["icp", "ixn"].contains(&ilk(m).as_str()) && m.serder.sn().ok() == Some(sn))
        .expect("the event");
    let sig = event.controller_sigs()[0].qb64().unwrap();
    let last = sig.chars().last().unwrap();
    let broken = format!(
        "{}{}",
        &sig[..sig.len() - 1],
        if last == 'A' { 'B' } else { 'A' }
    );
    assert_eq!(text.matches(&sig).count(), 1);
    text.replace(&sig, &broken).into_bytes()
}

#[test]
fn no_designation_is_read_from_a_log_that_does_not_verify() {
    // Designations mean nothing without a verified KEL. A broken signature on
    // the event anchoring them, or on any event of the log, fails every
    // designation reader loudly, rather than yielding what the stream claims.
    let signer = key(1);
    let created = created(&signer);
    let aid = created.state().prefix.clone();
    for sn in [0, 1, created.state().sn] {
        let kels = Kels::parse(&with_a_broken_signature(&created, sn)).expect("parses");
        let kel = |e: DidWebsError| matches!(e, DidWebsError::Kel(_));
        assert!(
            designated_aliases(&kels, &aid).is_err_and(kel),
            "aliases, sn {sn}"
        );
        assert!(
            designated_key_agreement(&kels, &aid).is_err_and(kel),
            "key agreement, sn {sn}"
        );
        assert!(
            designated_services(&kels, &aid).is_err_and(kel),
            "services, sn {sn}"
        );
    }
}

#[test]
fn a_historical_version_is_not_read_from_a_log_that_breaks_later() {
    // Under versionId the registry reader sees the whole log, so the whole log
    // must verify, not only the part up to the version asked for.
    let signer = key(1);
    let created = created(&signer);
    let latest = created.state().sn;
    let tampered = with_a_broken_signature(&created, latest);
    let then = DidWebs::parse(&format!("{}?versionId=1", created.did())).unwrap();
    let err = resolve_from_artifacts(&then, &tampered, None).expect_err("a broken log");
    assert!(matches!(err, DidWebsError::Kel(_)), "{err}");
}

#[test]
fn a_recovery_takes_the_designations_it_supersedes_with_it() {
    // P7. The identifier replaces its key agreement key: an interaction event
    // revokes the old designation and another issues the new one. Its next key
    // then rotates from the state before that change, at the sequence number
    // of the first of those events, superseding both. The stream carries all
    // of it; the document has the original key agreement key again.
    let signer = key(1);
    let created = created(&signer);
    let original = resolve(created.did(), created.artifacts()).unwrap();

    let (artifacts, state) = created.clone().into_parts();
    let replaced = update_controlled(
        ControlledUpdate::new(
            created.did(),
            artifacts,
            state,
            Change::KeyAgreement(vec![KeyAgreementKey::X25519([8; 32])]),
        ),
        &[&signer],
    )
    .expect("replace key agreement");
    let after = resolve(replaced.did(), replaced.artifacts()).unwrap();
    assert_ne!(after["keyAgreement"], original["keyAgreement"]);

    let next = key(2);
    let mut pending = prepare_rotation(
        created.did(),
        created.artifacts(),
        created.state(),
        &[pk(&next)],
        &Rotation::new(
            Threshold::Simple(1),
            vec![NextKey::PublicKey(pk(&key(3)))],
            Threshold::Simple(1),
        ),
    )
    .expect("prepare the recovery");
    pending.sign_with(&next as &dyn KeySigner).unwrap();
    let recovered =
        complete_rotation(created.did(), replaced.artifacts(), pending).expect("recover");
    assert_eq!(recovered.state().sn, created.state().sn + 1);

    let doc = resolve(recovered.did(), recovered.artifacts()).expect("resolves");
    assert_eq!(
        doc["keyAgreement"], original["keyAgreement"],
        "the replacement and its revocation of the original were superseded"
    );
    assert!(
        doc["verificationMethod"]
            .to_string()
            .contains(&pk(&next)[1..])
    );
}

/// `created`'s artifacts with a credential marked critical under each of
/// `count` schemas this resolver does not implement appended, none of them
/// issued. With `anchor_registry`, the registry they name is incepted and
/// its inception anchored in the KEL.
fn with_unissued_critical_credentials(
    created: &ControlledResult,
    signer: &Signer,
    count: usize,
    anchor_registry: bool,
) -> Artifacts {
    let aid = created.state().prefix.clone();
    let dt = "2026-01-01T00:00:00.000000+00:00";
    let (state, rip) = RegistryState::incept(&aid, &RegistryNonce([9; 16]), dt).unwrap();
    let mut keri_cesr = created.artifacts().keri_cesr.clone();
    if anchor_registry {
        let (_, at) = anchor(created.state(), signer, &[rip.seal()], &mut keri_cesr);
        keri_cesr.extend(rip.compose(&at).unwrap());
    }
    for n in 0..count {
        let schema = format!("{}{n:02}", &FOREIGN[..FOREIGN.len() - 2]);
        let credential = state
            .designation(
                &schema,
                &SadValue::from_json_value(&json!({ "dt": dt, "critical": true })),
            )
            .unwrap();
        keri_cesr.extend(credential.compose().unwrap());
    }
    Artifacts {
        keri_cesr,
        did_json: created.artifacts().did_json.clone(),
    }
}

#[test]
fn critical_credentials_count_toward_the_schema_bound_only_in_an_anchored_registry() {
    let signer = key(1);
    let created = created(&signer);

    let unanchored = with_unissued_critical_credentials(&created, &signer, 40, false);
    resolve(created.did(), &unanchored)
        .expect("credentials in a registry the KEL never anchored restrict nothing");

    let few = with_unissued_critical_credentials(&created, &signer, 16, true);
    resolve(created.did(), &few).expect("credentials that were never issued restrict nothing");

    let many = with_unissued_critical_credentials(&created, &signer, 17, true);
    let err = resolve(created.did(), &many).expect_err("past the schema bound");
    assert!(
        matches!(&err, DidWebsError::Stream(m) if m.contains("critical")),
        "{err}"
    );
}
