//! A deactivated identifier (§ Deactivate: its last rotation committed to no
//! next keys) does not resolve to a document carrying its last keys.
//!
//! The entry points that return a document alone refuse it with
//! `DidWebsError::Deactivated`; the ones that return metadata report
//! `deactivated` and a document with no keys, relationships or services. A
//! `versionId` before the deactivation still resolves the document as it
//! stood.

#![cfg(feature = "create")]

use affinidi_did_webs::create::{CreateConfig, create};
use affinidi_did_webs::update::{Change, UpdateConfig, update};
use affinidi_did_webs::{
    Artifacts, DidWebs, DidWebsError, HostPolicy, WebsResolver, resolve_from_artifacts,
    resolve_with_metadata,
};
use affinidi_keri::config::{InceptionConfig, RotationConfig};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SALT: &[u8] = &[11u8; 16];

/// An identifier at `host`, rotated once and then deactivated, with the
/// sequence number of that rotation. The deactivation follows it.
fn deactivated_at(host: &str) -> (String, Artifacts, u64) {
    let created = create(
        CreateConfig::builder(host)
            .inception(InceptionConfig::builder().salt(SALT.to_vec()).build())
            .build(),
    )
    .expect("create");
    let rotated = update(
        UpdateConfig {
            did: created.did().to_string(),
            prior: created.artifacts().clone(),
            custody: created.custody().clone(),
            change: Change::Rotate(RotationConfig::default()),
        },
        SALT,
    )
    .expect("rotate");
    let rotation_sn = resolve_with_metadata(
        &DidWebs::parse(created.did()).expect("parse"),
        &rotated.artifacts().keri_cesr,
        None,
    )
    .expect("the rotation resolves")
    .metadata
    .version_id;
    let deactivated = update(
        UpdateConfig {
            did: created.did().to_string(),
            prior: rotated.artifacts().clone(),
            custody: rotated.custody().clone(),
            change: Change::Rotate(RotationConfig {
                next_count: 0,
                next_threshold: 0,
                ..RotationConfig::default()
            }),
        },
        SALT,
    )
    .expect("rotate to no next keys");
    (
        created.did().to_string(),
        deactivated.into_artifacts(),
        rotation_sn,
    )
}

fn assert_no_keys(document: &affinidi_did_common::Document) {
    assert!(document.verification_method.is_empty(), "{document:?}");
    assert!(document.authentication.is_empty(), "{document:?}");
    assert!(document.assertion_method.is_empty(), "{document:?}");
    assert!(document.key_agreement.is_empty(), "{document:?}");
    assert!(document.capability_invocation.is_empty(), "{document:?}");
    assert!(document.capability_delegation.is_empty(), "{document:?}");
    assert!(document.service.is_empty(), "{document:?}");
}

#[test]
fn a_document_alone_is_refused_for_a_deactivated_identifier() {
    let (did, artifacts, _) = deactivated_at("example.com");
    let parsed = DidWebs::parse(&did).expect("parse");

    let err = resolve_from_artifacts(&parsed, &artifacts.keri_cesr, Some(&artifacts.did_json))
        .expect_err("a deactivated identifier has no current keys to return");
    assert!(
        matches!(err, DidWebsError::Deactivated(ref d) if d == &did),
        "{err:?}"
    );
}

#[test]
fn the_metadata_reports_deactivation_and_the_document_carries_no_keys() {
    let (did, artifacts, rotation_sn) = deactivated_at("example.com");
    let parsed = DidWebs::parse(&did).expect("parse");

    let resolution =
        resolve_with_metadata(&parsed, &artifacts.keri_cesr, Some(&artifacts.did_json))
            .expect("a deactivated identifier resolves with its metadata");
    assert!(resolution.metadata.deactivated);
    assert_eq!(resolution.metadata.to_json()["deactivated"], true);
    assert_eq!(resolution.metadata.version_id, rotation_sn + 1);
    assert_eq!(resolution.document.id.as_str(), did);
    assert!(
        resolution
            .document
            .also_known_as
            .iter()
            .any(|a| a.starts_with("did:keri:")),
        "the aliases stay"
    );
    assert_no_keys(&resolution.document);

    let err = resolution
        .into_document()
        .expect_err("the document alone is refused");
    assert!(matches!(err, DidWebsError::Deactivated(_)), "{err:?}");
}

#[test]
fn a_version_before_the_deactivation_resolves_with_its_keys() {
    let (did, artifacts, rotation_sn) = deactivated_at("example.com");
    let then = DidWebs::parse(&format!("{did}?versionId={rotation_sn}")).expect("parse");

    let resolution = resolve_with_metadata(&then, &artifacts.keri_cesr, None)
        .expect("the rotation before the deactivation resolves");
    assert!(!resolution.metadata.deactivated);
    assert_eq!(resolution.metadata.next_version_id, Some(rotation_sn + 1));
    assert!(!resolution.document.verification_method.is_empty());

    let document = resolve_from_artifacts(&then, &artifacts.keri_cesr, None)
        .expect("a document alone, as of a version that was not deactivated");
    assert!(!document.verification_method.is_empty());
    assert!(!document.authentication.is_empty());

    let at_deactivation =
        DidWebs::parse(&format!("{did}?versionId={}", rotation_sn + 1)).expect("parse");
    let err = resolve_from_artifacts(&at_deactivation, &artifacts.keri_cesr, None)
        .expect_err("the deactivating rotation is deactivated");
    assert!(matches!(err, DidWebsError::Deactivated(_)), "{err:?}");
}

async fn serve(server: &MockServer, aid: &str, artifact: &str, body: &[u8]) {
    Mock::given(method("GET"))
        .and(path(format!("/{aid}/{artifact}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
        .mount(server)
        .await;
}

#[tokio::test]
async fn the_network_resolver_refuses_the_document_and_reports_the_metadata() {
    let server = MockServer::start().await;
    let host = server.address().to_string().replace(':', "%3A");
    let (did, artifacts, _) = deactivated_at(&host);
    let aid = DidWebs::parse(&did).expect("parse").aid().to_string();
    serve(&server, &aid, "keri.cesr", &artifacts.keri_cesr).await;
    serve(&server, &aid, "did.json", &artifacts.did_json).await;

    let resolver = WebsResolver::with_policy(HostPolicy::AllowPrivate);
    let err = resolver
        .resolve(&did)
        .await
        .expect_err("a deactivated identifier has no current keys to return");
    assert!(matches!(err, DidWebsError::Deactivated(_)), "{err:?}");

    let resolution = resolver
        .resolve_with_metadata(&did)
        .await
        .expect("resolves with its metadata");
    assert!(resolution.metadata.deactivated);
    assert_no_keys(&resolution.document);
}
