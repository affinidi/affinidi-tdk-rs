//! A deactivated identifier (§ Deactivate: its last rotation committed to no
//! next keys) does not resolve to a document carrying keys as current ones.
//!
//! Deactivation is a property of the DID, read from the whole stream. The
//! entry points that return a document alone refuse a deactivated DID with
//! `DidWebsError::Deactivated`, whatever `versionId` is asked for.
//! `resolve_with_metadata` reports `deactivated` for every version; the
//! deactivating version's document carries no keys, relationships or
//! services, and an earlier version's is the document as it stood then.
//!
//! `fixtures/deactivated/` holds an identifier at `example.com` created by
//! this crate, rotated at sn 3 and deactivated at sn 4: `keri.cesr`,
//! `did.json` as `update` now publishes it (no keys), `legacy.did.json` as it
//! published it before (the full derivation), and `did.txt`, the DID.

use affinidi_did_webs::{
    DidWebs, DidWebsError, Kels, resolve_from_artifacts, resolve_with_metadata,
};

const KERI_CESR: &[u8] = include_bytes!("fixtures/deactivated/keri.cesr");
const DID_JSON: &[u8] = include_bytes!("fixtures/deactivated/did.json");
const LEGACY_DID_JSON: &[u8] = include_bytes!("fixtures/deactivated/legacy.did.json");
const DID: &str = include_str!("fixtures/deactivated/did.txt");
const ROTATION_SN: u64 = 3;
const DEACTIVATION_SN: u64 = 4;

fn did() -> &'static str {
    DID.trim()
}

fn at(version: u64) -> DidWebs {
    DidWebs::parse(&format!("{}?versionId={version}", did())).expect("parse")
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

fn assert_deactivated(err: &DidWebsError) {
    assert!(
        matches!(err, DidWebsError::Deactivated(d) if d == did()),
        "{err:?}"
    );
}

#[test]
fn the_fixture_is_deactivated_at_its_last_rotation() {
    let kels = Kels::parse(KERI_CESR).expect("parses");
    let aid = DidWebs::parse(did()).expect("parse").aid().to_string();
    assert!(kels.is_deactivated(&aid));
    assert_eq!(
        kels.sequence_numbers(&aid).into_iter().max(),
        Some(DEACTIVATION_SN)
    );
}

#[test]
fn a_document_alone_is_refused_for_a_deactivated_identifier() {
    let parsed = DidWebs::parse(did()).expect("parse");
    for published in [Some(DID_JSON), Some(LEGACY_DID_JSON), None] {
        let err = resolve_from_artifacts(&parsed, KERI_CESR, published)
            .expect_err("a deactivated identifier has no current keys to return");
        assert_deactivated(&err);
    }
}

#[test]
fn a_document_alone_is_refused_at_every_version() {
    for version in [ROTATION_SN, DEACTIVATION_SN] {
        let err = resolve_from_artifacts(&at(version), KERI_CESR, None)
            .expect_err("deactivation is a property of the DID, not of a version");
        assert_deactivated(&err);
    }
}

#[test]
fn the_metadata_reports_deactivation_and_the_document_carries_no_keys() {
    let parsed = DidWebs::parse(did()).expect("parse");
    for published in [DID_JSON, LEGACY_DID_JSON] {
        let resolution = resolve_with_metadata(&parsed, KERI_CESR, Some(published))
            .expect("either published form agrees with the stream");
        assert!(resolution.metadata.deactivated);
        assert_eq!(resolution.metadata.to_json()["deactivated"], true);
        assert_eq!(resolution.metadata.version_id, DEACTIVATION_SN);
        assert_eq!(resolution.document.id.as_str(), did());
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
        assert_deactivated(&err);
    }
}

#[test]
fn the_published_document_carries_no_keys() {
    let published: serde_json::Value = serde_json::from_slice(DID_JSON).expect("JSON");
    for member in [
        "verificationMethod",
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "service",
    ] {
        assert!(published.get(member).is_none(), "{member}: {published}");
    }
}

#[test]
fn a_published_document_with_other_keys_is_still_refused() {
    let parsed = DidWebs::parse(did()).expect("parse");
    let mut tampered: serde_json::Value = serde_json::from_slice(LEGACY_DID_JSON).expect("JSON");
    tampered["verificationMethod"][0]["publicKeyJwk"]["x"] =
        serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let tampered = serde_json::to_vec(&tampered).expect("JSON");
    let err = resolve_with_metadata(&parsed, KERI_CESR, Some(&tampered)).expect_err("neither form");
    assert!(matches!(err, DidWebsError::DocumentMismatch(_)), "{err:?}");
}

#[test]
fn an_earlier_version_resolves_with_its_keys_and_reports_deactivation() {
    let resolution = resolve_with_metadata(&at(ROTATION_SN), KERI_CESR, None)
        .expect("the rotation before the deactivation resolves");
    assert!(
        resolution.metadata.deactivated,
        "deactivation is a property of the DID"
    );
    assert_eq!(resolution.metadata.version_id, ROTATION_SN);
    assert_eq!(resolution.metadata.next_version_id, Some(DEACTIVATION_SN));
    assert!(!resolution.document.verification_method.is_empty());
    assert!(!resolution.document.authentication.is_empty());

    let at_deactivation = resolve_with_metadata(&at(DEACTIVATION_SN), KERI_CESR, None)
        .expect("the deactivating version resolves with its metadata");
    assert!(at_deactivation.metadata.deactivated);
    assert_no_keys(&at_deactivation.document);
}

#[cfg(feature = "create")]
mod created {
    use super::assert_no_keys;
    use affinidi_did_webs::create::{CreateConfig, create};
    use affinidi_did_webs::update::{Change, UpdateConfig, update};
    use affinidi_did_webs::{Artifacts, DidWebs, DidWebsError, HostPolicy, WebsResolver};
    use affinidi_keri::config::{InceptionConfig, RotationConfig};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SALT: &[u8] = &[11u8; 16];

    /// An identifier at `host`, created and then deactivated.
    fn deactivated_at(host: &str) -> (String, Artifacts) {
        let created = create(
            CreateConfig::builder(host)
                .inception(InceptionConfig::builder().salt(SALT.to_vec()).build())
                .build(),
        )
        .expect("create");
        let deactivated = update(
            UpdateConfig {
                did: created.did().to_string(),
                prior: created.artifacts().clone(),
                custody: created.custody().clone(),
                change: Change::Rotate(RotationConfig {
                    next_count: 0,
                    next_threshold: 0,
                    ..RotationConfig::default()
                }),
            },
            SALT,
        )
        .expect("rotate to no next keys");
        (created.did().to_string(), deactivated.into_artifacts())
    }

    #[test]
    fn a_deactivating_update_publishes_no_keys() {
        let (did, artifacts) = deactivated_at("example.com");
        let published: serde_json::Value =
            serde_json::from_slice(&artifacts.did_json).expect("JSON");
        assert!(published.get("verificationMethod").is_none(), "{published}");
        assert!(published.get("authentication").is_none(), "{published}");

        let resolution = affinidi_did_webs::resolve_with_metadata(
            &DidWebs::parse(&did).expect("parse"),
            &artifacts.keri_cesr,
            Some(&artifacts.did_json),
        )
        .expect("what update publishes agrees with the stream");
        assert!(resolution.metadata.deactivated);
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
        let (did, artifacts) = deactivated_at(&host);
        let aid = DidWebs::parse(&did).expect("parse").aid().to_string();
        serve(&server, &aid, "keri.cesr", &artifacts.keri_cesr).await;
        serve(&server, &aid, "did.json", &artifacts.did_json).await;

        let resolver = WebsResolver::with_policy(HostPolicy::AllowPrivate);
        let err = resolver
            .resolve(&did)
            .await
            .expect_err("a deactivated identifier has no current keys to return");
        assert!(
            matches!(&err, DidWebsError::Deactivated(d) if d == &did),
            "{err:?}"
        );

        let resolution = resolver
            .resolve_with_metadata(&did)
            .await
            .expect("resolves with its metadata");
        assert!(resolution.metadata.deactivated);
        assert_no_keys(&resolution.document);
    }
}
