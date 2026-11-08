//! Every message this crate builds is written in the field order KERI and ACDC
//! define.
//!
//! The order is part of the message: a SAID and a signature cover the exact
//! bytes, and keripy refuses an event whose fields are out of order. Since 0.9
//! the order is fixed by how each message is built (`sad!`), not by how
//! `serde_json` happens to be compiled, so a reordered literal would still
//! verify against this crate's own resolver. This test is what catches it.

#![cfg(feature = "create")]

use std::collections::{BTreeMap, BTreeSet};

use affinidi_did_webs::create::{CreateConfig, SelfEndpoint, create};
use affinidi_did_webs::update::{Change, UpdateConfig, update};
use affinidi_did_webs::{DesignatedService, Kels, KeyAgreementKey};
use affinidi_keri::config::{InceptionConfig, RotationConfig};
use affinidi_keri_core::SadValue;
use serde_json::json;

const SALT: &[u8] = &[42u8; 16];

fn keys(value: &SadValue) -> Vec<&str> {
    value
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect()
}

#[test]
fn every_built_message_is_in_keri_and_acdc_field_order() {
    let mut urls = BTreeMap::new();
    urls.insert("http".to_string(), "https://agent.example".to_string());
    let config = CreateConfig::builder("example.com")
        .inception(InceptionConfig::builder().salt(SALT.to_vec()).build())
        .service(SelfEndpoint {
            role: "agent".to_string(),
            urls,
        })
        .also_known_as("did:web:elsewhere.example:alice")
        .key_agreement(KeyAgreementKey::X25519([7u8; 32]))
        .designated_service(
            DesignatedService::new(
                "#didcomm",
                "DIDCommMessaging",
                json!({"uri": "did:webvh:QmMediator:mediator.example", "accept": ["didcomm/v2"]}),
            )
            .with_property("routingKeys", json!([])),
        )
        .build();
    let created = create(config).expect("create");

    // A replaced designation is revoked (`rev`); a rotation adds a `rot`.
    let replaced = update(
        UpdateConfig {
            did: created.did().to_string(),
            prior: created.artifacts().clone(),
            custody: created.custody().clone(),
            change: Change::AlsoKnownAs(vec![]),
        },
        SALT,
    )
    .expect("replace the aliases");
    let rotated = update(
        UpdateConfig {
            did: replaced.did().to_string(),
            prior: replaced.artifacts().clone(),
            custody: replaced.custody().clone(),
            change: Change::Rotate(RotationConfig::default()),
        },
        SALT,
    )
    .expect("rotate");

    let kels = Kels::parse(&rotated.artifacts().keri_cesr).expect("the stream parses");
    let mut seen = BTreeSet::new();
    for message in kels.messages() {
        // Read the bytes as published, in the order they were written.
        let sad: SadValue = serde_json::from_slice(message.serder.raw()).expect("a JSON message");
        let kind = match sad["v"].as_str() {
            Some(v) if v.starts_with("ACDC") => "acdc".to_string(),
            _ => sad["t"].as_str().expect("an ilk").to_string(),
        };
        let expected: &[&str] = match kind.as_str() {
            "icp" => &[
                "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a",
            ],
            // The KERI specification's rotation carries configuration traits
            // (`c`) between the backer changes and the anchors.
            "rot" => &[
                "v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "c", "a",
            ],
            "ixn" => &["v", "t", "d", "i", "s", "p", "a"],
            "rpy" => &["v", "t", "d", "dt", "r", "a"],
            "vcp" => &["v", "t", "d", "i", "ii", "s", "c", "bt", "b", "n"],
            "iss" => &["v", "t", "d", "i", "s", "ri", "dt"],
            "rev" => &["v", "t", "d", "i", "s", "ri", "p", "dt"],
            "acdc" => &["v", "d", "i", "ri", "s", "a", "r"],
            other => panic!("unexpected message type {other}"),
        };
        assert_eq!(keys(&sad), expected, "{kind}: {sad:?}");

        if kind == "acdc" {
            let attributes = &sad["a"];
            assert_eq!(&keys(attributes)[..2], ["d", "dt"], "{attributes:?}");
            if let Some(services) = attributes.get("services") {
                let entry = &services.as_array().expect("a list")[0];
                assert_eq!(
                    keys(entry),
                    ["id", "type", "serviceEndpoint", "routingKeys"],
                    "{entry:?}"
                );
            }
        }
        seen.insert(kind);
    }

    let all: BTreeSet<String> = ["icp", "rot", "ixn", "rpy", "vcp", "iss", "rev", "acdc"]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(seen, all, "the stream should carry every message type");
}
