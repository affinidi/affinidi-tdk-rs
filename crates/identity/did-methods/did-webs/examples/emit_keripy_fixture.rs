//! Write a `did:webs` identifier's published stream for keripy to check.
//!
//! One identifier through its lifecycle, every step by this crate's public API
//! on KERI 2.0: created with designated aliases, key agreement, a service and a
//! controller endpoint; its key agreement replaced (the old designation
//! revoked in its registry); rotated; then given a new endpoint, endorsed under
//! the rotation's key state.
//!
//! Writes, into the directory given:
//!
//! - `lifecycle.keri.cesr` and `lifecycle.did.json`, the published artifacts;
//! - `lifecycle.json`, what `verify_ours.py` checks keripy against: the KEL
//!   state, every registry with its messages and anchors, each credential's
//!   status as this crate reads it, and the endpoint replies.
//!
//! ```sh
//! cargo run -p affinidi-did-webs --features create --example emit_keripy_fixture -- \
//!     crates/identity/did-methods/did-webs/tests/fixtures/ours-v2
//! ```
//!
//! UUIDs and timestamps are fresh each run, so the output differs every time;
//! `tests/ours_v2.rs` checks the committed one still resolves.

use std::collections::BTreeMap;

use affinidi_did_webs::create::{CreateConfig, SelfEndpoint, create_controlled};
use affinidi_did_webs::update::{
    Change, ControlledUpdate, complete_rotation, prepare_rotation, update_controlled,
};
use affinidi_did_webs::{DesignatedService, DidWebs, KeyAgreementKey, resolve_from_artifacts};
use affinidi_keri::controller::{Inception, KeySigner, NextKey, Rotation};
use affinidi_keri_core::parser::{Attachment, ParsedMessage, parse_all};
use affinidi_keri_core::registry::{self, IssuerLog, Status};
use affinidi_keri_core::threshold::Threshold;
use affinidi_keri_crypto::{Salter, Signer};
use serde_json::{Value, json};

const HOST: &str = "example.com";
const SCHEMAS: [&str; 4] = [
    "EF9Iy-vwD8GRKghnzHHGwAA6sC0VEWNtZ2Sf4tfd4IAA",
    "EIW1ONwnh_dkiDZ3_xmUsBxh7X5u7luVOuCoRdCl3jPZ",
    "EJVZ789syil6R--yix7j8X4g_mHZCDIaSWM15MgkFQgG",
    "EBMCaUhHZqulCtix3fzRRsdW0_gfT3bMLsrp3c3ixpxx",
];

fn key(seed: u8) -> Signer {
    Salter::new("0A", vec![seed; 16])
        .unwrap()
        .signer("A", "0", "low", true)
        .unwrap()
}

fn pk(s: &Signer) -> String {
    s.public_key().unwrap()
}

fn endpoint(url: &str) -> SelfEndpoint {
    SelfEndpoint {
        role: "controller".into(),
        urls: BTreeMap::from([("https".into(), url.into())]),
    }
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: emit_keripy_fixture <dir>");
    let (k0, k1, k2) = (key(1), key(2), key(3));

    let created = create_controlled(
        CreateConfig::builder(HOST)
            .controlled(Inception::new(
                vec![pk(&k0)],
                Threshold::Simple(1),
                vec![NextKey::PublicKey(pk(&k1))],
                Threshold::Simple(1),
            ))
            .key_agreement(KeyAgreementKey::X25519([7; 32]))
            .designated_service(DesignatedService::new(
                "#didcomm",
                "DIDCommMessaging",
                json!({ "uri": "did:webvh:QmMediator:mediator.example", "accept": ["didcomm/v2"] }),
            ))
            .service(endpoint("https://example.com/"))
            .build(),
        &[&k0],
    )
    .expect("create");

    let (artifacts, state) = created.clone().into_parts();
    let replaced = update_controlled(
        ControlledUpdate::new(
            created.did(),
            artifacts,
            state,
            Change::KeyAgreement(vec![KeyAgreementKey::X25519([8; 32])]),
        ),
        &[&k0],
    )
    .expect("replace key agreement");

    let mut pending = prepare_rotation(
        replaced.did(),
        replaced.artifacts(),
        replaced.state(),
        &[pk(&k1)],
        &Rotation::new(
            Threshold::Simple(1),
            vec![NextKey::PublicKey(pk(&k2))],
            Threshold::Simple(1),
        ),
    )
    .expect("prepare rotation");
    pending.sign_with(&k1).expect("sign rotation");
    let rotated = complete_rotation(replaced.did(), replaced.artifacts(), pending).expect("rotate");

    let (artifacts, state) = rotated.clone().into_parts();
    let last = update_controlled(
        ControlledUpdate::new(
            rotated.did(),
            artifacts,
            state,
            Change::Services(vec![endpoint("https://example.com/v2/")]),
        ),
        &[&k1],
    )
    .expect("new endpoint");

    let did = DidWebs::parse(last.did()).unwrap();
    let artifacts = last.artifacts();
    resolve_from_artifacts(&did, &artifacts.keri_cesr, Some(&artifacts.did_json))
        .expect("the published artifacts resolve");

    let spec = spec(did.aid(), last.did(), &artifacts.keri_cesr);
    let dir = std::path::Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("lifecycle.keri.cesr"), &artifacts.keri_cesr).unwrap();
    std::fs::write(dir.join("lifecycle.did.json"), &artifacts.did_json).unwrap();
    let mut text = serde_json::to_string_pretty(&spec).unwrap();
    text.push('\n');
    std::fs::write(dir.join("lifecycle.json"), text).unwrap();
    println!(
        "lifecycle  {} bytes, KEL sn {}, {} credentials",
        artifacts.keri_cesr.len(),
        spec["kel"]["sn"],
        spec["credentials"].as_array().unwrap().len()
    );
}

fn sad_str<'a>(m: &'a ParsedMessage, field: &str) -> &'a str {
    m.serder
        .sad()
        .get(field)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
}

fn ilk(m: &ParsedMessage) -> String {
    m.serder.ilk().unwrap_or_default()
}

fn raw(m: &ParsedMessage) -> String {
    String::from_utf8(m.serder.raw().to_vec()).unwrap()
}

/// What keripy must agree with, read from the stream by this library.
fn spec(aid: &str, did: &str, stream: &[u8]) -> Value {
    let messages = parse_all(stream).unwrap();
    let log = IssuerLog::replay(&messages, aid).unwrap();

    // Where the KEL anchors a registry event: the event whose seals name it.
    let kel: Vec<&ParsedMessage> = messages
        .iter()
        .filter(|m| sad_str(m, "i") == aid && ["icp", "rot", "ixn"].contains(&ilk(m).as_str()))
        .collect();
    let anchor = |said: &str| {
        let event = kel
            .iter()
            .find(|e| {
                e.serder
                    .sad()
                    .get("a")
                    .and_then(|a| a.as_array())
                    .is_some_and(|seals| {
                        seals
                            .iter()
                            .any(|s| s.get("d").and_then(|d| d.as_str()) == Some(said))
                    })
            })
            .expect("anchored");
        json!({ "sn": event.serder.sn().unwrap(), "said": event.serder.said().unwrap() })
    };
    let last = kel.last().unwrap();

    let mut credentials = Vec::new();
    for schema in SCHEMAS {
        let found = registry::designations(&messages, &log, schema).unwrap();
        assert!(found.rejected.is_empty(), "{:?}", found.rejected);
        for c in found.credentials {
            let rip = messages
                .iter()
                .find(|m| ilk(m) == "rip" && sad_str(m, "d") == c.registry)
                .unwrap();
            let acm = messages
                .iter()
                .find(|m| ilk(m) == "acm" && sad_str(m, "d") == c.said)
                .unwrap();
            let updates: Vec<Value> = messages
                .iter()
                .filter(|m| ilk(m) == "bup" && sad_str(m, "rd") == c.registry)
                .map(|u| {
                    let d = u
                        .attachments
                        .iter()
                        .find_map(|a| match a {
                            Attachment::BlindedStates(s) => s.first().cloned(),
                            _ => None,
                        })
                        .unwrap();
                    let state = match d.state.as_str() {
                        "0Missued" => "issued",
                        "Yrevoked" => "revoked",
                        other => panic!("state {other}"),
                    };
                    json!({
                        "raw": raw(u),
                        "anchor": anchor(sad_str(u, "d")),
                        "disclosure": {
                            "blid": d.blid, "uuid": d.uuid, "acdc": d.acdc, "state": state,
                        },
                    })
                })
                .collect();
            credentials.push(json!({
                "schema": schema,
                "registry": c.registry,
                "credential": c.said,
                "expect": if c.status == Status::Issued { "issued" } else { "revoked" },
                "rip": { "raw": raw(rip), "anchor": anchor(&c.registry) },
                "acm": { "raw": raw(acm) },
                "updates": updates,
            }));
        }
    }

    json!({
        "note": "created (aliases, key agreement, a service, a controller endpoint), key agreement replaced, rotated, a new endpoint endorsed under the rotation",
        "did": did,
        "kel": {
            "prefix": aid,
            "sn": last.serder.sn().unwrap(),
            "said": last.serder.said().unwrap(),
        },
        "ends": [[aid, "controller", aid]],
        "locs": [[aid, "https", "https://example.com/v2/"]],
        "credentials": credentials,
    })
}
