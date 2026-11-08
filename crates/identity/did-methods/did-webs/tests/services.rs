//! Service endpoints appear only when the AID signed for them.
//!
//! Two signed replies must agree: `/end/role/add` from the AID authorising an
//! endpoint identifier in a role, and `/loc/scheme` from that identifier saying
//! where it is. The published artifact carries neither, so these are built with
//! real keys and real signatures.

use affinidi_cesr::Counter;
use affinidi_did_webs::{DidWebs, Kels, resolve_from_artifacts, service_endpoints};
use affinidi_keri_core::said;
use affinidi_keri_core::serder::Serder;
use affinidi_keri_core::version::SerializationKind;
use affinidi_keri_crypto::{Diger, Signer};
use serde_json::json;

fn signer(seed: u8) -> Signer {
    Signer::new("A", [seed; 32].to_vec()).expect("signer")
}

fn fix_version(sad: &mut serde_json::Value) {
    let placeholder = "#".repeat(44);
    let (d, i) = (sad["d"].clone(), sad.get("i").cloned());
    let self_addressing = i.as_ref() == Some(&d);
    sad["d"] = json!(placeholder);
    if self_addressing {
        sad["i"] = json!(placeholder);
    }
    let len = serde_json::to_vec(sad).expect("serialize").len();
    sad["v"] = json!(format!("KERI10JSON{len:06x}_"));
    sad["d"] = d;
    if let Some(i) = i {
        sad["i"] = i;
    }
}

fn inception(controller: &Signer, next: &Signer) -> Serder {
    let next_digest = Diger::from_data("E", next.verfer().qb64().expect("qb64").as_bytes())
        .expect("digest")
        .qb64()
        .expect("qb64");
    let mut sad = json!({
        "v": "KERI10JSON000000_", "t": "icp", "d": "", "i": "", "s": "0",
        "kt": "1", "k": [controller.verfer().qb64().expect("qb64")],
        "nt": "1", "n": [next_digest],
        "bt": "0", "b": [], "c": [], "a": [],
    });
    fix_version(&mut sad);
    said::compute_said(&mut sad, "d", "E", SerializationKind::Json).expect("said");
    Serder::new(SerializationKind::Json, sad).expect("serder")
}

/// A `rpy` message. `dt` drives supersedence, so it is explicit.
fn reply(route: &str, attrs: serde_json::Value, dt: &str) -> Serder {
    let mut sad = json!({
        "v": "KERI10JSON000000_", "t": "rpy", "d": "", "dt": dt,
        "r": route, "a": attrs,
    });
    fix_version(&mut sad);
    said::compute_said(&mut sad, "d", "E", SerializationKind::Json).expect("said");
    Serder::new(SerializationKind::Json, sad).expect("serder")
}

/// Append an event with controller indexed signatures (`-A` in the 1.x table).
fn push_signed(out: &mut Vec<u8>, serder: &Serder, s: &Signer) {
    out.extend_from_slice(serder.raw());
    out.extend_from_slice(
        Counter::new("-A", 1)
            .expect("counter")
            .qb64()
            .expect("qb64")
            .as_bytes(),
    );
    out.extend_from_slice(
        s.sign_indexed(serder.raw(), 0, true)
            .expect("sign")
            .qb64()
            .expect("qb64")
            .as_bytes(),
    );
}

/// Append a reply with a transferable indexed signature group (`-F`), which is
/// how a transferable identifier signs something outside its own KEL.
fn push_reply(out: &mut Vec<u8>, serder: &Serder, signer_prefix: &str, said: &str, s: &Signer) {
    out.extend_from_slice(serder.raw());

    let sig = s
        .sign_indexed(serder.raw(), 0, true)
        .expect("sign")
        .qb64()
        .expect("qb64");
    let inner = format!(
        "{}{sig}",
        Counter::new("-A", 1)
            .expect("counter")
            .qb64()
            .expect("qb64")
    );
    // prefix + sequence number + establishment SAID, then the signatures.
    let body = format!("{signer_prefix}0AAAAAAAAAAAAAAAAAAAAAAA{said}{inner}");
    out.extend_from_slice(
        Counter::new("-F", 1)
            .expect("counter")
            .qb64()
            .expect("qb64")
            .as_bytes(),
    );
    out.extend_from_slice(body.as_bytes());
}

struct Fixture {
    aid: String,
    agent: String,
    stream: Vec<u8>,
}

/// An AID that authorises `agent` in the `agent` role, where the agent has
/// published an http location for itself.
fn authorised(role_dt: &str, loc_dt: &str, cut: Option<&str>) -> Fixture {
    let (controller, next) = (signer(1), signer(2));
    let (agent_key, agent_next) = (signer(5), signer(6));

    let icp = inception(&controller, &next);
    let aid = icp.prefix().expect("prefix");
    let agent_icp = inception(&agent_key, &agent_next);
    let agent = agent_icp.prefix().expect("prefix");

    let mut stream = Vec::new();
    push_signed(&mut stream, &icp, &controller);
    push_signed(&mut stream, &agent_icp, &agent_key);

    let add = reply(
        "/end/role/add",
        json!({"cid": aid, "role": "agent", "eid": agent}),
        role_dt,
    );
    push_reply(
        &mut stream,
        &add,
        &aid,
        &icp.said().expect("said"),
        &controller,
    );

    if let Some(cut_dt) = cut {
        let cut_rpy = reply(
            "/end/role/cut",
            json!({"cid": aid, "role": "agent", "eid": agent}),
            cut_dt,
        );
        push_reply(
            &mut stream,
            &cut_rpy,
            &aid,
            &icp.said().expect("said"),
            &controller,
        );
    }

    let loc = reply(
        "/loc/scheme",
        json!({"eid": agent, "scheme": "http", "url": "http://agent.example:5642"}),
        loc_dt,
    );
    push_reply(
        &mut stream,
        &loc,
        &agent,
        &agent_icp.said().expect("said"),
        &agent_key,
    );

    Fixture { aid, agent, stream }
}

#[test]
fn an_authorised_endpoint_becomes_a_service() {
    let f = authorised(
        "2026-01-01T00:00:00.000000+00:00",
        "2026-01-01T00:00:00.000000+00:00",
        None,
    );
    let kels = Kels::parse(&f.stream).expect("parses");

    let services = service_endpoints(&kels, &f.aid).expect("KEL verifies");
    assert_eq!(services.len(), 1, "got {services:?}");
    assert_eq!(services[0].role, "agent");
    assert_eq!(services[0].eid, f.agent);
    assert_eq!(
        services[0].urls.get("http").map(String::as_str),
        Some("http://agent.example:5642"),
    );
    assert_eq!(services[0].id(), format!("#{}/agent", f.agent));
}

#[test]
fn the_resolved_document_carries_it() {
    let f = authorised(
        "2026-01-01T00:00:00.000000+00:00",
        "2026-01-01T00:00:00.000000+00:00",
        None,
    );
    let did = DidWebs::parse(&format!("did:webs:example.com:{}", f.aid)).expect("valid did");

    let doc = resolve_from_artifacts(&did, &f.stream, None).expect("resolves");
    assert_eq!(doc.service.len(), 1, "got {:?}", doc.service);
    assert_eq!(doc.service[0].type_, vec!["agent".to_string()]);
}

#[test]
fn a_later_cut_withdraws_the_authorisation() {
    let f = authorised(
        "2026-01-01T00:00:00.000000+00:00",
        "2026-01-01T00:00:00.000000+00:00",
        Some("2026-06-01T00:00:00.000000+00:00"),
    );
    let kels = Kels::parse(&f.stream).expect("parses");
    assert!(
        service_endpoints(&kels, &f.aid)
            .expect("verifies")
            .is_empty(),
        "a cut must withdraw the endpoint",
    );
}

#[test]
fn an_earlier_cut_does_not_withdraw_a_later_add() {
    // Reply messages supersede by timestamp, so a stale `cut` replayed after
    // the `add` must not take effect.
    let f = authorised(
        "2026-06-01T00:00:00.000000+00:00",
        "2026-01-01T00:00:00.000000+00:00",
        Some("2026-01-01T00:00:00.000000+00:00"),
    );
    let kels = Kels::parse(&f.stream).expect("parses");
    assert_eq!(
        service_endpoints(&kels, &f.aid).expect("verifies").len(),
        1,
        "a stale cut must not withdraw a newer authorisation",
    );
}

#[test]
fn an_authorisation_for_another_aid_is_ignored() {
    let f = authorised(
        "2026-01-01T00:00:00.000000+00:00",
        "2026-01-01T00:00:00.000000+00:00",
        None,
    );
    let kels = Kels::parse(&f.stream).expect("parses");

    // The agent has its own verified KEL in this stream, but it authorised
    // nothing — the authorisation names our AID as `cid`, not the agent.
    assert!(
        service_endpoints(&kels, &f.agent)
            .expect("verifies")
            .is_empty(),
    );
}

#[test]
fn an_endpoint_that_never_said_where_it_is_publishes_nothing() {
    // Authorised, but no /loc/scheme. A service entry with no endpoint is
    // worse than no service entry.
    let (controller, next) = (signer(1), signer(2));
    let (agent_key, agent_next) = (signer(5), signer(6));
    let icp = inception(&controller, &next);
    let aid = icp.prefix().expect("prefix");
    let agent_icp = inception(&agent_key, &agent_next);
    let agent = agent_icp.prefix().expect("prefix");

    let mut stream = Vec::new();
    push_signed(&mut stream, &icp, &controller);
    push_signed(&mut stream, &agent_icp, &agent_key);
    let add = reply(
        "/end/role/add",
        json!({"cid": aid, "role": "agent", "eid": agent}),
        "2026-01-01T00:00:00.000000+00:00",
    );
    push_reply(
        &mut stream,
        &add,
        &aid,
        &icp.said().expect("said"),
        &controller,
    );

    let kels = Kels::parse(&stream).expect("parses");
    assert!(
        service_endpoints(&kels, &aid).expect("verifies").is_empty(),
        "an authorisation with no location must publish nothing",
    );
}

#[test]
fn a_location_signed_by_someone_else_is_ignored() {
    // The agent is authorised, but the /loc/scheme naming it is signed by the
    // controller rather than the agent. A third party saying where someone
    // else can be reached is a redirection, not a location.
    let (controller, next) = (signer(1), signer(2));
    let (agent_key, agent_next) = (signer(5), signer(6));
    let icp = inception(&controller, &next);
    let aid = icp.prefix().expect("prefix");
    let agent_icp = inception(&agent_key, &agent_next);
    let agent = agent_icp.prefix().expect("prefix");

    let mut stream = Vec::new();
    push_signed(&mut stream, &icp, &controller);
    push_signed(&mut stream, &agent_icp, &agent_key);
    let add = reply(
        "/end/role/add",
        json!({"cid": aid, "role": "agent", "eid": agent}),
        "2026-01-01T00:00:00.000000+00:00",
    );
    push_reply(
        &mut stream,
        &add,
        &aid,
        &icp.said().expect("said"),
        &controller,
    );

    let loc = reply(
        "/loc/scheme",
        json!({"eid": agent, "scheme": "http", "url": "http://attacker.example"}),
        "2026-01-01T00:00:00.000000+00:00",
    );
    // Signed by the controller, claiming to be the agent's location.
    push_reply(
        &mut stream,
        &loc,
        &aid,
        &icp.said().expect("said"),
        &controller,
    );

    let kels = Kels::parse(&stream).expect("parses");
    assert!(
        service_endpoints(&kels, &aid).expect("verifies").is_empty(),
        "a location must be signed by the endpoint it describes",
    );
}

#[test]
fn an_unsigned_authorisation_is_ignored() {
    let (controller, next) = (signer(1), signer(2));
    let (agent_key, agent_next) = (signer(5), signer(6));
    let icp = inception(&controller, &next);
    let aid = icp.prefix().expect("prefix");
    let agent_icp = inception(&agent_key, &agent_next);
    let agent = agent_icp.prefix().expect("prefix");

    let mut stream = Vec::new();
    push_signed(&mut stream, &icp, &controller);
    push_signed(&mut stream, &agent_icp, &agent_key);

    // Appended with no signature at all.
    let add = reply(
        "/end/role/add",
        json!({"cid": aid, "role": "agent", "eid": agent}),
        "2026-01-01T00:00:00.000000+00:00",
    );
    stream.extend_from_slice(add.raw());

    let loc = reply(
        "/loc/scheme",
        json!({"eid": agent, "scheme": "http", "url": "http://agent.example:5642"}),
        "2026-01-01T00:00:00.000000+00:00",
    );
    push_reply(
        &mut stream,
        &loc,
        &agent,
        &agent_icp.said().expect("said"),
        &agent_key,
    );

    let kels = Kels::parse(&stream).expect("parses");
    assert!(
        service_endpoints(&kels, &aid).expect("verifies").is_empty(),
        "an unsigned authorisation must not create a service",
    );
}

// ── Thresholds and BADA ordering ────────────────────────────────────────────

fn digest_of(s: &Signer) -> String {
    Diger::from_data("E", s.verfer().qb64().expect("qb64").as_bytes())
        .expect("digest")
        .qb64()
        .expect("qb64")
}

/// An inception with several current keys and a signing threshold.
fn multi_key_inception(keys: &[&Signer], next: &[&Signer], kt: usize) -> Serder {
    let mut sad = json!({
        "v": "KERI10JSON000000_", "t": "icp", "d": "", "i": "", "s": "0",
        "kt": kt.to_string(),
        "k": keys.iter().map(|k| k.verfer().qb64().expect("qb64")).collect::<Vec<_>>(),
        "nt": kt.to_string(),
        "n": next.iter().map(|k| digest_of(k)).collect::<Vec<_>>(),
        "bt": "0", "b": [], "c": [], "a": [],
    });
    fix_version(&mut sad);
    said::compute_said(&mut sad, "d", "E", SerializationKind::Json).expect("said");
    Serder::new(SerializationKind::Json, sad).expect("serder")
}

/// A rotation to `new_key`, committing to `next`.
fn rotation(prefix: &str, prior: &str, sn: u64, new_key: &Signer, next: &Signer) -> Serder {
    let mut sad = json!({
        "v": "KERI10JSON000000_", "t": "rot", "d": "", "i": prefix,
        "s": format!("{sn:x}"), "p": prior,
        "kt": "1", "k": [new_key.verfer().qb64().expect("qb64")],
        "nt": "1", "n": [digest_of(next)],
        "bt": "0", "br": [], "ba": [], "c": [], "a": [],
    });
    fix_version(&mut sad);
    said::compute_said(&mut sad, "d", "E", SerializationKind::Json).expect("said");
    Serder::new(SerializationKind::Json, sad).expect("serder")
}

/// Append an event signed by each of `signers` at its own index.
fn push_multi_signed(out: &mut Vec<u8>, serder: &Serder, signers: &[&Signer]) {
    out.extend_from_slice(serder.raw());
    let counter = Counter::new("-A", signers.len()).expect("counter");
    out.extend_from_slice(counter.qb64().expect("qb64").as_bytes());
    for (i, s) in signers.iter().enumerate() {
        let sig = s.sign_indexed(serder.raw(), i, true).expect("sign");
        out.extend_from_slice(sig.qb64().expect("qb64").as_bytes());
    }
}

/// Append a reply in a transferable signature group carrying the signatures
/// of `signers`, each at the index given.
fn push_reply_signed_by(
    out: &mut Vec<u8>,
    serder: &Serder,
    signer_prefix: &str,
    said: &str,
    signers: &[(usize, &Signer)],
) {
    out.extend_from_slice(serder.raw());
    let mut inner = Counter::new("-A", signers.len())
        .expect("counter")
        .qb64()
        .expect("qb64");
    for (index, s) in signers {
        inner.push_str(
            &s.sign_indexed(serder.raw(), *index, true)
                .expect("sign")
                .qb64()
                .expect("qb64"),
        );
    }
    let body = format!("{signer_prefix}0AAAAAAAAAAAAAAAAAAAAAAA{said}{inner}");
    out.extend_from_slice(
        Counter::new("-F", 1)
            .expect("counter")
            .qb64()
            .expect("qb64")
            .as_bytes(),
    );
    out.extend_from_slice(body.as_bytes());
}

/// A self-designated `agent` endpoint for a 2-of-2 identifier, its
/// authorisation signed by the keys at `role_signers`.
fn two_of_two(role_signers: &[usize]) -> (String, Vec<u8>) {
    let keys = [signer(11), signer(12)];
    let next = [signer(13), signer(14)];
    let icp = multi_key_inception(&[&keys[0], &keys[1]], &[&next[0], &next[1]], 2);
    let aid = icp.prefix().expect("prefix");
    let icp_said = icp.said().expect("said");

    let mut stream = Vec::new();
    push_multi_signed(&mut stream, &icp, &[&keys[0], &keys[1]]);

    let dt = "2026-01-01T00:00:00.000000+00:00";
    let add = reply(
        "/end/role/add",
        json!({"cid": aid, "role": "agent", "eid": aid}),
        dt,
    );
    let signers: Vec<(usize, &Signer)> = role_signers.iter().map(|i| (*i, &keys[*i])).collect();
    push_reply_signed_by(&mut stream, &add, &aid, &icp_said, &signers);

    let loc = reply(
        "/loc/scheme",
        json!({"eid": aid, "scheme": "https", "url": "https://agent.example/"}),
        dt,
    );
    push_reply_signed_by(
        &mut stream,
        &loc,
        &aid,
        &icp_said,
        &[(0, &keys[0]), (1, &keys[1])],
    );
    (aid, stream)
}

#[test]
fn a_reply_meeting_the_signing_threshold_is_accepted() {
    let (aid, stream) = two_of_two(&[0, 1]);
    let kels = Kels::parse(&stream).expect("parses");
    assert_eq!(service_endpoints(&kels, &aid).expect("verifies").len(), 1);
}

#[test]
fn one_key_of_a_two_of_two_identifier_cannot_authorise_an_endpoint() {
    // A single valid signature is not the controller speaking when the key
    // state requires two. Accepting it would let one compromised key of a
    // multi-key identifier redirect its services.
    for lone in [0, 1] {
        let (aid, stream) = two_of_two(&[lone]);
        let kels = Kels::parse(&stream).expect("parses");
        assert!(
            service_endpoints(&kels, &aid).expect("verifies").is_empty(),
            "key {lone} alone authorised an endpoint",
        );
    }
}

#[test]
fn the_same_signature_twice_does_not_count_as_two_signers() {
    let (aid, stream) = two_of_two(&[0, 0]);
    let kels = Kels::parse(&stream).expect("parses");
    assert!(service_endpoints(&kels, &aid).expect("verifies").is_empty());
}

#[test]
fn a_rotated_out_key_cannot_outrank_the_current_key_with_a_future_dt() {
    // BADA orders replies by the establishment event that signed them first,
    // and only then by `dt`. Ordering by `dt` alone lets whoever holds a key
    // the controller has rotated away from sign a `cut` dated 2099 and win
    // every comparison after it — undoing exactly what the rotation was for.
    let (k0, k1, k2) = (signer(21), signer(22), signer(23));
    let icp = inception(&k0, &k1);
    let aid = icp.prefix().expect("prefix");
    let icp_said = icp.said().expect("said");
    let rot = rotation(&aid, &icp_said, 1, &k1, &k2);
    let rot_said = rot.said().expect("said");

    let mut stream = Vec::new();
    push_signed(&mut stream, &icp, &k0);
    push_signed(&mut stream, &rot, &k1);

    // The old key's forged withdrawal, dated far in the future.
    let forged_cut = reply(
        "/end/role/cut",
        json!({"cid": aid, "role": "agent", "eid": aid}),
        "2099-01-01T00:00:00.000000+00:00",
    );
    push_reply(&mut stream, &forged_cut, &aid, &icp_said, &k0);

    // The controller's authorisation under the current key, dated today.
    let dt = "2026-06-01T00:00:00.000000+00:00";
    let add = reply(
        "/end/role/add",
        json!({"cid": aid, "role": "agent", "eid": aid}),
        dt,
    );
    push_reply(&mut stream, &add, &aid, &rot_said, &k1);
    let loc = reply(
        "/loc/scheme",
        json!({"eid": aid, "scheme": "https", "url": "https://agent.example/"}),
        dt,
    );
    push_reply(&mut stream, &loc, &aid, &rot_said, &k1);

    let kels = Kels::parse(&stream).expect("parses");
    assert_eq!(
        service_endpoints(&kels, &aid).expect("verifies").len(),
        1,
        "a reply under the rotated-out key must not supersede one under the current key",
    );
}

#[test]
fn a_reply_naming_an_interaction_event_is_not_signed_under_any_key_state() {
    // A signature group names the *establishment* event whose keys signed.
    // An interaction event has a sequence number but no key state of its own.
    let (k0, k1) = (signer(31), signer(32));
    let icp = inception(&k0, &k1);
    let aid = icp.prefix().expect("prefix");
    let mut ixn = json!({
        "v": "KERI10JSON000000_", "t": "ixn", "d": "", "i": aid, "s": "1",
        "p": icp.said().expect("said"), "a": [],
    });
    fix_version(&mut ixn);
    said::compute_said(&mut ixn, "d", "E", SerializationKind::Json).expect("said");
    let ixn = Serder::new(SerializationKind::Json, ixn).expect("serder");

    let mut stream = Vec::new();
    push_signed(&mut stream, &icp, &k0);
    push_signed(&mut stream, &ixn, &k0);

    let dt = "2026-01-01T00:00:00.000000+00:00";
    let add = reply(
        "/end/role/add",
        json!({"cid": aid, "role": "agent", "eid": aid}),
        dt,
    );
    push_reply(&mut stream, &add, &aid, &ixn.said().expect("said"), &k0);
    let loc = reply(
        "/loc/scheme",
        json!({"eid": aid, "scheme": "https", "url": "https://agent.example/"}),
        dt,
    );
    push_reply(&mut stream, &loc, &aid, &icp.said().expect("said"), &k0);

    let kels = Kels::parse(&stream).expect("parses");
    assert!(service_endpoints(&kels, &aid).expect("verifies").is_empty());
}

#[test]
fn a_reply_whose_dt_is_not_a_timestamp_is_ignored() {
    let f = authorised("not a timestamp", "2026-01-01T00:00:00.000000+00:00", None);
    let kels = Kels::parse(&f.stream).expect("parses");
    assert!(
        service_endpoints(&kels, &f.aid)
            .expect("verifies")
            .is_empty()
    );
}
