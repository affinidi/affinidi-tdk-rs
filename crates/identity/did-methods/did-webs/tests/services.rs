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
