//! How much a `keri.cesr` stream may ask a resolver to do.
//!
//! A stream past `MAX_STREAM_MESSAGES` messages, `MAX_STREAM_SIGNATURES`
//! signatures, `MAX_STREAM_BACKERS` witness entries or `MAX_STREAM_SEALS`
//! seals is refused before anything in it is verified. Within those,
//! the key state at each establishment event is recorded once, while the log
//! is verified, and every signature group naming one is checked against that
//! record rather than a replay of the log.

use affinidi_did_webs::kel::{
    MAX_STREAM_BACKERS, MAX_STREAM_MESSAGES, MAX_STREAM_SEALS, MAX_STREAM_SIGNATURES,
};
use affinidi_did_webs::{DidWebsError, Kels};

const KERI_CESR: &[u8] = include_bytes!("fixtures/ENro7uf0.keri.cesr");
const AID: &str = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";

/// The fixture's inception event, with its signature, as one message.
fn inception() -> (String, String) {
    let stream = std::str::from_utf8(KERI_CESR).expect("the fixture is text");
    let body_end = stream.find("}-").expect("an attachment follows the body") + 1;
    let body = &stream[..body_end];
    // `-VAn` wraps the attachments; `-AAB` is one controller signature.
    let sigs = &stream[body_end..];
    let at = sigs.find("-AAB").expect("one controller signature") + 4;
    let signature = &sigs[at..at + 88];
    (body.to_string(), signature.to_string())
}

/// The fixture's inception body with `field`'s empty list replaced by
/// `entries`, and its version string's size corrected. Its SAID no longer
/// matches, which parsing does not check.
fn inception_with(field: &str, entries: &[String]) -> String {
    let (body, signature) = inception();
    let empty = format!("\"{field}\":[]");
    assert!(body.contains(&empty), "{body}");
    let body = body.replace(&empty, &format!("\"{field}\":[{}]", entries.join(",")));
    let size_at = body.find("JSON").expect("a version string") + 4;
    let body = format!(
        "{}{:06x}{}",
        &body[..size_at],
        body.len(),
        &body[size_at + 6..]
    );
    format!("{body}-AAB{signature}")
}

#[test]
fn a_stream_naming_too_many_witnesses_is_refused() {
    let witness = format!("\"B{}\"", "A".repeat(43));
    let within = inception_with("b", &vec![witness.clone(); MAX_STREAM_BACKERS]);
    Kels::parse(within.as_bytes()).expect("the bound itself parses");

    let past = inception_with("b", &vec![witness; MAX_STREAM_BACKERS + 1]);
    let Err(err) = Kels::parse(past.as_bytes()) else {
        panic!("a stream past the witness bound must be refused");
    };
    assert!(
        matches!(err, DidWebsError::Stream(ref m) if m.contains("witnesses")),
        "{err:?}"
    );
}

#[test]
fn a_stream_anchoring_too_many_seals_is_refused() {
    let seal = format!("{{\"s\":\"0\",\"d\":\"E{}\"}}", "A".repeat(43));
    let within = inception_with("a", &vec![seal.clone(); MAX_STREAM_SEALS]);
    Kels::parse(within.as_bytes()).expect("the bound itself parses");

    let past = inception_with("a", &vec![seal; MAX_STREAM_SEALS + 1]);
    let Err(err) = Kels::parse(past.as_bytes()) else {
        panic!("a stream past the seal bound must be refused");
    };
    assert!(
        matches!(err, DidWebsError::Stream(ref m) if m.contains("seals")),
        "{err:?}"
    );
}

#[test]
fn the_fixture_is_within_the_bounds() {
    let kels = Kels::parse(KERI_CESR).expect("parses");
    assert!(kels.messages().len() < MAX_STREAM_MESSAGES);
    kels.key_state(AID).expect("verifies");
}

#[test]
fn a_stream_with_too_many_messages_is_refused() {
    let (body, signature) = inception();
    let message = format!("{body}-AAB{signature}");
    let stream = message.repeat(MAX_STREAM_MESSAGES + 1);

    let Err(err) = Kels::parse(stream.as_bytes()) else {
        panic!("a stream past the message bound must be refused");
    };
    assert!(
        matches!(err, DidWebsError::Stream(ref m) if m.contains("messages")),
        "{err:?}"
    );

    let at_the_bound = message.repeat(MAX_STREAM_MESSAGES);
    let kels = Kels::parse(at_the_bound.as_bytes()).expect("the bound itself is accepted");
    assert_eq!(kels.messages().len(), MAX_STREAM_MESSAGES);
}

#[test]
fn a_stream_with_too_many_signatures_is_refused() {
    let (body, signature) = inception();
    // `-A__` is the largest count a two-character counter holds: 4095.
    let per_message = 4095;
    let message = format!("{body}-A__{}", signature.repeat(per_message));
    let messages = MAX_STREAM_SIGNATURES / per_message + 1;
    let stream = message.repeat(messages);

    let Err(err) = Kels::parse(stream.as_bytes()) else {
        panic!("a stream past the signature bound must be refused");
    };
    assert!(
        matches!(err, DidWebsError::Stream(ref m) if m.contains("signatures")),
        "{err:?}"
    );

    let within = message.repeat(MAX_STREAM_SIGNATURES / per_message);
    Kels::parse(within.as_bytes()).expect("under the bound parses");
}

#[test]
fn a_signature_group_must_name_an_establishment_event() {
    let kels = Kels::parse(KERI_CESR).expect("parses");
    let said_of = |ilk: &str| {
        kels.messages()
            .iter()
            .find(|m| m.serder.ilk().ok().as_deref() == Some(ilk))
            .and_then(|m| m.serder.said().ok())
            .expect("the fixture carries one")
    };

    let at_inception = kels.key_state_at(AID, AID).expect("the inception");
    assert_eq!(at_inception.sn, 0);
    assert_eq!(at_inception.prefix, AID);

    let err = kels
        .key_state_at(AID, &said_of("ixn"))
        .expect_err("an interaction event names no key state");
    assert!(
        matches!(err, DidWebsError::Kel(ref m) if m.contains("not an establishment event")),
        "{err:?}"
    );

    let err = kels
        .key_state_at(AID, &said_of("vcp"))
        .expect_err("not one of the AID's key events");
    assert!(
        matches!(err, DidWebsError::Kel(ref m) if m.contains("no event with SAID")),
        "{err:?}"
    );
}

#[test]
fn kels_can_move_between_threads() {
    fn is_send<T: Send>() {}
    is_send::<Kels>();
}

#[test]
fn each_establishment_event_answers_with_the_key_state_it_installed() {
    // An identifier created by this crate, rotated twice (see
    // `tests/deactivated.rs`).
    let stream: &[u8] = include_bytes!("fixtures/deactivated/keri.cesr");
    let did = include_str!("fixtures/deactivated/did.txt").trim();
    let aid = affinidi_did_webs::DidWebs::parse(did)
        .expect("parse")
        .aid()
        .to_string();
    let kels = Kels::parse(stream).expect("parses");
    let current = kels.key_state(&aid).expect("verifies");
    let establishment: Vec<(String, u64, Vec<String>)> = kels
        .messages()
        .iter()
        .filter(|m| m.serder.prefix().ok().as_deref() == Some(aid.as_str()))
        .filter(|m| matches!(m.serder.ilk().ok().as_deref(), Some("icp" | "rot")))
        .map(|m| {
            let keys = m
                .serder
                .sad()
                .get("k")
                .and_then(|k| k.as_array())
                .expect("a key list")
                .iter()
                .filter_map(|k| k.as_str().map(str::to_owned))
                .collect();
            let sn = m.serder.sn().expect("a sequence number");
            (m.serder.said().expect("a SAID"), sn, keys)
        })
        .collect();
    assert_eq!(establishment.len(), 3);

    for (said, sn, keys) in &establishment {
        let state = kels
            .key_state_at(&aid, said)
            .expect("an establishment event");
        assert_eq!(state.sn, *sn);
        assert_eq!(&state.keys, keys);
        assert!(state.backers.is_empty() && state.next_keys.is_empty());
    }
    assert_eq!(
        kels.key_state_at(&aid, &establishment[2].0)
            .expect("the last")
            .keys,
        current.keys
    );
}
