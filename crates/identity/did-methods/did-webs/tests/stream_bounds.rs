//! How much a `keri.cesr` stream may ask a resolver to do.
//!
//! A stream past `MAX_STREAM_MESSAGES` messages or `MAX_STREAM_SIGNATURES`
//! signatures is refused before anything in it is verified. Within those,
//! the key state at each establishment event is recorded once, while the log
//! is verified, and every signature group naming one is checked against that
//! record rather than a replay of the log.

use affinidi_did_webs::kel::{MAX_STREAM_MESSAGES, MAX_STREAM_SIGNATURES};
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

#[test]
fn the_fixture_is_within_both_bounds() {
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

#[cfg(feature = "create")]
#[test]
fn each_establishment_event_answers_with_the_key_state_it_installed() {
    use affinidi_did_webs::create::{CreateConfig, create};
    use affinidi_did_webs::update::{Change, UpdateConfig, update};
    use affinidi_keri::config::{InceptionConfig, RotationConfig};

    let salt = [5u8; 16];
    let created = create(
        CreateConfig::builder("example.com")
            .inception(InceptionConfig::builder().salt(salt.to_vec()).build())
            .build(),
    )
    .expect("create");
    let mut artifacts = created.artifacts().clone();
    let mut custody = created.custody().clone();
    for _ in 0..3 {
        let rotated = update(
            UpdateConfig {
                did: created.did().to_string(),
                prior: artifacts,
                custody,
                change: Change::Rotate(RotationConfig::default()),
            },
            &salt,
        )
        .expect("rotate");
        custody = rotated.custody().clone();
        artifacts = rotated.into_artifacts();
    }

    let aid = affinidi_did_webs::DidWebs::parse(created.did())
        .expect("parse")
        .aid()
        .to_string();
    let kels = Kels::parse(&artifacts.keri_cesr).expect("parses");
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
    assert_eq!(establishment.len(), 4);

    for (said, sn, keys) in &establishment {
        let state = kels
            .key_state_at(&aid, said)
            .expect("an establishment event");
        assert_eq!(state.sn, *sn);
        assert_eq!(&state.keys, keys);
    }
    assert_eq!(
        kels.key_state_at(&aid, &establishment[3].0)
            .expect("the last")
            .keys,
        current.keys
    );
}
