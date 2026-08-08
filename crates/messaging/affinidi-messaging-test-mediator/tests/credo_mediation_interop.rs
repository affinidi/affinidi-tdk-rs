//! Credo conformance for coordinate-mediation 1.0 and message-pickup 2.0.
//!
//! `tests/fixtures/credo_mediation.json` holds the request messages **Credo
//! itself builds**, via its real message classes, written by
//! `interop/didcomm-v1`. Replaying them proves the mediator answers what Credo
//! actually sends rather than what the RFC says it should — a distinction that
//! already cost one bug in this feature (Credo emits `routing/1.0/forward` with
//! the `https://didcomm.org` prefix that almost no specification example
//! shows).
//!
//! The fixtures carry all three of the v1 dual-form traps at once:
//!
//! * `@type` in the `https://didcomm.org` spelling, not `did:sov`;
//! * `recipient_key` as `did:key`, not base58;
//! * `~transport.return_route` present on some requests and **absent on
//!   `status-request`** — so a mediator that only replies when asked to would
//!   leave Credo waiting forever.
//!
//! The reverse direction — proving Credo *accepts* the mediator's replies — is
//! the `mediation.mjs` half of the harness, which parses each recorded reply
//! through `JsonTransformer.fromJSON` against the matching Credo class. Set
//! `DIDCOMM_V1_EMIT_REPLIES=1` to record them.

#![cfg(feature = "didcomm-v1")]

use affinidi_messaging_didcomm_v1::envelope::{self, EnvelopeProtection, RecipientKey};
use affinidi_messaging_didcomm_v1::identity::{PrivateIdentity, Verkey};
use affinidi_messaging_didcomm_v1::message::{MessageV1, pack};
use affinidi_messaging_didcomm_v1::protocols::{
    basic_message::BasicMessage, coordinate_mediation as cm, forward, message_pickup as mp,
};
use affinidi_messaging_test_mediator::{MediatorACLSet, TestMediator};
use serde_json::{Value, json};

const FIXTURES: &str = include_str!("fixtures/credo_mediation.json");

/// Look up one of Credo's generated requests by name.
fn credo_request(name: &str) -> MessageV1 {
    let fixtures: Value = serde_json::from_str(FIXTURES).expect("fixtures parse");
    let message = fixtures["requests"]
        .as_array()
        .expect("requests")
        .iter()
        .find(|r| r["name"] == name)
        .unwrap_or_else(|| panic!("fixture `{name}` is missing"))["message"]
        .clone();

    MessageV1::from_json(&serde_json::to_vec(&message).unwrap())
        .unwrap_or_else(|e| panic!("Credo's `{name}` must parse as a v1 message: {e}"))
}

/// The recipient key Credo's keylist fixtures register, in whatever spelling
/// the fixture used.
fn fixture_recipient_key() -> Verkey {
    let request = credo_request("keylist_update_add");
    let updates = cm::parse_keylist_update(&request).expect("keylist-update parses");
    updates[0].recipient_key
}

struct Client {
    identity: PrivateIdentity,
    mediator_verkey: Verkey,
    endpoint: String,
    http: reqwest::Client,
    recorded: Vec<(String, Value)>,
}

impl Client {
    async fn request(&mut self, name: &str, msg: &MessageV1) -> MessageV1 {
        let packed =
            pack::pack_encrypted_authcrypt(msg, &self.identity, &[self.mediator_verkey]).unwrap();

        let response = self
            .http
            .post(&self.endpoint)
            .body(packed)
            .send()
            .await
            .expect("POST /inbound");
        let status = response.status();
        let body = response.text().await.expect("body");
        assert!(
            status.is_success(),
            "mediator rejected Credo's `{name}`: {status} {body}"
        );

        let x25519 = self.identity.x25519_private();
        let keys = [RecipientKey {
            verkey: self.identity.verkey,
            x25519_private: &x25519,
        }];
        let opened = envelope::open(&body, &keys).unwrap_or_else(|e| {
            panic!("the reply to `{name}` must be a v1 envelope we can open: {e}")
        });
        assert_eq!(
            opened.protection,
            EnvelopeProtection::Authcrypt {
                sender_verkey: self.mediator_verkey
            },
            "replies must be authenticated as coming from the mediator"
        );

        let reply = MessageV1::from_json(&opened.plaintext).expect("reply is a v1 message");
        self.recorded.push((
            name.to_string(),
            serde_json::from_slice(&reply.to_json().unwrap()).unwrap(),
        ));
        reply
    }
}

/// Replay Credo's own requests through the mediator, in the order a wallet
/// sends them.
#[tokio::test]
async fn mediator_answers_credos_own_requests() {
    let mediator = TestMediator::builder()
        .didcomm_v1(true, true)
        .global_acl_default(MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap())
        .spawn()
        .await
        .expect("spawn mediator");

    let endpoint = format!("{}inbound", mediator.endpoint());
    let mediator_verkey = mediator.didcomm_v1_routing_verkey().unwrap();
    let http = reqwest::Client::new();

    let mut client = Client {
        identity: PrivateIdentity::generate("did:example:credo-wallet").unwrap(),
        mediator_verkey,
        endpoint: endpoint.clone(),
        http: http.clone(),
        recorded: Vec::new(),
    };

    // ── mediate-request ─────────────────────────────────────────────────
    let request = credo_request("mediate_request");
    // Credo sends the modern document URI; if the mediator only matched
    // `did:sov` this would already fail.
    assert!(
        request.typ.starts_with("https://didcomm.org/"),
        "the fixture must carry Credo's own type spelling"
    );
    let grant = client.request("mediate_request", &request).await;
    assert_eq!(
        cm::CoordinateMediation::classify(&grant),
        Some(cm::CoordinateMediation::MediateGrant)
    );
    assert_eq!(grant.explicit_thid(), Some(request.id.as_str()));

    // ── keylist-update (add), with a did:key recipient_key ──────────────
    let add = credo_request("keylist_update_add");
    let recipient = fixture_recipient_key();
    assert!(
        add.body["updates"][0]["recipient_key"]
            .as_str()
            .unwrap()
            .starts_with("did:key:"),
        "the fixture must carry Credo's did:key spelling"
    );
    let response = client.request("keylist_update_add", &add).await;
    assert_eq!(
        response.body["updated"][0]["result"], "success",
        "a did:key recipient_key from Credo must register"
    );

    // ── a message arrives for that key ──────────────────────────────────
    let sender = PrivateIdentity::generate("did:example:sender").unwrap();
    let payload = BasicMessage::new("from a Credo-shaped world")
        .unwrap()
        .finalize();
    let inner = pack::pack_encrypted_anoncrypt(&payload, &[recipient]).unwrap();
    let wrapped = forward::wrap_in_forward(&recipient, &inner, &mediator_verkey).unwrap();
    let _ = sender;

    let forwarded = http.post(&endpoint).body(wrapped).send().await.unwrap();
    assert!(
        forwarded.status().is_success(),
        "a forward to the key Credo registered must be accepted"
    );

    // ── status-request — note: Credo sends NO ~transport here ───────────
    let status_request = credo_request("status_request");
    assert!(
        !mp::wants_return_route(&status_request),
        "Credo's status-request carries no ~transport; the mediator must reply anyway, \
         or a real wallet waits forever"
    );
    let status = client.request("status_request", &status_request).await;
    assert_eq!(
        mp::MessagePickup::classify(&status),
        Some(mp::MessagePickup::Status)
    );
    assert_eq!(status.body["message_count"], 1);

    // ── delivery-request ────────────────────────────────────────────────
    let delivery = client
        .request("delivery_request", &credo_request("delivery_request"))
        .await;
    assert_eq!(
        mp::MessagePickup::classify(&delivery),
        Some(mp::MessagePickup::Delivery)
    );
    let delivered = mp::parse_delivery(&delivery).expect("delivery parses");
    assert_eq!(delivered.len(), 1);

    // ── messages-received, with the id we were actually given ───────────
    let mut ack = credo_request("messages_received");
    ack.body
        .insert("message_id_list".into(), json!([delivered[0].id.clone()]));
    let status = client.request("messages_received", &ack).await;
    assert_eq!(
        mp::MessagePickup::classify(&status),
        Some(mp::MessagePickup::Status)
    );
    assert_eq!(
        status.body["message_count"], 0,
        "acknowledged messages must be dropped"
    );

    // ── keylist-update (remove) ─────────────────────────────────────────
    let response = client
        .request(
            "keylist_update_remove",
            &credo_request("keylist_update_remove"),
        )
        .await;
    assert_eq!(
        response.body["updated"][0]["result"], "success",
        "a did:key recipient_key must be removable"
    );

    emit_replies_for_credo(&client.recorded);
}

/// Record the mediator's replies for `interop/didcomm-v1/mediation.mjs`, which
/// validates each against its Credo class.
///
/// Off unless `DIDCOMM_V1_EMIT_REPLIES=1`: a CI run should assert, not write
/// files into the source tree.
fn emit_replies_for_credo(recorded: &[(String, Value)]) {
    if std::env::var("DIDCOMM_V1_EMIT_REPLIES").as_deref() != Ok("1") {
        return;
    }

    let replies: Vec<Value> = recorded
        .iter()
        .map(|(name, reply)| json!({ "name": name, "reply": reply }))
        .collect();

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../interop/didcomm-v1/rust-mediation-replies.json"
    );
    std::fs::write(
        path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&json!({ "replies": replies })).unwrap()
        ),
    )
    .expect("interop/didcomm-v1 exists");
    println!("wrote {} replies to {path}", replies.len());
}

/// Every reply the mediator generates must carry an `@id` Credo will accept.
///
/// Credo validates `@id` against `/[-_./a-zA-Z0-9]{8,64}/` on receipt, so an id
/// shorter than 8 characters is rejected before the message is looked at. Our
/// ids are UUIDs, but the `~thread.thid` echoes the *client's* id — this pins
/// that we do not generate anything shorter ourselves.
#[test]
fn generated_ids_satisfy_credos_length_rule() {
    let messages = [
        cm::mediate_request().unwrap(),
        cm::mediate_grant(
            "0123456789abcdef",
            "https://mediator.example/inbound",
            &[Verkey::from_bytes([1u8; 32])],
            cm::KeyFormat::Base58,
        )
        .unwrap(),
        cm::mediate_deny("0123456789abcdef").unwrap(),
        mp::status("0123456789abcdef", 0, None, false).unwrap(),
    ];

    for msg in messages {
        assert!(
            (8..=64).contains(&msg.id.len()),
            "`{}` generated an @id of {} chars; Credo requires 8..=64",
            msg.typ,
            msg.id.len()
        );
        assert!(
            msg.id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c)),
            "`{}` generated an @id with characters Credo's pattern rejects: {}",
            msg.typ,
            msg.id
        );
    }
}
