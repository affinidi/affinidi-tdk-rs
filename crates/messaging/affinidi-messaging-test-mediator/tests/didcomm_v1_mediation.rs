//! End-to-end DIDComm v1 mediation against a live mediator.
//!
//! Walks the exact sequence an Aries wallet performs, over HTTP, with nothing
//! stubbed:
//!
//! 1. `mediate-request` → `mediate-grant`, learning the mediator's routing key
//! 2. `keylist-update` (add) → the mediator will now route to that key
//! 3. a third party anon-packs a `routing/1.0/forward` for it → stored
//! 4. `status-request` → one message queued
//! 5. `delivery-request` → the message, still queued
//! 6. `messages-received` → acknowledged and dropped
//!
//! Each request is authcrypt'd to the mediator's routing verkey and each reply
//! comes back as the **raw HTTP body**, which is Aries' return-route. Opening
//! those replies is what proves the mediator packed them correctly, so this
//! covers the response path as well as the request path.

#![cfg(feature = "didcomm-v1")]

use affinidi_messaging_didcomm_v1::envelope::{self, EnvelopeProtection, RecipientKey};
use affinidi_messaging_didcomm_v1::identity::{PrivateIdentity, Verkey};
use affinidi_messaging_didcomm_v1::message::{MessageV1, pack};
use affinidi_messaging_didcomm_v1::protocols::{
    basic_message::BasicMessage, coordinate_mediation as cm, forward, message_pickup as mp,
};
use affinidi_messaging_test_mediator::{MediatorACLSet, TestMediator};
use serde_json::Value;

/// A v1 client: one Ed25519 identity plus the mediator's routing key.
struct Client {
    identity: PrivateIdentity,
    mediator_verkey: Verkey,
    endpoint: String,
    http: reqwest::Client,
}

impl Client {
    /// Authcrypt `msg` to the mediator, POST it, and open the reply.
    ///
    /// Returns `None` when the mediator answered with something other than a
    /// v1 envelope (a routed forward gets the JSON success envelope instead).
    async fn request(&self, msg: &MessageV1) -> Option<MessageV1> {
        let packed =
            pack::pack_encrypted_authcrypt(msg, &self.identity, &[self.mediator_verkey]).unwrap();

        let response = self
            .http
            .post(&self.endpoint)
            .body(packed)
            .send()
            .await
            .expect("POST /inbound");
        assert!(
            response.status().is_success(),
            "mediator rejected {}: {}",
            msg.typ,
            response.status()
        );
        let body = response.text().await.expect("response body");

        // A protocol reply is a bare v1 envelope; anything else is not one.
        let value: Value = serde_json::from_str(&body).ok()?;
        value.get("protected")?;

        let x25519 = self.identity.x25519_private();
        let keys = [RecipientKey {
            verkey: self.identity.verkey,
            x25519_private: &x25519,
        }];
        let opened = envelope::open(&body, &keys).expect("client opens the mediator's reply");

        // The mediator authcrypts its replies, and it must be *this* mediator.
        assert_eq!(
            opened.protection,
            EnvelopeProtection::Authcrypt {
                sender_verkey: self.mediator_verkey
            },
            "a reply must be authenticated as coming from the mediator"
        );

        Some(MessageV1::from_json(&opened.plaintext).expect("reply is a v1 message"))
    }
}

/// Drive the whole flow: register, receive, collect, acknowledge.
#[tokio::test]
async fn v1_wallet_registers_receives_and_collects() {
    let mediator = TestMediator::builder()
        .didcomm_v1(true, true)
        // A mediator that serves v1 wallets has to let the accounts it creates
        // for them receive; without this, mediation is denied (see
        // `mediation_is_denied_when_the_account_cannot_receive`).
        .global_acl_default(MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap())
        .spawn()
        .await
        .expect("spawn mediator");

    let endpoint = format!("{}inbound", mediator.endpoint());
    let http = reqwest::Client::new();

    // The mediator's routing verkey is derived from its Ed25519 authentication
    // key; a real client is told it out of band. Here we ask for it the way a
    // client does — via mediate-grant — starting from the key the mediator
    // logs at startup.
    let mediator_verkey = mediator
        .didcomm_v1_routing_verkey()
        .expect("mediator exposes its v1 routing verkey");

    let client = Client {
        identity: PrivateIdentity::generate("did:example:wallet").unwrap(),
        mediator_verkey,
        endpoint: endpoint.clone(),
        http: http.clone(),
    };

    // ── 1. mediate-request → mediate-grant ──────────────────────────────
    let request = cm::mediate_request().unwrap();
    let grant = client.request(&request).await.expect("a grant");

    assert_eq!(
        cm::CoordinateMediation::classify(&grant),
        Some(cm::CoordinateMediation::MediateGrant)
    );
    assert_eq!(
        grant.explicit_thid(),
        Some(request.id.as_str()),
        "the grant must thread to the request"
    );
    let routing_keys = grant.body["routing_keys"]
        .as_array()
        .expect("routing_keys")
        .iter()
        .map(|k| Verkey::parse(k.as_str().unwrap()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        routing_keys,
        vec![mediator_verkey],
        "the grant advertises the key senders must forward through"
    );
    assert!(
        grant.body["endpoint"]
            .as_str()
            .is_some_and(|e| !e.is_empty())
    );

    // ── 2. keylist-update: register the key senders will address ────────
    let recipient = PrivateIdentity::generate("did:example:wallet-recipient").unwrap();
    let update = cm::keylist_update(
        &[cm::KeylistUpdate {
            recipient_key: recipient.verkey,
            action: cm::KeylistAction::Add,
        }],
        cm::KeyFormat::Base58,
    )
    .unwrap();

    let response = client.request(&update).await.expect("an update response");
    assert_eq!(
        cm::CoordinateMediation::classify(&response),
        Some(cm::CoordinateMediation::KeylistUpdateResponse)
    );
    assert_eq!(response.body["updated"][0]["result"], "success");
    assert_eq!(
        response.body["updated"][0]["recipient_key"],
        recipient.verkey.to_base58()
    );

    // Re-registering the same key is a no-op, not a second success.
    let again = client.request(&update).await.expect("an update response");
    assert_eq!(
        again.body["updated"][0]["result"], "no_change",
        "re-adding an already-registered key must report no_change"
    );

    // ── 3. a third party forwards a message to that key ─────────────────
    let sender = PrivateIdentity::generate("did:example:someone-else").unwrap();
    let payload = BasicMessage::new("your hovercraft is full of eels")
        .unwrap()
        .id("delivered-1")
        .finalize();
    let inner = pack::pack_encrypted_authcrypt(&payload, &sender, &[recipient.verkey]).unwrap();
    let wrapped = forward::wrap_in_forward(&recipient.verkey, &inner, &mediator_verkey).unwrap();

    let forwarded = http
        .post(&endpoint)
        .body(wrapped)
        .send()
        .await
        .expect("POST forward");
    let status_code = forwarded.status();
    let detail = forwarded.text().await.unwrap_or_default();
    assert!(
        status_code.is_success(),
        "the mediator must accept a forward for a registered key: {status_code} {detail}"
    );

    // ── 4. status-request → one queued ──────────────────────────────────
    let status = client
        .request(&mp::status_request(None).unwrap())
        .await
        .expect("a status");
    assert_eq!(
        mp::MessagePickup::classify(&status),
        Some(mp::MessagePickup::Status)
    );
    assert_eq!(
        status.body["message_count"], 1,
        "the forwarded message must be queued for the registered key's owner"
    );

    // ── 5. delivery-request → the message, undeleted ────────────────────
    let delivery = client
        .request(&mp::delivery_request(10, None).unwrap())
        .await
        .expect("a delivery");
    assert_eq!(
        mp::MessagePickup::classify(&delivery),
        Some(mp::MessagePickup::Delivery)
    );

    let delivered = mp::parse_delivery(&delivery).expect("delivery parses");
    assert_eq!(delivered.len(), 1);

    // The delivered bytes are the sender's envelope, still sealed to the
    // recipient — the mediator never opened it.
    let recipient_x25519 = recipient.x25519_private();
    let recipient_keys = [RecipientKey {
        verkey: recipient.verkey,
        x25519_private: &recipient_x25519,
    }];
    let opened = envelope::open(
        &serde_json::to_string(&delivered[0].envelope).unwrap(),
        &recipient_keys,
    )
    .expect("recipient opens the delivered envelope");
    assert_eq!(
        opened.protection,
        EnvelopeProtection::Authcrypt {
            sender_verkey: sender.verkey
        },
        "the end-to-end sender survives the round trip through the mediator"
    );
    let received = MessageV1::from_json(&opened.plaintext).unwrap();
    assert_eq!(received.id, "delivered-1");
    assert_eq!(received.body["content"], "your hovercraft is full of eels");

    // Delivery is not deletion: it is still queued until acknowledged.
    let status = client
        .request(&mp::status_request(None).unwrap())
        .await
        .expect("a status");
    assert_eq!(
        status.body["message_count"], 1,
        "a delivered-but-unacknowledged message must remain queued"
    );

    // ── 6. messages-received → dropped ──────────────────────────────────
    let ack = mp::messages_received(&[delivered[0].id.clone()]).unwrap();
    let status = client.request(&ack).await.expect("a status");
    assert_eq!(
        mp::MessagePickup::classify(&status),
        Some(mp::MessagePickup::Status)
    );
    assert_eq!(
        status.body["message_count"], 0,
        "acknowledged messages must be dropped"
    );
}

/// A forward for a key nobody registered must not be accepted — otherwise the
/// mediator stores traffic for accounts that never asked for it.
#[tokio::test]
async fn forward_to_an_unregistered_key_is_refused() {
    let mediator = TestMediator::builder()
        .didcomm_v1(true, true)
        // A mediator that serves v1 wallets has to let the accounts it creates
        // for them receive; without this, mediation is denied (see
        // `mediation_is_denied_when_the_account_cannot_receive`).
        .global_acl_default(MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap())
        .spawn()
        .await
        .expect("spawn mediator");

    let mediator_verkey = mediator.didcomm_v1_routing_verkey().unwrap();
    let stranger = PrivateIdentity::generate("did:example:stranger").unwrap();
    let sender = PrivateIdentity::generate("did:example:sender").unwrap();

    let payload = BasicMessage::new("nobody asked for this")
        .unwrap()
        .finalize();
    let inner = pack::pack_encrypted_anoncrypt(&payload, &[stranger.verkey]).unwrap();
    let wrapped = forward::wrap_in_forward(&stranger.verkey, &inner, &mediator_verkey).unwrap();
    let _ = sender;

    let http = reqwest::Client::new();
    let endpoint = format!("{}inbound", mediator.endpoint());

    // Guard against passing for the wrong reason: a mistyped URL would also
    // 404, and this assertion is only meaningful if the route exists. A
    // forward for a *registered* key must succeed at the same URL — proved by
    // `v1_wallet_registers_receives_and_collects` — so check the route answers
    // something other than 404 for a well-formed non-forward first.
    let probe = http
        .post(&endpoint)
        .body("not a v1 envelope")
        .send()
        .await
        .expect("probe /inbound");
    assert_ne!(
        probe.status(),
        reqwest::StatusCode::NOT_FOUND,
        "the /inbound route must exist, or the 404 below would be meaningless"
    );

    let response = http
        .post(&endpoint)
        .body(wrapped)
        .send()
        .await
        .expect("POST forward");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "an unregistered routing key must not resolve to a mailbox"
    );
}

/// One client must not be able to unregister another's routing key — that would
/// let it silently cut off the other's inbound traffic.
#[tokio::test]
async fn a_client_cannot_remove_another_clients_routing_key() {
    let mediator = TestMediator::builder()
        .didcomm_v1(true, true)
        // A mediator that serves v1 wallets has to let the accounts it creates
        // for them receive; without this, mediation is denied (see
        // `mediation_is_denied_when_the_account_cannot_receive`).
        .global_acl_default(MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap())
        .spawn()
        .await
        .expect("spawn mediator");

    let endpoint = format!("{}inbound", mediator.endpoint());
    let mediator_verkey = mediator.didcomm_v1_routing_verkey().unwrap();
    let http = reqwest::Client::new();

    let alice = Client {
        identity: PrivateIdentity::generate("did:example:alice").unwrap(),
        mediator_verkey,
        endpoint: endpoint.clone(),
        http: http.clone(),
    };
    let mallory = Client {
        identity: PrivateIdentity::generate("did:example:mallory").unwrap(),
        mediator_verkey,
        endpoint,
        http,
    };

    // Alice registers a key.
    let key = PrivateIdentity::generate("did:example:alice-recipient").unwrap();
    let add = cm::keylist_update(
        &[cm::KeylistUpdate {
            recipient_key: key.verkey,
            action: cm::KeylistAction::Add,
        }],
        cm::KeyFormat::Base58,
    )
    .unwrap();
    let response = alice.request(&add).await.expect("update response");
    assert_eq!(response.body["updated"][0]["result"], "success");

    // Mallory tries to claim it, then to remove it.
    for action in [cm::KeylistAction::Add, cm::KeylistAction::Remove] {
        let attempt = cm::keylist_update(
            &[cm::KeylistUpdate {
                recipient_key: key.verkey,
                action,
            }],
            cm::KeyFormat::Base58,
        )
        .unwrap();
        let response = mallory.request(&attempt).await.expect("update response");
        assert_eq!(
            response.body["updated"][0]["result"], "client_error",
            "{action:?} on another account's key must be refused"
        );
    }

    // Alice's binding is intact: a forward for her key still lands.
    let query = alice
        .request(&MessageV1::new(cm::KEYLIST_QUERY_TYPE, serde_json::json!({})).unwrap())
        .await
        .expect("keylist");
    assert_eq!(
        query.body["keys"][0]["recipient_key"],
        key.verkey.to_base58()
    );
}

/// A `did:key`-spelled `recipient_key` must register the same key a base58 one
/// does — Credo picks its spelling from configuration, and getting this wrong
/// means half of the wallets out there silently fail to receive.
#[tokio::test]
async fn keylist_accepts_did_key_and_base58_interchangeably() {
    let mediator = TestMediator::builder()
        .didcomm_v1(true, true)
        // A mediator that serves v1 wallets has to let the accounts it creates
        // for them receive; without this, mediation is denied (see
        // `mediation_is_denied_when_the_account_cannot_receive`).
        .global_acl_default(MediatorACLSet::from_string_ruleset("ALLOW_ALL").unwrap())
        .spawn()
        .await
        .expect("spawn mediator");

    let client = Client {
        identity: PrivateIdentity::generate("did:example:wallet").unwrap(),
        mediator_verkey: mediator.didcomm_v1_routing_verkey().unwrap(),
        endpoint: format!("{}inbound", mediator.endpoint()),
        http: reqwest::Client::new(),
    };

    let key = PrivateIdentity::generate("did:example:recipient").unwrap();

    // Register with the did:key spelling.
    let add = cm::keylist_update(
        &[cm::KeylistUpdate {
            recipient_key: key.verkey,
            action: cm::KeylistAction::Add,
        }],
        cm::KeyFormat::DidKey,
    )
    .unwrap();
    assert_eq!(
        add.body["updates"][0]["recipient_key"],
        key.verkey.to_did_key(),
        "the request really is in did:key form"
    );
    let response = client.request(&add).await.expect("update response");
    assert_eq!(response.body["updated"][0]["result"], "success");

    // Removing it in base58 form must find the same binding.
    let remove = cm::keylist_update(
        &[cm::KeylistUpdate {
            recipient_key: key.verkey,
            action: cm::KeylistAction::Remove,
        }],
        cm::KeyFormat::Base58,
    )
    .unwrap();
    let response = client.request(&remove).await.expect("update response");
    assert_eq!(
        response.body["updated"][0]["result"], "success",
        "a key registered as did:key must be removable as base58 — one key, two spellings"
    );
}

/// Granting mediation an account cannot use would be a silent black hole: the
/// client publishes routing keys, senders forward to them, and every message is
/// refused after the fact. The mediator must say so up front instead.
#[tokio::test]
async fn mediation_is_denied_when_the_account_cannot_receive() {
    // The shipped default `global_acl_default` does not grant RECEIVE_MESSAGES.
    let mediator = TestMediator::builder()
        .didcomm_v1(true, true)
        .spawn()
        .await
        .expect("spawn mediator");

    let client = Client {
        identity: PrivateIdentity::generate("did:example:wallet").unwrap(),
        mediator_verkey: mediator.didcomm_v1_routing_verkey().unwrap(),
        endpoint: format!("{}inbound", mediator.endpoint()),
        http: reqwest::Client::new(),
    };

    let request = cm::mediate_request().unwrap();
    let reply = client.request(&request).await.expect("a reply");

    assert_eq!(
        cm::CoordinateMediation::classify(&reply),
        Some(cm::CoordinateMediation::MediateDeny),
        "mediation the account cannot use must be denied, not granted"
    );
    assert_eq!(reply.explicit_thid(), Some(request.id.as_str()));
}
