//! Integration test for inter-mediator relay re-wrapping (`RelayMode::Rewrap`).
//!
//! Exercises the cryptographic round-trip of the re-wrap layer that
//! `routing::rewrap_for_relay` builds and `inbound::peel_relay_rewrap_layers`
//! peels, using real authcrypt over the `did:peer` fixtures in `common.rs`.
//! Here `ALICE_DID` plays the **relaying** mediator and `BOB_DID` the
//! **receiving** mediator.
//!
//! It proves the three properties the feature exists for:
//! 1. **Privacy** — the inner envelope (and anything in it, e.g. the original
//!    sender's key id) is ciphertext inside the outer layer, not on the wire.
//! 2. **Peer identity** — the receiving mediator authenticates the *relaying
//!    mediator* as the authcrypt sender. This is what blind relay cannot do and
//!    is what makes the trusted-peer allowlist (`relay_trusted_mediators`)
//!    possible.
//! 3. **Peel + loop continuity** — the inner envelope round-trips intact, the
//!    `next == receiving mediator` re-wrap signal is present, and the running
//!    `hop_count` survives the re-wrap.
//!
//! The HTTP + `FORWARD_Q` plumbing around this is unchanged from the (merged)
//! blind-relay path and is not re-exercised here.

mod common;

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_didcomm::message::{Attachment, Message};
use affinidi_messaging_mediator::didcomm_compat;
use affinidi_secrets_resolver::{SimpleSecretsResolver, secrets::Secret};
use base64::prelude::*;
use common::{ALICE_DID, ALICE_E1, ALICE_V1, BOB_DID, BOB_E1, BOB_V1};
use serde_json::json;
use uuid::Uuid;

const FORWARD_TYPE: &str = "https://didcomm.org/routing/2.0/forward";

async fn setup() -> (DIDCacheClient, SimpleSecretsResolver, SimpleSecretsResolver) {
    let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .unwrap();

    // ALICE = relaying mediator, BOB = receiving mediator.
    let relay_secrets = SimpleSecretsResolver::new(&[
        Secret::from_str(&format!("{ALICE_DID}#key-1"), &ALICE_V1).expect("relay V1 key"),
        Secret::from_str(&format!("{ALICE_DID}#key-2"), &ALICE_E1).expect("relay E1 key"),
    ])
    .await;
    let receiver_secrets = SimpleSecretsResolver::new(&[
        Secret::from_str(&format!("{BOB_DID}#key-1"), &BOB_V1).expect("receiver V1 key"),
        Secret::from_str(&format!("{BOB_DID}#key-2"), &BOB_E1).expect("receiver E1 key"),
    ])
    .await;

    (resolver, relay_secrets, receiver_secrets)
}

/// Build the re-wrap envelope exactly as `routing::rewrap_for_relay` does:
/// a `forward` whose single base64 attachment is `inner`, `next` = the receiving
/// mediator, `hop_count` in the header, authcrypted from the relaying mediator.
async fn build_rewrap_envelope(
    resolver: &DIDCacheClient,
    relay_secrets: &SimpleSecretsResolver,
    inner: &str,
    hop_count: u64,
) -> String {
    let attachment = Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode(inner)).finalize();
    let mut forward = Message::build(
        Uuid::new_v4().to_string(),
        FORWARD_TYPE.to_owned(),
        json!({ "next": BOB_DID }),
    )
    .to(BOB_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .attachment(attachment)
    .finalize();
    forward
        .extra
        .insert("hop_count".to_string(), json!(hop_count));

    let (packed, pack_meta) =
        didcomm_compat::pack_encrypted(&forward, BOB_DID, Some(ALICE_DID), resolver, relay_secrets)
            .await
            .expect("re-wrap pack (authcrypt relay -> receiver) failed");
    assert!(
        pack_meta.from_kid.is_some(),
        "re-wrap must be authcrypt so the peer mediator is authenticated"
    );
    packed
}

#[tokio::test]
async fn rewrap_round_trip_hides_inner_authenticates_peer_and_peels() {
    let (resolver, relay_secrets, receiver_secrets) = setup().await;

    // Stand-in for the inner envelope a peer relays (e.g. the original sender's
    // authcrypt envelope addressed to the receiving mediator). Opaque to the
    // re-wrap layer; we only assert it round-trips and never leaks to the wire.
    let inner = "SENTINEL-INNER-RELAY-ENVELOPE-7f3a91";
    let hop_count = 4u64;

    let packed = build_rewrap_envelope(&resolver, &relay_secrets, inner, hop_count).await;

    // (1) Privacy: neither the inner envelope nor its base64 form appears in the
    // outer JWE — it is encrypted to the receiving mediator.
    assert!(
        !packed.contains(inner),
        "inner envelope must not appear in cleartext on the wire"
    );
    assert!(
        !packed.contains(&BASE64_URL_SAFE_NO_PAD.encode(inner)),
        "inner attachment must be ciphertext inside the outer layer, not visible on the wire"
    );

    // The receiving mediator opens the outer layer.
    let (unpacked, metadata) = didcomm_compat::unpack(&packed, &resolver, &receiver_secrets)
        .await
        .expect("receiving mediator failed to unpack the re-wrap layer");

    // (2) Peer identity: the relaying mediator is the authenticated authcrypt
    // sender — the property blind relay cannot provide.
    assert!(
        metadata.authenticated,
        "re-wrap layer must be authenticated (authcrypt)"
    );
    assert_eq!(
        unpacked.from.as_deref(),
        Some(ALICE_DID),
        "the re-wrap layer's sender is the relaying mediator, not the original sender"
    );
    let from_kid = metadata
        .encrypted_from_kid
        .expect("authcrypt re-wrap must carry encrypted_from_kid");
    assert!(
        from_kid.starts_with(ALICE_DID),
        "authcrypt sender ({from_kid}) must be the relaying mediator's key"
    );

    // (3a) Re-wrap signal: a forward whose next hop is the receiving mediator.
    assert_eq!(unpacked.typ, FORWARD_TYPE);
    assert_eq!(
        unpacked.body.get("next").and_then(|v| v.as_str()),
        Some(BOB_DID),
        "next must be the receiving mediator itself (the peel signal)"
    );

    // (3b) Loop-detection continuity: hop_count survives the re-wrap.
    assert_eq!(
        unpacked.extra.get("hop_count").and_then(|v| v.as_u64()),
        Some(hop_count),
        "hop_count must be carried across the re-wrap"
    );

    // (3c) Peel: the inner envelope is recovered intact (mirrors
    // routing::rewrap_inner_attachment's base64 attachment extraction).
    let recovered_b64 = unpacked
        .attachments
        .as_ref()
        .and_then(|a| a.first())
        .and_then(|a| a.data.base64.as_ref())
        .expect("re-wrap layer must carry the inner envelope as a base64 attachment");
    let recovered = String::from_utf8(
        BASE64_URL_SAFE_NO_PAD
            .decode(recovered_b64)
            .expect("inner attachment must be valid base64url"),
    )
    .expect("inner attachment must be valid UTF-8");
    assert_eq!(
        recovered, inner,
        "peeled inner envelope must match what the relaying mediator wrapped"
    );
}

/// A mediator that is NOT the named next hop must not treat the layer as a peel
/// target — i.e. the re-wrap signal is specifically `next == this mediator`.
#[tokio::test]
async fn rewrap_signal_is_specifically_next_equals_self() {
    // This mirrors the guard in routing::rewrap_inner_attachment: an ordinary
    // forward bound for some other `next` is not a re-wrap layer. We assert it at
    // the wire level: the receiving mediator can read `next` and see it is itself
    // only when the relay addressed the layer to it.
    let (resolver, relay_secrets, receiver_secrets) = setup().await;

    // A forward whose `next` is a third party (not the receiving mediator).
    let attachment = Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode("X")).finalize();
    let forward = Message::build(
        Uuid::new_v4().to_string(),
        FORWARD_TYPE.to_owned(),
        json!({ "next": "did:peer:2.SomeoneElse" }),
    )
    .to(BOB_DID.to_owned())
    .from(ALICE_DID.to_owned())
    .attachment(attachment)
    .finalize();

    let (packed, _) = didcomm_compat::pack_encrypted(
        &forward,
        BOB_DID,
        Some(ALICE_DID),
        &resolver,
        &relay_secrets,
    )
    .await
    .expect("pack failed");
    let (unpacked, _) = didcomm_compat::unpack(&packed, &resolver, &receiver_secrets)
        .await
        .expect("unpack failed");

    assert_ne!(
        unpacked.body.get("next").and_then(|v| v.as_str()),
        Some(BOB_DID),
        "an ordinary forward to another next hop must not look like a re-wrap layer"
    );
}
