//! DIDComm v1 (Aries RFC 0019) forward ingress.
//!
//! An Aries client that routes through a mediator anoncrypts a
//! `routing/1.0/forward` **to the mediator's routing verkey**, wrapping an inner
//! envelope already sealed end-to-end to the final recipient. The mediator
//! opens only the outer layer: it learns where to deliver, never what was said.
//!
//! ```text
//! anoncrypt(to = mediator routing verkey)
//!   └── { "@type": ".../routing/1.0/forward",
//!         "to":  "<recipient base58 verkey>",
//!         "msg": { …inner envelope, opaque to us… } }
//! ```
//!
//! # Why the sender is anonymous
//!
//! By construction. RFC 0019 anon-packs a forward so the mediator cannot see
//! who sent it, so there is no authenticated sender to apply a sender-side ACL
//! to — the mediator applies the **recipient's** access list instead, exactly as
//! the TSP path does for a relayed message. That is a real difference from this
//! mediator's v2 posture, which is why accepting an unauthenticated v1 forward
//! is opt-in per deployment (`[didcomm_v1] allow_unauthenticated_forwards`).
//!
//! # Why the recipient is a verkey
//!
//! v1 has no DID anywhere in the envelope. The `to` is a bare Ed25519 verkey,
//! resolved to a local account through the store's routing-key index (see
//! [`MediatorStore::v1_routing_key_bind`]). Until the coordinate-mediation
//! protocol lands there is no client-facing way to create those bindings, so a
//! forward for an unbound verkey is refused as "not local".
//!
//! [`MediatorStore::v1_routing_key_bind`]: affinidi_messaging_mediator_common::store::MediatorStore::v1_routing_key_bind

use affinidi_messaging_didcomm_v1::envelope::{
    self, EnvelopeProtection, ProtectedHeader, RecipientKey,
};
use affinidi_messaging_didcomm_v1::identity::Verkey;
use affinidi_messaging_didcomm_v1::protocols::forward;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::{
    compat::UnpackMetadata,
    problem_report::{ProblemReportScope, ProblemReportSorter},
    sending::InboundMessageResponse,
};
use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use http::StatusCode;
use sha256::digest;
use tracing::{Instrument, Level, debug, span, warn};

use crate::SharedData;
use crate::common::authz::{self, Capability};
use crate::common::session::Session;
use crate::messages::store::store_message;
use crate::messages::{ProcessMessageResponse, WrapperType};

/// Whether `body` is a DIDComm **v1** envelope.
///
/// A v2 JWE and a v1 envelope share `protected` / `iv` / `ciphertext` / `tag`,
/// so shape alone cannot separate them. Two independent discriminators are used
/// together:
///
/// * a v2 JWE carries `recipients` at the **top level**, whereas v1 nests them
///   *inside* the protected header;
/// * v1's protected header declares `"typ": "JWM/1.0"`.
///
/// Requiring both means a malformed or unknown envelope falls through to the v2
/// path and gets v2's error, rather than being misreported as a broken v1
/// message.
pub(crate) fn is_didcomm_v1(body: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    if !envelope::is_envelope(&value) || value.get("recipients").is_some() {
        return false;
    }

    let Some(protected) = value.get("protected").and_then(|p| p.as_str()) else {
        return false;
    };
    // RFC 0019 requires decoders to accept padded and unpadded base64url.
    let Ok(decoded) = URL_SAFE_NO_PAD
        .decode(protected)
        .or_else(|_| URL_SAFE.decode(protected))
    else {
        return false;
    };
    serde_json::from_slice::<ProtectedHeader>(&decoded)
        .map(|header| header.typ == envelope::ENVELOPE_TYP)
        .unwrap_or(false)
}

/// What an inbound v1 message resulted in.
pub(crate) enum V1Outcome {
    /// A forward was routed and stored for its recipient. Answered with the
    /// mediator's usual JSON success envelope.
    Stored(InboundMessageResponse),
    /// A protocol request was answered. The packed v1 envelope must go back as
    /// the **raw HTTP body**: that is how Aries does synchronous
    /// request/response over a one-way transport, and Credo's
    /// `isValidJweStructure` accepts exactly this shape (`protected` / `iv` /
    /// `ciphertext` / `tag`) as an inbound message. Wrapping it in the JSON
    /// success envelope would hand the client a reply it cannot parse.
    Reply(String),
}

/// Handle an inbound DIDComm v1 message.
///
/// A **forward** is routed: the outer anoncrypt layer is opened with the
/// mediator's routing key, the `to` verkey resolved to a local account, that
/// account's ACLs applied, and the inner envelope stored verbatim for pickup.
/// The inner bytes are never parsed — they are sealed to the recipient.
///
/// A **coordinate-mediation or message-pickup request** is answered instead,
/// and the packed reply comes back as [`V1Outcome::Reply`].
pub(crate) async fn handle_inbound_didcomm_v1(
    state: &SharedData,
    session: &Session,
    raw: &str,
) -> Result<V1Outcome, MediatorError> {
    let _span = span!(Level::DEBUG, "handle_inbound_didcomm_v1");
    async move {
        if !state.config.didcomm_v1.enabled {
            return Err(v1_problem(
                session,
                37,
                "protocol.unsupported",
                "DIDComm v1 is not enabled on this mediator".to_string(),
                StatusCode::BAD_REQUEST,
            ));
        }

        let identity = state.didcomm_v1_identity().await?;
        let x25519_private = identity.identity.x25519_private();
        let keys = [RecipientKey {
            verkey: identity.verkey(),
            x25519_private: &x25519_private,
        }];

        // The outer layer is addressed to this mediator. A failure here is a
        // message we are not the recipient of, or one that is malformed —
        // either way we cannot route it.
        let opened = envelope::open(raw, &keys).map_err(|e| {
            v1_problem(
                session,
                37,
                "message.didcomm_v1.unpack",
                format!("couldn't open the DIDComm v1 envelope addressed to this mediator: {e}"),
                StatusCode::BAD_REQUEST,
            )
        })?;

        // The mediator is the outer recipient, so it is *its own* unpack: no
        // sender bindings are consulted and none are needed. An authcrypt outer
        // layer is accepted (some agents authcrypt forwards) but its sender is
        // deliberately not used for routing — RFC 0019 anon-packs forwards, so
        // treating a sometimes-present sender as authoritative would make
        // delivery depend on the sender's choice of packing.
        let message = affinidi_messaging_didcomm_v1::MessageV1::from_json(&opened.plaintext)
            .map_err(|e| {
                v1_problem(
                    session,
                    37,
                    "message.didcomm_v1.malformed",
                    format!("DIDComm v1 payload is not a valid message: {e}"),
                    StatusCode::BAD_REQUEST,
                )
            })?;

        // A mediation or pickup request is answered here rather than routed.
        // These are authcrypt'd, so opening the envelope proved which verkey
        // sent it — and that authenticated key, not anything the message
        // claims, is the identity the request is served for.
        if let Some(request) = crate::messages::v1_mediation::V1Request::classify(&message) {
            let EnvelopeProtection::Authcrypt { sender_verkey } = opened.protection else {
                return Err(v1_problem(
                    session,
                    37,
                    "message.didcomm_v1.anonymous_request",
                    "coordinate-mediation and message-pickup requests must be authcrypt'd: an \
                     anonymous request names no client to answer for"
                        .to_string(),
                    StatusCode::BAD_REQUEST,
                ));
            };

            let reply = crate::messages::v1_mediation::handle(
                state,
                session,
                request,
                &message,
                &sender_verkey,
            )
            .await?;

            let packed = pack_v1_reply(state, session, &reply, &sender_verkey).await?;
            return Ok(V1Outcome::Reply(packed));
        }

        if !forward::is_forward(&message) {
            return Err(v1_problem(
                session,
                37,
                "message.didcomm_v1.not_forward",
                format!(
                    "the mediator only accepts DIDComm v1 `routing/1.0/forward` messages, got `{}`",
                    message.typ
                ),
                StatusCode::BAD_REQUEST,
            ));
        }

        let to_verkey = forward::destination(&message).map_err(|e| {
            v1_problem(
                session,
                37,
                "message.didcomm_v1.destination",
                format!("forward has no usable `to` verkey: {e}"),
                StatusCode::BAD_REQUEST,
            )
        })?;
        let inner = forward::extract_payload(&message).map_err(|e| {
            v1_problem(
                session,
                37,
                "message.didcomm_v1.payload",
                format!("forward has no usable `msg` payload: {e}"),
                StatusCode::BAD_REQUEST,
            )
        })?;

        deliver_v1_forward(state, session, &to_verkey.to_base58(), &inner)
            .await
            .map(V1Outcome::Stored)
    }
    .instrument(_span)
    .await
}

/// Resolve `to_verkey` to a local account, apply its ACLs, and store `inner`.
async fn deliver_v1_forward(
    state: &SharedData,
    session: &Session,
    to_verkey: &str,
    inner: &str,
) -> Result<InboundMessageResponse, MediatorError> {
    let Some(to_did) = state.database.v1_routing_key_lookup(to_verkey).await? else {
        // Deliberately the same shape of answer as "no such account": a prober
        // learns only that this mediator will not route for that verkey.
        return Err(crate::messages::delivery_refused(
            session,
            None,
            "no local account is bound to that DIDComm v1 routing key",
        ));
    };

    let to_hash = digest(to_did.as_bytes());

    // The forward is anonymous by construction, so there is no sender to apply
    // an access list against — `None` makes the recipient's access-list check
    // evaluate on its mode alone, exactly as the TSP relay path does.
    let Some(recipient) = state.database.delivery_decision(&to_hash, None).await? else {
        warn!(
            %to_verkey,
            "v1 routing key resolves to a DID with no account record; treating as unknown"
        );
        return Err(crate::messages::delivery_refused(
            session,
            None,
            "no local account is bound to that DIDComm v1 routing key",
        ));
    };

    if authz::require_capability(&recipient.acls, Capability::ReceiveMessages).is_err() {
        return Err(crate::messages::delivery_refused(
            session,
            None,
            "recipient is not authorized to receive messages through this mediator",
        ));
    }

    if !recipient.access_list_allows {
        return Err(crate::messages::delivery_refused(
            session,
            None,
            "delivery blocked by the recipient's access list",
        ));
    }

    // Stored verbatim as the JSON text the recipient's v1 agent expects. A
    // pickup client tells it apart from a v2 envelope the same way this handler
    // did — see `is_didcomm_v1`.
    let data = ProcessMessageResponse {
        store_message: true,
        force_live_delivery: false,
        forward_message: false,
        data: WrapperType::Envelope(
            to_did.clone(),
            inner.to_string(),
            state.clock.unix_secs() + state.config.limits.message_expiry_seconds,
        ),
    };

    debug!(%to_verkey, %to_did, "DIDComm v1 forward stored for local recipient");
    store_message(state, session, &data, &UnpackMetadata::default()).await
}

/// Authcrypt a reply from the mediator's routing key back to the client.
///
/// Authcrypt rather than anoncrypt: the client has to know the answer really
/// came from its mediator. A `mediate-grant` an attacker could forge would let
/// them nominate their own routing keys and capture the client's inbound
/// traffic.
async fn pack_v1_reply(
    state: &SharedData,
    session: &Session,
    reply: &affinidi_messaging_didcomm_v1::MessageV1,
    recipient: &Verkey,
) -> Result<String, MediatorError> {
    let identity = state.didcomm_v1_identity().await?;
    affinidi_messaging_didcomm_v1::message::pack::pack_encrypted_authcrypt(
        reply,
        &identity.identity,
        &[*recipient],
    )
    .map_err(|e| {
        v1_problem(
            session,
            37,
            "message.didcomm_v1.pack",
            format!("couldn't pack the DIDComm v1 reply: {e}"),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    })
}

/// A v1-scoped problem report, mirroring the TSP path's `tsp_problem`.
fn v1_problem(
    session: &Session,
    code: u16,
    descriptor: &str,
    detail: String,
    status: StatusCode,
) -> MediatorError {
    MediatorError::problem(
        code,
        &session.session_id,
        None,
        ProblemReportSorter::Error,
        ProblemReportScope::Message,
        descriptor,
        "{1}",
        vec![detail],
        status,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_messaging_didcomm_v1::message::unpack::{NoBindings, UnpackResult, unpack};
    use affinidi_messaging_didcomm_v1::{
        PrivateIdentity, message::pack, protocols::basic_message::BasicMessage,
    };

    fn v1_forward_envelope() -> (String, PrivateIdentity, PrivateIdentity) {
        let mediator = PrivateIdentity::generate("did:example:mediator").unwrap();
        let bob = PrivateIdentity::generate("did:example:bob").unwrap();
        let msg = BasicMessage::new("hello").unwrap().finalize();
        let inner = pack::pack_encrypted_anoncrypt(&msg, &[bob.verkey]).unwrap();
        let outer = forward::wrap_in_forward(&bob.verkey, &inner, &mediator.verkey).unwrap();
        (outer, mediator, bob)
    }

    #[test]
    fn recognises_a_v1_envelope() {
        let (outer, _, _) = v1_forward_envelope();
        assert!(is_didcomm_v1(outer.as_bytes()));
    }

    /// A v2 JWE must not be mistaken for v1 — it has top-level `recipients` and
    /// a different `typ`, and misrouting it would give the caller a nonsense
    /// error from the wrong protocol handler.
    #[test]
    fn does_not_claim_a_v2_jwe() {
        let v2 = serde_json::json!({
            "protected": URL_SAFE_NO_PAD.encode(
                br#"{"typ":"application/didcomm-encrypted+json","alg":"ECDH-1PU+A256KW","enc":"A256CBC-HS512"}"#
            ),
            "recipients": [{ "header": { "kid": "did:example:bob#key-1" }, "encrypted_key": "x" }],
            "iv": "aXY",
            "ciphertext": "Y3Q",
            "tag": "dGFn",
        });
        assert!(!is_didcomm_v1(
            serde_json::to_string(&v2).unwrap().as_bytes()
        ));
    }

    #[test]
    fn does_not_claim_non_envelopes() {
        assert!(!is_didcomm_v1(b"not json"));
        assert!(!is_didcomm_v1(br#"{"@id":"1","@type":"t"}"#));
        // Envelope shape but an unknown `typ` — falls through to the v2 path.
        let odd = serde_json::json!({
            "protected": URL_SAFE_NO_PAD.encode(br#"{"typ":"JWM/9.9","alg":"Anoncrypt","enc":"x","recipients":[]}"#),
            "iv": "aXY",
            "ciphertext": "Y3Q",
            "tag": "dGFn",
        });
        assert!(!is_didcomm_v1(
            serde_json::to_string(&odd).unwrap().as_bytes()
        ));
    }

    /// The mediator must be able to open the outer layer and read the routing
    /// information, while the inner envelope stays sealed to the recipient.
    #[test]
    fn mediator_reads_routing_without_reading_the_payload() {
        let (outer, mediator, bob) = v1_forward_envelope();

        let x25519 = mediator.x25519_private();
        let keys = [RecipientKey {
            verkey: mediator.verkey,
            x25519_private: &x25519,
        }];
        let opened = envelope::open(&outer, &keys).expect("mediator opens the outer layer");

        let message =
            affinidi_messaging_didcomm_v1::MessageV1::from_json(&opened.plaintext).unwrap();
        assert!(forward::is_forward(&message));
        assert_eq!(forward::destination(&message).unwrap(), bob.verkey);

        // The inner is an envelope the mediator cannot open with its own key.
        let inner = forward::extract_payload(&message).unwrap();
        assert!(envelope::open(&inner, &keys).is_err());

        // ...but Bob can.
        let bob_x25519 = bob.x25519_private();
        let bob_keys = [RecipientKey {
            verkey: bob.verkey,
            x25519_private: &bob_x25519,
        }];
        let delivered = unpack(&inner, &[&bob], &NoBindings).expect("bob unpacks");
        assert!(matches!(delivered, UnpackResult::Anoncrypt { .. }));
        let _ = bob_keys;
    }

    /// The outer forward really is anonymous, so the mediator has no sender to
    /// route or authorise on — the reason recipient-side ACLs carry the weight.
    #[test]
    fn outer_forward_is_anonymous_to_the_mediator() {
        let (outer, mediator, _) = v1_forward_envelope();
        let result = unpack(&outer, &[&mediator], &NoBindings).expect("mediator unpacks");
        assert!(
            matches!(result, UnpackResult::Anoncrypt { .. }),
            "a v1 forward must not expose a sender to the mediator"
        );
        assert!(!result.is_authcrypt());
    }
}
