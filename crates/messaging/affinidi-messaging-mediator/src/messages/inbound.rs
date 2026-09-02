#[cfg(feature = "didcomm")]
use crate::didcomm_compat::MetaEnvelope;
#[cfg(feature = "didcomm")]
use crate::messages::MessageHandler;
#[cfg(feature = "didcomm")]
use crate::messages::protocols::routing::{relay_peer_trusted, rewrap_inner_attachment};
use crate::{SharedData, common::session::Session};
// Shared by both the DIDComm direct-delivery path and the TSP delivery path.
#[cfg(feature = "didcomm")]
use crate::common::authz::Capability;
#[cfg(any(feature = "didcomm", feature = "tsp"))]
use crate::{common::authz, messages::store::store_message};
use affinidi_messaging_mediator_common::errors::MediatorError;
#[cfg(feature = "didcomm")]
use affinidi_messaging_mediator_common::tasks::forwarding::RelayMode;
#[cfg(any(feature = "didcomm", feature = "tsp"))]
use affinidi_messaging_sdk::messages::compat::UnpackMetadata;
use affinidi_messaging_sdk::messages::{
    problem_report::{ProblemReportScope, ProblemReportSorter},
    sending::InboundMessageResponse,
};
#[cfg(feature = "tsp")]
use affinidi_tsp::MetaEnvelope as TspMetaEnvelope;
#[cfg(feature = "tsp")]
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use http::StatusCode;
#[cfg(any(feature = "didcomm", feature = "tsp"))]
use sha256::digest;
#[cfg(feature = "didcomm")]
use tracing::{Instrument, debug, span, warn};

#[cfg(any(feature = "didcomm", feature = "tsp"))]
use super::{ProcessMessageResponse, WrapperType};

/// Reject a message larger than `limits.message_size`.
///
/// Every ingress path (HTTP `POST /inbound`, WebSocket text, WebSocket binary /
/// TSP) funnels through `handle_inbound` or `handle_inbound_tsp`, so this is the
/// one place the ceiling has to hold.
///
/// The transport caps (`http_size`, `ws_size`) are deliberately *larger* than
/// this — they bound a single request or frame, whereas this bounds the message
/// the mediator will copy, queue, store, and fan out. Every in-memory buffer is
/// sized against this value, so it has to be enforced for those bounds to mean
/// anything.
fn check_message_size(
    state: &SharedData,
    session: &Session,
    len: usize,
) -> Result<(), MediatorError> {
    let limit = state.config.limits.message_size;
    if len > limit {
        return Err(MediatorError::problem(
            37,
            &session.session_id,
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Message,
            "message.size.exceeded",
            "Message size {1} exceeds the mediator limit of {2} bytes",
            vec![len.to_string(), limit.to_string()],
            StatusCode::PAYLOAD_TOO_LARGE,
        ));
    }
    Ok(())
}

pub(crate) async fn handle_inbound(
    #[cfg_attr(not(feature = "didcomm"), allow(unused_variables))] state: &SharedData,
    session: &Session,
    #[cfg_attr(not(feature = "didcomm"), allow(unused_variables))] message: &str,
) -> Result<InboundMessageResponse, MediatorError> {
    check_message_size(state, session, message.len())?;

    // Try DIDComm first if enabled
    #[cfg(feature = "didcomm")]
    {
        return handle_inbound_didcomm(state, session, message).await;
    }

    // If only TSP is enabled, we don't support text-based inbound yet
    #[cfg(not(feature = "didcomm"))]
    {
        Err(MediatorError::problem(
            37,
            &session.session_id,
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "protocol.unsupported",
            "No protocol handler available for this message format",
            vec![],
            StatusCode::BAD_REQUEST,
        ))
    }
}

/// Handle an inbound TSP message, sniffed at ingress by its CESR magic byte.
///
/// Parses the cleartext envelope (no keys) and, for a **Direct** message
/// addressed to a **locally-served** recipient, stores it for pickup — reusing
/// the protocol-neutral store path that DIDComm direct delivery uses. The TSP
/// message is base64url-encoded for storage (which is its CESR qb64 text form),
/// so it rides the existing UTF-8 string store/pickup pipeline; a pickup client
/// recognises it by the qb64 (`-E…`) prefix and decodes it back to qb2.
///
/// Routed/Nested/Control message types, remote recipients (routing/relay), and
/// the TSP↔DIDComm bridge land in later PRs. The mediator does not decrypt or
/// verify the message — exactly as for an opaque DIDComm envelope it forwards —
/// the recipient authenticates the sender end-to-end on unpack.
#[cfg(feature = "tsp")]
pub(crate) async fn handle_inbound_tsp(
    state: &SharedData,
    session: &Session,
    raw: &[u8],
) -> Result<InboundMessageResponse, MediatorError> {
    use affinidi_tsp::MessageType as TspMessageType;

    check_message_size(state, session, raw.len())?;

    let meta = TspMetaEnvelope::parse(raw).map_err(|e| {
        MediatorError::problem(
            37,
            &session.session_id,
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Message,
            "message.tsp.malformed",
            "Malformed TSP message envelope: {1}",
            vec![e.to_string()],
            StatusCode::BAD_REQUEST,
        )
    })?;

    use affinidi_tsp::message::routed::{RouteStep, next_hop, pack_routed};

    // The message kind (Direct/Routed/Nested/Control) now lives in the ENCRYPTED
    // payload, not the cleartext envelope, so a keys-free relay can no longer
    // dispatch on it. Route on the cleartext *receiver* instead:
    //   * receiver != this mediator → opaque pass-through: store for the local
    //     recipient to pick up (Direct/Routed/Nested/Control are all just carried).
    //   * receiver == this mediator → we hold the key, so unpack to learn the kind
    //     and act as the relay hop (Routed) / metadata-privacy intermediary (Nested).
    if meta.receiver != state.config.mediator_did {
        return deliver_tsp_local(state, session, raw).await;
    }

    let identity = state.tsp_identity().await?;
    let sender = resolve_tsp_vid(state, &meta.sender, &session.session_id).await?;
    let unpacked = affinidi_tsp::message::direct::unpack(
        raw,
        &identity.decryption_key,
        &sender.signing_key,
    )
    .map_err(|e| {
        tsp_problem(
            session,
            37,
            "message.tsp.unpack",
            format!("couldn't unpack TSP layer addressed to mediator: {e}"),
            StatusCode::BAD_REQUEST,
        )
    })?;

    match unpacked.message_type {
        // We are a relay hop: unwrap our routing layer and forward the onward
        // message, re-sealing as this mediator unless we are the last hop (the
        // opaque inner is already sealed to the final recipient).
        TspMessageType::Routed => {
            let step = next_hop(&unpacked).map_err(|e| {
                tsp_problem(
                    session,
                    37,
                    "message.tsp.route",
                    format!("malformed TSP route: {e}"),
                    StatusCode::BAD_REQUEST,
                )
            })?;

            match step {
                // Last relay hop: `next` is the final recipient named in the route
                // and `inner` is already sealed end-to-end to them. Deliver the
                // opaque inner — which may be a TSP *or* a DIDComm message — to that
                // recipient, who handles it natively on pickup. This is the
                // TSP↔DIDComm bridge point: the mediator forwards on the route, not
                // on the inner's (possibly non-TSP) envelope.
                RouteStep::Forward {
                    next,
                    remaining,
                    inner,
                } if remaining.is_empty() => {
                    forward_to_next(state, session, &next, &meta.sender, &inner).await
                }
                // Intermediate hop: re-seal the onward route to the next hop,
                // authenticating as this mediator, and forward.
                RouteStep::Forward {
                    next,
                    remaining,
                    inner,
                } => {
                    let next_vid = resolve_tsp_vid(state, &next, &session.session_id).await?;
                    let resealed = pack_routed(
                        &inner,
                        &remaining,
                        &identity.vid,
                        &next,
                        &identity.signing_key,
                        &next_vid.encryption_key,
                    )
                    .map_err(|e| {
                        tsp_problem(
                            session,
                            37,
                            "message.tsp.reseal",
                            format!("couldn't re-seal routed TSP message: {e}"),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        )
                    })?
                    .bytes;
                    forward_to_next(state, session, &next, &identity.vid, &resealed).await
                }
                // Empty route: `inner` is sealed to its own final recipient —
                // deliver by its (TSP) envelope.
                RouteStep::Deliver { inner } => deliver_tsp_local(state, session, &inner).await,
            }
        }

        // We are the metadata-privacy intermediary (TSP §5.5): reveal the inner
        // message — itself a packed TSP message sealed end-to-end to its final
        // recipient — and route it by its own (sealed) envelope.
        TspMessageType::Nested => {
            // The unpacked payload IS the inner packed message. Route it by its own
            // (sealed) envelope — its recipient may be local or on another mediator,
            // and the inner may be TSP or an opaque DIDComm bridge payload.
            let inner_meta = TspMetaEnvelope::parse(&unpacked.payload).map_err(|e| {
                tsp_problem(
                    session,
                    37,
                    "message.tsp.malformed",
                    format!("malformed nested inner TSP envelope: {e}"),
                    StatusCode::BAD_REQUEST,
                )
            })?;
            forward_to_next(
                state,
                session,
                &inner_meta.receiver,
                &meta.sender,
                &unpacked.payload,
            )
            .await
        }

        // Direct or Control addressed to the mediator itself: store it for the
        // mediator's own pickup (the mediator is the addressed recipient). Direct
        // and Control messages destined for *local accounts* never reach here —
        // they took the `receiver != mediator` opaque pass-through above.
        TspMessageType::Direct | TspMessageType::Control => {
            deliver_tsp_local(state, session, raw).await
        }
    }
}

/// Deliver a TSP message to the local recipient named in *its own envelope*:
/// parse the envelope and hand off to [`deliver_opaque`]. Used for Direct
/// delivery and the empty-route (`Deliver`) relay case, where the recipient is
/// the TSP receiver rather than a route hop.
#[cfg(feature = "tsp")]
async fn deliver_tsp_local(
    state: &SharedData,
    session: &Session,
    bytes: &[u8],
) -> Result<InboundMessageResponse, MediatorError> {
    let meta = TspMetaEnvelope::parse(bytes).map_err(|e| {
        tsp_problem(
            session,
            37,
            "message.tsp.malformed",
            format!("malformed TSP message: {e}"),
            StatusCode::BAD_REQUEST,
        )
    })?;
    deliver_opaque(state, session, &meta.receiver, &meta.sender, bytes).await
}

/// Deliver an opaque message to a known local recipient: check the recipient is a
/// local account, apply its access-list against `from_vid`, then store the bytes
/// for pickup. The bytes are **not** parsed — this is the TSP↔DIDComm bridge
/// primitive. A routed relay carries an opaque inner (which may be a DIDComm
/// message) and delivers it to the route's named recipient, who recognises and
/// handles it natively on pickup; the mediator never reads it. `from_vid` is the
/// authenticated sender the mediator routes on (the routing-layer sender for a
/// relayed message, or the envelope sender for Direct), against which the
/// recipient's access-list is applied. Remote recipients (forwarding on to
/// another mediator) are not yet handled.
#[cfg(feature = "tsp")]
async fn deliver_opaque(
    state: &SharedData,
    session: &Session,
    to_vid: &str,
    from_vid: &str,
    bytes: &[u8],
) -> Result<InboundMessageResponse, MediatorError> {
    let to_hash = digest(to_vid.as_bytes());
    let from_hash = digest(from_vid.as_bytes());

    // Recipient-side ACL checks, mirroring DIDComm direct delivery: existence,
    // RECEIVE_MESSAGES and the access-list verdict all come from one lookup.
    // The mediator routes on the authenticated sender and the recipient
    // verifies the (opaque) message end-to-end on pickup.
    let Some(recipient) = state
        .database
        .delivery_decision(&to_hash, Some(&from_hash))
        .await?
    else {
        return Err(tsp_delivery_refused(
            session,
            "recipient is not local to this mediator",
        ));
    };

    if authz::require_capability(&recipient.acls, Capability::ReceiveMessages).is_err() {
        return Err(tsp_delivery_refused(
            session,
            "recipient is not authorized to receive messages through this mediator",
        ));
    }

    if !recipient.access_list_allows {
        return Err(tsp_delivery_refused(
            session,
            "delivery blocked by the recipient's access list",
        ));
    }

    // Store in the form the recipient's protocol expects, so a pickup client can
    // recognise and decode it. A TSP message is stored as base64url(qb2) = its
    // CESR qb64 text (`-E…`); a bridged DIDComm message is stored as its plain
    // JWE/JWS text. Both ride the same UTF-8 string store; the client sniffs the
    // prefix (qb64 vs `{`/`ey`) on pickup.
    let encoded = if affinidi_tsp::is_tsp(bytes) {
        BASE64_URL_SAFE_NO_PAD.encode(bytes)
    } else {
        std::str::from_utf8(bytes)
            .map_err(|e| {
                tsp_problem(
                    session,
                    37,
                    "message.bridge.malformed",
                    format!("bridged inner is neither a TSP message nor valid UTF-8 text: {e}"),
                    StatusCode::BAD_REQUEST,
                )
            })?
            .to_string()
    };
    let data = ProcessMessageResponse {
        store_message: true,
        force_live_delivery: false,
        forward_message: false,
        data: WrapperType::Envelope(
            to_vid.to_string(),
            encoded,
            state.clock.unix_secs() + state.config.limits.message_expiry_seconds,
        ),
    };

    tracing::debug!(%to_vid, %from_vid, "TSP/bridged message stored for local recipient");
    store_message(state, session, &data, &UnpackMetadata::default()).await
}

/// Forward a relayed message to the next hop named in the route: deliver locally
/// if it is a local account, otherwise enqueue it for delivery to the next hop's
/// remote TSP endpoint.
#[cfg(feature = "tsp")]
async fn forward_to_next(
    state: &SharedData,
    session: &Session,
    next: &str,
    from_vid: &str,
    bytes: &[u8],
) -> Result<InboundMessageResponse, MediatorError> {
    if state
        .database
        .account_exists(&digest(next.as_bytes()))
        .await?
    {
        deliver_opaque(state, session, next, from_vid, bytes).await
    } else {
        forward_tsp_remote(state, session, next, from_vid, bytes).await
    }
}

/// Enqueue a relayed message for delivery to the next hop's **remote** TSP
/// endpoint. The next hop's transport endpoint is read from its DID document
/// (`TSPTransport` service, via [`tsp_forward_endpoint`]); the message is queued
/// (as base64url(qb2)) on the shared forwarding queue, and the forwarding
/// processor POSTs the raw qb2 to the remote mediator's `/inbound`. A next hop
/// that resolves back to this mediator is rejected as a loop.
#[cfg(feature = "tsp")]
async fn forward_tsp_remote(
    state: &SharedData,
    session: &Session,
    next: &str,
    from_vid: &str,
    bytes: &[u8],
) -> Result<InboundMessageResponse, MediatorError> {
    use affinidi_messaging_mediator_common::store::types::ForwardQueueEntry;

    let resolved = resolve_tsp_vid(state, next, &session.session_id).await?;
    let endpoint_url = tsp_forward_endpoint(state, session, next, &resolved).await?;

    let entry = ForwardQueueEntry {
        stream_id: String::new(),
        message: BASE64_URL_SAFE_NO_PAD.encode(bytes),
        to_did_hash: digest(next.as_bytes()),
        from_did_hash: digest(from_vid.as_bytes()),
        from_did: from_vid.to_string(),
        to_did: next.to_string(),
        endpoint_url: endpoint_url.clone(),
        received_at_ms: state.clock.unix_millis(),
        delay_milli: 0,
        expires_at: state.clock.unix_secs() + state.config.limits.message_expiry_seconds,
        retry_count: 0,
        hop_count: 1,
    };

    state
        .database
        .forward_queue_enqueue(&entry, state.config.limits.forward_task_queue)
        .await
        .map_err(|e| {
            tsp_problem(
                session,
                90,
                "message.tsp.forward.enqueue",
                format!("couldn't enqueue TSP message for remote forwarding: {e}"),
                StatusCode::SERVICE_UNAVAILABLE,
            )
        })?;

    tracing::info!(%next, %endpoint_url, "TSP message enqueued for remote forwarding");
    Ok(InboundMessageResponse::Forwarded)
}

/// What a resolved `TSPTransport` advertisement tells this mediator to do with a
/// message for that VID, decided without any I/O.
#[cfg(feature = "tsp")]
#[derive(Debug, PartialEq, Eq)]
enum TspRelay {
    /// Relay to this transport URL.
    Direct(String),
    /// The VID names its mediator by **DID**. That mediator's own document
    /// carries the transport URL, one resolve away.
    ViaMediator(String),
    /// The advertisement points back at this mediator — the URL is one of our own
    /// authorities, or the named mediator is us. Carries the offending value for
    /// the error message.
    Loop(String),
    /// Nothing to go on: no `TSPTransport` service, or one this mediator has no
    /// delivery rule for.
    Nothing,
}

/// Classify a resolved VID's TSP transport advertisement.
///
/// [`affinidi_tsp::ResolvedVid`] has already split the `TSPTransport`
/// `serviceEndpoint`s by what they name — transport URLs in `endpoints`, mediator
/// DIDs in `mediators` — so this only has to decide *which* to act on and whether
/// it comes back to us.
///
/// A direct URL wins over a mediator DID when a document publishes both: the
/// document is telling us it can be reached without a relay. Within `endpoints`
/// the first entry decides, in document order — the same rule the DIDComm
/// classifier follows, where every URL it can parse is either "ours" or a remote
/// hop and the scan stops on whichever comes first. A first entry that is ours is
/// reported as a loop rather than skipped: the document has told us the message
/// belongs *here*, and quietly relaying to some later entry would send it back
/// out on a route its own document contradicts.
#[cfg(feature = "tsp")]
fn classify_tsp_relay(
    resolved: &affinidi_tsp::ResolvedVid,
    mediator_did: &str,
    self_authorities: &std::collections::HashSet<(String, u16)>,
) -> TspRelay {
    if let Some(url) = resolved.endpoints.first() {
        return if crate::server::uri_points_at_self(url.as_str(), self_authorities) {
            TspRelay::Loop(url.to_string())
        } else {
            TspRelay::Direct(url.to_string())
        };
    }

    match resolved.mediators.first() {
        // Named us as its mediator, yet reached this function — which only runs
        // when there is no local account for it. There is nowhere onward to send
        // it, and POSTing to our own `/inbound` would spin.
        Some(did) if did == mediator_did => TspRelay::Loop(did.clone()),
        Some(did) => TspRelay::ViaMediator(did.clone()),
        None => TspRelay::Nothing,
    }
}

/// The transport URL to relay a TSP message for `next` to.
///
/// A `TSPTransport` service names its transport one of two ways:
///
/// - **By URL** — relayed there directly, unless the authority is one of ours,
///   which means the message came back to us.
/// - **By DID** — the shape the VTI stack publishes: a persona's `#tsp` service
///   carries its *mediator's DID*, and the transport URL lives in that mediator's
///   own document. Resolved one hop, and that document's own `TSPTransport` URL
///   used.
///
/// Only one hop of indirection is followed, exactly as the DIDComm forward path
/// does in `protocols::routing::service_endpoint_for_remote`: a mediator's own
/// document is expected to publish a URL, and chasing further would let a chain
/// of documents steer this mediator's relay.
///
/// Before the indirection arm existed, a DID-valued endpoint was taken for a
/// transport URL — `did:` parses as a URL — and the forwarding processor was
/// handed `did:webvh:…` to POST to, which failed inside the HTTP client
/// (`builder error for url`) and retried until the message was abandoned. The
/// failure has to happen *here*, where the next hop can be named, or not at all.
#[cfg(feature = "tsp")]
async fn tsp_forward_endpoint(
    state: &SharedData,
    session: &Session,
    next: &str,
    resolved: &affinidi_tsp::ResolvedVid,
) -> Result<String, MediatorError> {
    let mediator = match classify_tsp_relay(
        resolved,
        &state.config.mediator_did,
        &state.self_authorities,
    ) {
        TspRelay::Direct(url) => return Ok(url),
        TspRelay::Loop(what) => {
            return Err(tsp_problem(
                session,
                94,
                "protocol.forwarding.loop_detected",
                format!("TSP next hop {next} resolves back to this mediator ({what})"),
                StatusCode::LOOP_DETECTED,
            ));
        }
        TspRelay::Nothing => {
            return Err(tsp_problem(
                session,
                58,
                "message.tsp.no_endpoint",
                format!("next hop {next} publishes no TSP transport endpoint"),
                StatusCode::NOT_FOUND,
            ));
        }
        TspRelay::ViaMediator(did) => did,
    };

    // One hop: the peer mediator's own document carries the transport URL.
    let peer = resolve_tsp_vid(state, &mediator, &session.session_id)
        .await
        .map_err(|e| {
            tsp_problem(
                session,
                58,
                "message.tsp.mediator.unresolvable",
                format!("next hop {next} is mediated by {mediator}, which did not resolve: {e}"),
                StatusCode::BAD_GATEWAY,
            )
        })?;

    match classify_tsp_relay(&peer, &state.config.mediator_did, &state.self_authorities) {
        TspRelay::Direct(url) => Ok(url),
        TspRelay::Loop(what) => Err(tsp_problem(
            session,
            94,
            "protocol.forwarding.loop_detected",
            format!(
                "TSP next hop {next} is mediated by {mediator}, which resolves back to this \
                 mediator ({what})"
            ),
            StatusCode::LOOP_DETECTED,
        )),
        // A second hop of indirection is deliberately not chased.
        TspRelay::ViaMediator(_) | TspRelay::Nothing => Err(tsp_problem(
            session,
            58,
            "message.tsp.no_endpoint",
            format!(
                "next hop {next} is mediated by {mediator}, whose document publishes no TSP \
                 transport URL"
            ),
            StatusCode::NOT_FOUND,
        )),
    }
}

/// Resolve a DID-based TSP VID to its keys + endpoints.
#[cfg(feature = "tsp")]
async fn resolve_tsp_vid(
    state: &SharedData,
    did: &str,
    session_id: &str,
) -> Result<affinidi_tsp::ResolvedVid, MediatorError> {
    affinidi_tsp::DidVidResolver::new(state.did_resolver.clone())
        .resolve_did(did)
        .await
        .map_err(|e| {
            MediatorError::problem(
                58,
                session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "message.tsp.resolve",
                "couldn't resolve TSP VID: {1}",
                vec![format!("{did}: {e}")],
                StatusCode::BAD_GATEWAY,
            )
        })
}

/// Build a TSP protocol problem report with a single human-readable message.
#[cfg(feature = "tsp")]
/// Refuse delivery without saying why.
///
/// Spec Rev 3 §3.7: "Any response — an error, a different timing, a change in
/// subsequent behavior — is information available to a party that has not
/// authenticated itself." The three reasons a local delivery is refused —
/// the recipient is not hosted here, it may not receive, its access list
/// blocked this sender — are each a fact about *another* DID, and answering
/// them separately lets an authenticated peer enumerate which DIDs this
/// mediator serves and probe their ACLs. The same reasoning the challenge
/// path already applies, where an unknown DID is refused identically to a
/// blocked one.
///
/// The reason is logged against the session, so an operator keeps full
/// diagnostics; only the sender is told nothing.
///
/// This refuses rather than acknowledging. A uniform *success* would hide the
/// reason equally well and would be the stricter reading of §3.7, but it would
/// tell a sender its message was accepted when it was dropped — the failure
/// R1.1 exists to prevent, and the one this repository treats as the most
/// consequential lie a transport can tell.
fn tsp_delivery_refused(session: &Session, reason: &str) -> MediatorError {
    warn!(
        session = %session.session_id,
        reason = %reason,
        "TSP delivery refused; the sender is told only that it was refused"
    );
    tsp_problem(
        session,
        73,
        "delivery.refused",
        "Message not accepted for delivery".to_string(),
        StatusCode::FORBIDDEN,
    )
}

fn tsp_problem(
    session: &Session,
    code: u16,
    code_str: &str,
    message: String,
    status: StatusCode,
) -> MediatorError {
    MediatorError::problem(
        code,
        &session.session_id,
        None,
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        code_str,
        &message,
        vec![],
        status,
    )
}

#[cfg(feature = "didcomm")]
async fn handle_inbound_didcomm(
    state: &SharedData,
    session: &Session,
    message: &str,
) -> Result<InboundMessageResponse, MediatorError> {
    let _span = span!(
        tracing::Level::DEBUG,
        "handle_inbound",
        session = &session.session_id
    );

    async move {
        // Re-wrap relay (RelayMode::Rewrap): a peer mediator may have wrapped the
        // message in one or more `forward`-to-us layers (see `rewrap_for_relay`).
        // Authenticate the relaying peer and strip those layers before the normal
        // path runs on the innermost envelope. In the default `Blind` mode this is
        // skipped entirely, so existing behaviour is unchanged.
        let peeled;
        let message: &str = if state.config.processors.forwarding.relay_mode == RelayMode::Rewrap {
            peeled = peel_relay_rewrap_layers(state, session, message.to_string()).await?;
            &peeled
        } else {
            message
        };

        let envelope = match MetaEnvelope::new(message, &state.did_resolver).await {
            Ok(envelope) => envelope,
            Err(e) => {
                return Err(MediatorError::problem_with_log(
                    37,
                    &session.session_id,
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.envelope.read",
                    "Couldn't read DIDComm envelope: {1}",
                    vec![e.to_string()],
                    StatusCode::BAD_REQUEST,
                    format!("Couldn't read DIDComm envelope: {e}"),
                ));
            }
        };

        match &envelope.to_did {
            Some(to_did) => {
                if to_did == &state.config.mediator_did {
                    // Message is to the mediator
                    let (msg, metadata) = match envelope
                        .unpack(
                            &state.did_resolver,
                            &*state.config.security.mediator_secrets,
                        )
                        .await
                    {
                        Ok(ok) => ok,
                        Err(e) => {
                            return Err(MediatorError::problem_with_log(
                                32,
                                &session.session_id,
                                None,
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "message.unpack",
                                "Message unpack failed: envelope {1} Reason: {2}",
                                vec![message.to_string(), e.to_string()],
                                StatusCode::FORBIDDEN,
                                format!("Message unpack failed. Reason: {e}"),
                            ));
                        }
                    };

                    debug!(
                        id = msg.id,
                        typ = msg.typ,
                        from = msg.from.as_deref().unwrap_or("anon"),
                        "Message unpacked"
                    );

                    // Block truly anonymous messages (no sender authentication).
                    // A message is considered authenticated if EITHER:
                    // - authcrypt (ECDH-1PU) was used (metadata.authenticated == true), OR
                    // - a JWS signature is present (metadata.sign_from.is_some())
                    if !metadata.authenticated
                        && metadata.sign_from.is_none()
                        && state.config.security.block_anonymous_outer_envelope
                    {
                        return Err(MediatorError::problem(
                            50,
                            &session.session_id,
                            Some(msg.id.clone()),
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "message.anonymous",
                            "Mediator is not allowing anonymous messages (no authcrypt or JWS signature)",
                            vec![],
                            StatusCode::BAD_REQUEST,
                        ));
                    }

                    // Does the sender identity match the session DID?
                    // The sender can be identified by JWS signing (sign_from) or
                    // authcrypt encryption (encrypted_from_kid).
                    // Skip for unauthenticated sessions (e.g. inter-mediator relay):
                    // there is no session DID to match against.
                    if state.config.security.force_session_did_match && session.authenticated {
                        let sender_kid =
                            metadata.sign_from.as_ref().or(metadata.encrypted_from_kid.as_ref());
                        check_session_sender_match(session, &msg.id, &sender_kid)?;
                    }

                    // Process the message
                    let response = msg.process(state, session, &metadata).await?;
                    debug!("Message processed successfully");
                    store_message(state, session, &response, &metadata).await
                } else {
                    // this is a direct delivery method
                    if !state.config.security.local_direct_delivery_allowed {
                        return Err(MediatorError::problem(
                            71,
                            &session.session_id,
                            None,
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "direct_delivery.denied",
                            "Mediator is not accepting direct delivery of DIDComm messages. They must be wrapped in a forwarding envelope",
                            vec![],
                            StatusCode::FORBIDDEN,
                        ));
                    }

                    // Everything the recipient side needs — existence, ACL bits
                    // and the access-list verdict — comes from one lookup. The
                    // three facts all derive from the same stored record, so
                    // asking for them separately cost three reads of it.
                    let to_hash = digest(to_did);
                    let from_hash = envelope.from_did.as_ref().map(digest);
                    let Some(recipient) = state
                        .database
                        .delivery_decision(&to_hash, from_hash.as_deref())
                        .await?
                    else {
                        return Err(MediatorError::problem(
                            72,
                            &session.session_id,
                            None,
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "direct_delivery.recipient.unknown",
                            "Direct Delivery Recipient is not known on this Mediator",
                            vec![],
                            StatusCode::FORBIDDEN,
                        ));
                    };

                    // The mediator cannot decrypt a direct-delivery envelope, so the
                    // claimed sender (JWE `skid` header) is unverified. When
                    // session/sender matching is enforced, bind it to the
                    // authenticated session DID before it is trusted for ACL checks.
                    //
                    // Skipped for unauthenticated sessions, exactly as the forward
                    // branch above skips it: an inter-mediator relay hop arrives on
                    // the anonymous `ANON-INBOUND` session, whose DID is empty, so the
                    // comparison could only ever fail. It reaches *this* branch rather
                    // than the forward branch because [`RelayMode::Blind`] — the
                    // default — relays the peer's inner envelope verbatim, and that
                    // envelope is addressed to the local recipient, not to this
                    // mediator. Without the guard, blind relay cannot deliver at all.
                    //
                    // The cost is real and worth naming: on a blind relay hop the
                    // claimed sender stays unverified, and it is that claimed sender
                    // which `delivery_decision` above hashed into `from_hash` for the
                    // recipient's access-list verdict. A relaying peer can therefore
                    // present any sender DID it likes. This is inherent to blind
                    // relay — by construction the receiving mediator cannot see who
                    // relayed — not something this guard gives away: the alternative
                    // is refusing the hop, which is the bug being fixed.
                    // [`RelayMode::Rewrap`] plus `relay_trusted_mediators` is the
                    // posture for deployments that need the peer authenticated.
                    if state.config.security.force_session_did_match && session.authenticated {
                        check_direct_delivery_session_match(session, envelope.from_did.as_deref())?;
                    }

                    // Check if the message will pass ACL Checks
                    if let Some(from_hash) = from_hash.as_deref() {
                        let from_acls = authz::effective_acls(state, from_hash).await?;

                        if authz::require_capability(&from_acls, Capability::SendMessages).is_err() {
                            return Err(MediatorError::problem(
                                44,
                                &session.session_id,
                                None,
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "authorization.send",
                                "Sender DID is not authorized to send messages through this mediator",
                                vec![],
                                StatusCode::FORBIDDEN,
                            ));
                        }
                    } else if !state.config.security.local_direct_delivery_allow_anon {
                        return Err(MediatorError::problem(
                            50,
                            &session.session_id,
                            None,
                            ProblemReportSorter::Warning,
                            ProblemReportScope::Message,
                            "message.anonymous",
                            "Anonymous direct delivery is not allowed by this mediator",
                            vec![],
                            StatusCode::FORBIDDEN,
                        ));
                    }
                    // Recipient-side gates, both answered from the single
                    // lookup above. RECEIVE_MESSAGES mirrors the sender's
                    // SEND_MESSAGES check: a DID whose ACLs withhold it does
                    // not accept directly-delivered messages at all, whoever
                    // the sender is. Checked before the access list because it
                    // is the coarser of the two.
                    if authz::require_capability(&recipient.acls, Capability::ReceiveMessages)
                        .is_err()
                    {
                        return Err(MediatorError::problem(
                            74,
                            &session.session_id,
                            None,
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "authorization.receive",
                            "Recipient DID is not authorized to receive messages through this mediator",
                            vec![],
                            StatusCode::FORBIDDEN,
                        ));
                    }

                    if !recipient.access_list_allows {
                        return Err(MediatorError::problem(
                            73,
                            &session.session_id,
                            None,
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "authorization.access_list.denied",
                            "Delivery blocked due to ACLs (access_list denied)",
                            vec![],
                            StatusCode::FORBIDDEN,
                        ));
                    }

                    let data = ProcessMessageResponse {
                        store_message: true,
                        force_live_delivery: false,
                        forward_message: false,
                        data: WrapperType::Envelope(
                            to_did.into(),
                            message.into(),
                            state.clock.unix_secs()
                                + state.config.limits.message_expiry_seconds,
                        ),
                    };

                    debug!("Direct delivery message from({:?}) to({}) msg_hash({})", envelope.from_did, to_did, envelope.sha256_hash);

                    store_message(state, session, &data, &UnpackMetadata::default()).await
                }
            }
            _ =>   Err(MediatorError::problem_with_log(
                51,
                &session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "message.to",
                "There is no to_did on the envelope! Can't deliver an unknown message. Message: {1}",
                vec![message.to_string()],
                StatusCode::UNPROCESSABLE_ENTITY,
                "There is no to_did on the envelope! Can't deliver an unknown message.",
            ))
        }
    }
    .instrument(_span)
    .await
}

/// Strip peer-mediator re-wrap layers from an inbound message (RelayMode::Rewrap).
///
/// A re-wrap layer is a `forward` addressed to this mediator whose `next` hop is
/// *also* this mediator — the envelope a peer produces in [`rewrap_for_relay`].
/// For each such layer this authenticates the relaying peer (the authcrypt
/// `from`) against the trusted-peer allowlist, then replaces the message with
/// the inner attachment and repeats, returning the innermost envelope once it is
/// no longer a re-wrap layer. Bounded by `max_hops` to stop relay loops.
///
/// Any decrypt/unpack failure here is *not* fatal: the message is handed back
/// unchanged so the normal inbound path produces the canonical error. The cost
/// is one extra unpack of the outer layer on a rewrap-mode mediator; acceptable
/// for an opt-in relay posture.
#[cfg(feature = "didcomm")]
async fn peel_relay_rewrap_layers(
    state: &SharedData,
    session: &Session,
    message: String,
) -> Result<String, MediatorError> {
    let mut current = message;
    let mut depth: u32 = 0;
    loop {
        let envelope = match MetaEnvelope::new(&current, &state.did_resolver).await {
            Ok(e) => e,
            Err(_) => return Ok(current),
        };
        if envelope.to_did.as_deref() != Some(state.config.mediator_did.as_str()) {
            return Ok(current);
        }
        let (msg, _meta) = match envelope
            .unpack(
                &state.did_resolver,
                &*state.config.security.mediator_secrets,
            )
            .await
        {
            Ok(ok) => ok,
            Err(_) => return Ok(current),
        };
        let Some(inner) = rewrap_inner_attachment(&state.config.mediator_did, &msg) else {
            return Ok(current);
        };

        // Authenticate the relaying peer mediator before peeling its layer.
        if !relay_peer_trusted(
            &state.config.processors.forwarding.relay_trusted_mediators,
            msg.from.as_deref(),
        ) {
            return Err(MediatorError::problem(
                60,
                &session.session_id,
                Some(msg.id.clone()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authorization.relay.untrusted_peer",
                "Relaying mediator is not in the trusted relay allowlist",
                vec![],
                StatusCode::FORBIDDEN,
            ));
        }

        depth += 1;
        if depth > state.config.processors.forwarding.max_hops {
            return Err(MediatorError::problem(
                94,
                &session.session_id,
                Some(msg.id.clone()),
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "protocol.forwarding.loop_detected",
                "Re-wrap relay exceeded maximum hop count, possible loop",
                vec![],
                StatusCode::LOOP_DETECTED,
            ));
        }

        debug!(
            peer = msg.from.as_deref().unwrap_or("anon"),
            depth, "Peeled inter-mediator relay re-wrap layer"
        );
        current = inner;
    }
}

/// Ensure the Session DID and the message sender DID match.
/// The sender can be identified by either a JWS signature (`sign_from`)
/// or authcrypt encryption (`encrypted_from_kid`). Both are key IDs
/// in the form `did:...#key-N` — the DID is extracted from the fragment.
#[cfg(feature = "didcomm")]
fn check_session_sender_match(
    session: &Session,
    msg_id: &str,
    sender_kid: &Option<&String>,
) -> Result<(), MediatorError> {
    if let Some(kid) = sender_kid
        && let Some((did, _fragment)) = kid.split_once('#')
        && did == session.did
    {
        return Ok(());
    }

    let sender_display = sender_kid.map(|s| s.as_str()).unwrap_or("anonymous");

    Err(MediatorError::problem_with_log(
        52,
        &session.session_id,
        Some(msg_id.to_string()),
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        "authorization.did.session_mismatch",
        "Sender DID ({1}) doesn't match session DID",
        vec![sender_display.to_string()],
        StatusCode::BAD_REQUEST,
        format!("Sender DID ({sender_display}) doesn't match session DID"),
    ))
}

/// Ensure a direct-delivery envelope's claimed sender matches the session DID.
///
/// The mediator holds no key for a directly-delivered envelope, so `from_did`
/// here is whatever the JWE `skid` header claims — unverified. It is also the
/// value that feeds the recipient's access-list lookup, so on an authenticated
/// session it has to be pinned to the DID that authenticated.
///
/// Only the caller can decide whether the session is one that can be matched
/// against: an anonymous inter-mediator relay hop has no session DID, and is
/// exempted at the call site rather than here.
#[cfg(feature = "didcomm")]
fn check_direct_delivery_session_match(
    session: &Session,
    claimed_sender: Option<&str>,
) -> Result<(), MediatorError> {
    if claimed_sender == Some(session.did.as_str()) {
        return Ok(());
    }

    let claimed = claimed_sender.unwrap_or("anonymous");
    Err(MediatorError::problem_with_log(
        52,
        &session.session_id,
        None,
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        "authorization.did.session_mismatch",
        "Sender DID ({1}) doesn't match session DID",
        vec![claimed.to_string()],
        StatusCode::BAD_REQUEST,
        format!("Direct-delivery envelope sender ({claimed}) doesn't match session DID"),
    ))
}

#[cfg(test)]
#[cfg(feature = "didcomm")]
mod tests {
    use super::*;

    // --- check_session_sender_match tests ---
    // The function accepts a sender_kid (key ID like "did:...#key-N") and
    // checks that the DID portion matches the session DID.

    fn make_session(did: &str) -> Session {
        Session {
            did: did.to_string(),
            session_id: "test-session".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn sender_match_jws_signature_matching() {
        let session = make_session("did:example:alice");
        let kid = "did:example:alice#key-0".to_string();
        assert!(check_session_sender_match(&session, "msg-1", &Some(&kid)).is_ok());
    }

    #[test]
    fn sender_match_authcrypt_kid_matching() {
        // Authcrypt encrypted_from_kid uses the same did#key format
        let session = make_session("did:webvh:Qmc572jbs:webvh.example.com:vta");
        let kid = "did:webvh:Qmc572jbs:webvh.example.com:vta#key-1".to_string();
        assert!(check_session_sender_match(&session, "msg-1", &Some(&kid)).is_ok());
    }

    #[test]
    fn sender_match_wrong_did_rejected() {
        let session = make_session("did:example:alice");
        let kid = "did:example:mallory#key-0".to_string();
        assert!(check_session_sender_match(&session, "msg-1", &Some(&kid)).is_err());
    }

    #[test]
    fn sender_match_none_anonymous_rejected() {
        let session = make_session("did:example:alice");
        assert!(check_session_sender_match(&session, "msg-1", &None).is_err());
    }

    #[test]
    fn sender_match_kid_without_fragment_rejected() {
        // A bare DID without #key fragment should not match
        let session = make_session("did:example:alice");
        let kid = "did:example:alice".to_string();
        assert!(check_session_sender_match(&session, "msg-1", &Some(&kid)).is_err());
    }

    #[test]
    fn sender_match_different_key_same_did_ok() {
        // Different key fragments from the same DID should all be accepted
        let session = make_session("did:example:alice");
        let key0 = "did:example:alice#key-0".to_string();
        let key1 = "did:example:alice#key-1".to_string();
        let signing = "did:example:alice#signing-key".to_string();
        assert!(check_session_sender_match(&session, "msg-1", &Some(&key0)).is_ok());
        assert!(check_session_sender_match(&session, "msg-1", &Some(&key1)).is_ok());
        assert!(check_session_sender_match(&session, "msg-1", &Some(&signing)).is_ok());
    }

    // --- check_direct_delivery_session_match tests ---
    // The direct-delivery sibling of the above: it compares the whole claimed
    // sender DID (from the JWE `skid`) against the session DID, with no key
    // fragment involved.

    #[test]
    fn direct_delivery_sender_matching_session_ok() {
        let session = make_session("did:example:alice");
        assert!(check_direct_delivery_session_match(&session, Some("did:example:alice")).is_ok());
    }

    #[test]
    fn direct_delivery_wrong_sender_rejected() {
        let session = make_session("did:example:alice");
        assert!(
            check_direct_delivery_session_match(&session, Some("did:example:mallory")).is_err()
        );
    }

    #[test]
    fn direct_delivery_anonymous_sender_rejected() {
        let session = make_session("did:example:alice");
        assert!(check_direct_delivery_session_match(&session, None).is_err());
    }

    /// The bug this guard fixes: an inter-mediator relay hop arrives on the
    /// anonymous session, whose DID is empty, so *every* claimed sender
    /// mismatches. The call site must not run the check for such a session —
    /// this asserts the check really does fail there, which is why the
    /// `session.authenticated` guard is load-bearing rather than cosmetic.
    #[test]
    fn anonymous_relay_session_would_reject_every_sender() {
        let relay_session = Session {
            session_id: "ANON-INBOUND".to_string(),
            ..Default::default()
        };
        assert!(!relay_session.authenticated);
        assert!(
            check_direct_delivery_session_match(&relay_session, Some("did:example:alice")).is_err()
        );
        assert!(
            check_direct_delivery_session_match(&relay_session, Some("did:example:bob")).is_err()
        );
    }

    // --- anonymous message detection tests ---
    // These test the logic used in handle_inbound for the anonymous check:
    //   !metadata.authenticated && metadata.sign_from.is_none()

    /// Helper: build UnpackMetadata for the given scenario
    fn make_metadata(
        authenticated: bool,
        sign_from: Option<&str>,
        encrypted_from_kid: Option<&str>,
    ) -> UnpackMetadata {
        let mut metadata = UnpackMetadata::default();
        metadata.encrypted = true;
        metadata.authenticated = authenticated;
        metadata.anonymous_sender = !authenticated;
        metadata.sign_from = sign_from.map(String::from);
        metadata.encrypted_from_kid = encrypted_from_kid.map(String::from);
        metadata
    }

    /// Returns true if the metadata would be blocked by block_anonymous_outer_envelope
    fn is_anonymous(metadata: &UnpackMetadata) -> bool {
        !metadata.authenticated && metadata.sign_from.is_none()
    }

    /// Returns the sender_kid that would be used for session/admin checks
    fn sender_kid(metadata: &UnpackMetadata) -> Option<String> {
        metadata
            .sign_from
            .clone()
            .or(metadata.encrypted_from_kid.clone())
    }

    #[test]
    fn authcrypt_only_is_not_anonymous() {
        // ECDH-1PU (authcrypt): authenticated=true, no JWS signature
        // This is what the SDK's pack_encrypted(Some(from)) produces
        let meta = make_metadata(true, None, Some("did:example:alice#key-1"));
        assert!(!is_anonymous(&meta));
        assert_eq!(
            sender_kid(&meta),
            Some("did:example:alice#key-1".to_string())
        );
    }

    #[test]
    fn jws_signed_anoncrypt_is_not_anonymous() {
        // Anoncrypt JWE + JWS signature wrapper: authenticated=false, sign_from set
        let meta = make_metadata(false, Some("did:example:alice#key-0"), None);
        assert!(!is_anonymous(&meta));
        assert_eq!(
            sender_kid(&meta),
            Some("did:example:alice#key-0".to_string())
        );
    }

    #[test]
    fn authcrypt_plus_jws_is_not_anonymous() {
        // Both authcrypt AND JWS: the strongest authentication
        let meta = make_metadata(
            true,
            Some("did:example:alice#key-0"),
            Some("did:example:alice#key-1"),
        );
        assert!(!is_anonymous(&meta));
        // JWS sign_from takes priority over encrypted_from_kid
        assert_eq!(
            sender_kid(&meta),
            Some("did:example:alice#key-0".to_string())
        );
    }

    #[test]
    fn anoncrypt_only_is_anonymous() {
        // ECDH-ES (anoncrypt): no sender authentication at all
        let meta = make_metadata(false, None, None);
        assert!(is_anonymous(&meta));
        assert_eq!(sender_kid(&meta), None);
    }

    #[test]
    fn anoncrypt_with_encrypted_from_kid_none_is_anonymous() {
        // Anoncrypt doesn't set encrypted_from_kid either
        let meta = make_metadata(false, None, None);
        assert!(is_anonymous(&meta));
    }
}

#[cfg(all(test, feature = "tsp"))]
mod tsp_tests {
    use affinidi_tsp::message::direct;
    use affinidi_tsp::{MessageType as TspMessageType, PrivateVid, is_tsp};
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

    /// The storage-format contract for TSP messages: a TSP message (raw CESR
    /// qb2, leads with the `0xD4` magic byte) is stored base64url-encoded, which
    /// is its CESR qb64 text form (`-E…`). This must round-trip exactly, stay
    /// distinguishable from a DIDComm JSON envelope (`{`), and decode back to a
    /// recognisable TSP message — so a pickup client can identify and decode it.
    #[test]
    fn tsp_storage_encoding_roundtrips_and_is_recognisable() {
        let alice = PrivateVid::generate("did:example:alice");
        let bob = PrivateVid::generate("did:example:bob");

        let packed = direct::pack(
            b"hello over TSP",
            TspMessageType::Direct,
            "did:example:alice",
            "did:example:bob",
            &alice.signing_key,
            &bob.encryption_key,
        )
        .unwrap();
        let raw = &packed.bytes;
        assert!(is_tsp(raw), "packed message leads with the TSP magic byte");

        // This is exactly what handle_inbound_tsp stores.
        let stored = BASE64_URL_SAFE_NO_PAD.encode(raw);

        // The stored form is CESR qb64 text and is unambiguously not DIDComm JSON.
        assert!(stored.starts_with("-E"), "qb64 envelope-code prefix");
        assert!(
            !stored.starts_with('{'),
            "distinct from a DIDComm JSON envelope"
        );

        // A pickup client base64url-decodes back to the exact original bytes.
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(stored.as_bytes()).unwrap();
        assert_eq!(&decoded, raw, "decode round-trips the qb2 bytes exactly");
        assert!(
            is_tsp(&decoded),
            "decoded bytes are a recognisable TSP message"
        );
    }
}

/// Unit coverage for the TSP relay classifier — the DID-vs-URL decision that
/// [`forward_tsp_remote`] makes before anything is enqueued. Pure: no store, no
/// resolver, no session.
#[cfg(test)]
#[cfg(feature = "tsp")]
mod tsp_relay_tests {
    use super::{TspRelay, classify_tsp_relay};
    use crate::server::normalize_host;
    use affinidi_tsp::ResolvedVid;
    use std::collections::HashSet;

    /// This mediator.
    const US: &str = "did:web:us.example";
    /// The mediator named in the production failure, verbatim.
    const PEER_MEDIATOR: &str = "did:webvh:QmbHZC8JUpUD1XrdEcNiAPTxke4WpDyBPjjigPpEwYZiq5:dids.firstperson.dev:firstperson-mediator";
    /// The transport URL that peer mediator's own document publishes.
    const PEER_URL: &str = "https://mediator.firstperson.dev/mediator/v1";

    fn authorities(entries: &[(&str, u16)]) -> HashSet<(String, u16)> {
        entries
            .iter()
            .map(|(host, port)| (normalize_host(host), *port))
            .collect()
    }

    fn no_authorities() -> HashSet<(String, u16)> {
        HashSet::new()
    }

    /// A resolved VID advertising the given transport URLs and mediator DIDs.
    fn vid(id: &str, endpoints: &[&str], mediators: &[&str]) -> ResolvedVid {
        ResolvedVid {
            id: id.to_string(),
            signing_key: [1u8; 32],
            encryption_key: [2u8; 32],
            endpoints: endpoints
                .iter()
                .map(|u| url::Url::parse(u).expect("test endpoint parses"))
                .collect(),
            mediators: mediators.iter().map(|d| d.to_string()).collect(),
        }
    }

    /// The production shape: a persona whose `#tsp` service names its mediator by
    /// DID is an indirection to follow, never a URL to POST to.
    #[test]
    fn a_mediator_did_is_followed_as_indirection() {
        let persona = vid("did:web:persona.example", &[], &[PEER_MEDIATOR]);
        assert_eq!(
            classify_tsp_relay(&persona, US, &no_authorities()),
            TspRelay::ViaMediator(PEER_MEDIATOR.to_string())
        );
    }

    /// And the second half of that shape: the mediator's own document publishes
    /// the transport URL, which is what the forward is actually sent to.
    #[test]
    fn the_mediators_own_document_yields_the_transport_url() {
        let mediator = vid(PEER_MEDIATOR, &[PEER_URL], &[]);
        assert_eq!(
            classify_tsp_relay(&mediator, US, &no_authorities()),
            TspRelay::Direct(PEER_URL.to_string())
        );
    }

    /// A VID that publishes its own URL is relayed straight there — the
    /// unmediated case, unchanged.
    #[test]
    fn a_direct_url_is_relayed_as_is() {
        let peer = vid("did:web:peer.example", &["https://peer.example/v1"], &[]);
        assert_eq!(
            classify_tsp_relay(&peer, US, &no_authorities()),
            TspRelay::Direct("https://peer.example/v1".to_string())
        );
    }

    /// Both advertised: the URL wins. A document that can be reached without a
    /// relay is telling us so.
    #[test]
    fn a_direct_url_wins_over_a_mediator_did() {
        let peer = vid(
            "did:web:peer.example",
            &["https://peer.example/v1"],
            &[PEER_MEDIATOR],
        );
        assert_eq!(
            classify_tsp_relay(&peer, US, &no_authorities()),
            TspRelay::Direct("https://peer.example/v1".to_string())
        );
    }

    /// The pre-existing loop guard, kept: a transport URL on one of our own
    /// authorities is the message coming back to us.
    #[test]
    fn a_url_on_one_of_our_authorities_is_a_loop() {
        let peer = vid("did:web:peer.example", &["http://127.0.0.1:7037/"], &[]);
        assert_eq!(
            classify_tsp_relay(&peer, US, &authorities(&[("127.0.0.1", 7037)])),
            TspRelay::Loop("http://127.0.0.1:7037/".to_string())
        );
    }

    /// The same guard extended to the indirection arm: a next hop that names
    /// *us* as its mediator has no account here (that is the only way this code
    /// is reached), so following it would POST to our own `/inbound`.
    #[test]
    fn naming_this_mediator_as_the_mediator_is_a_loop() {
        let peer = vid("did:web:peer.example", &[], &[US]);
        assert_eq!(
            classify_tsp_relay(&peer, US, &no_authorities()),
            TspRelay::Loop(US.to_string())
        );
    }

    /// No `TSPTransport` service at all — nothing to relay to, and the caller
    /// turns this into a "publishes no TSP transport endpoint" problem report
    /// rather than enqueueing something undeliverable.
    #[test]
    fn no_advertisement_is_nothing() {
        let peer = vid("did:web:peer.example", &[], &[]);
        assert_eq!(
            classify_tsp_relay(&peer, US, &no_authorities()),
            TspRelay::Nothing
        );
    }

    /// The regression, stated end to end over the two documents: the persona
    /// classifies to its mediator's DID, and *that* document — not the persona's
    /// — is where the URL comes from. Nothing anywhere hands `did:webvh:…` on as
    /// something to connect to.
    #[test]
    fn the_two_document_indirection_resolves_to_the_mediators_url() {
        let persona = vid("did:web:persona.example", &[], &[PEER_MEDIATOR]);
        let TspRelay::ViaMediator(mediator_did) =
            classify_tsp_relay(&persona, US, &no_authorities())
        else {
            panic!("a DID-valued TSPTransport endpoint must classify as indirection");
        };
        assert_eq!(mediator_did, PEER_MEDIATOR);

        let mediator = vid(&mediator_did, &[PEER_URL], &[]);
        assert_eq!(
            classify_tsp_relay(&mediator, US, &no_authorities()),
            TspRelay::Direct(PEER_URL.to_string())
        );
    }

    /// One hop only. If the peer mediator's own document *also* only names
    /// another mediator, the caller stops rather than chasing — a chain of
    /// documents must not be able to steer this mediator's relay.
    #[test]
    fn a_second_hop_of_indirection_is_not_chased() {
        let mediator = vid(PEER_MEDIATOR, &[], &["did:web:third.example"]);
        assert_eq!(
            classify_tsp_relay(&mediator, US, &no_authorities()),
            TspRelay::ViaMediator("did:web:third.example".to_string())
        );
        // `tsp_forward_endpoint` maps this second-hop `ViaMediator` onto the same
        // "no transport URL" error as `Nothing`, and does not resolve again.
    }
}

#[cfg(test)]
#[cfg(feature = "tsp")]
mod tsp_refusal_tests {
    use super::tsp_delivery_refused;
    use crate::common::session::Session;

    /// Rev 3 §3.7: the reasons a local TSP delivery is refused must be
    /// indistinguishable to the sender, or an authenticated peer can enumerate
    /// which DIDs this mediator serves and probe their access lists.
    ///
    /// Asserted here rather than end-to-end because this is where the property
    /// lives: every refusal goes through one helper that ignores its reason
    /// when building the response. An e2e comparison would need two recipients
    /// differing only in why they are refused, and the obvious pair —
    /// hosted-but-blocked against not-hosted-at-all — is not comparable, since
    /// an unresolvable DID fails in the client before a request is ever sent.
    #[test]
    fn every_refusal_reason_produces_the_same_response() {
        let session = Session {
            did: "did:example:alice".to_string(),
            session_id: "test-session".to_string(),
            ..Default::default()
        };

        let reasons = [
            "recipient is not local to this mediator",
            "recipient is not authorized to receive messages through this mediator",
            "delivery blocked by the recipient's access list",
        ];

        let rendered: Vec<String> = reasons
            .iter()
            .map(|r| format!("{:?}", tsp_delivery_refused(&session, r)))
            .collect();

        for other in &rendered[1..] {
            assert_eq!(
                &rendered[0], other,
                "refusals must be indistinguishable to the sender"
            );
        }

        for reason in reasons {
            assert!(
                !rendered[0].contains(reason),
                "the response leaked the reason: {reason}"
            );
        }
    }
}

