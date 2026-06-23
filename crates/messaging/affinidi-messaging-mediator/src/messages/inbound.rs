#[cfg(feature = "didcomm")]
use crate::didcomm_compat::MetaEnvelope;
#[cfg(feature = "didcomm")]
use crate::messages::MessageHandler;
#[cfg(feature = "didcomm")]
use crate::messages::protocols::routing::{relay_peer_trusted, rewrap_inner_attachment};
use crate::{SharedData, common::session::Session};
// Shared by both the DIDComm direct-delivery path and the TSP delivery path.
#[cfg(any(feature = "didcomm", feature = "tsp"))]
use crate::{common::authz, messages::store::store_message};
#[cfg(feature = "didcomm")]
use crate::common::authz::Capability;
#[cfg(feature = "tsp")]
use affinidi_tsp::MetaEnvelope as TspMetaEnvelope;
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
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use http::StatusCode;
#[cfg(any(feature = "didcomm", feature = "tsp"))]
use sha256::digest;
#[cfg(feature = "didcomm")]
use tracing::{Instrument, debug, span};

#[cfg(any(feature = "didcomm", feature = "tsp"))]
use super::{ProcessMessageResponse, WrapperType};

pub(crate) async fn handle_inbound(
    #[cfg_attr(not(feature = "didcomm"), allow(unused_variables))] state: &SharedData,
    session: &Session,
    #[cfg_attr(not(feature = "didcomm"), allow(unused_variables))] message: &str,
) -> Result<InboundMessageResponse, MediatorError> {
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
/// recognises it by the qb64 (`1AAF…`) prefix and decodes it back to qb2.
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

    match meta.message_type {
        // Direct: deliver to the (local) recipient named in the envelope.
        TspMessageType::Direct => deliver_tsp_local(state, session, raw).await,

        // Routed addressed to *this mediator*: we are a relay hop. Unwrap our
        // routing layer (sealed to us) and forward the onward message to the next
        // hop, re-sealing as this mediator unless we are the last hop (in which
        // case the opaque inner is already sealed to the final recipient).
        TspMessageType::Routed if meta.receiver == state.config.mediator_did => {
            let identity = state.tsp_identity().await?;
            let sender = resolve_tsp_vid(state, &meta.sender, &session.session_id).await?;
            let unpacked = affinidi_tsp::message::direct::unpack(
                raw,
                &identity.decryption_key,
                &sender.encryption_key,
                &sender.signing_key,
            )
            .map_err(|e| {
                tsp_problem(
                    session,
                    37,
                    "message.tsp.unpack",
                    format!("couldn't unpack routed TSP layer: {e}"),
                    StatusCode::BAD_REQUEST,
                )
            })?;

            let step = next_hop(&unpacked.payload).map_err(|e| {
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
                        &identity.decryption_key,
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

        // Routed addressed to a *local account* (that account is itself the hop):
        // store it opaquely for them to pick up and relay onward.
        TspMessageType::Routed => deliver_tsp_local(state, session, raw).await,

        // Nested / Control relay are not handled yet.
        _ => Err(tsp_problem(
            session,
            37,
            "protocol.tsp.unsupported",
            "Only TSP Direct and Routed messages are handled so far".to_string(),
            StatusCode::NOT_IMPLEMENTED,
        )),
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

    if !state.database.account_exists(&to_hash).await? {
        return Err(tsp_problem(
            session,
            58,
            "direct_delivery.recipient.unknown",
            "TSP recipient is not local to this mediator (remote forwarding not yet enabled)"
                .to_string(),
            StatusCode::NOT_FOUND,
        ));
    }

    // Access-list check (sender → recipient), mirroring DIDComm direct delivery.
    // The mediator routes on the authenticated sender and the recipient verifies
    // the (opaque) message end-to-end on pickup.
    let from_hash = digest(from_vid.as_bytes());
    if authz::check_access_list(state.database.as_ref(), &to_hash, Some(&from_hash))
        .await
        .is_err()
    {
        return Err(tsp_problem(
            session,
            73,
            "authorization.access_list.denied",
            "Delivery blocked due to ACLs (access_list denied)".to_string(),
            StatusCode::FORBIDDEN,
        ));
    }

    // Store in the form the recipient's protocol expects, so a pickup client can
    // recognise and decode it. A TSP message is stored as base64url(qb2) = its
    // CESR qb64 text (`1AAF…`); a bridged DIDComm message is stored as its plain
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
    if state.database.account_exists(&digest(next.as_bytes())).await? {
        deliver_opaque(state, session, next, from_vid, bytes).await
    } else {
        forward_tsp_remote(state, session, next, from_vid, bytes).await
    }
}

/// Enqueue a relayed message for delivery to the next hop's **remote** TSP
/// endpoint. The next hop's transport endpoint is read from its DID document
/// (`TSPTransport` service); the message is queued (as base64url(qb2)) on the
/// shared forwarding queue, and the forwarding processor POSTs the raw qb2 to the
/// remote mediator's `/inbound`. A next hop that resolves back to this mediator is
/// rejected as a loop.
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
    let endpoint_url = resolved
        .endpoints
        .first()
        .map(|u| u.to_string())
        .ok_or_else(|| {
            tsp_problem(
                session,
                58,
                "message.tsp.no_endpoint",
                format!("next hop {next} publishes no TSP transport endpoint"),
                StatusCode::NOT_FOUND,
            )
        })?;

    // Loop guard: the next hop must not resolve back to this mediator.
    if tsp_endpoint_is_self(&endpoint_url, &state.self_authorities) {
        return Err(tsp_problem(
            session,
            94,
            "protocol.forwarding.loop_detected",
            format!("TSP next hop {next} resolves back to this mediator"),
            StatusCode::LOOP_DETECTED,
        ));
    }

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

/// Whether `endpoint` resolves back to this mediator — the loop guard for remote
/// TSP forwarding, mirroring the DIDComm forward path's self-detection.
#[cfg(feature = "tsp")]
fn tsp_endpoint_is_self(
    endpoint: &str,
    self_authorities: &std::collections::HashSet<(String, u16)>,
) -> bool {
    let Ok(url) = url::Url::parse(endpoint) else {
        return false;
    };
    let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
        return false;
    };
    self_authorities.contains(&(host.to_lowercase(), port))
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

                    // Check that the recipient account is local to the mediator
                    if !state.database.account_exists(&digest(to_did)).await? {
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
                    }

                    // The mediator cannot decrypt a direct-delivery envelope, so the
                    // claimed sender (JWE `skid` header) is unverified. When
                    // session/sender matching is enforced, bind it to the
                    // authenticated session DID before it is trusted for ACL checks.
                    if state.config.security.force_session_did_match
                        && envelope.from_did.as_deref() != Some(session.did.as_str())
                    {
                        let claimed = envelope.from_did.as_deref().unwrap_or("anonymous");
                        return Err(MediatorError::problem_with_log(
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
                        ));
                    }

                    let from_hash = envelope.from_did.as_ref().map(digest);
                    // Check if the message will pass ACL Checks
                    if let Some(from) = &envelope.from_did {
                        let from_acls = if let Some(acl) = state
                            .database
                            .get_did_acl(&digest(from))
                            .await? {
                                acl
                        } else {
                            state.config.security.global_acl_default.clone()
                        };

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
                    if authz::check_access_list(
                        state.database.as_ref(),
                        &digest(to_did),
                        from_hash.as_deref(),
                    )
                    .await
                    .is_err()
                    {
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

    // --- anonymous message detection tests ---
    // These test the logic used in handle_inbound for the anonymous check:
    //   !metadata.authenticated && metadata.sign_from.is_none()

    /// Helper: build UnpackMetadata for the given scenario
    fn make_metadata(
        authenticated: bool,
        sign_from: Option<&str>,
        encrypted_from_kid: Option<&str>,
    ) -> UnpackMetadata {
        UnpackMetadata {
            encrypted: true,
            authenticated,
            anonymous_sender: !authenticated,
            sign_from: sign_from.map(String::from),
            encrypted_from_kid: encrypted_from_kid.map(String::from),
            ..Default::default()
        }
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
    /// is its CESR qb64 text form (`1AAF…`). This must round-trip exactly, stay
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
            &alice.decryption_key,
            &bob.encryption_key,
        )
        .unwrap();
        let raw = &packed.bytes;
        assert!(is_tsp(raw), "packed message leads with the TSP magic byte");

        // This is exactly what handle_inbound_tsp stores.
        let stored = BASE64_URL_SAFE_NO_PAD.encode(raw);

        // The stored form is CESR qb64 text and is unambiguously not DIDComm JSON.
        assert!(stored.starts_with("1AAF"), "qb64 envelope-code prefix");
        assert!(!stored.starts_with('{'), "distinct from a DIDComm JSON envelope");

        // A pickup client base64url-decodes back to the exact original bytes.
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(stored.as_bytes()).unwrap();
        assert_eq!(&decoded, raw, "decode round-trips the qb2 bytes exactly");
        assert!(is_tsp(&decoded), "decoded bytes are a recognisable TSP message");
    }
}
