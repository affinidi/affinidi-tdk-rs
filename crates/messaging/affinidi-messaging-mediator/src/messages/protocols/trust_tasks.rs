//! Trust Tasks framework consumer — handles inbound [Trust Task] documents
//! carried over the DIDComm binding envelope.
//!
//! A Trust Task request arrives as a DIDComm message whose `type` is the binding
//! envelope URI and whose `body` is the full `TrustTask<P>` document. This module
//! is the *single core*: it runs the framework's `consume_inbound` pipeline and
//! the per-task handlers (which delegate to the same `state.database.*` methods
//! the legacy DIDComm protocols use). The response is a `TrustTask<R>` packed back
//! through the mediator's existing outbound path — exactly like the trust-ping
//! pong — so no separate binding/agent plumbing is needed here.
//!
//! This first cut handles `messaging/ping`; account / acl / access-list follow.
//!
//! [Trust Task]: https://trusttasks.org

use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_mediator_common::types::accounts::{Account, AccountType};
use affinidi_messaging_mediator_common::types::acls::{AccessListModeType, MediatorACLSet};
use affinidi_messaging_sdk::messages::compat::UnpackMetadata;
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use http::StatusCode;
use serde_json::Value;
use std::str::FromStr;
use trust_tasks_rs::specs::messaging::{account, ping};
use trust_tasks_rs::{
    ConsumeOutcome, Payload, ProofPolicy, ProofVerifier, TransportContext, TransportHandler,
    TrustTask, TypeUri, VerificationError, consume_inbound,
};
use uuid::Uuid;

use crate::SharedData;
use crate::common::session::Session;
use crate::messages::protocols::mediator::acls::check_permissions;
use crate::messages::{ProcessMessageResponse, WrapperType};

/// DIDComm `type` URI of a Trust Tasks binding envelope.
pub const ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";
/// Stable identifier for this transport binding.
const BINDING_URI: &str = "https://trusttasks.org/binding/didcomm/0.1";

/// The mediator's [`TransportHandler`] for one inbound exchange. The DIDComm
/// layer already verified the sender, so the framework's transport-authenticated
/// `issuer` is that DID and the `recipient` is the mediator.
struct MediatorTransport {
    mediator_did: String,
    sender_did: String,
}

impl TransportHandler for MediatorTransport {
    fn binding_uri(&self) -> &str {
        BINDING_URI
    }

    fn derive_parties(&self) -> TransportContext {
        TransportContext {
            issuer: Some(self.sender_did.clone()),
            recipient: Some(self.mediator_did.clone()),
        }
    }
}

/// No-op proof verifier — the management tasks are transport-authenticated, so
/// the consume pipeline runs with [`ProofPolicy::AcceptUnverified`] and this is
/// never invoked; it only satisfies the type parameter.
struct NoProof;

#[async_trait::async_trait]
impl ProofVerifier for NoProof {
    async fn verify<P>(&self, _doc: &TrustTask<P>) -> Result<(), VerificationError>
    where
        P: serde::Serialize + Send + Sync,
    {
        Ok(())
    }
}

/// Consume an inbound Trust Tasks envelope and produce the response.
pub(crate) async fn process(
    message: &Message,
    state: &SharedData,
    session: &Session,
    metadata: &UnpackMetadata,
) -> Result<ProcessMessageResponse, MediatorError> {
    let mediator_did = state.config.mediator_did.clone();

    // The DIDComm-verified sender (prefer the JWS signer, fall back to the
    // authcrypt sender), stripped of its key fragment → the framework VID.
    let sender_kid = metadata
        .sign_from
        .clone()
        .or_else(|| metadata.encrypted_from_kid.clone())
        .ok_or_else(|| {
            tt_problem(
                session,
                "message.trust_task.unauthenticated",
                "Trust Task envelopes require an authenticated sender".into(),
                StatusCode::BAD_REQUEST,
            )
        })?;
    let sender_did = sender_kid
        .split('#')
        .next()
        .unwrap_or(&sender_kid)
        .to_string();

    // The body is the full TrustTask document.
    let doc: TrustTask<Value> = serde_json::from_value(message.body.clone()).map_err(|e| {
        tt_problem(
            session,
            "message.trust_task.malformed",
            format!("body is not a Trust Task document: {e}"),
            StatusCode::BAD_REQUEST,
        )
    })?;

    let now_secs = state.clock.unix_secs();
    let now = chrono::DateTime::from_timestamp(now_secs as i64, 0).unwrap_or_else(chrono::Utc::now);

    // Route by task type. (ping + account/get so far; the rest of the
    // account / acl / access-list families extend this chain.)
    let response_value: Value = if doc.type_uri == type_uri_of::<ping::v0_1::Payload>() {
        match consume_ping(downcast(&doc, session)?, &mediator_did, &sender_did, now).await? {
            Some(value) => value,
            // identity_mismatch with no transport sender → emit nothing.
            None => return Ok(ProcessMessageResponse::default()),
        }
    } else if doc.type_uri == type_uri_of::<account::get::v0_1::Payload>() {
        consume_account_get(
            downcast(&doc, session)?,
            state,
            session,
            &Some(sender_kid.clone()),
            &mediator_did,
            now,
        )
        .await?
    } else if doc.type_uri == type_uri_of::<account::list::v0_1::Payload>() {
        consume_account_list(downcast(&doc, session)?, state, session, &mediator_did, now).await?
    } else {
        return Err(tt_problem(
            session,
            "protocol.trust_task.unsupported",
            format!("unsupported Trust Task type: {}", doc.type_uri),
            StatusCode::NOT_IMPLEMENTED,
        ));
    };

    // Pack the response back through the mediator's existing outbound path.
    // `thid` threads it to the request so the caller's live-stream correlates it.
    let response_msg =
        Message::build(Uuid::new_v4().to_string(), ENVELOPE_TYPE.to_string(), response_value)
            .thid(message.id.clone())
            .to(sender_did)
            .from(mediator_did)
            .created_time(now_secs)
            .expires_time(now_secs + 300)
            .finalize();

    Ok(ProcessMessageResponse {
        store_message: true,
        force_live_delivery: false,
        data: WrapperType::Message(Box::new(response_msg)),
        forward_message: false,
    })
}

/// The canonical request type URI of a generated payload `P`.
fn type_uri_of<P: Payload>() -> TypeUri {
    TypeUri::from_str(P::TYPE_URI).expect("generated payload has a valid type URI")
}

/// Re-deserialise a type-erased document into the typed payload `P`.
fn downcast<P: serde::de::DeserializeOwned>(
    doc: &TrustTask<Value>,
    session: &Session,
) -> Result<TrustTask<P>, MediatorError> {
    serde_json::from_value(serde_json::to_value(doc).map_err(serialize_err)?).map_err(|e| {
        tt_problem(
            session,
            "message.trust_task.malformed",
            format!("payload does not match the task type: {e}"),
            StatusCode::BAD_REQUEST,
        )
    })
}

/// Handle `messaging/account/get`: read-only, self-or-admin. Returns the
/// mediator's view of the named account as a `TrustTask<Response>` JSON value.
async fn consume_account_get(
    typed: TrustTask<account::get::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    // Framework basics: addressed to this mediator and not expired.
    typed.validate_basic(now, mediator_did).map_err(|reason| {
        tt_problem(
            session,
            "message.trust_task.rejected",
            format!("Trust Task failed basic validation: {reason:?}"),
            StatusCode::BAD_REQUEST,
        )
    })?;

    // Authz: the caller must be the target account itself, or an admin.
    let target_hash = typed.payload.did.to_string();
    if !check_permissions(
        session,
        std::slice::from_ref(&target_hash),
        state.config.security.block_remote_admin_msgs,
        sender_kid,
    ) {
        return Err(tt_problem(
            session,
            "authorization.account.denied",
            format!("not permitted to read account {target_hash}"),
            StatusCode::FORBIDDEN,
        ));
    }

    let account = state
        .database
        .account_get(&target_hash)
        .await?
        .ok_or_else(|| {
            tt_problem(
                session,
                "account.not_found",
                format!("account {target_hash} not found"),
                StatusCode::NOT_FOUND,
            )
        })?;

    let response = account::get::v0_1::Response {
        account: map_account_get(&account),
        ext: None,
    };
    let response_doc = typed.respond_with(Uuid::new_v4().to_string(), response);
    serde_json::to_value(&response_doc).map_err(serialize_err)
}

/// Handle `messaging/account/list`: admin-only, read-only. Returns one page of the
/// mediator's accounts (with an opaque continuation cursor) as a `TrustTask<Response>`.
async fn consume_account_list(
    typed: TrustTask<account::list::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    typed.validate_basic(now, mediator_did).map_err(|reason| {
        tt_problem(
            session,
            "message.trust_task.rejected",
            format!("Trust Task failed basic validation: {reason:?}"),
            StatusCode::BAD_REQUEST,
        )
    })?;

    // Authz: admin-only (listing every account is an administrative action).
    if !matches!(
        session.account_type,
        AccountType::Admin | AccountType::RootAdmin
    ) {
        return Err(tt_problem(
            session,
            "authorization.admin_required",
            "account/list requires an admin account".to_string(),
            StatusCode::FORBIDDEN,
        ));
    }

    // The wire cursor is an opaque string over the store's numeric cursor.
    let cursor: u32 = typed
        .payload
        .cursor
        .as_ref()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let limit: u32 = typed.payload.limit.map(|n| n.get() as u32).unwrap_or(100);

    let page = state.database.account_list(cursor, limit).await?;
    let accounts = page.accounts.iter().map(map_account_list).collect();
    // The store returns cursor 0 when the listing is exhausted.
    let next_cursor = (page.cursor != 0)
        .then(|| account::list::v0_1::ResponseNextCursor::from_str(&page.cursor.to_string()))
        .transpose()
        .map_err(|e| {
            tt_problem(
                session,
                "account.list.cursor",
                format!("couldn't encode the continuation cursor: {e}"),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })?;

    let response = account::list::v0_1::Response {
        accounts,
        next_cursor,
        ext: None,
    };
    let response_doc = typed.respond_with(Uuid::new_v4().to_string(), response);
    serde_json::to_value(&response_doc).map_err(serialize_err)
}

/// Map the mediator's internal [`Account`] to the wire `account/get` shape.
///
/// The DID is carried as the mediator's account hash — a valid `Vid` per the
/// messaging spec's privacy note (the mediator never holds the full DID). The
/// `u64` ACL bitfield is decoded into the spec's named booleans; `didcommEnabled`
/// / `tspEnabled` have no bitfield slot and are reported as `None`.
fn map_account_get(acc: &Account) -> account::get::v0_1::Account {
    use account::get::v0_1::{
        Account as WireAccount, AccountType as WireType, MediatorAcl, MediatorAclAccessListMode,
        QueueLimits, Vid,
    };

    let acl = MediatorACLSet::from_u64(acc.acls);
    let access_list_mode = match acl.get_access_list_mode().0 {
        AccessListModeType::ExplicitAllow => MediatorAclAccessListMode::ExplicitAllow,
        AccessListModeType::ExplicitDeny => MediatorAclAccessListMode::ExplicitDeny,
    };

    WireAccount {
        did: Vid::from_str(&acc.did_hash).expect("an account hash is a non-empty Vid string"),
        account_type: match acc._type {
            AccountType::Standard => WireType::Standard,
            AccountType::Admin => WireType::Admin,
            AccountType::RootAdmin => WireType::RootAdmin,
            AccountType::Mediator => WireType::Mediator,
            AccountType::Unknown => WireType::Standard,
        },
        acl: MediatorAcl {
            access_list_mode: Some(access_list_mode),
            blocked: Some(acl.get_blocked()),
            local: Some(acl.get_local()),
            send_messages: Some(acl.get_send_messages().0),
            receive_messages: Some(acl.get_receive_messages().0),
            send_forwarded: Some(acl.get_send_forwarded().0),
            receive_forwarded: Some(acl.get_receive_forwarded().0),
            create_invites: Some(acl.get_create_invites().0),
            anon_receive: Some(acl.get_anon_receive().0),
            self_manage_list: Some(acl.get_self_manage_list()),
            self_manage_send_queue_limit: Some(acl.get_self_manage_send_queue_limit()),
            self_manage_receive_queue_limit: Some(acl.get_self_manage_receive_queue_limit()),
            didcomm_enabled: None,
            tsp_enabled: None,
        },
        access_list_count: Some(acc.access_list_count as u64),
        queue_limits: Some(QueueLimits {
            send_queue_limit: acc.queue_send_limit.map(|v| v as i64),
            receive_queue_limit: acc.queue_receive_limit.map(|v| v as i64),
        }),
        send_queue_count: Some(acc.send_queue_count as u64),
        send_queue_bytes: Some(acc.send_queue_bytes),
        receive_queue_count: Some(acc.receive_queue_count as u64),
        receive_queue_bytes: Some(acc.receive_queue_bytes),
    }
}

/// Same mapping as [`map_account_get`] but for the `account/list` module's copy of
/// the shared `Account` type. The two are generated from the one shared schema and
/// are structurally identical, so we reuse the get mapping via a JSON round-trip
/// rather than duplicate the bitfield decode.
fn map_account_list(acc: &Account) -> account::list::v0_1::Account {
    serde_json::from_value(
        serde_json::to_value(map_account_get(acc)).expect("get Account serialises"),
    )
    .expect("get and list Account share the one shared schema")
}

fn tt_problem(
    session: &Session,
    code: &str,
    message: String,
    status: StatusCode,
) -> MediatorError {
    MediatorError::problem(
        37,
        &session.session_id,
        None,
        ProblemReportSorter::Error,
        ProblemReportScope::Protocol,
        code,
        &message,
        vec![],
        status,
    )
}

fn serialize_err(e: serde_json::Error) -> MediatorError {
    MediatorError::InternalError(
        14,
        "NA".to_string(),
        format!("couldn't serialise Trust Task response: {e}"),
    )
}

/// Run the `ping` task through the framework's consume pipeline, returning the
/// response document as JSON (`None` when the framework suppresses the response).
async fn consume_ping(
    doc: TrustTask<ping::v0_1::Payload>,
    mediator_did: &str,
    sender_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<Value>, MediatorError> {
    let transport = MediatorTransport {
        mediator_did: mediator_did.to_string(),
        sender_did: sender_did.to_string(),
    };
    let outcome = consume_inbound(
        &transport,
        ProofPolicy::<NoProof>::AcceptUnverified,
        doc,
        mediator_did,
        now,
        || Uuid::new_v4().to_string(),
        |req, _parties| async move {
            let response = ping::v0_1::Response {
                ext: None,
                nonce: req.payload.nonce.clone(),
                protocols: vec!["didcomm".to_string(), "tsp".to_string()],
                server_time: now,
                status: ping::v0_1::ResponseStatus::Ok,
            };
            Ok(req.respond_with(Uuid::new_v4().to_string(), response))
        },
    )
    .await;

    Ok(match outcome {
        ConsumeOutcome::Handled(resp) => Some(serde_json::to_value(&resp).map_err(serialize_err)?),
        ConsumeOutcome::Rejected(err) => Some(serde_json::to_value(&err).map_err(serialize_err)?),
        ConsumeOutcome::Suppressed => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_rs::TrustTask;

    #[tokio::test]
    async fn ping_consume_returns_ok_and_echoes_nonce() {
        let mut doc = TrustTask::for_payload(
            "urn:uuid:ping-1",
            ping::v0_1::Payload {
                nonce: Some("nonce-xyz".to_string()),
                ext: None,
            },
        );
        doc.issuer = Some("did:example:alice".to_string());
        doc.recipient = Some("did:example:mediator".to_string());

        let value =
            consume_ping(doc, "did:example:mediator", "did:example:alice", chrono::Utc::now())
                .await
                .expect("consume ok")
                .expect("a response, not suppressed");

        let resp: TrustTask<ping::v0_1::Response> =
            serde_json::from_value(value).expect("ping response document");
        assert!(matches!(resp.payload.status, ping::v0_1::ResponseStatus::Ok));
        assert_eq!(resp.payload.nonce.as_deref(), Some("nonce-xyz"));
        assert!(resp.payload.protocols.iter().any(|p| p == "tsp"));
        // respond_with swaps the parties: the mediator answers alice.
        assert_eq!(resp.issuer.as_deref(), Some("did:example:mediator"));
        assert_eq!(resp.recipient.as_deref(), Some("did:example:alice"));
    }
}
