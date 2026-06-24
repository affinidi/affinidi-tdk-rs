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
use affinidi_messaging_mediator_common::types::acls::{
    ACLError, AccessListModeType, MediatorACLSet,
};
use affinidi_messaging_mediator_common::types::administration::AdminAccount as MediatorAdminAccount;
use affinidi_messaging_mediator_common::types::audit::{AuditAction, AuditLogEntry};
use affinidi_messaging_sdk::messages::compat::UnpackMetadata;
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use http::StatusCode;
use serde_json::Value;
use sha256::digest;
use std::str::FromStr;
use subtle::ConstantTimeEq;
use std::collections::HashSet;
use trust_tasks_rs::specs::messaging::{access_list, account, acl, admin, ping};
use trust_tasks_rs::{
    ConsumeOutcome, Payload, ProofPolicy, ProofVerifier, TransportContext, TransportHandler,
    TrustTask, TypeUri, VerificationError, consume_inbound,
};
use uuid::Uuid;

use crate::SharedData;
use crate::common::session::Session;
use crate::messages::protocols::mediator::acls::check_permissions;
use crate::messages::protocols::mediator::record_audit;
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

    // Route by task type across the ping / account / acl / access-list families.
    let sk = Some(sender_kid.clone());
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
    } else if doc.type_uri == type_uri_of::<account::change_queue_limits::v0_1::Payload>() {
        consume_account_change_queue_limits(
            downcast(&doc, session)?,
            state,
            session,
            &Some(sender_kid.clone()),
            &mediator_did,
            now,
        )
        .await?
    } else if doc.type_uri == type_uri_of::<account::remove::v0_1::Payload>() {
        consume_account_remove(
            downcast(&doc, session)?,
            state,
            session,
            &Some(sender_kid.clone()),
            &mediator_did,
            now,
        )
        .await?
    } else if doc.type_uri == type_uri_of::<account::change_type::v0_1::Payload>() {
        consume_account_change_type(downcast(&doc, session)?, state, session, &mediator_did, now)
            .await?
    } else if doc.type_uri == type_uri_of::<account::add::v0_1::Payload>() {
        consume_account_add(downcast(&doc, session)?, state, session, &mediator_did, now).await?
    } else if doc.type_uri == type_uri_of::<acl::get::v0_1::Payload>() {
        consume_acl_get(
            downcast(&doc, session)?,
            state,
            session,
            &Some(sender_kid.clone()),
            &mediator_did,
            now,
        )
        .await?
    } else if doc.type_uri == type_uri_of::<acl::set::v0_1::Payload>() {
        consume_acl_set(downcast(&doc, session)?, state, session, &sk, &mediator_did, now).await?
    } else if doc.type_uri == type_uri_of::<access_list::add::v0_1::Payload>() {
        consume_access_list_add(downcast(&doc, session)?, state, session, &sk, &mediator_did, now)
            .await?
    } else if doc.type_uri == type_uri_of::<access_list::remove::v0_1::Payload>() {
        consume_access_list_remove(
            downcast(&doc, session)?,
            state,
            session,
            &sk,
            &mediator_did,
            now,
        )
        .await?
    } else if doc.type_uri == type_uri_of::<access_list::clear::v0_1::Payload>() {
        consume_access_list_clear(
            downcast(&doc, session)?,
            state,
            session,
            &sk,
            &mediator_did,
            now,
        )
        .await?
    } else if doc.type_uri == type_uri_of::<access_list::get::v0_1::Payload>() {
        consume_access_list_get(downcast(&doc, session)?, state, session, &sk, &mediator_did, now)
            .await?
    } else if doc.type_uri == type_uri_of::<access_list::list::v0_1::Payload>() {
        consume_access_list_list(downcast(&doc, session)?, state, session, &sk, &mediator_did, now)
            .await?
    } else if doc.type_uri == type_uri_of::<admin::add::v0_1::Payload>() {
        consume_admin_add(downcast(&doc, session)?, state, session, &mediator_did, now).await?
    } else if doc.type_uri == type_uri_of::<admin::strip::v0_1::Payload>() {
        consume_admin_strip(downcast(&doc, session)?, state, session, &mediator_did, now).await?
    } else if doc.type_uri == type_uri_of::<admin::list::v0_1::Payload>() {
        consume_admin_list(downcast(&doc, session)?, state, session, &mediator_did, now).await?
    } else if doc.type_uri == type_uri_of::<admin::audit_log::v0_1::Payload>() {
        consume_admin_audit_log(downcast(&doc, session)?, state, session, &mediator_did, now).await?
    } else if doc.type_uri == type_uri_of::<admin::config::v0_1::Payload>() {
        consume_admin_config(downcast(&doc, session)?, state, session, &mediator_did, now).await?
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
    let accounts = page
        .accounts
        .iter()
        .map(to_wire_account::<account::list::v0_1::Account>)
        .collect();
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

/// Handle `messaging/account/change-queue-limits`: self-or-admin. A standard account
/// may only change a limit it is permitted to self-manage, and its values are capped
/// at the mediator's hard maximum; an admin sets any value. Returns the updated view.
async fn consume_account_change_queue_limits(
    typed: TrustTask<account::change_queue_limits::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
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
            format!("not permitted to change queue limits for account {target_hash}"),
            StatusCode::FORBIDDEN,
        ));
    }

    // The wire carries i64; the store works in i32. A member omitted is unchanged.
    let req_send = typed.payload.queue_limits.send_queue_limit.map(|v| v as i32);
    let req_receive = typed.payload.queue_limits.receive_queue_limit.map(|v| v as i32);

    // A standard account may only touch limits it self-manages, capped at the hard
    // maximum; an admin sets any value.
    let (send_queue_limit, receive_queue_limit) =
        if session.account_type == AccountType::Standard {
            (
                gate_self_managed_limit(
                    req_send,
                    session.acls.get_self_manage_send_queue_limit(),
                    state.config.limits.queued_send_messages_hard,
                ),
                gate_self_managed_limit(
                    req_receive,
                    session.acls.get_self_manage_receive_queue_limit(),
                    state.config.limits.queued_receive_messages_hard,
                ),
            )
        } else {
            (req_send, req_receive)
        };

    state
        .database
        .account_change_queue_limits(&target_hash, send_queue_limit, receive_queue_limit)
        .await?;
    record_audit(
        state,
        session,
        &target_hash,
        AuditAction::AccountChangeQueueLimits,
        format!("send={send_queue_limit:?} receive={receive_queue_limit:?}"),
    )
    .await;

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
    let response = account::change_queue_limits::v0_1::Response {
        account: to_wire_account(&account),
        ext: None,
    };
    let response_doc = typed.respond_with(Uuid::new_v4().to_string(), response);
    serde_json::to_value(&response_doc).map_err(serialize_err)
}

/// A standard account may change a queue limit only if it self-manages that limit;
/// the value is capped at the mediator's hard maximum. The `-1` (unlimited) and `-2`
/// sentinels pass through unchanged. Not self-managed → leave the limit unchanged.
fn gate_self_managed_limit(requested: Option<i32>, self_managed: bool, hard: i32) -> Option<i32> {
    if !self_managed {
        return None;
    }
    match requested {
        Some(-1) | Some(-2) => requested,
        Some(limit) if limit > hard => Some(hard),
        other => other,
    }
}

/// Handle `messaging/account/remove`: self-or-admin. Refuses to remove the
/// mediator's own account or the root admin (both compared in constant time).
/// Returns the target id and whether a record was removed.
async fn consume_account_remove(
    typed: TrustTask<account::remove::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
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
            format!("not permitted to remove account {target_hash}"),
            StatusCode::FORBIDDEN,
        ));
    }

    // Never remove the mediator's own account or the root admin.
    let protected = state
        .config
        .mediator_did_hash
        .as_bytes()
        .ct_eq(target_hash.as_bytes())
        .unwrap_u8()
        == 1
        || digest(&state.config.admin_did)
            .as_bytes()
            .ct_eq(target_hash.as_bytes())
            .unwrap_u8()
            == 1;
    if protected {
        return Err(tt_problem(
            session,
            "account.remove.protected",
            "the mediator and root-admin accounts cannot be removed".to_string(),
            StatusCode::FORBIDDEN,
        ));
    }

    let removed = state
        .database
        .account_remove(&session.to_store_session(), &target_hash)
        .await?;
    record_audit(
        state,
        session,
        &target_hash,
        AuditAction::AccountRemove,
        "account removed".to_string(),
    )
    .await;

    let response = account::remove::v0_1::Response {
        did: typed.payload.did.clone(),
        ext: None,
        removed,
    };
    let response_doc = typed.respond_with(Uuid::new_v4().to_string(), response);
    serde_json::to_value(&response_doc).map_err(serialize_err)
}

/// Handle `messaging/account/change-type`: admin-only, with root-admin guards —
/// only a root admin may assign root-admin or modify a root-admin account. A
/// faithful port of the legacy admin-set transitions (promote / demote / switch).
/// Returns the account's realized view after the change.
async fn consume_account_change_type(
    typed: TrustTask<account::change_type::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use account::change_type::v0_1::AccountType as WireType;

    typed.validate_basic(now, mediator_did).map_err(|reason| {
        tt_problem(
            session,
            "message.trust_task.rejected",
            format!("Trust Task failed basic validation: {reason:?}"),
            StatusCode::BAD_REQUEST,
        )
    })?;

    let target_hash = typed.payload.did.to_string();
    let new_type = match typed.payload.account_type {
        WireType::Standard => AccountType::Standard,
        WireType::Admin => AccountType::Admin,
        WireType::RootAdmin => AccountType::RootAdmin,
        WireType::Mediator => AccountType::Mediator,
    };

    let denied = |reason: &str| {
        tt_problem(
            session,
            "authorization.permission",
            reason.to_string(),
            StatusCode::FORBIDDEN,
        )
    };

    // Must be an admin to change types at all.
    if !state.database.check_admin_account(&session.did_hash).await? {
        return Err(denied("admin access is required to change account types"));
    }
    // Only a root admin may assign the root-admin role.
    if new_type == AccountType::RootAdmin && session.account_type != AccountType::RootAdmin {
        return Err(denied("root-admin access is required to assign the root-admin role"));
    }

    let current = state.database.account_get(&target_hash).await?;
    if let Some(current) = &current {
        if current._type == AccountType::RootAdmin && session.account_type != AccountType::RootAdmin
        {
            return Err(denied("root-admin access is required to modify a root-admin account"));
        } else if current._type == new_type {
            // No change — report the account as-is.
            return change_type_response(&typed, current);
        } else if current._type.is_admin() && new_type.is_admin() {
            // Switching between admin roles is a plain set-role (below).
        } else if current._type.is_admin() && !new_type.is_admin() {
            // Demotion — strip admin rights first.
            state
                .database
                .strip_admin_accounts(vec![target_hash.clone()])
                .await?;
        } else if !current._type.is_admin() && new_type.is_admin() {
            // Promotion — add admin rights, carrying the existing ACL set.
            state
                .database
                .setup_admin_account(&target_hash, new_type, &MediatorACLSet::from_u64(current.acls))
                .await?;
            record_audit(
                state,
                session,
                &target_hash,
                AuditAction::AccountChangeType,
                format!("type -> {new_type}"),
            )
            .await;
            return change_type_fetch_response(&typed, state, session, &target_hash).await;
        }
    }

    state
        .database
        .account_set_role(&target_hash, &new_type)
        .await?;
    record_audit(
        state,
        session,
        &target_hash,
        AuditAction::AccountChangeType,
        format!("type -> {new_type}"),
    )
    .await;
    change_type_fetch_response(&typed, state, session, &target_hash).await
}

/// Build a `change-type` response from an account.
fn change_type_response(
    typed: &TrustTask<account::change_type::v0_1::Payload>,
    account: &Account,
) -> Result<Value, MediatorError> {
    let response = account::change_type::v0_1::Response {
        account: to_wire_account(account),
        ext: None,
    };
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Re-read the account after a change and build the `change-type` response.
async fn change_type_fetch_response(
    typed: &TrustTask<account::change_type::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    target_hash: &str,
) -> Result<Value, MediatorError> {
    let account = state
        .database
        .account_get(target_hash)
        .await?
        .ok_or_else(|| {
            tt_problem(
                session,
                "account.not_found",
                format!("account {target_hash} not found after change"),
                StatusCode::NOT_FOUND,
            )
        })?;
    change_type_response(typed, &account)
}

/// Handle `messaging/account/add`. In `ExplicitAllow` mode only an admin may add
/// accounts; in `ExplicitDeny` mode any authenticated account may. An admin may
/// supply the new account's ACL (applied onto the mediator default); a non-admin
/// gets the default. Creating an admin / root-admin account requires admin /
/// root-admin rights. Returns the created account's realized view.
async fn consume_account_add(
    typed: TrustTask<account::add::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use account::add::v0_1::AccountType as WireType;

    typed.validate_basic(now, mediator_did).map_err(|reason| {
        tt_problem(
            session,
            "message.trust_task.rejected",
            format!("Trust Task failed basic validation: {reason:?}"),
            StatusCode::BAD_REQUEST,
        )
    })?;

    let target_hash = typed.payload.did.to_string();
    let new_type = match typed.payload.account_type {
        WireType::Standard => AccountType::Standard,
        WireType::Admin => AccountType::Admin,
        WireType::RootAdmin => AccountType::RootAdmin,
        WireType::Mediator => AccountType::Mediator,
    };
    let is_admin = matches!(
        session.account_type,
        AccountType::Admin | AccountType::RootAdmin
    );

    let denied = |reason: &str| {
        tt_problem(
            session,
            "authorization.permission",
            reason.to_string(),
            StatusCode::FORBIDDEN,
        )
    };

    // In allowlist mode only admins may add accounts.
    if state.config.security.mediator_acl_mode == AccessListModeType::ExplicitAllow && !is_admin {
        return Err(denied("admin access is required to add accounts"));
    }
    // Creating a privileged account requires the matching privilege.
    if new_type == AccountType::RootAdmin && session.account_type != AccountType::RootAdmin {
        return Err(denied("root-admin access is required to create a root-admin account"));
    }
    if new_type.is_admin() && !is_admin {
        return Err(denied("admin access is required to create an admin account"));
    }

    // ACLs: an admin may supply them (applied onto the mediator default); a non-admin
    // always gets the default.
    let acls = match (is_admin, &typed.payload.acl) {
        (true, Some(acl)) => merge_wire_acl(
            serde_json::to_value(acl).map_err(serialize_err)?,
            state.config.security.global_acl_default.clone(),
        )?,
        _ => state.config.security.global_acl_default.clone(),
    };

    let account = state.database.account_add(&target_hash, &acls, None).await?;
    // Apply a non-standard role if requested (the guards above already authorized it).
    let account = if new_type != AccountType::Standard {
        state
            .database
            .account_set_role(&target_hash, &new_type)
            .await?;
        state
            .database
            .account_get(&target_hash)
            .await?
            .unwrap_or(account)
    } else {
        account
    };

    record_audit(
        state,
        session,
        &target_hash,
        AuditAction::AccountAdd,
        "account created".to_string(),
    )
    .await;

    let response = account::add::v0_1::Response {
        account: to_wire_account(&account),
        ext: None,
    };
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Handle `messaging/acl/get`: self-or-admin, read-only, batched. Returns one entry
/// per known DID and lists any unknown DIDs separately.
async fn consume_acl_get(
    typed: TrustTask<acl::get::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use acl::get::v0_1::{Entry, Response, Vid};

    typed.validate_basic(now, mediator_did).map_err(|reason| {
        tt_problem(
            session,
            "message.trust_task.rejected",
            format!("Trust Task failed basic validation: {reason:?}"),
            StatusCode::BAD_REQUEST,
        )
    })?;

    let dids: Vec<String> = typed.payload.dids.iter().map(|v| v.to_string()).collect();
    if !check_permissions(
        session,
        &dids,
        state.config.security.block_remote_admin_msgs,
        sender_kid,
    ) {
        return Err(tt_problem(
            session,
            "authorization.account.denied",
            "not permitted to read one or more of the requested ACLs".to_string(),
            StatusCode::FORBIDDEN,
        ));
    }

    let mut entries = Vec::new();
    let mut unknown = Vec::new();
    for did in &dids {
        let vid = Vid::from_str(did).expect("a requested DID is a valid Vid");
        match state.database.get_did_acl(did).await? {
            Some(aclset) => entries.push(Entry {
                acl: to_wire_acl(&aclset),
                did: vid,
            }),
            None => unknown.push(vid),
        }
    }

    let response = Response {
        entries,
        ext: None,
        unknown,
    };
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Handle `messaging/acl/set`: admin-only. Applies the wire ACL as a partial update
/// onto the account's current ACL (the reverse map preserves the per-capability
/// change bits) and returns the realized ACL. Non-admin self-service ACL changes are
/// not supported here — they are refused.
async fn consume_acl_set(
    typed: TrustTask<acl::set::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    validate_tt_basic(&typed, session, mediator_did, now)?;

    let target_hash = typed.payload.did.to_string();
    let is_admin = matches!(
        session.account_type,
        AccountType::Admin | AccountType::RootAdmin
    );

    // Self-or-admin: a non-admin may only set its own ACL.
    if !check_permissions(
        session,
        std::slice::from_ref(&target_hash),
        state.config.security.block_remote_admin_msgs,
        sender_kid,
    ) {
        return Err(tt_problem(
            session,
            "authorization.account.denied",
            format!("not permitted to set the ACL for {target_hash}"),
            StatusCode::FORBIDDEN,
        ));
    }

    let base = state
        .database
        .get_did_acl(&target_hash)
        .await?
        .unwrap_or_default();
    let acl_value = serde_json::to_value(&typed.payload.acl).map_err(serialize_err)?;

    // A non-admin may only change flags it is permitted to self-manage.
    if !is_admin {
        ensure_self_manageable(&acl_value, &base, session)?;
    }

    let merged = merge_wire_acl(acl_value, base)?;

    let stored = state.database.set_did_acl(&target_hash, &merged).await?;
    record_audit(
        state,
        session,
        &target_hash,
        AuditAction::SetAcl,
        format!("acl -> {:#018x}", stored.to_u64()),
    )
    .await;

    let response = acl::set::v0_1::Response {
        acl: to_wire_acl(&stored),
        did: typed.payload.did.clone(),
        ext: None,
    };
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Access-list authz: self-or-admin for the target, plus the `self_manage_list`
/// capability for a standard account performing a write.
fn authorize_access_list(
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    target_hash: &str,
    write: bool,
) -> Result<(), MediatorError> {
    if !check_permissions(
        session,
        std::slice::from_ref(&target_hash.to_string()),
        state.config.security.block_remote_admin_msgs,
        sender_kid,
    ) {
        return Err(tt_problem(
            session,
            "authorization.account.denied",
            format!("not permitted to access the access list for {target_hash}"),
            StatusCode::FORBIDDEN,
        ));
    }
    if write
        && session.account_type == AccountType::Standard
        && !session.acls.get_self_manage_list()
    {
        return Err(tt_problem(
            session,
            "authorization.account.denied",
            "this account may not self-manage its access list".to_string(),
            StatusCode::FORBIDDEN,
        ));
    }
    Ok(())
}

/// The current size of a DID's access list (0 if the account is unknown).
async fn access_list_count(state: &SharedData, target_hash: &str) -> u64 {
    state
        .database
        .account_get(target_hash)
        .await
        .ok()
        .flatten()
        .map(|a| a.access_list_count as u64)
        .unwrap_or(0)
}

/// Gate a non-admin `acl/set`: a standard account may change a capability only when
/// its per-capability self-change bit is set, and may never touch the admin-only flags
/// (`blocked`, `local`, the `selfManage*` bits). A flag whose requested value equals
/// the current value is not a change. Faithful to the legacy `acls_set` self-service
/// rules.
fn ensure_self_manageable(
    acl_value: &Value,
    base: &MediatorACLSet,
    session: &Session,
) -> Result<(), MediatorError> {
    let req: account::get::v0_1::MediatorAcl = serde_json::from_value(acl_value.clone())
        .map_err(|e| serialize_err_msg(format!("invalid ACL payload: {e}")))?;
    let cur = decode_acl_canonical(base);
    let deny = |flag: &str| -> Result<(), MediatorError> {
        Err(tt_problem(
            session,
            "authorization.acl.not_self_manageable",
            format!("this account may not change `{flag}`"),
            StatusCode::FORBIDDEN,
        ))
    };

    // Capabilities self-manageable when the account's self-change bit is set.
    if req.access_list_mode.is_some()
        && req.access_list_mode != cur.access_list_mode
        && !base.get_access_list_mode().1
    {
        return deny("accessListMode");
    }
    if req.send_messages.is_some()
        && req.send_messages != cur.send_messages
        && !base.get_send_messages().1
    {
        return deny("sendMessages");
    }
    if req.receive_messages.is_some()
        && req.receive_messages != cur.receive_messages
        && !base.get_receive_messages().1
    {
        return deny("receiveMessages");
    }
    if req.send_forwarded.is_some()
        && req.send_forwarded != cur.send_forwarded
        && !base.get_send_forwarded().1
    {
        return deny("sendForwarded");
    }
    if req.receive_forwarded.is_some()
        && req.receive_forwarded != cur.receive_forwarded
        && !base.get_receive_forwarded().1
    {
        return deny("receiveForwarded");
    }
    if req.create_invites.is_some()
        && req.create_invites != cur.create_invites
        && !base.get_create_invites().1
    {
        return deny("createInvites");
    }
    if req.anon_receive.is_some()
        && req.anon_receive != cur.anon_receive
        && !base.get_anon_receive().1
    {
        return deny("anonReceive");
    }

    // Admin-only flags: a non-admin may never change these.
    if req.blocked.is_some() && req.blocked != cur.blocked {
        return deny("blocked");
    }
    if req.local.is_some() && req.local != cur.local {
        return deny("local");
    }
    if req.self_manage_list.is_some() && req.self_manage_list != cur.self_manage_list {
        return deny("selfManageList");
    }
    if req.self_manage_send_queue_limit.is_some()
        && req.self_manage_send_queue_limit != cur.self_manage_send_queue_limit
    {
        return deny("selfManageSendQueueLimit");
    }
    if req.self_manage_receive_queue_limit.is_some()
        && req.self_manage_receive_queue_limit != cur.self_manage_receive_queue_limit
    {
        return deny("selfManageReceiveQueueLimit");
    }

    Ok(())
}

/// Handle `messaging/access-list/add`: self-or-admin (+ `self_manage_list` for a
/// standard account). Adds entries (truncated at the mediator limit); reports those
/// actually inserted and the new count.
async fn consume_access_list_add(
    typed: TrustTask<access_list::add::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use access_list::add::v0_1::{Response, Vid};
    validate_tt_basic(&typed, session, mediator_did, now)?;
    let target_hash = typed.payload.did.to_string();
    authorize_access_list(state, session, sender_kid, &target_hash, true)?;

    let hashes: Vec<String> = typed.payload.entries.iter().map(|v| v.to_string()).collect();
    let result = state
        .database
        .access_list_add(state.config.limits.access_list_limit, &target_hash, &hashes)
        .await?;
    record_audit(
        state,
        session,
        &target_hash,
        AuditAction::AccessListAdd,
        format!("added {} entries", result.did_hashes.len()),
    )
    .await;

    let added = result
        .did_hashes
        .iter()
        .map(|h| Vid::from_str(h).expect("a stored hash is a valid Vid"))
        .collect();
    let response = Response {
        access_list_count: access_list_count(state, &target_hash).await,
        added,
        did: typed.payload.did.clone(),
        ext: None,
    };
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Handle `messaging/access-list/remove`: self-or-admin (+ `self_manage_list`).
/// Reports which of the requested entries were present (and thus removed).
async fn consume_access_list_remove(
    typed: TrustTask<access_list::remove::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use access_list::remove::v0_1::{Response, Vid};
    validate_tt_basic(&typed, session, mediator_did, now)?;
    let target_hash = typed.payload.did.to_string();
    authorize_access_list(state, session, sender_kid, &target_hash, true)?;

    let hashes: Vec<String> = typed.payload.entries.iter().map(|v| v.to_string()).collect();
    // Those present before removal are exactly those removed.
    let present = state.database.access_list_get(&target_hash, &hashes).await?.did_hashes;
    state.database.access_list_remove(&target_hash, &hashes).await?;
    record_audit(
        state,
        session,
        &target_hash,
        AuditAction::AccessListRemove,
        format!("removed {} entries", present.len()),
    )
    .await;

    let removed = present
        .iter()
        .map(|h| Vid::from_str(h).expect("a stored hash is a valid Vid"))
        .collect();
    let response = Response {
        access_list_count: access_list_count(state, &target_hash).await,
        did: typed.payload.did.clone(),
        ext: None,
        removed,
    };
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Handle `messaging/access-list/clear`: self-or-admin (+ `self_manage_list`).
async fn consume_access_list_clear(
    typed: TrustTask<access_list::clear::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    validate_tt_basic(&typed, session, mediator_did, now)?;
    let target_hash = typed.payload.did.to_string();
    authorize_access_list(state, session, sender_kid, &target_hash, true)?;

    state.database.access_list_clear(&target_hash).await?;
    record_audit(
        state,
        session,
        &target_hash,
        AuditAction::AccessListClear,
        "access list cleared".to_string(),
    )
    .await;

    let response = access_list::clear::v0_1::Response {
        access_list_count: access_list_count(state, &target_hash).await,
        did: typed.payload.did.clone(),
        ext: None,
    };
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Handle `messaging/access-list/get`: self-or-admin, read-only. Partitions the
/// requested entries into those present in the list and those absent.
async fn consume_access_list_get(
    typed: TrustTask<access_list::get::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use access_list::get::v0_1::Response;
    validate_tt_basic(&typed, session, mediator_did, now)?;
    let target_hash = typed.payload.did.to_string();
    authorize_access_list(state, session, sender_kid, &target_hash, false)?;

    let hashes: Vec<String> = typed.payload.entries.iter().map(|v| v.to_string()).collect();
    let present: HashSet<String> = state
        .database
        .access_list_get(&target_hash, &hashes)
        .await?
        .did_hashes
        .into_iter()
        .collect();

    let mut present_vids = Vec::new();
    let mut absent_vids = Vec::new();
    for v in &typed.payload.entries {
        if present.contains(v.as_str()) {
            present_vids.push(v.clone());
        } else {
            absent_vids.push(v.clone());
        }
    }

    let response = Response {
        absent: absent_vids,
        did: typed.payload.did.clone(),
        ext: None,
        present: present_vids,
    };
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Handle `messaging/access-list/list`: self-or-admin, read-only, cursor-paged.
async fn consume_access_list_list(
    typed: TrustTask<access_list::list::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    sender_kid: &Option<String>,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use access_list::list::v0_1::{Response, ResponseNextCursor, Vid};
    validate_tt_basic(&typed, session, mediator_did, now)?;
    let target_hash = typed.payload.did.to_string();
    authorize_access_list(state, session, sender_kid, &target_hash, false)?;

    let cursor: u64 = typed
        .payload
        .cursor
        .as_ref()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let page = state.database.access_list_list(&target_hash, cursor).await?;
    let entries = page
        .did_hashes
        .iter()
        .map(|h| Vid::from_str(h).expect("a stored hash is a valid Vid"))
        .collect();
    // Both `None` and `Some(0)` mean the listing is exhausted.
    let next_cursor = match page.cursor {
        None | Some(0) => None,
        Some(c) => Some(
            ResponseNextCursor::from_str(&c.to_string())
                .map_err(|e| serialize_err_msg(format!("cursor: {e}")))?,
        ),
    };

    let response = Response {
        access_list_count: access_list_count(state, &target_hash).await,
        did: typed.payload.did.clone(),
        entries,
        ext: None,
        next_cursor,
    };
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Reject a non-admin caller of an admin-only task.
fn require_admin(session: &Session, task: &str) -> Result<(), MediatorError> {
    if matches!(
        session.account_type,
        AccountType::Admin | AccountType::RootAdmin
    ) {
        Ok(())
    } else {
        Err(tt_problem(
            session,
            "authorization.admin_required",
            format!("{task} requires an admin account"),
            StatusCode::FORBIDDEN,
        ))
    }
}

/// Handle `messaging/admin/add`: admin-only. Grants admin rights to the named
/// accounts (with the mediator's default ACL) and echoes the now-admin set.
async fn consume_admin_add(
    typed: TrustTask<admin::add::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    validate_tt_basic(&typed, session, mediator_did, now)?;
    require_admin(session, "admin/add")?;

    let dids: Vec<String> = typed.payload.dids.iter().map(|v| v.to_string()).collect();
    state
        .database
        .add_admin_accounts(dids.clone(), &state.config.security.global_acl_default)
        .await?;
    for did in &dids {
        record_audit(state, session, did, AuditAction::AdminAdd, "promoted to admin".to_string()).await;
    }

    let response = admin::add::v0_1::Response {
        admins: typed.payload.dids.clone(),
        ext: None,
    };
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Handle `messaging/admin/strip`: admin-only. Removes admin rights from the named
/// accounts (demoting them to standard) and echoes the stripped set.
async fn consume_admin_strip(
    typed: TrustTask<admin::strip::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    validate_tt_basic(&typed, session, mediator_did, now)?;
    require_admin(session, "admin/strip")?;

    let dids: Vec<String> = typed.payload.dids.iter().map(|v| v.to_string()).collect();
    state.database.strip_admin_accounts(dids.clone()).await?;
    for did in &dids {
        record_audit(state, session, did, AuditAction::AdminStrip, "admin rights stripped".to_string())
            .await;
    }

    let response = admin::strip::v0_1::Response {
        ext: None,
        stripped: typed.payload.dids.clone(),
    };
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Handle `messaging/admin/list`: admin-only. Pages the mediator's admin accounts.
async fn consume_admin_list(
    typed: TrustTask<admin::list::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use admin::list::v0_1::{Response, ResponseNextCursor};
    validate_tt_basic(&typed, session, mediator_did, now)?;
    require_admin(session, "admin/list")?;

    let cursor: u32 = typed
        .payload
        .cursor
        .as_ref()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let limit: u32 = typed.payload.limit.map(|n| n.get() as u32).unwrap_or(100);

    let page = state.database.list_admin_accounts(cursor, limit).await?;
    let admins = page.accounts.iter().map(map_admin_account).collect();
    let next_cursor = (page.cursor != 0)
        .then(|| ResponseNextCursor::from_str(&page.cursor.to_string()))
        .transpose()
        .map_err(|e| serialize_err_msg(format!("cursor: {e}")))?;

    let response = Response {
        admins,
        ext: None,
        next_cursor,
    };
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Handle `messaging/admin/audit-log`: admin-only. Pages the privileged-change log.
async fn consume_admin_audit_log(
    typed: TrustTask<admin::audit_log::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    use admin::audit_log::v0_1::{Response, ResponseNextCursor};
    validate_tt_basic(&typed, session, mediator_did, now)?;
    require_admin(session, "admin/audit-log")?;

    let cursor: u32 = typed
        .payload
        .cursor
        .as_ref()
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let limit: u32 = typed.payload.limit.map(|n| n.get() as u32).unwrap_or(100);

    let page = state.database.audit_log_list(cursor, limit).await?;
    let entries = page.entries.iter().map(map_audit_entry).collect();
    let next_cursor = (page.cursor != 0)
        .then(|| ResponseNextCursor::from_str(&page.cursor.to_string()))
        .transpose()
        .map_err(|e| serialize_err_msg(format!("cursor: {e}")))?;

    let response = Response {
        entries,
        ext: None,
        next_cursor,
    };
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

/// Handle `messaging/admin/config`: admin-only. Returns the mediator's software
/// version and current configuration.
async fn consume_admin_config(
    typed: TrustTask<admin::config::v0_1::Payload>,
    state: &SharedData,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Value, MediatorError> {
    validate_tt_basic(&typed, session, mediator_did, now)?;
    require_admin(session, "admin/config")?;

    let config = serde_json::to_value(&state.config)
        .map_err(serialize_err)?
        .as_object()
        .cloned()
        .unwrap_or_default();
    let response = admin::config::v0_1::Response {
        config,
        ext: None,
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    serde_json::to_value(typed.respond_with(Uuid::new_v4().to_string(), response))
        .map_err(serialize_err)
}

fn map_admin_account(a: &MediatorAdminAccount) -> admin::list::v0_1::AdminAccount {
    use admin::list::v0_1::{AccountType as WireType, AdminAccount as Wire, Vid};
    Wire {
        account_type: match a._type {
            AccountType::Standard => WireType::Standard,
            AccountType::Admin => WireType::Admin,
            AccountType::RootAdmin => WireType::RootAdmin,
            AccountType::Mediator => WireType::Mediator,
            AccountType::Unknown => WireType::Standard,
        },
        did: Vid::from_str(&a.did_hash).expect("an account hash is a valid Vid"),
    }
}

fn map_audit_entry(e: &AuditLogEntry) -> admin::audit_log::v0_1::AuditEntry {
    use admin::audit_log::v0_1::{AuditEntry as Wire, Vid};
    Wire {
        action: map_audit_action(e.action),
        actor: Vid::from_str(&e.actor_did_hash).expect("an account hash is a valid Vid"),
        detail: Some(e.detail.clone()),
        target: Vid::from_str(&e.target_did_hash).expect("an account hash is a valid Vid"),
        timestamp: e.timestamp,
    }
}

fn map_audit_action(a: AuditAction) -> admin::audit_log::v0_1::AuditAction {
    use admin::audit_log::v0_1::AuditAction as W;
    match a {
        AuditAction::SetAcl => W::SetAcl,
        AuditAction::AccessListAdd => W::AccessListAdd,
        AuditAction::AccessListRemove => W::AccessListRemove,
        AuditAction::AccessListClear => W::AccessListClear,
        AuditAction::AccountAdd => W::AccountAdd,
        AuditAction::AccountRemove => W::AccountRemove,
        AuditAction::AccountChangeType => W::AccountChangeType,
        AuditAction::AccountChangeQueueLimits => W::AccountChangeQueueLimits,
        AuditAction::AdminAdd => W::AdminAdd,
        AuditAction::AdminStrip => W::AdminStrip,
    }
}

/// Map the mediator's internal [`Account`] to the wire `account/get` shape.
///
/// The DID is carried as the mediator's account hash — a valid `Vid` per the
/// messaging spec's privacy note (the mediator never holds the full DID). The
/// `u64` ACL bitfield is decoded into the spec's named booleans; `didcommEnabled`
/// / `tspEnabled` have no bitfield slot and are reported as `None`.
fn map_account_get(acc: &Account) -> account::get::v0_1::Account {
    use account::get::v0_1::{Account as WireAccount, AccountType as WireType, QueueLimits, Vid};

    WireAccount {
        did: Vid::from_str(&acc.did_hash).expect("an account hash is a non-empty Vid string"),
        account_type: match acc._type {
            AccountType::Standard => WireType::Standard,
            AccountType::Admin => WireType::Admin,
            AccountType::RootAdmin => WireType::RootAdmin,
            AccountType::Mediator => WireType::Mediator,
            AccountType::Unknown => WireType::Standard,
        },
        acl: decode_acl_canonical(&MediatorACLSet::from_u64(acc.acls)),
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

/// Re-shape [`map_account_get`]'s output into another `messaging/*` module's copy of
/// the shared `Account` type. typify generates a structurally-identical `Account`
/// per spec module; they all derive from the one shared schema, so a JSON round-trip
/// converts between them without re-implementing the bitfield decode.
fn decode_acl_canonical(acl: &MediatorACLSet) -> account::get::v0_1::MediatorAcl {
    use account::get::v0_1::{MediatorAcl, MediatorAclAccessListMode};
    MediatorAcl {
        access_list_mode: Some(match acl.get_access_list_mode().0 {
            AccessListModeType::ExplicitAllow => MediatorAclAccessListMode::ExplicitAllow,
            AccessListModeType::ExplicitDeny => MediatorAclAccessListMode::ExplicitDeny,
        }),
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
    }
}

/// Decode an ACL set into any `messaging/*` module's copy of `MediatorAcl`.
fn to_wire_acl<T: serde::de::DeserializeOwned>(acl: &MediatorACLSet) -> T {
    serde_json::from_value(serde_json::to_value(decode_acl_canonical(acl)).expect("acl serialises"))
        .expect("messaging MediatorAcl types share the one shared schema")
}

/// Apply a wire `MediatorAcl` (from any module, passed as JSON) onto a base ACL set
/// as a **partial update**: each present value flag is set; absent flags and the
/// per-capability "self-change" bits — which the wire form does not carry — are left
/// as they are in `base`. `didcommEnabled`/`tspEnabled` have no bitfield slot and are
/// ignored. This is the reverse of [`decode_acl_canonical`].
fn merge_wire_acl(acl_value: Value, mut base: MediatorACLSet) -> Result<MediatorACLSet, MediatorError> {
    use account::get::v0_1::{MediatorAcl, MediatorAclAccessListMode};
    let acl: MediatorAcl = serde_json::from_value(acl_value).map_err(|e| {
        MediatorError::InternalError(14, "NA".to_string(), format!("invalid ACL payload: {e}"))
    })?;
    let acl_err =
        |e: ACLError| MediatorError::InternalError(14, "NA".to_string(), format!("ACL update rejected: {e}"));

    if let Some(mode) = acl.access_list_mode {
        let mode = match mode {
            MediatorAclAccessListMode::ExplicitAllow => AccessListModeType::ExplicitAllow,
            MediatorAclAccessListMode::ExplicitDeny => AccessListModeType::ExplicitDeny,
        };
        let self_change = base.get_access_list_mode().1;
        base.set_access_list_mode(mode, self_change, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.blocked {
        base.set_blocked(v);
    }
    if let Some(v) = acl.local {
        base.set_local(v);
    }
    if let Some(v) = acl.send_messages {
        let sc = base.get_send_messages().1;
        base.set_send_messages(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.receive_messages {
        let sc = base.get_receive_messages().1;
        base.set_receive_messages(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.send_forwarded {
        let sc = base.get_send_forwarded().1;
        base.set_send_forwarded(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.receive_forwarded {
        let sc = base.get_receive_forwarded().1;
        base.set_receive_forwarded(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.create_invites {
        let sc = base.get_create_invites().1;
        base.set_create_invites(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.anon_receive {
        let sc = base.get_anon_receive().1;
        base.set_anon_receive(v, sc, true).map_err(acl_err)?;
    }
    if let Some(v) = acl.self_manage_list {
        base.set_self_manage_list(v);
    }
    if let Some(v) = acl.self_manage_send_queue_limit {
        base.set_self_manage_send_queue_limit(v);
    }
    if let Some(v) = acl.self_manage_receive_queue_limit {
        base.set_self_manage_receive_queue_limit(v);
    }
    Ok(base)
}

fn to_wire_account<T: serde::de::DeserializeOwned>(acc: &Account) -> T {
    serde_json::from_value(serde_json::to_value(map_account_get(acc)).expect("get Account serialises"))
        .expect("messaging Account types share the one shared schema")
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

/// Framework basics: the request is addressed to this mediator and not expired.
fn validate_tt_basic<P>(
    typed: &TrustTask<P>,
    session: &Session,
    mediator_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), MediatorError> {
    typed.validate_basic(now, mediator_did).map_err(|reason| {
        tt_problem(
            session,
            "message.trust_task.rejected",
            format!("Trust Task failed basic validation: {reason:?}"),
            StatusCode::BAD_REQUEST,
        )
    })
}

fn serialize_err_msg(msg: String) -> MediatorError {
    MediatorError::InternalError(14, "NA".to_string(), msg)
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

    /// The reverse ACL map (`merge_wire_acl`) must exactly invert the decode
    /// (`decode_acl_canonical`): decoding a bitfield to the wire form and merging it
    /// back onto the same base must reproduce the original `u64`. Covers the value
    /// bits, the preserved per-capability change bits, and the self-manage flags.
    #[test]
    fn acl_reverse_map_round_trips() {
        let cases = [
            MediatorACLSet::default().to_u64(),
            MediatorACLSet::from_string_ruleset("ALLOW_ALL")
                .expect("ALLOW_ALL ruleset")
                .to_u64(),
            MediatorACLSet::from_string_ruleset("DENY_ALL")
                .expect("DENY_ALL ruleset")
                .to_u64(),
            MediatorACLSet::from_string_ruleset("ALLOW_ALL, ALLOW_ALL_SELF_CHANGE")
                .expect("mixed ruleset")
                .to_u64(),
        ];
        for bits in cases {
            let decoded = decode_acl_canonical(&MediatorACLSet::from_u64(bits));
            let value = serde_json::to_value(&decoded).expect("acl serialises");
            let merged = merge_wire_acl(value, MediatorACLSet::from_u64(bits))
                .expect("merge succeeds");
            assert_eq!(
                merged.to_u64(),
                bits,
                "decode→merge must reproduce {bits:#018x}"
            );
        }
    }
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
