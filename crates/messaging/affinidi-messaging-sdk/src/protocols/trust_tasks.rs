//! Trust Tasks client — send the messaging [Trust Tasks] to a mediator and get
//! the typed response.
//!
//! Accessed via [`crate::ATM::trust_tasks`]. Each task is a typed `TrustTask<P>`
//! document carried over the DIDComm binding envelope (a DIDComm message whose
//! `type` is the [`ENVELOPE_TYPE`] and whose `body` is the document). The mediator
//! consumes it through the Trust Tasks framework and returns a `TrustTask<R>`.
//!
//! This is the **rationalized** `messaging/*` surface (19 → 9 active tasks,
//! affinidi/affinidi-tdk-rs#667): partial updates go through `account_update`
//! (role + capabilities + queue limits in one task, superseding
//! `change-type` / `change-queue-limits` / `acl/set` / `admin/add` / `admin/strip`)
//! and `access_list_update` (`clear` → `add` → `remove`, superseding the three
//! single-verb writers); role-filtered `account_list` supersedes `admin/list`;
//! the `entries` membership filter on `access_list_list` supersedes
//! `access-list/get`; and the generic `audit/list` / `config/show` tasks replace
//! `admin/audit-log` / `admin/config`.
//!
//! [Trust Tasks]: https://trusttasks.org
//!
//! `ping`, `account/{get,list,add,update}`, `audit/list` and `message/status`
//! are spoken at 0.2, falling back to 0.1 for a mediator that predates 0.2
//! (see [`trust_task_versions`](super::trust_task_versions)); callers only see
//! the 0.2 types. The other tasks have no 0.2.
//!
//! `monitor/subscribe` is spoken at 0.1 ([`TrustTasksOps::monitor_subscribe`])
//! and at 0.2 ([`TrustTasksOps::monitor_subscribe_with`], which adds mux
//! membership events). [`decode_monitor_event`] decodes every batch at 0.2,
//! traffic only; [`decode_monitor_event_v0_3`] decodes every batch at 0.3,
//! with its membership events. Older batches are converted to either.

use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use crate::tasks::messaging::{access_list, account, acl, message, monitor, ping, queue, stats};
use crate::tasks::{audit, config};
use affinidi_did_common::DocumentExt;
use affinidi_messaging_didcomm::message::Message;
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_secrets_resolver::secrets::{KeyType, Secret};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha256::digest;
use tracing::warn;
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use trust_tasks_rs::TrustTask;
use uuid::Uuid;

#[cfg(feature = "tsp")]
use crate::protocols::trust_task_versions::StatusGate;
use crate::protocols::trust_task_versions::{
    Current, MediatorSpeaks, is_unsupported_error, speaks_from_version,
};
use crate::{ATM, errors::ATMError, profiles::ATMProfile, transports::SendMessageResponse};

/// DIDComm `type` URI of a Trust Tasks binding envelope.
pub const ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";

/// Top-level member of a Trust Task request asking the mediator to report a
/// refusal with a `trust-task-error` document (Trust Tasks SPEC §8) rather
/// than a DIDComm problem report. Every request this SDK sends carries it,
/// with the value [`ERROR_FORMAT_DOCUMENT`]; a mediator that predates it
/// ignores it (SPEC §4.2 allows additional top-level members) and answers
/// with problem reports as before. Either way the failure is an [`ATMError`]:
/// [`ATMError::TrustTaskError`] or [`ATMError::ProblemReport`].
pub const ERROR_FORMAT_MEMBER: &str = "x-errorFormat";

/// The value of [`ERROR_FORMAT_MEMBER`] that asks for `trust-task-error`
/// documents.
pub const ERROR_FORMAT_DOCUMENT: &str = "trust-task-error";

/// Trust Tasks client operations, obtained from [`crate::ATM::trust_tasks`].
pub struct TrustTasksOps<'a> {
    pub(crate) atm: &'a ATM,
}

/// Finish a generated payload builder.
///
/// trust-tasks-rs 0.17 made the generated payload structs `#[non_exhaustive]`,
/// so a downstream crate can no longer name every member in a struct literal.
/// That is the point of the change: the registry can add an OPTIONAL member to
/// a payload without it being a breaking change for every consumer that had
/// spelled out the old member list.
///
/// The cost is that "is every required member set?" moves from compile time to
/// this conversion. The builder starts each required member as
/// `Err("no value supplied for …")`, so a member this crate forgets to set
/// becomes an `ATMError` at send time rather than a compile error — which is
/// why every call below sets its required members explicitly and lets only the
/// optional ones default.
fn payload<P, B>(builder: B) -> Result<P, ATMError>
where
    B: TryInto<P>,
    B::Error: std::fmt::Display,
{
    builder
        .try_into()
        .map_err(|e| ATMError::MsgSendError(format!("invalid trust-task payload: {e}")))
}

impl TrustTasksOps<'_> {
    /// Send a `messaging/ping` Trust Task to the mediator and return its response
    /// (server time, status, and the protocols the mediator supports). An optional
    /// `nonce` is echoed back, letting the caller correlate the reply.
    pub async fn ping(
        &self,
        profile: &Arc<ATMProfile>,
        nonce: Option<String>,
    ) -> Result<ping::v0_2::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let p: ping::v0_2::Payload = payload(ping::v0_2::Payload::builder().nonce(nonce))?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<ping::v0_2::Response> =
            self.exchange_current(profile, task, Current::Ping).await?;
        Ok(response.payload)
    }

    /// Send a `messaging/account/get` Trust Task and return the mediator's view of
    /// the account. `did_hash` names the target account; `None` requests the
    /// caller's own account (self). Self requests need no admin rights; fetching
    /// another account requires an admin profile.
    pub async fn account_get(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
    ) -> Result<account::get::v0_2::Account, ATMError> {
        self.account_get_with_activity(profile, did_hash, false)
            .await
    }

    /// [`account_get`](Self::account_get), additionally asking for the
    /// account's activity times (`last_received_at`, `last_authenticated_at`)
    /// when `include_activity` is set.
    ///
    /// **Only ask a mediator that serves it.** The member is new, and a
    /// mediator that predates it refuses the whole request as a schema
    /// violation rather than ignoring the member. Gate on the mediator's
    /// version, as the console does.
    pub async fn account_get_with_activity(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
        include_activity: bool,
    ) -> Result<account::get::v0_2::Account, ATMError> {
        self.account_get_detailed(profile, did_hash, include_activity, false)
            .await
    }

    /// [`account_get`](Self::account_get), asking for the account's activity
    /// times and/or its lifetime counters (`stats`).
    ///
    /// **Only ask a mediator that serves them.** Both are new request
    /// members, and a mediator that predates one refuses the whole request as
    /// a schema violation rather than ignoring the member. Gate on the
    /// mediator's version, as the console does.
    pub async fn account_get_detailed(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
        include_activity: bool,
        include_stats: bool,
    ) -> Result<account::get::v0_2::Account, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let target = did_hash.unwrap_or_else(|| digest(&profile.inner.did));

        let did = account::get::v0_2::Vid::from_str(&target)
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let p: account::get::v0_2::Payload = payload(
            account::get::v0_2::Payload::builder()
                .did(did)
                .include_activity(include_activity.then_some(true))
                .include_stats(include_stats.then_some(true)),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<account::get::v0_2::Response> = self
            .exchange_current(profile, task, Current::AccountGet)
            .await?;
        Ok(response.payload.account)
    }

    /// Send a `messaging/account/list` Trust Task (admin only) and return one page
    /// of accounts plus an opaque `next_cursor` (present only when more remain).
    /// Pass the previous page's cursor to continue; `None` starts from the top.
    /// `account_type` filters the enumeration to one role — `Some(Admin)` /
    /// `Some(RootAdmin)` enumerates the mediator's administrators (this supersedes
    /// the retired `messaging/admin/list`).
    pub async fn account_list(
        &self,
        profile: &Arc<ATMProfile>,
        cursor: Option<String>,
        limit: Option<u32>,
        account_type: Option<account::list::v0_2::AccountType>,
    ) -> Result<account::list::v0_2::Response, ATMError> {
        self.account_list_with_activity(profile, cursor, limit, account_type, false)
            .await
    }

    /// [`account_list`](Self::account_list), additionally asking for each
    /// account's activity times when `include_activity` is set. The same
    /// caution applies: only ask a mediator that serves it.
    pub async fn account_list_with_activity(
        &self,
        profile: &Arc<ATMProfile>,
        cursor: Option<String>,
        limit: Option<u32>,
        account_type: Option<account::list::v0_2::AccountType>,
        include_activity: bool,
    ) -> Result<account::list::v0_2::Response, ATMError> {
        self.account_list_detailed(
            profile,
            cursor,
            limit,
            account_type,
            include_activity,
            false,
        )
        .await
    }

    /// [`account_list`](Self::account_list), asking for each account's
    /// activity times and/or its lifetime counters. The same caution applies:
    /// only ask a mediator that serves them.
    #[allow(clippy::too_many_arguments)]
    pub async fn account_list_detailed(
        &self,
        profile: &Arc<ATMProfile>,
        cursor: Option<String>,
        limit: Option<u32>,
        account_type: Option<account::list::v0_2::AccountType>,
        include_activity: bool,
        include_stats: bool,
    ) -> Result<account::list::v0_2::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;

        let cursor = cursor
            .map(|c| account::list::v0_2::PayloadCursor::from_str(&c))
            .transpose()
            .map_err(|e| ATMError::MsgSendError(format!("invalid cursor: {e}")))?;
        let limit = limit.and_then(|l| std::num::NonZeroU64::new(l as u64));

        let p: account::list::v0_2::Payload = payload(
            account::list::v0_2::Payload::builder()
                .account_type(account_type)
                .cursor(cursor)
                .include_activity(include_activity.then_some(true))
                .include_stats(include_stats.then_some(true))
                .limit(limit),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<account::list::v0_2::Response> = self
            .exchange_current(profile, task, Current::AccountList)
            .await?;
        Ok(response.payload)
    }

    /// Send a `messaging/account/update` Trust Task — one partial update for a
    /// served account's role, capabilities, and queue limits (superseding the
    /// retired `change-type` / `change-queue-limits` / `acl/set` /
    /// `admin/add` / `admin/strip`). `did_hash` names the target; `None` is the
    /// caller's own account. Every member is optional and an omitted member leaves
    /// that facet unchanged:
    /// - `account_type` — admin only; assigning or touching `rootAdmin` requires a
    ///   root admin.
    /// - `acl` — partial capability update; a non-admin may only change flags it
    ///   self-manages.
    /// - `queue_limits` — `Some(-1)` = unlimited, `None` member = unchanged; a
    ///   standard account may only change limits it self-manages.
    ///
    /// Returns the account's realized view after the update.
    pub async fn account_update(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
        account_type: Option<account::update::v0_2::AccountType>,
        acl: Option<account::update::v0_2::MediatorAcl>,
        queue_limits: Option<account::update::v0_2::QueueLimits>,
    ) -> Result<account::update::v0_2::Account, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let target = did_hash.unwrap_or_else(|| digest(&profile.inner.did));

        let did = account::update::v0_2::Vid::from_str(&target)
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let p: account::update::v0_2::Payload = payload(
            account::update::v0_2::Payload::builder()
                .account_type(account_type)
                .acl(acl)
                .did(did)
                .queue_limits(queue_limits),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<account::update::v0_2::Response> = self
            .exchange_current(profile, task, Current::AccountUpdate)
            .await?;
        Ok(response.payload.account)
    }

    /// Send a `messaging/account/remove` Trust Task and return whether a record was
    /// removed. `did_hash` names the target; `None` removes the caller's own account.
    /// Self-or-admin; the mediator's own and the root-admin accounts can't be removed.
    pub async fn account_remove(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
    ) -> Result<bool, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let target = did_hash.unwrap_or_else(|| digest(&profile.inner.did));

        let did = account::remove::v0_1::Vid::from_str(&target)
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let p: account::remove::v0_1::Payload =
            payload(account::remove::v0_1::Payload::builder().did(did))?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<account::remove::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(response.payload.removed)
    }

    /// Send a `messaging/acl/get` Trust Task (self-or-admin) for one or more accounts.
    /// Returns the per-DID ACL entries plus the DIDs the mediator didn't recognise.
    pub async fn acl_get(
        &self,
        profile: &Arc<ATMProfile>,
        did_hashes: Vec<String>,
    ) -> Result<acl::get::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;

        let dids = did_hashes
            .iter()
            .map(|d| acl::get::v0_1::Vid::from_str(d))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let p: acl::get::v0_1::Payload = payload(acl::get::v0_1::Payload::builder().dids(dids))?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<acl::get::v0_1::Response> = self.exchange(profile, task).await?;
        Ok(response.payload)
    }

    /// Send a `messaging/account/add` Trust Task and return the created account's view.
    /// In allowlist mode only an admin may add accounts; in denylist mode any
    /// authenticated account may. `acl` is optional — an admin's is applied onto the
    /// mediator default, a non-admin's is ignored (the default is used). Creating an
    /// admin / root-admin account requires the matching privilege.
    pub async fn account_add(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: String,
        account_type: account::add::v0_2::AccountType,
        acl: Option<account::add::v0_2::MediatorAcl>,
    ) -> Result<account::add::v0_2::Account, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;

        let did = account::add::v0_2::Vid::from_str(&did_hash)
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        // Initial queue limits are left unset so the mediator default applies;
        // adjust with `account_update` after creation.
        let p: account::add::v0_2::Payload = payload(
            account::add::v0_2::Payload::builder()
                .account_type(account_type)
                .acl(acl)
                .did(did),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<account::add::v0_2::Response> = self
            .exchange_current(profile, task, Current::AccountAdd)
            .await?;
        Ok(response.payload.account)
    }

    /// `messaging/access-list/update` — modify an account's access list in one
    /// task (self-or-admin; `None` = own list), superseding the retired
    /// `access-list/add` / `remove` / `clear`. Members are applied in the fixed
    /// order **`clear`, `add`, `remove`**, so `clear + add` replaces the list
    /// wholesale. Returns the entries actually added and removed plus the new count.
    pub async fn access_list_update(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
        clear: bool,
        add: Vec<String>,
        remove: Vec<String>,
    ) -> Result<access_list::update::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let target = did_hash.unwrap_or_else(|| digest(&profile.inner.did));
        let did = access_list::update::v0_1::Vid::from_str(&target)
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let to_vids = |entries: Vec<String>| {
            entries
                .iter()
                .map(|e| access_list::update::v0_1::Vid::from_str(e))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| ATMError::MsgSendError(format!("invalid access-list entry: {e}")))
        };
        let p: access_list::update::v0_1::Payload = payload(
            access_list::update::v0_1::Payload::builder()
                .add(to_vids(add)?)
                .clear(clear.then_some(true))
                .did(did)
                .remove(to_vids(remove)?),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());
        let response: TrustTask<access_list::update::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(response.payload)
    }

    /// `messaging/access-list/list` — page through an account's access list (self-or-
    /// admin; `None` = own list). Returns entries plus an opaque `next_cursor`.
    /// `entries` turns the enumeration into a **membership check** (superseding the
    /// retired `access-list/get`): only the supplied DIDs present in the list are
    /// returned, so a supplied DID absent from the response is not a member.
    pub async fn access_list_list(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
        cursor: Option<String>,
        limit: Option<u32>,
        entries: Option<Vec<String>>,
    ) -> Result<access_list::list::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let target = did_hash.unwrap_or_else(|| digest(&profile.inner.did));
        let did = access_list::list::v0_1::Vid::from_str(&target)
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let cursor = cursor
            .map(|c| access_list::list::v0_1::PayloadCursor::from_str(&c))
            .transpose()
            .map_err(|e| ATMError::MsgSendError(format!("invalid cursor: {e}")))?;
        let limit = limit.and_then(|l| std::num::NonZeroU64::new(l as u64));
        let entries = entries
            .unwrap_or_default()
            .iter()
            .map(|e| access_list::list::v0_1::Vid::from_str(e))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ATMError::MsgSendError(format!("invalid access-list entry: {e}")))?;
        let p: access_list::list::v0_1::Payload = payload(
            access_list::list::v0_1::Payload::builder()
                .cursor(cursor)
                .did(did)
                .entries(entries)
                .limit(limit),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());
        let response: TrustTask<access_list::list::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(response.payload)
    }

    /// Generic `audit/list` (admin only) — page the mediator's privileged-change
    /// audit log, newest first (superseding the retired `messaging/admin/audit-log`).
    pub async fn audit_list(
        &self,
        profile: &Arc<ATMProfile>,
        cursor: Option<String>,
        limit: Option<u32>,
    ) -> Result<audit::list::v0_2::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        // Only the two members this method exposes are set; `action`, `actor`,
        // `contextId`, `from`, `outcome` and `to` are filters the builder leaves
        // unset, which is an unfiltered listing.
        let p: audit::list::v0_2::Payload = payload(
            audit::list::v0_2::Payload::builder()
                .cursor(cursor)
                .limit(limit.and_then(|l| std::num::NonZeroU64::new(l as u64))),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());
        let response: TrustTask<audit::list::v0_2::Response> = self
            .exchange_current(profile, task, Current::AuditList)
            .await?;
        Ok(response.payload)
    }

    /// Generic `config/show` (admin only) — read the mediator's effective runtime
    /// configuration as per-key fields (superseding the retired
    /// `messaging/admin/config`; the software version is the `mediator.version` key).
    /// `keys` narrows the result; `None` returns every key.
    pub async fn config_show(
        &self,
        profile: &Arc<ATMProfile>,
        keys: Option<Vec<String>>,
    ) -> Result<config::show::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let keys = keys
            .map(|ks| {
                ks.iter()
                    .map(|k| config::show::v0_1::PayloadKeysItem::from_str(k))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()
            .map_err(|e| ATMError::MsgSendError(format!("invalid configuration key: {e}")))?;
        let p: config::show::v0_1::Payload =
            payload(config::show::v0_1::Payload::builder().keys(keys))?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());
        let response: TrustTask<config::show::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(response.payload)
    }

    /// Generic `config/reload` (rootAdmin only) — re-read the mediator's
    /// limits from its configuration file and environment without a restart.
    /// Returns the keys whose running value changed; keys that apply only at
    /// a restart are never among them.
    pub async fn config_reload(
        &self,
        profile: &Arc<ATMProfile>,
    ) -> Result<config::reload::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let p: config::reload::v0_1::Payload = serde_json::from_value(serde_json::json!({}))
            .map_err(|e| ATMError::MsgSendError(format!("config/reload payload: {e}")))?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());
        let response: TrustTask<config::reload::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(response.payload)
    }

    /// Generic `config/patch` (rootAdmin only) — change mediator limits at
    /// runtime. `overrides` maps keys such as `limits.queued_send_messages_hard`
    /// to their new value; `null` removes a key's override. Each key is checked
    /// on its own: the response lists which took effect now (`applied`), which
    /// were stored for the next start (`pending_restart`), and which were
    /// refused, with the reason (`rejected`). Accepted changes are stored, so
    /// they survive a restart.
    pub async fn config_patch(
        &self,
        profile: &Arc<ATMProfile>,
        overrides: serde_json::Map<String, serde_json::Value>,
    ) -> Result<config::patch::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let p: config::patch::v0_1::Payload =
            payload(config::patch::v0_1::Payload::builder().overrides(overrides))?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());
        let response: TrustTask<config::patch::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(response.payload)
    }

    /// Send a `messaging/stats/show` Trust Task (admin only) and return the
    /// mediator's telemetry: version and uptime, live connections, lifetime
    /// message counters (monotonic — derive rates from successive readings),
    /// forwarding and circuit-breaker state, and the latest queue-survey
    /// aggregate (absent until the mediator's first survey completes).
    pub async fn stats_show(
        &self,
        profile: &Arc<ATMProfile>,
    ) -> Result<stats::show::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let p: stats::show::v0_1::Payload = payload(stats::show::v0_1::Payload::builder())?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<stats::show::v0_1::Response> = self.exchange(profile, task).await?;
        Ok(response.payload)
    }

    /// Send a `messaging/message/list` Trust Task and return one page of
    /// stored-message metadata from an account's receive or send queue, oldest
    /// first — never bodies. `did_hash = None` lists the caller's own queue
    /// (which must be served locally); another account needs admin rights.
    /// `peer` narrows to one counterparty (the sender in a receive queue, the
    /// recipient in a send queue). Pass the previous page's `next_cursor` to
    /// continue.
    pub async fn message_list(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
        queue: message::list::v0_1::Queue,
        peer: Option<String>,
        cursor: Option<String>,
        limit: Option<u32>,
    ) -> Result<message::list::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let vid = |v: String| {
            message::list::v0_1::Vid::from_str(&v)
                .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))
        };
        let did = did_hash.map(vid).transpose()?;
        let peer = peer.map(vid).transpose()?;
        let cursor = cursor
            .map(|c| message::list::v0_1::PayloadCursor::from_str(&c))
            .transpose()
            .map_err(|e| ATMError::MsgSendError(format!("invalid cursor: {e}")))?;
        let limit = limit.and_then(|l| std::num::NonZeroU64::new(l as u64));

        let p: message::list::v0_1::Payload = payload(
            message::list::v0_1::Payload::builder()
                .did(did)
                .queue(queue)
                .peer(peer)
                .cursor(cursor)
                .limit(limit),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<message::list::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(response.payload)
    }

    /// Send a `messaging/message/get` Trust Task and return one stored message
    /// exactly as the mediator holds it — still encrypted — with its metadata.
    /// `did_hash = None` reads from the caller's own queues; another account's
    /// message needs a rootAdmin, and the mediator audits the read. This is not
    /// a pickup: the message stays queued and its delivery state is unchanged.
    ///
    /// A caller holding the recipient's key-agreement secret can unpack the
    /// returned envelope locally.
    pub async fn message_get(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
        msg_id: &str,
    ) -> Result<message::get::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let did = did_hash
            .map(|d| message::get::v0_1::Vid::from_str(&d))
            .transpose()
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let msg_id = message::get::v0_1::PayloadMsgId::from_str(msg_id)
            .map_err(|e| ATMError::MsgSendError(format!("invalid message id: {e}")))?;

        let p: message::get::v0_1::Payload = payload(
            message::get::v0_1::Payload::builder()
                .did(did)
                .msg_id(msg_id),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<message::get::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(response.payload)
    }

    /// Send a `messaging/message/delete` Trust Task: remove up to 100 stored
    /// messages from an account's queues. `did_hash = None` is the caller's own
    /// account; another account needs admin rights, and a privileged account
    /// (admin, rootAdmin, mediator) a rootAdmin. The response reports each id
    /// in request order — an id not in that account's queues is `notFound`,
    /// never a whole-call failure, and never reported deleted unless it was.
    pub async fn message_delete(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
        msg_ids: &[String],
    ) -> Result<message::delete::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let did = did_hash
            .map(|d| message::delete::v0_1::Vid::from_str(&d))
            .transpose()
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let ids = msg_ids
            .iter()
            .map(|id| message::delete::v0_1::PayloadMsgIdsItem::from_str(id))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ATMError::MsgSendError(format!("invalid message id: {e}")))?;

        let p: message::delete::v0_1::Payload = payload(
            message::delete::v0_1::Payload::builder()
                .did(did)
                .msg_ids(ids),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<message::delete::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(response.payload)
    }

    /// Send a `messaging/queue/purge` Trust Task: remove every message in one
    /// account queue — optionally only those exchanged with `peer` or older
    /// than `older_than_seconds`. With `dry_run = true` nothing is removed and
    /// `matched` says what would be; interactive tools should dry-run first
    /// and confirm the count. Undelivered messages are gone, not returned.
    ///
    /// `did_hash = None` is the caller's own account; another needs admin
    /// rights, and a privileged account a rootAdmin. The mediator audits every
    /// real purge.
    ///
    /// To confirm a dry run without removing messages stored after it, use
    /// [`queue_purge_with`](Self::queue_purge_with) and
    /// [`QueuePurge::stored_before`].
    pub async fn queue_purge(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
        queue: queue::purge::v0_1::Queue,
        peer: Option<String>,
        older_than_seconds: Option<u64>,
        dry_run: bool,
    ) -> Result<queue::purge::v0_1::Response, ATMError> {
        let purge = QueuePurge {
            did_hash,
            peer,
            older_than_seconds,
            dry_run,
            ..QueuePurge::new(queue)
        };
        self.queue_purge_with(profile, &purge).await
    }

    /// Send the `messaging/queue/purge` Trust Task `purge` describes.
    ///
    /// The response's `selected_at` is the instant the mediator took the
    /// selection, when it reports one. Send a dry run's `selected_at` back as
    /// [`QueuePurge::stored_before`] on the confirming purge so it removes
    /// nothing stored after the preview the operator confirmed. A mediator
    /// that predates `storedBefore` refuses a request carrying it.
    pub async fn queue_purge_with(
        &self,
        profile: &Arc<ATMProfile>,
        purge: &QueuePurge,
    ) -> Result<queue::purge::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let p = purge.payload()?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<queue::purge::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(response.payload)
    }

    /// Send a `messaging/monitor/subscribe` Trust Task: open (or, with
    /// `renew`, renew and re-filter) a leased live tap on the mediator's
    /// traffic metadata. Events arrive as `messaging/monitor/event` batches on
    /// the profile's **live stream** — never in its queue — so the profile must
    /// have its websocket enabled; read them with
    /// [`decode_monitor_event`](super::trust_tasks::decode_monitor_event).
    ///
    /// An administrator may watch anything; any other account only its own
    /// traffic (an omitted `dids` filter is narrowed to it). Renew before
    /// `expires_at`; the default lease is 300 s.
    ///
    /// This is `monitor/subscribe` 0.1: traffic events only. For mux
    /// membership events, or to turn traffic events off, use
    /// [`monitor_subscribe_with`](Self::monitor_subscribe_with).
    #[allow(deprecated)]
    pub async fn monitor_subscribe(
        &self,
        profile: &Arc<ATMProfile>,
        filter: Option<monitor::subscribe::v0_1::MonitorFilter>,
        lease_seconds: Option<u32>,
        max_events_per_second: Option<u32>,
        renew: Option<String>,
    ) -> Result<monitor::subscribe::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let renew = renew
            .map(|r| monitor::subscribe::v0_1::PayloadSubscriptionId::from_str(&r))
            .transpose()
            .map_err(|e| ATMError::MsgSendError(format!("invalid subscription id: {e}")))?;
        let p: monitor::subscribe::v0_1::Payload = payload(
            monitor::subscribe::v0_1::Payload::builder()
                .filter(filter)
                .lease_seconds(lease_seconds.map(i64::from))
                .max_events_per_second(
                    max_events_per_second.and_then(|n| std::num::NonZeroU64::new(n as u64)),
                )
                .subscription_id(renew),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<monitor::subscribe::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(response.payload)
    }

    /// Send a `messaging/monitor/unsubscribe` Trust Task, ending a subscription
    /// and returning how many events it sent and dropped.
    pub async fn monitor_unsubscribe(
        &self,
        profile: &Arc<ATMProfile>,
        subscription_id: &str,
    ) -> Result<monitor::unsubscribe::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let id = monitor::unsubscribe::v0_1::PayloadSubscriptionId::from_str(subscription_id)
            .map_err(|e| ATMError::MsgSendError(format!("invalid subscription id: {e}")))?;
        let p: monitor::unsubscribe::v0_1::Payload =
            payload(monitor::unsubscribe::v0_1::Payload::builder().subscription_id(id))?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<monitor::unsubscribe::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(response.payload)
    }

    /// Send a `messaging/monitor/subscribe` 0.2 Trust Task: open (or, with
    /// [`MonitorSubscription::renew`], renew and re-filter) a leased live tap
    /// that can also carry mux membership events — a member DID attached to
    /// or detached from a principal's mux connection.
    ///
    /// Membership events are opt-in: set [`MonitorSubscription::membership`].
    /// Batches arrive at `messaging/monitor/event` 0.3 on the profile's live
    /// stream; read them with [`decode_monitor_event_v0_3`]. The response's
    /// `membership` is the filter in force, and is absent when the mediator
    /// sends none (none asked for, or mux not enabled there). An
    /// administrator sees every change; any other account only changes it is
    /// party to.
    ///
    /// A mediator that predates 0.2 refuses the request as an unsupported
    /// type; [`monitor_subscribe`](Self::monitor_subscribe) still works there
    /// for traffic events.
    pub async fn monitor_subscribe_with(
        &self,
        profile: &Arc<ATMProfile>,
        subscription: &MonitorSubscription,
    ) -> Result<monitor::subscribe::v0_2::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let p = subscription.payload()?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<monitor::subscribe::v0_2::Response> =
            self.exchange(profile, task).await?;
        Ok(response.payload)
    }

    /// Send a `messaging/message/status` Trust Task: where each message this
    /// profile sent now stands at its mediator — `queued`, `delivered`,
    /// `collected` (removed by the recipient), `withdrawn`, `discarded` (removed
    /// by the mediator before the recipient took it) or `unknown` — one entry
    /// per id, in the order asked. At most 100 ids per call.
    ///
    /// The ids are the mediator's message identifiers — for a DIDComm send, the
    /// `sha256` of the packed message this SDK returns as a `SendReceipt`
    /// `hop_id`. The mediator answers only for messages this profile sent, and
    /// `unknown` for anything else.
    pub async fn message_status(
        &self,
        profile: &Arc<ATMProfile>,
        msg_ids: &[String],
    ) -> Result<message::status::v0_2::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;

        let ids = msg_ids
            .iter()
            .map(|id| message::status::v0_2::PayloadMsgIdsItem::from_str(id))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ATMError::MsgSendError(format!("invalid message id: {e}")))?;
        let p: message::status::v0_2::Payload =
            payload(message::status::v0_2::Payload::builder().msg_ids(ids))?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        #[cfg(feature = "tsp")]
        let track_timeout = match self.status_gate_over_tsp(profile).await? {
            None => false,
            Some(StatusGate::Ask { track_timeout }) => track_timeout,
            Some(StatusGate::Unserved) => {
                return Err(ATMError::ProblemReport(
                    "e.p.protocol.trust_task.unsupported".into(),
                    "this mediator does not answer messaging/message/status over TSP".into(),
                    "NONE".into(),
                ));
            }
        };

        let response: Result<TrustTask<message::status::v0_2::Response>, ATMError> = self
            .exchange_current(profile, task, Current::MessageStatus)
            .await;
        #[cfg(feature = "tsp")]
        if track_timeout
            && let Err(ATMError::MsgReceiveError(text)) = &response
            && text.starts_with(crate::protocols::trust_task_versions::TSP_NO_REPLY)
        {
            self.atm
                .inner
                .status_over_tsp
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .unanswered_until
                .insert(
                    mediator_did.to_string(),
                    std::time::Instant::now()
                        + crate::protocols::trust_task_versions::STATUS_UNANSWERED_FOR,
                );
        }
        Ok(response?.payload)
    }

    /// Whether to send the status task to the profile's mediator over TSP;
    /// `None` when it does not go over TSP.
    #[cfg(feature = "tsp")]
    async fn status_gate_over_tsp(
        &self,
        profile: &Arc<ATMProfile>,
    ) -> Result<Option<StatusGate>, ATMError> {
        use crate::protocols::tsp::SendProtocol;
        let (_, mediator_did) = profile.dids()?;
        if self
            .atm
            .tsp()
            .select_protocol(profile, mediator_did)
            .await?
            != SendProtocol::Tsp
        {
            return Ok(None);
        }
        // Reads the mediator's version from `/readyz` the first time.
        self.mediator_speaks(profile).await?;
        Ok(Some(
            self.atm
                .inner
                .status_over_tsp
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .gate(mediator_did, std::time::Instant::now()),
        ))
    }

    /// Send a `messaging/queue/status` Trust Task and return one account's two
    /// queues, live: depth, bytes, effective limit, saturation and the age of
    /// the oldest message. `did_hash` names the account; `None` is the caller's
    /// own (self needs no admin rights). `include_peers = Some(n)` also returns
    /// each queue's top `n` counterparties — in the send queue, the recipients
    /// that have not yet collected.
    pub async fn queue_status(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
        include_peers: Option<u32>,
    ) -> Result<queue::status::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;

        let did = did_hash
            .map(|d| queue::status::v0_1::Vid::from_str(&d))
            .transpose()
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let include_peers = include_peers.and_then(|n| std::num::NonZeroU64::new(n as u64));

        let p: queue::status::v0_1::Payload = payload(
            queue::status::v0_1::Payload::builder()
                .did(did)
                .include_peers(include_peers),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<queue::status::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(response.payload)
    }

    /// Send a `messaging/queue/list` Trust Task (admin only) and return one page
    /// of accounts ranked, descending, by `sort` on the chosen `queue`
    /// (defaults: the receive queue, by message count, skipping empty queues).
    ///
    /// The ranking comes from the mediator's periodic queue survey —
    /// `snapshot_at` says when it ran. Pass the previous page's `next_cursor` to
    /// continue; a cursor from a survey that has since been replaced is refused,
    /// and the caller starts again from the top.
    pub async fn queue_list(
        &self,
        profile: &Arc<ATMProfile>,
        queue: Option<queue::list::v0_1::Queue>,
        sort: Option<queue::list::v0_1::PayloadSort>,
        min_count: Option<u64>,
        cursor: Option<String>,
        limit: Option<u32>,
    ) -> Result<queue::list::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;

        let cursor = cursor
            .map(|c| queue::list::v0_1::PayloadCursor::from_str(&c))
            .transpose()
            .map_err(|e| ATMError::MsgSendError(format!("invalid cursor: {e}")))?;
        let limit = limit.and_then(|l| std::num::NonZeroU64::new(l as u64));

        let p: queue::list::v0_1::Payload = payload(
            queue::list::v0_1::Payload::builder()
                .queue(queue)
                .sort(sort)
                .min_count(min_count)
                .cursor(cursor)
                .limit(limit),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<queue::list::v0_1::Response> = self.exchange(profile, task).await?;
        Ok(response.payload)
    }

    /// Exchange a task the SDK speaks at 0.2 (see
    /// [`trust_task_versions`](super::trust_task_versions)): as 0.2 to a
    /// mediator that serves it, otherwise as 0.1 with the reply converted to
    /// the 0.2 shape. Either way the caller gets the 0.2 `R`.
    async fn exchange_current<P, R>(
        &self,
        profile: &Arc<ATMProfile>,
        task: TrustTask<P>,
        current: Current,
    ) -> Result<TrustTask<R>, ATMError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let (_, mediator_did) = profile.dids()?;
        let doc = serde_json::to_value(&task)
            .map_err(|e| ATMError::MsgSendError(format!("couldn't serialise Trust Task: {e}")))?;

        if self.mediator_speaks(profile).await? == MediatorSpeaks::V0_2 {
            match self
                .exchange::<Value, R>(profile, value_task(doc.clone())?)
                .await
            {
                // Refused before any handler ran: nothing was done, so the
                // same request is re-sent as 0.1 below.
                Err(e) if is_unsupported_error(&e) => {
                    self.remember_speaks(mediator_did, MediatorSpeaks::V0_1Only);
                }
                other => return other,
            }
        }

        let mut doc = doc;
        current
            .to_v0_1_request(&mut doc)
            .map_err(ATMError::MsgSendError)?;
        // A fresh id: the 0.1 document is a different request.
        doc["id"] = Value::String(new_id());
        let reply: TrustTask<Value> = self.exchange(profile, value_task(doc)?).await?;
        let mut reply = serde_json::to_value(&reply)
            .map_err(|e| ATMError::MsgReceiveError(format!("couldn't read the reply: {e}")))?;
        current
            .to_v0_2_reply(&mut reply)
            .map_err(ATMError::MsgReceiveError)?;
        decode_body(&reply)
    }

    /// What the profile's mediator serves, learnt once per mediator.
    ///
    /// Over DIDComm the answer is 0.2 until the mediator refuses it, which an
    /// older one does at once. Over TSP an older mediator files an unknown type
    /// as mail and never answers, so its version is read from `/readyz` first.
    async fn mediator_speaks(&self, profile: &Arc<ATMProfile>) -> Result<MediatorSpeaks, ATMError> {
        let (_, mediator_did) = profile.dids()?;
        if let Some(known) = self
            .atm
            .inner
            .mediator_speaks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(mediator_did)
            .copied()
        {
            return Ok(known);
        }

        #[cfg(feature = "tsp")]
        {
            use crate::protocols::tsp::SendProtocol;
            if self
                .atm
                .tsp()
                .select_protocol(profile, mediator_did)
                .await?
                == SendProtocol::Tsp
            {
                let version = self.probe_mediator_version(profile).await;
                self.atm
                    .inner
                    .status_over_tsp
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .versions
                    .insert(
                        mediator_did.to_string(),
                        version
                            .as_deref()
                            .and_then(crate::protocols::trust_task_versions::parse_version),
                    );
                let speaks = speaks_from_version(version.as_deref());
                self.remember_speaks(mediator_did, speaks);
                return Ok(speaks);
            }
        }
        #[cfg(not(feature = "tsp"))]
        let _ = speaks_from_version;

        Ok(MediatorSpeaks::V0_2)
    }

    fn remember_speaks(&self, mediator_did: &str, speaks: MediatorSpeaks) {
        self.atm
            .inner
            .mediator_speaks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(mediator_did.to_string(), speaks);
    }

    /// The mediator's version from its `/readyz`, if it answers in time.
    #[cfg(feature = "tsp")]
    async fn probe_mediator_version(&self, profile: &ATMProfile) -> Option<String> {
        let base = profile.get_mediator_rest_endpoint()?;
        let url = format!("{}/readyz", base.trim_end_matches('/'));
        let response = self
            .atm
            .get_tdk()
            .client()
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .ok()?;
        let body: Value = response.json().await.ok()?;
        body["version"].as_str().map(str::to_string)
    }

    /// Stamp `issuedAt`, sign, wrap the `TrustTask<P>` in the DIDComm binding
    /// envelope, authcrypt + send it to the mediator, and decode the reply's body
    /// as a `TrustTask<R>`.
    ///
    /// Every document leaves with `issuedAt` set, and with a Data Integrity
    /// `proof` whenever the profile holds an Ed25519 key it can sign with — see
    /// [`Self::sign`]. Most `messaging/*` specs require both on the request, and a
    /// mediator that enforces them refuses a document that lacks them.
    /// Send one Trust Task document and return the mediator's response,
    /// over whichever transport this profile and mediator have in common.
    ///
    /// Every `trust_tasks()` method funnels through here, so this is the only
    /// place the wire is chosen. [`TspOps::select_protocol`] makes that choice
    /// from the configured [`TspPolicy`]: the default (`Off`) is DIDComm, so
    /// nothing moves wire until an application opts in, and `Preferred` picks
    /// TSP only for a mediator known to speak it with a relationship already
    /// in place — which is also what TSP requires before it will accept the
    /// reply.
    ///
    /// The document and its proof are identical either way. Only the envelope
    /// around it and the way the reply is collected differ.
    ///
    /// [`TspOps::select_protocol`]: crate::protocols::tsp::TspOps::select_protocol
    /// [`TspPolicy`]: crate::protocols::tsp::TspPolicy
    async fn exchange<P, R>(
        &self,
        profile: &Arc<ATMProfile>,
        mut task: TrustTask<P>,
    ) -> Result<TrustTask<R>, ATMError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let (profile_did, _) = profile.dids()?;

        task.issued_at = Some(chrono::Utc::now());
        let thread_id = task.id.clone();
        let body = serde_json::to_value(&task)
            .map_err(|e| ATMError::MsgSendError(format!("couldn't serialise Trust Task: {e}")))?;
        let body = self.sign(profile_did, body).await?;

        #[cfg(feature = "tsp")]
        {
            use crate::protocols::tsp::SendProtocol;
            let (_, mediator_did) = profile.dids()?;
            if self
                .atm
                .tsp()
                .select_protocol(profile, mediator_did)
                .await?
                == SendProtocol::Tsp
            {
                return self.exchange_tsp(profile, body, &thread_id).await;
            }
        }
        let _ = &thread_id;
        self.exchange_didcomm(profile, body, true).await
    }

    /// The DIDComm arm: the document rides the Trust Tasks envelope, and the
    /// mediator's reply comes back on the same request. `delete_reply`:
    /// delete the reply once read. The answer to `messaging/mux/ack` is
    /// pushed, never stored, so it has nothing to delete, and a delete for it
    /// would only queue another ack.
    async fn exchange_didcomm<R>(
        &self,
        profile: &Arc<ATMProfile>,
        body: Value,
        delete_reply: bool,
    ) -> Result<TrustTask<R>, ATMError>
    where
        R: DeserializeOwned,
    {
        let atm = self.atm;
        let (profile_did, mediator_did) = profile.dids()?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let request = RequestIds::of(&body);
        let msg = Message::build(new_id(), ENVELOPE_TYPE.to_string(), body)
            .to(mediator_did.into())
            .from(profile_did.into())
            .created_time(now)
            .expires_time(now + 10)
            .finalize();
        let msg_id = msg.id.clone();

        let (packed, _) = atm
            .inner
            .pack_encrypted(&msg, mediator_did, Some(profile_did))
            .await
            .map_err(|e| ATMError::MsgSendError(format!("couldn't pack Trust Task: {e}")))?;

        // The reply is matched to the envelope by its DIDComm `thid`; a
        // refusal inside it is matched to the Trust Task itself as well.
        match atm
            .send_message_inner(profile, &packed, &msg_id, true, true, delete_reply)
            .await?
        {
            SendMessageResponse::Message(response) => decode_reply(&response.body, &request),
            _ => Err(ATMError::MsgReceiveError(
                "no response from mediator for the Trust Task".to_owned(),
            )),
        }
    }

    /// The TSP arm: the document is the payload of a TSP Direct message to the
    /// mediator, which seals its reply back and delivers it like any other
    /// message. The reply is collected from the inbox by thread id.
    ///
    /// **Nothing else's mail is touched.** The inbox is read with
    /// `DoNotDelete` and only the matched reply is deleted, so a frame meant
    /// for another reader of the same mailbox stays where it is — a
    /// request/response that consumed what it read would destroy exactly the
    /// unsolicited traffic a client is otherwise waiting for.
    #[cfg(feature = "tsp")]
    async fn exchange_tsp<R>(
        &self,
        profile: &Arc<ATMProfile>,
        body: Value,
        thread_id: &str,
    ) -> Result<TrustTask<R>, ATMError>
    where
        R: DeserializeOwned,
    {
        use affinidi_messaging_mediator_types::messages::MessageProtocol;

        use crate::messages::{DeleteMessageRequest, fetch::FetchOptions};

        let (_, mediator_did) = profile.dids()?;
        let request = RequestIds::of(&body);
        let payload = serde_json::to_vec(&body)
            .map_err(|e| ATMError::MsgSendError(format!("couldn't serialise Trust Task: {e}")))?;
        self.atm.tsp().send(profile, mediator_did, &payload).await?;

        let deadline = SystemTime::now() + TSP_REPLY_TIMEOUT;
        loop {
            // Walk the whole inbox, not just its first page: a reply is only
            // ever *somewhere* in the mailbox, and traffic arriving alongside
            // it must not be able to push it out of view and time the
            // exchange out.
            let mut cursor: Option<String> = None;
            loop {
                let page = self
                    .atm
                    .fetch_messages(
                        profile,
                        &FetchOptions {
                            limit: TSP_REPLY_PAGE,
                            start_id: cursor.clone(),
                            delete_policy: crate::messages::FetchDeletePolicy::DoNotDelete,
                        },
                    )
                    .await?;
                if page.success.is_empty() {
                    break;
                }
                // Advance past this page; without a cursor to advance by, stop
                // rather than re-read the same page for the whole deadline.
                cursor = page.success.last().and_then(|e| e.receive_id.clone());

                for element in &page.success {
                    // Only TSP bodies can hold the sealed reply. The mediator
                    // tags the wire protocol on pickup, so nothing has to be
                    // sniffed.
                    if element.protocol != Some(MessageProtocol::Tsp) {
                        continue;
                    }
                    let Some(stored) = &element.msg else { continue };
                    // A body this profile cannot unpack is someone else's
                    // problem, not an error for this exchange.
                    let Ok((payload, sender)) = self.atm.tsp().unpack(profile, stored).await else {
                        continue;
                    };
                    // **The reply has to be the mediator's.** A thread id is
                    // only an identifier; without this, any peer holding a
                    // relationship could seal a document carrying it and have
                    // it answer someone else's Trust Task.
                    if sender != mediator_did {
                        continue;
                    }
                    let Ok(doc) = serde_json::from_slice::<Value>(&payload) else {
                        continue;
                    };
                    // Correlated here, before it is read: a reply (a refusal
                    // included) whose `threadId` is not this request's is left
                    // in the inbox for whoever it answers.
                    if !answers_thread(&doc, thread_id) {
                        continue;
                    }
                    // Matched: take it out of the inbox, and only it. A failed
                    // delete leaves the reply to be re-read later, so it is
                    // said out loud rather than swallowed.
                    if let Err(e) = self
                        .atm
                        .delete_messages_direct(
                            profile,
                            &DeleteMessageRequest {
                                message_ids: vec![element.msg_id.clone()],
                            },
                        )
                        .await
                    {
                        warn!(
                            message_id = %element.msg_id,
                            "Trust Task reply consumed but not deleted; it stays in the inbox: {e}"
                        );
                    }
                    return decode_reply(&doc, &request);
                }

                if cursor.is_none() || SystemTime::now() >= deadline {
                    break;
                }
            }

            if SystemTime::now() >= deadline {
                return Err(ATMError::MsgReceiveError(format!(
                    "{} within {}s",
                    crate::protocols::trust_task_versions::TSP_NO_REPLY,
                    TSP_REPLY_TIMEOUT.as_secs()
                )));
            }
            tokio::time::sleep(TSP_REPLY_POLL).await;
        }
    }
}

impl TrustTasksOps<'_> {
    /// Attach a Data Integrity proof (`eddsa-jcs-2022`, `assertionMethod`) made
    /// with the profile's Ed25519 key.
    ///
    /// A profile with no Ed25519 key it can sign with — a P-256-only DID, or one
    /// whose DID document can't be resolved right now — sends the document
    /// **unsigned** and warns, rather than failing a call that worked before this
    /// SDK signed anything. That is a deliberate transition: the mediator is the
    /// party that decides whether an unsigned request is acceptable, and once it
    /// enforces proofs it answers `proofRequired`, which surfaces as an error
    /// here. A signing failure with a key in hand is an error, never a silent
    /// downgrade.
    pub(crate) async fn sign(&self, did: &str, mut doc: Value) -> Result<Value, ATMError> {
        // Before signing, so the proof covers it like any other member.
        ask_for_error_documents(&mut doc);
        let Some(secret) = self.signing_secret(did).await else {
            warn!(
                did,
                "no Ed25519 signing key for this profile; sending the Trust Task unsigned — \
                 a mediator that enforces proofs will refuse it"
            );
            return Ok(doc);
        };
        sign_trust_task(&doc, &secret, SignOptions::new())
            .await
            .map_err(|e| ATMError::MsgSendError(format!("couldn't sign Trust Task: {e}")))
    }

    /// The profile's Ed25519 secret to sign with: an `assertionMethod` key if the
    /// DID document declares one (the proof purpose the signature asserts), else
    /// an `authentication` key — a `did:peer:2` profile typically has only the
    /// latter.
    async fn signing_secret(&self, did: &str) -> Option<Secret> {
        let doc = match self.atm.inner.tdk_common.did_resolver().resolve(did).await {
            Ok(resolved) => resolved.doc,
            Err(e) => {
                warn!(did, error = %e, "couldn't resolve own DID to pick a Trust Task signing key");
                return None;
            }
        };
        let resolver = self.atm.inner.tdk_common.secrets_resolver();
        let assertion = doc.find_assertion_method(None);
        let authentication = doc.find_authentication(None);
        for kid in assertion.into_iter().chain(authentication) {
            if let Some(secret) = resolver.get_secret(kid).await
                && secret.get_key_type() == KeyType::Ed25519
            {
                return Some(secret);
            }
        }
        None
    }
}

/// What [`TrustTasksOps::monitor_subscribe_with`] asks for
/// (`messaging/monitor/subscribe` 0.2). The default is the 0.1 subscription:
/// every traffic event the requester may see, no membership events.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct MonitorSubscription {
    /// Selects traffic events; `None` selects all the requester may see.
    pub filter: Option<monitor::subscribe::v0_2::MonitorFilter>,
    /// Opts in to mux membership events and selects which; `None` sends none.
    /// An empty filter selects every one the requester may see.
    pub membership: Option<monitor::subscribe::v0_2::MembershipFilter>,
    /// `false` turns traffic events off, for a membership-only tap; `filter`
    /// must then be `None`.
    pub traffic: bool,
    /// How long the subscription lives unless renewed (10–3600 s; the
    /// mediator's default is 300).
    pub lease_seconds: Option<u32>,
    /// The rate ceiling the subscriber can absorb (1–1000).
    pub max_events_per_second: Option<u32>,
    /// Renew or re-filter this existing subscription instead of opening one.
    pub renew: Option<String>,
}

impl Default for MonitorSubscription {
    fn default() -> Self {
        Self {
            filter: None,
            membership: None,
            traffic: true,
            lease_seconds: None,
            max_events_per_second: None,
            renew: None,
        }
    }
}

impl MonitorSubscription {
    /// Every traffic event the requester may see, no membership events.
    pub fn new() -> Self {
        Self::default()
    }

    /// Only mux membership events (traffic off), selected by `membership`.
    pub fn membership_only(membership: monitor::subscribe::v0_2::MembershipFilter) -> Self {
        Self {
            membership: Some(membership),
            traffic: false,
            ..Self::default()
        }
    }

    /// Select traffic events with `filter`.
    pub fn filter(mut self, filter: monitor::subscribe::v0_2::MonitorFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Opt in to mux membership events selected by `membership`.
    pub fn membership(mut self, membership: monitor::subscribe::v0_2::MembershipFilter) -> Self {
        self.membership = Some(membership);
        self
    }

    /// Turn traffic events on or off.
    pub fn traffic(mut self, traffic: bool) -> Self {
        self.traffic = traffic;
        self
    }

    /// The lease, in seconds.
    pub fn lease_seconds(mut self, seconds: u32) -> Self {
        self.lease_seconds = Some(seconds);
        self
    }

    /// The rate ceiling, in events per second.
    pub fn max_events_per_second(mut self, rate: u32) -> Self {
        self.max_events_per_second = Some(rate);
        self
    }

    /// Renew or re-filter the subscription `subscription_id`.
    pub fn renew(mut self, subscription_id: impl Into<String>) -> Self {
        self.renew = Some(subscription_id.into());
        self
    }

    /// The request payload. `traffic` is sent only when off, so a
    /// subscription with traffic on and no membership filter reads exactly
    /// as at 0.1.
    pub(crate) fn payload(&self) -> Result<monitor::subscribe::v0_2::Payload, ATMError> {
        if !self.traffic && self.filter.is_some() {
            return Err(ATMError::ConfigError(
                "a monitor subscription with traffic off takes no traffic filter".into(),
            ));
        }
        let renew = self
            .renew
            .as_deref()
            .map(monitor::subscribe::v0_2::PayloadSubscriptionId::from_str)
            .transpose()
            .map_err(|e| ATMError::MsgSendError(format!("invalid subscription id: {e}")))?;
        payload(
            monitor::subscribe::v0_2::Payload::builder()
                .filter(self.filter.clone())
                .membership(self.membership.clone())
                .traffic((!self.traffic).then_some(false))
                .lease_seconds(self.lease_seconds.map(i64::from))
                .max_events_per_second(
                    self.max_events_per_second
                        .and_then(|n| std::num::NonZeroU64::new(u64::from(n))),
                )
                .subscription_id(renew),
        )
    }
}

/// What [`TrustTasksOps::queue_purge_with`] asks for
/// (`messaging/queue/purge` 0.1): which messages of one account queue to
/// remove, or with `dry_run` only count.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct QueuePurge {
    /// The account whose queue to purge; `None` is the requester's own.
    pub did_hash: Option<String>,
    /// Which of the account's queues.
    pub queue: queue::purge::v0_1::Queue,
    /// Only messages exchanged with this counterparty.
    pub peer: Option<String>,
    /// Only messages queued at least this many seconds.
    pub older_than_seconds: Option<u64>,
    /// Only messages stored at or before this instant.
    pub stored_before: Option<chrono::DateTime<chrono::Utc>>,
    /// Count what would be purged and remove nothing.
    pub dry_run: bool,
}

impl QueuePurge {
    /// Every message in `queue` of the requester's own account, removed.
    pub fn new(queue: queue::purge::v0_1::Queue) -> Self {
        Self {
            did_hash: None,
            queue,
            peer: None,
            older_than_seconds: None,
            stored_before: None,
            dry_run: false,
        }
    }

    /// Purge the queue of the account `did_hash` instead of the requester's.
    pub fn did_hash(mut self, did_hash: impl Into<String>) -> Self {
        self.did_hash = Some(did_hash.into());
        self
    }

    /// Only messages exchanged with `peer`.
    pub fn peer(mut self, peer: impl Into<String>) -> Self {
        self.peer = Some(peer.into());
        self
    }

    /// Only messages queued at least `seconds`.
    pub fn older_than_seconds(mut self, seconds: u64) -> Self {
        self.older_than_seconds = Some(seconds);
        self
    }

    /// Only messages stored at or before `instant` — a dry run's
    /// `selected_at` when confirming it.
    pub fn stored_before(mut self, instant: chrono::DateTime<chrono::Utc>) -> Self {
        self.stored_before = Some(instant);
        self
    }

    /// Count what would be purged and remove nothing.
    pub fn dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    pub(crate) fn payload(&self) -> Result<queue::purge::v0_1::Payload, ATMError> {
        let vid = |v: &str| {
            queue::purge::v0_1::Vid::from_str(v)
                .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))
        };
        let did = self.did_hash.as_deref().map(vid).transpose()?;
        let peer = self.peer.as_deref().map(vid).transpose()?;
        payload(
            queue::purge::v0_1::Payload::builder()
                .did(did)
                .queue(self.queue)
                .peer(peer)
                .older_than_seconds(self.older_than_seconds)
                .stored_before(self.stored_before)
                .dry_run(Some(self.dry_run)),
        )
    }
}

/// Recognise a `messaging/monitor/event` batch among live-stream messages.
///
/// Returns `None` for anything else, so a live-stream reader can route monitor
/// batches to its display and pass every other message on.
///
/// A mediator before 0.48.0 pushes 0.1 batches; one is converted to the 0.2
/// shape (each event's `at` → `occurredAt`) and parsed as the 0.2 type, so
/// callers only see 0.2.
///
/// A 0.3 batch (sent to a `monitor/subscribe` 0.2 subscription) is read
/// as 0.2 too: its traffic events are kept and its membership events
/// dropped. Use [`decode_monitor_event_v0_3`] to see them.
///
/// A batch is one document, so one event that does not parse refuses the
/// whole batch, as it did at 0.1. That is logged at `warn` with the reason,
/// so a dropped batch is visible rather than indistinguishable from a
/// message that was never a monitor batch.
#[allow(deprecated)]
pub fn decode_monitor_event(message: &Message) -> Option<TrustTask<monitor::event::v0_2::Payload>> {
    use serde::Deserialize as _;
    use trust_tasks_rs::Payload as _;
    if message.typ != ENVELOPE_TYPE {
        return None;
    }
    let ty = message.body.get("type").and_then(Value::as_str)?;
    let parsed = if ty == monitor::event::v0_2::Payload::TYPE_URI {
        // Deserialised from the borrowed body: no copy on the current version.
        TrustTask::<monitor::event::v0_2::Payload>::deserialize(&message.body)
    } else if ty == MONITOR_EVENT_V0_1 {
        // The rename needs an owned copy; only a pre-0.48.0 mediator sends this.
        let mut doc = message.body.clone();
        monitor_event_to_v0_2(&mut doc);
        TrustTask::<monitor::event::v0_2::Payload>::deserialize(doc)
    } else if ty == monitor::event::v0_3::Payload::TYPE_URI {
        let mut doc = message.body.clone();
        monitor_event_v0_3_to_v0_2(&mut doc);
        TrustTask::<monitor::event::v0_2::Payload>::deserialize(doc)
    } else {
        return None;
    };
    parsed
        .inspect_err(|e| warn!(r#type = ty, error = %e, "dropping a monitor/event batch that does not parse"))
        .ok()
}

/// The `messaging/monitor/event` Type URI a mediator before 0.48.0 pushes.
const MONITOR_EVENT_V0_1: &str = "https://trusttasks.org/spec/messaging/monitor/event/0.1";

/// Recognise a `messaging/monitor/event` batch among live-stream messages,
/// at 0.3: traffic events, and the mux membership events of a subscription
/// that opted in to them ([`TrustTasksOps::monitor_subscribe_with`]).
///
/// `membership` is empty and `membership_dropped` is `None` on a batch for a
/// subscription without membership events. A 0.2 or 0.1 batch (from a
/// `monitor/subscribe` 0.1 subscription, or an older mediator) is converted
/// and read the same way: it never carries membership events.
///
/// Returns `None` for anything else, and for a batch that does not parse
/// (logged at `warn`), as [`decode_monitor_event`] does.
pub fn decode_monitor_event_v0_3(
    message: &Message,
) -> Option<TrustTask<monitor::event::v0_3::Payload>> {
    use serde::Deserialize as _;
    use trust_tasks_rs::Payload as _;
    if message.typ != ENVELOPE_TYPE {
        return None;
    }
    let ty = message.body.get("type").and_then(Value::as_str)?;
    let parsed = if ty == monitor::event::v0_3::Payload::TYPE_URI {
        TrustTask::<monitor::event::v0_3::Payload>::deserialize(&message.body)
    } else if ty == MONITOR_EVENT_V0_2 || ty == MONITOR_EVENT_V0_1 {
        // 0.3 extends 0.2 with optional members only.
        let mut doc = message.body.clone();
        if ty == MONITOR_EVENT_V0_1 {
            monitor_event_to_v0_2(&mut doc);
        }
        doc["type"] = Value::String(monitor::event::v0_3::Payload::TYPE_URI.to_string());
        TrustTask::<monitor::event::v0_3::Payload>::deserialize(doc)
    } else {
        return None;
    };
    parsed
        .inspect_err(|e| warn!(r#type = ty, error = %e, "dropping a monitor/event batch that does not parse"))
        .ok()
}

/// The `messaging/monitor/event` 0.2 Type URI.
const MONITOR_EVENT_V0_2: &str = "https://trusttasks.org/spec/messaging/monitor/event/0.2";

/// Rewrite a 0.3 monitor batch as the 0.2 one, in place: drop the
/// membership members 0.3 added. Its traffic events are the same.
fn monitor_event_v0_3_to_v0_2(doc: &mut Value) {
    doc["type"] = Value::String(MONITOR_EVENT_V0_2.to_string());
    if let Some(payload) = doc.get_mut("payload").and_then(Value::as_object_mut) {
        payload.remove("membership");
        payload.remove("membershipDropped");
    }
}

/// Rewrite a 0.1 monitor batch as the 0.2 one, in place: 0.2 renames each
/// event's `at` to `occurredAt` and changes nothing else.
fn monitor_event_to_v0_2(doc: &mut Value) {
    doc["type"] = Value::String(MONITOR_EVENT_V0_2.to_string());
    if let Some(events) = doc
        .get_mut("payload")
        .and_then(|p| p.get_mut("events"))
        .and_then(Value::as_array_mut)
    {
        for event in events.iter_mut().filter_map(Value::as_object_mut) {
            if let Some(at) = event.remove("at") {
                event.insert("occurredAt".to_string(), at);
            }
        }
    }
}

/// A serialised Trust Task document, as a `TrustTask<Value>` to send as-is.
fn value_task(doc: Value) -> Result<TrustTask<Value>, ATMError> {
    serde_json::from_value(doc)
        .map_err(|e| ATMError::MsgSendError(format!("couldn't serialise Trust Task: {e}")))
}

pub(crate) fn new_id() -> String {
    format!("urn:uuid:{}", Uuid::new_v4())
}

/// How long a Trust Task sent over TSP waits for its reply.
#[cfg(feature = "tsp")]
pub(crate) const TSP_REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// How often the inbox is read while waiting for it.
#[cfg(feature = "tsp")]
const TSP_REPLY_POLL: std::time::Duration = std::time::Duration::from_millis(200);
/// How much of the inbox one read looks at.
#[cfg(feature = "tsp")]
const TSP_REPLY_PAGE: usize = 20;

/// Ask the mediator to refuse `doc` with a `trust-task-error` document
/// ([`ERROR_FORMAT_MEMBER`]). A value the caller already set is kept.
pub(crate) fn ask_for_error_documents(doc: &mut Value) {
    if let Some(obj) = doc.as_object_mut() {
        obj.entry(ERROR_FORMAT_MEMBER)
            .or_insert_with(|| Value::String(ERROR_FORMAT_DOCUMENT.to_string()));
    }
}

/// Read the mediator's answer to the Trust Task `request`: the response
/// document, or the `trust-task-error` it refused the task with, as
/// [`ATMError::TrustTaskError`].
///
/// A `trust-task-error` is taken as the refusal only when it names the
/// request: its `threadId` is the request's thread, or its `inResponseTo.id`
/// is the request's `id` ([`TrustTaskRefusal::answers`]). One that names another
/// request is not an answer to this one, and fails the exchange as any other
/// unexpected reply does ([`ATMError::MsgReceiveError`]).
///
/// [`TrustTaskRefusal::answers`]: crate::errors::TrustTaskRefusal::answers
pub(crate) fn decode_reply<R: DeserializeOwned>(
    reply: &Value,
    request: &RequestIds,
) -> Result<TrustTask<R>, ATMError> {
    if crate::errors::is_trust_task_error(reply) {
        let Some(refusal) = crate::errors::TrustTaskRefusal::from_document(reply) else {
            return Err(ATMError::MsgReceiveError(
                "the mediator answered with a trust-task-error document without a code and retryable"
                    .to_string(),
            ));
        };
        if !refusal.answers(&request.id, request.thread_id.as_deref()) {
            return Err(ATMError::MsgReceiveError(
                "the reply is a trust-task-error for another request, not an answer to this Trust Task"
                    .to_string(),
            ));
        }
        return Err(ATMError::TrustTaskError(Box::new(refusal)));
    }
    decode_body(reply)
}

/// Whether `doc`, read from the TSP inbox, is the answer on `thread_id`: its
/// `threadId` is the request's. Anything else, a refusal of another request
/// included, stays in the inbox for whoever it answers.
#[cfg(feature = "tsp")]
fn answers_thread(doc: &Value, thread_id: &str) -> bool {
    doc.get("threadId").and_then(Value::as_str) == Some(thread_id)
}

/// The `id` and `threadId` of a Trust Task request, which its answer names.
#[derive(Clone, Debug, Default)]
pub(crate) struct RequestIds {
    pub(crate) id: String,
    pub(crate) thread_id: Option<String>,
}

impl RequestIds {
    /// Read from the request document as sent.
    pub(crate) fn of(request: &Value) -> Self {
        let text = |k: &str| request.get(k).and_then(Value::as_str).map(str::to_string);
        Self {
            id: text("id").unwrap_or_default(),
            thread_id: text("threadId"),
        }
    }
}

/// Read a Trust Task response document. A `trust-task-error` is never one:
/// a refusal is read, against its request, by [`decode_reply`].
pub(crate) fn decode_body<R: DeserializeOwned>(body: &Value) -> Result<TrustTask<R>, ATMError> {
    if crate::errors::is_trust_task_error(body) {
        return Err(ATMError::MsgReceiveError(
            "a trust-task-error document is not a Trust Task response".to_string(),
        ));
    }
    serde_json::from_value(body.clone()).map_err(|e| {
        ATMError::MsgReceiveError(format!("response is not a Trust Task document: {e}"))
    })
}

// ─── DID multiplexing (`messaging/mux/*/0.1`) ────────────────────────────────

use crate::protocols::mux::MuxCapability;
use crate::tasks::messaging::mux as mux_tasks;

/// Build a `messaging/mux/*` task from a JSON payload, letting the generated
/// type check its shape before anything is sent.
/// What [`TrustTasksOps::mux_connections`] lists. Every member is optional;
/// the default lists every live mux connection, 50 per page, with up to
/// 1000 member entries per page.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MuxConnectionsQuery {
    /// Only connections authenticated as this DID.
    pub principal: Option<String>,
    /// Only connections carrying this member DID; each then lists that
    /// member alone.
    pub member: Option<String>,
    /// The page's budget of member entries, summed over its connections
    /// (0–1000). `Some(0)` lists connections without their members.
    pub member_limit: Option<u64>,
    /// The most connections per page (1–100).
    pub limit: Option<u64>,
    /// The previous page's `next_cursor`.
    pub cursor: Option<String>,
}

impl MuxConnectionsQuery {
    /// Every live mux connection.
    pub fn all() -> Self {
        Self::default()
    }

    /// Only `principal`'s connections.
    pub fn principal(mut self, did: impl Into<String>) -> Self {
        self.principal = Some(did.into());
        self
    }

    /// Only connections carrying `member`.
    pub fn member(mut self, did: impl Into<String>) -> Self {
        self.member = Some(did.into());
        self
    }

    /// The page's member budget.
    pub fn member_limit(mut self, n: u64) -> Self {
        self.member_limit = Some(n);
        self
    }

    /// The most connections per page.
    pub fn limit(mut self, n: u64) -> Self {
        self.limit = Some(n);
        self
    }

    /// Continue from a previous page's `next_cursor`.
    pub fn cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    /// The `messaging/mux/connections` payload: only the members set.
    fn payload(&self) -> Value {
        let mut payload = json!({});
        if let Some(p) = &self.principal {
            payload["principal"] = json!(p);
        }
        if let Some(m) = &self.member {
            payload["member"] = json!(m);
        }
        if let Some(n) = self.member_limit {
            payload["memberLimit"] = json!(n);
        }
        if let Some(l) = self.limit {
            payload["limit"] = json!(l);
        }
        if let Some(c) = &self.cursor {
            payload["cursor"] = json!(c);
        }
        payload
    }
}

#[cfg(test)]
mod mux_connections_tests {
    use super::*;

    #[test]
    fn a_query_sets_only_what_it_names() {
        assert_eq!(MuxConnectionsQuery::all().payload(), json!({}));
        let q = MuxConnectionsQuery::all()
            .principal("did:example:phone")
            .member("did:example:work")
            .member_limit(0)
            .limit(10)
            .cursor("c1");
        let payload = q.payload();
        assert_eq!(
            payload,
            json!({ "principal": "did:example:phone", "member": "did:example:work",
                    "memberLimit": 0, "limit": 10, "cursor": "c1" })
        );
        // It is a valid request payload for the generated type.
        serde_json::from_value::<mux_tasks::connections::v0_1::Payload>(payload)
            .expect("the payload matches the spec");
    }

    /// The list, update and revoke payloads both wires send are valid
    /// request payloads for the generated types.
    #[test]
    fn shared_mux_payloads_match_the_spec() {
        let list = mux_list_payload(true, Some("c1".into()), Some(5));
        assert_eq!(list, json!({ "as": "member", "cursor": "c1", "limit": 5 }));
        serde_json::from_value::<mux_tasks::list::v0_1::Payload>(list).expect("list");
        serde_json::from_value::<mux_tasks::list::v0_1::Payload>(mux_list_payload(
            false, None, None,
        ))
        .expect("bare list");

        let at = chrono::DateTime::parse_from_rfc3339("2026-12-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let update = mux_update_payload("g1", Some(&[MuxCapability::Receive]), Some(at));
        assert_eq!(
            update,
            json!({ "grantId": "g1", "scope": ["receive"], "expiresAt": "2026-12-01T00:00:00Z" })
        );
        serde_json::from_value::<mux_tasks::update::v0_1::Payload>(update).expect("update");

        let revoke = mux_revoke_payload(false, vec!["g1".into()], vec!["did:example:w".into()]);
        assert_eq!(
            revoke,
            json!({ "as": "principal", "grantIds": ["g1"], "dids": ["did:example:w"] })
        );
        serde_json::from_value::<mux_tasks::revoke::v0_1::Payload>(revoke).expect("revoke");
    }

    /// The admin-list, admin-revoke and admin-revoke-all payloads are valid
    /// request payloads for the generated types.
    #[test]
    fn mux_admin_payloads_match_the_spec() {
        let list = mux_admin_list_payload(Some("did:example:p"), None, Some("c1".into()), Some(50))
            .unwrap();
        assert_eq!(
            list,
            json!({ "principal": "did:example:p", "cursor": "c1", "limit": 50 })
        );
        serde_json::from_value::<mux_tasks::admin_list::v0_1::Payload>(list).expect("list");
        let list = mux_admin_list_payload(None, Some("did:example:m"), None, None).unwrap();
        assert_eq!(list, json!({ "member": "did:example:m" }));
        serde_json::from_value::<mux_tasks::admin_list::v0_1::Payload>(list).expect("bare list");

        let revoke = mux_admin_revoke_payload(
            Some("did:example:p"),
            Some("did:example:m"),
            &["g1".into()],
            Some(10),
        )
        .unwrap();
        assert_eq!(
            revoke,
            json!({ "principal": "did:example:p", "member": "did:example:m",
                    "grantIds": ["g1"], "limit": 10 })
        );
        serde_json::from_value::<mux_tasks::admin_revoke::v0_1::Payload>(revoke).expect("revoke");
        let revoke = mux_admin_revoke_payload(Some("did:example:p"), None, &[], None).unwrap();
        assert_eq!(revoke, json!({ "principal": "did:example:p" }));
        serde_json::from_value::<mux_tasks::admin_revoke::v0_1::Payload>(revoke)
            .expect("bare revoke");

        let all = mux_admin_revoke_all_payload("did:example:m", 3);
        assert_eq!(all, json!({ "did": "did:example:m", "epoch": 3 }));
        serde_json::from_value::<mux_tasks::admin_revoke_all::v0_1::Payload>(all)
            .expect("revoke-all");
    }

    #[test]
    fn mux_admin_selections_the_spec_refuses_are_refused_here() {
        assert!(mux_admin_list_payload(None, None, None, None).is_err());
        assert!(mux_admin_revoke_payload(None, None, &[], None).is_err());
        // Grant ids are unique only on a member's record.
        assert!(
            mux_admin_revoke_payload(Some("did:example:p"), None, &["g1".into()], None).is_err()
        );
    }

    #[test]
    fn mux_admin_responses_decode() {
        let list: mux_tasks::admin_list::v0_1::Response = serde_json::from_value(json!({
            "grants": [{
                "grantId": "g1", "did": "did:example:m", "principal": "did:example:p",
                "state": "active", "scope": ["receive", "delete"],
                "expiresAt": "2026-12-01T00:00:00Z", "epoch": 2,
                "signedAt": "2026-11-01T00:00:00Z", "narrowed": true
            }],
            "epoch": 2,
            "nextCursor": "c2"
        }))
        .expect("admin-list response");
        assert_eq!(list.grants.len(), 1);
        assert_eq!(list.grants[0].epoch, 2);
        assert_eq!(list.epoch, Some(2));
        assert!(list.next_cursor.is_some());

        let revoke: mux_tasks::admin_revoke::v0_1::Response = serde_json::from_value(json!({
            "revoked": [{ "grantId": "g1", "did": "did:example:m", "principal": "did:example:p" }],
            "remaining": 4,
            "unmatchedGrantIds": ["g9"]
        }))
        .expect("admin-revoke response");
        assert_eq!(revoke.revoked.len(), 1);
        assert_eq!(revoke.remaining, 4);
        assert_eq!(revoke.unmatched_grant_ids.len(), 1);

        let all: mux_tasks::admin_revoke_all::v0_1::Response = serde_json::from_value(json!({
            "did": "did:example:m", "epoch": 4, "epochAdvanced": true, "revokedGrants": 2
        }))
        .expect("admin-revoke-all response");
        assert!(all.epoch_advanced);
        assert_eq!((all.epoch, all.revoked_grants), (4, 2));
    }

    fn revoke_round(revoked: usize, remaining: u64) -> mux_tasks::admin_revoke::v0_1::Response {
        let revoked: Vec<Value> = (0..revoked)
            .map(|n| json!({ "grantId": format!("g{n}"), "did": "did:example:m", "principal": "did:example:p" }))
            .collect();
        serde_json::from_value(json!({ "revoked": revoked, "remaining": remaining })).unwrap()
    }

    /// Replays `rounds` in order, counting the requests sent.
    async fn replay(
        max_rounds: usize,
        rounds: Vec<Result<mux_tasks::admin_revoke::v0_1::Response, ATMError>>,
    ) -> (Result<MuxAdminRevokeOutcome, ATMError>, usize) {
        let rounds = std::sync::Mutex::new(rounds.into_iter());
        let sent = std::sync::atomic::AtomicUsize::new(0);
        let outcome = revoke_rounds(max_rounds, || {
            sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let next = rounds.lock().unwrap().next().expect("no round left");
            async move { next }
        })
        .await;
        (outcome, sent.into_inner())
    }

    #[tokio::test]
    async fn revoke_until_done_stops_when_nothing_remains() {
        let (outcome, sent) =
            replay(10, vec![Ok(revoke_round(3, 2)), Ok(revoke_round(2, 0))]).await;
        let outcome = outcome.unwrap();
        assert!(outcome.is_done());
        assert_eq!(
            (outcome.revoked.len(), outcome.remaining, outcome.rounds),
            (5, 0, 2)
        );
        assert_eq!(sent, 2);
    }

    #[tokio::test]
    async fn revoke_until_done_is_bounded_by_max_rounds() {
        let rounds = (0..5).map(|_| Ok(revoke_round(1, 100))).collect();
        let (outcome, sent) = replay(3, rounds).await;
        let outcome = outcome.unwrap();
        assert!(matches!(outcome.stopped, MuxAdminRevokeStop::MaxRounds));
        assert_eq!(
            (outcome.revoked.len(), outcome.remaining, outcome.rounds),
            (3, 100, 3)
        );
        assert_eq!(sent, 3);

        // Zero rounds still sends one.
        let (outcome, sent) = replay(0, vec![Ok(revoke_round(1, 1))]).await;
        assert_eq!((outcome.unwrap().rounds, sent), (1, 1));
    }

    #[tokio::test]
    async fn revoke_until_done_stops_on_a_round_that_revokes_nothing() {
        let (outcome, sent) =
            replay(10, vec![Ok(revoke_round(2, 5)), Ok(revoke_round(0, 5))]).await;
        let outcome = outcome.unwrap();
        assert!(matches!(outcome.stopped, MuxAdminRevokeStop::NoProgress));
        assert_eq!((outcome.revoked.len(), outcome.remaining), (2, 5));
        assert_eq!(sent, 2);
    }

    #[tokio::test]
    async fn revoke_until_done_keeps_what_was_done_when_a_later_round_fails() {
        let contended = || {
            ATMError::ProblemReport(
                "messaging/mux/admin-revoke:contended".into(),
                "send it again".into(),
                "NONE".into(),
            )
        };
        let (outcome, _) = replay(10, vec![Ok(revoke_round(2, 5)), Err(contended())]).await;
        let outcome = outcome.unwrap();
        assert!(matches!(outcome.stopped, MuxAdminRevokeStop::Failed(_)));
        assert_eq!((outcome.revoked.len(), outcome.rounds), (2, 1));

        // Nothing done yet: the first round's refusal is the error.
        let (outcome, sent) = replay(10, vec![Err(contended())]).await;
        assert!(outcome.is_err());
        assert_eq!(sent, 1);
    }
}

/// The `messaging/mux/list` payload; shared by both wires.
pub(crate) fn mux_list_payload(
    as_member: bool,
    cursor: Option<String>,
    limit: Option<u64>,
) -> Value {
    let mut payload = json!({ "as": if as_member { "member" } else { "principal" } });
    if let Some(c) = cursor {
        payload["cursor"] = json!(c);
    }
    if let Some(l) = limit {
        payload["limit"] = json!(l);
    }
    payload
}

/// The `messaging/mux/update` payload; shared by both wires.
pub(crate) fn mux_update_payload(
    grant_id: &str,
    scope: Option<&[MuxCapability]>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Value {
    let mut payload = json!({ "grantId": grant_id });
    if let Some(s) = scope {
        payload["scope"] = json!(s);
    }
    if let Some(e) = expires_at {
        payload["expiresAt"] = json!(e.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    }
    payload
}

/// The `messaging/mux/revoke` payload; shared by both wires.
pub(crate) fn mux_revoke_payload(
    as_member: bool,
    grant_ids: Vec<String>,
    dids: Vec<String>,
) -> Value {
    let mut payload = json!({ "as": if as_member { "member" } else { "principal" } });
    if !grant_ids.is_empty() {
        payload["grantIds"] = json!(grant_ids);
    }
    if !dids.is_empty() {
        payload["dids"] = json!(dids);
    }
    payload
}

/// The `messaging/mux/admin-list` payload. At least one of `principal` and
/// `member` is required.
pub(crate) fn mux_admin_list_payload(
    principal: Option<&str>,
    member: Option<&str>,
    cursor: Option<String>,
    limit: Option<u64>,
) -> Result<Value, ATMError> {
    let mut payload = mux_admin_selection(principal, member)?;
    if let Some(c) = cursor {
        payload["cursor"] = json!(c);
    }
    if let Some(l) = limit {
        payload["limit"] = json!(l);
    }
    Ok(payload)
}

/// The `messaging/mux/admin-revoke` payload. At least one of `principal`
/// and `member` is required, and `grant_ids` only go with `member`.
pub(crate) fn mux_admin_revoke_payload(
    principal: Option<&str>,
    member: Option<&str>,
    grant_ids: &[String],
    limit: Option<u64>,
) -> Result<Value, ATMError> {
    if !grant_ids.is_empty() && member.is_none() {
        return Err(ATMError::ConfigError(
            "mux admin-revoke names grant ids only with a member DID".into(),
        ));
    }
    let mut payload = mux_admin_selection(principal, member)?;
    if !grant_ids.is_empty() {
        payload["grantIds"] = json!(grant_ids);
    }
    if let Some(l) = limit {
        payload["limit"] = json!(l);
    }
    Ok(payload)
}

/// The `messaging/mux/admin-revoke-all` payload.
pub(crate) fn mux_admin_revoke_all_payload(did: &str, epoch: u64) -> Value {
    json!({ "did": did, "epoch": epoch })
}

fn mux_admin_selection(principal: Option<&str>, member: Option<&str>) -> Result<Value, ATMError> {
    if principal.is_none() && member.is_none() {
        return Err(ATMError::ConfigError(
            "a mux admin task names a principal DID, a member DID or both".into(),
        ));
    }
    let mut payload = json!({});
    if let Some(p) = principal {
        payload["principal"] = json!(p);
    }
    if let Some(m) = member {
        payload["member"] = json!(m);
    }
    Ok(payload)
}

/// What [`TrustTasksOps::mux_admin_revoke_until_done`] did.
#[derive(Debug)]
#[non_exhaustive]
pub struct MuxAdminRevokeOutcome {
    /// Every grant revoked, over all rounds, in the order revoked.
    pub revoked: Vec<mux_tasks::admin_revoke::v0_1::GrantRef>,
    /// Requested grant ids that named no stored grant (from the first round).
    pub unmatched_grant_ids: Vec<mux_tasks::admin_revoke::v0_1::GrantId>,
    /// Grants still matching after the last round; `0` when done.
    pub remaining: u64,
    /// How many `admin-revoke` requests were answered.
    pub rounds: usize,
    /// Why it stopped.
    pub stopped: MuxAdminRevokeStop,
}

impl MuxAdminRevokeOutcome {
    /// Whether every matching grant is gone.
    pub fn is_done(&self) -> bool {
        matches!(self.stopped, MuxAdminRevokeStop::Done)
    }
}

/// Why [`TrustTasksOps::mux_admin_revoke_until_done`] stopped.
#[derive(Debug)]
#[non_exhaustive]
pub enum MuxAdminRevokeStop {
    /// No matching grant remains.
    Done,
    /// It sent the most rounds it was allowed; `remaining` still match.
    MaxRounds,
    /// A round revoked nothing while grants still matched; sending it again
    /// would not help.
    NoProgress,
    /// A round after the first failed. What earlier rounds revoked stays
    /// revoked; a `…:contended` refusal can be sent again.
    Failed(ATMError),
}

/// Send `round` until no grant remains, at most `max_rounds` times.
/// The first round's error is returned as is: nothing was revoked yet.
async fn revoke_rounds<F, Fut>(
    max_rounds: usize,
    mut round: F,
) -> Result<MuxAdminRevokeOutcome, ATMError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<mux_tasks::admin_revoke::v0_1::Response, ATMError>>,
{
    let mut outcome = MuxAdminRevokeOutcome {
        revoked: Vec::new(),
        unmatched_grant_ids: Vec::new(),
        remaining: 0,
        rounds: 0,
        stopped: MuxAdminRevokeStop::MaxRounds,
    };
    while outcome.rounds < max_rounds.max(1) {
        let response = match round().await {
            Ok(response) => response,
            Err(e) if outcome.rounds == 0 => return Err(e),
            Err(e) => {
                outcome.stopped = MuxAdminRevokeStop::Failed(e);
                return Ok(outcome);
            }
        };
        outcome.rounds += 1;
        if outcome.rounds == 1 {
            outcome.unmatched_grant_ids = response.unmatched_grant_ids;
        }
        let progressed = !response.revoked.is_empty();
        outcome.revoked.extend(response.revoked);
        outcome.remaining = response.remaining;
        if outcome.remaining == 0 {
            outcome.stopped = MuxAdminRevokeStop::Done;
            return Ok(outcome);
        }
        if !progressed {
            outcome.stopped = MuxAdminRevokeStop::NoProgress;
            return Ok(outcome);
        }
    }
    Ok(outcome)
}

/// Most ids in one `messaging/mux/ack` (the mediator's delete limit).
pub(crate) const MUX_ACK_MAX: usize = 100;

pub(crate) fn mux_task<P>(
    profile: &Arc<ATMProfile>,
    payload: Value,
) -> Result<TrustTask<P>, ATMError>
where
    P: trust_tasks_rs::Payload + DeserializeOwned,
{
    let (profile_did, mediator_did) = profile.dids()?;
    let p: P = serde_json::from_value(payload)
        .map_err(|e| ATMError::MsgSendError(format!("invalid mux payload: {e}")))?;
    let mut task = TrustTask::for_payload(new_id(), p);
    task.issuer = Some(profile_did.to_string());
    task.recipient = Some(mediator_did.to_string());
    Ok(task)
}

impl TrustTasksOps<'_> {
    /// Sign and send on this profile's own DIDComm connection, never over
    /// TSP: `attach` and `detach` act on the mux connection they arrive on,
    /// so they must travel on the mux socket.
    async fn exchange_on_socket<P, R>(
        &self,
        profile: &Arc<ATMProfile>,
        mut task: TrustTask<P>,
        delete_reply: bool,
    ) -> Result<TrustTask<R>, ATMError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let (profile_did, _) = profile.dids()?;
        task.issued_at = Some(chrono::Utc::now());
        let body = serde_json::to_value(&task)
            .map_err(|e| ATMError::MsgSendError(format!("couldn't serialise Trust Task: {e}")))?;
        let body = self.sign(profile_did, body).await?;
        self.exchange_didcomm(profile, body, delete_reply).await
    }

    /// `messaging/mux/grant`: store grant statements (from
    /// [`sign_grant`](crate::protocols::mux::sign_grant)). Either the member
    /// or the principal may send them; each is accepted or refused on its own.
    pub async fn mux_grant(
        &self,
        profile: &Arc<ATMProfile>,
        statements: Vec<Value>,
    ) -> Result<mux_tasks::grant::v0_1::Response, ATMError> {
        let task =
            mux_task::<mux_tasks::grant::v0_1::Payload>(profile, json!({ "grants": statements }))?;
        let r: TrustTask<mux_tasks::grant::v0_1::Response> = self.exchange(profile, task).await?;
        Ok(r.payload)
    }

    /// `messaging/mux/attach` on this profile's **mux connection**: attach
    /// statements (from [`sign_attach`](crate::protocols::mux::sign_attach),
    /// bound to the connection's current [`MuxReady`](crate::protocols::mux::MuxReady)).
    pub async fn mux_attach(
        &self,
        profile: &Arc<ATMProfile>,
        statements: Vec<Value>,
    ) -> Result<mux_tasks::attach::v0_1::Response, ATMError> {
        let task = mux_task::<mux_tasks::attach::v0_1::Payload>(
            profile,
            json!({ "attachments": statements }),
        )?;
        let r: TrustTask<mux_tasks::attach::v0_1::Response> =
            self.exchange_on_socket(profile, task, true).await?;
        Ok(r.payload)
    }

    /// `messaging/mux/detach` on this profile's mux connection: drop session
    /// attaches. A DID carried by a stored grant stays (revoke it instead).
    pub async fn mux_detach(
        &self,
        profile: &Arc<ATMProfile>,
        dids: Vec<String>,
    ) -> Result<mux_tasks::detach::v0_1::Response, ATMError> {
        let task = mux_task::<mux_tasks::detach::v0_1::Payload>(profile, json!({ "dids": dids }))?;
        let r: TrustTask<mux_tasks::detach::v0_1::Response> =
            self.exchange_on_socket(profile, task, true).await?;
        Ok(r.payload)
    }

    /// `messaging/mux/ack` on this profile's mux connection: delete
    /// delivered messages by id (`sha256` of the packed message, as
    /// `UnpackMetadata::sha256_hash` gives it): the profile's own, and each
    /// member's while the member holds `delete` on this connection. Each id
    /// comes back `acked` or `refused` (`notFound`, `notPermitted`).
    ///
    /// Use this, not a REST delete, for member messages: one mediator
    /// instance holds the connection and only it knows the members, so a REST
    /// delete that lands on another instance is refused. At most 100 ids per
    /// call. Fails when the profile has no ready mux connection.
    pub async fn mux_ack(
        &self,
        profile: &Arc<ATMProfile>,
        message_ids: &[String],
    ) -> Result<mux_tasks::ack::v0_1::Response, ATMError> {
        if message_ids.len() > MUX_ACK_MAX {
            return Err(ATMError::ConfigError(format!(
                "mux_ack takes at most {MUX_ACK_MAX} ids, got {}",
                message_ids.len()
            )));
        }
        let ready = match profile.mux_ready().await {
            Some(rx) => rx.borrow().is_some(),
            None => false,
        };
        if !ready {
            return Err(ATMError::Disconnected(
                "messaging/mux/ack needs a ready mux connection".into(),
            ));
        }
        let task = mux_task::<mux_tasks::ack::v0_1::Payload>(
            profile,
            json!({ "messageIds": message_ids }),
        )?;
        let r: TrustTask<mux_tasks::ack::v0_1::Response> =
            self.exchange_on_socket(profile, task, false).await?;
        Ok(r.payload)
    }

    /// `messaging/mux/list`: the grants this profile holds as a principal, or
    /// (`as_member`) the grants on its own DID and its current epoch.
    pub async fn mux_list(
        &self,
        profile: &Arc<ATMProfile>,
        as_member: bool,
        cursor: Option<String>,
        limit: Option<u64>,
    ) -> Result<mux_tasks::list::v0_1::Response, ATMError> {
        let task = mux_task::<mux_tasks::list::v0_1::Payload>(
            profile,
            mux_list_payload(as_member, cursor, limit),
        )?;
        let r: TrustTask<mux_tasks::list::v0_1::Response> = self.exchange(profile, task).await?;
        Ok(r.payload)
    }

    /// `messaging/mux/connections`: an administrator's view of the
    /// mediator's live mux connections, one page at a time. Each connection
    /// lists its principal, wire (`didcomm`/`tsp`), opening time, exact
    /// member count and, within the page's member budget, its members with
    /// source, scope, expiry and whether their live delivery is active there.
    /// `coverage` says whether the answer covers every instance of the
    /// mediator or only the one that answered: show that to the operator.
    ///
    /// Administrator accounts only; anyone else is refused. Pass the previous
    /// page's `next_cursor` in `query.cursor`, with the same filters, to
    /// continue.
    pub async fn mux_connections(
        &self,
        profile: &Arc<ATMProfile>,
        query: &MuxConnectionsQuery,
    ) -> Result<mux_tasks::connections::v0_1::Response, ATMError> {
        let task = mux_task::<mux_tasks::connections::v0_1::Payload>(profile, query.payload())?;
        let r: TrustTask<mux_tasks::connections::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(r.payload)
    }

    /// `messaging/mux/update`: narrow a grant (smaller scope and/or earlier
    /// expiry). Either party may; widening needs a new grant.
    pub async fn mux_update(
        &self,
        profile: &Arc<ATMProfile>,
        grant_id: &str,
        scope: Option<&[MuxCapability]>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<mux_tasks::update::v0_1::Response, ATMError> {
        let task = mux_task::<mux_tasks::update::v0_1::Payload>(
            profile,
            mux_update_payload(grant_id, scope, expires_at),
        )?;
        let r: TrustTask<mux_tasks::update::v0_1::Response> = self.exchange(profile, task).await?;
        Ok(r.payload)
    }

    /// `messaging/mux/revoke`. As principal: `dids` are member DIDs to drop.
    /// As member (`as_member`): `dids` are principals to remove. `grant_ids`
    /// name grants directly either way.
    pub async fn mux_revoke(
        &self,
        profile: &Arc<ATMProfile>,
        as_member: bool,
        grant_ids: Vec<String>,
        dids: Vec<String>,
    ) -> Result<mux_tasks::revoke::v0_1::Response, ATMError> {
        let task = mux_task::<mux_tasks::revoke::v0_1::Payload>(
            profile,
            mux_revoke_payload(as_member, grant_ids, dids),
        )?;
        let r: TrustTask<mux_tasks::revoke::v0_1::Response> = self.exchange(profile, task).await?;
        Ok(r.payload)
    }

    /// `messaging/mux/revoke-all`: void every grant a member issued under an
    /// epoch, with a statement from
    /// [`sign_revoke_all`](crate::protocols::mux::sign_revoke_all).
    pub async fn mux_revoke_all(
        &self,
        profile: &Arc<ATMProfile>,
        statement: Value,
    ) -> Result<mux_tasks::revoke_all::v0_1::Response, ATMError> {
        let task = mux_task::<mux_tasks::revoke_all::v0_1::Payload>(
            profile,
            json!({ "revocation": statement }),
        )?;
        let r: TrustTask<mux_tasks::revoke_all::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(r.payload)
    }

    /// `messaging/mux/admin-list`: an administrator lists the stored grants
    /// of a `principal` DID, of a `member` DID, or between the two (at least
    /// one is required), one page at a time — each grant's parties, state,
    /// effective scope and expiry, and the epoch it was signed under. Never
    /// the signed statements. With `member`, the response's `epoch` is that
    /// DID's current epoch, which [`mux_admin_revoke_all`](Self::mux_admin_revoke_all)
    /// names.
    ///
    /// Pass the previous page's `next_cursor` as `cursor`, with the same
    /// DIDs, to continue; `limit` is 1–500 (the mediator's default is 100).
    /// Administrator accounts only: anyone else is refused with
    /// `authorization.admin_required`.
    pub async fn mux_admin_list(
        &self,
        profile: &Arc<ATMProfile>,
        principal: Option<&str>,
        member: Option<&str>,
        cursor: Option<String>,
        limit: Option<u64>,
    ) -> Result<mux_tasks::admin_list::v0_1::Response, ATMError> {
        let task = mux_task::<mux_tasks::admin_list::v0_1::Payload>(
            profile,
            mux_admin_list_payload(principal, member, cursor, limit)?,
        )?;
        let r: TrustTask<mux_tasks::admin_list::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(r.payload)
    }

    /// `messaging/mux/admin-revoke`: an administrator revokes stored grants
    /// of other accounts — a `principal` DID's, a `member` DID's, or those
    /// between the two (at least one is required) — optionally only the
    /// `grant_ids` of `member`. Revoked grants are deleted and their members
    /// detached before the mediator answers; the statements can never be
    /// stored again.
    ///
    /// One request revokes at most `limit` grants (1–500; default 500), and
    /// `remaining` counts those still matching: send it again, or use
    /// [`mux_admin_revoke_until_done`](Self::mux_admin_revoke_until_done).
    /// A grant whose party is a root administrator is refused
    /// (`…:protectedAccount`, nothing revoked) unless the requester is one.
    /// Administrator accounts only.
    pub async fn mux_admin_revoke(
        &self,
        profile: &Arc<ATMProfile>,
        principal: Option<&str>,
        member: Option<&str>,
        grant_ids: &[String],
        limit: Option<u64>,
    ) -> Result<mux_tasks::admin_revoke::v0_1::Response, ATMError> {
        let task = mux_task::<mux_tasks::admin_revoke::v0_1::Payload>(
            profile,
            mux_admin_revoke_payload(principal, member, grant_ids, limit)?,
        )?;
        let r: TrustTask<mux_tasks::admin_revoke::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(r.payload)
    }

    /// [`mux_admin_revoke`](Self::mux_admin_revoke), sent again while
    /// grants still match, at most `max_rounds` times (at least once).
    ///
    /// Returns everything revoked and why it stopped: no grant left, the
    /// round limit, a round that revoked nothing, or a later round's error.
    /// An error in the first round, when nothing has been revoked, is
    /// returned as the error.
    pub async fn mux_admin_revoke_until_done(
        &self,
        profile: &Arc<ATMProfile>,
        principal: Option<&str>,
        member: Option<&str>,
        grant_ids: &[String],
        limit: Option<u64>,
        max_rounds: usize,
    ) -> Result<MuxAdminRevokeOutcome, ATMError> {
        revoke_rounds(max_rounds, || {
            self.mux_admin_revoke(profile, principal, member, grant_ids, limit)
        })
        .await
    }

    /// `messaging/mux/admin-revoke-all`: an administrator advances member
    /// `did`'s epoch, voiding every grant on it (they stay listed as
    /// `epochRevoked`) and ending its session attaches, without the member's
    /// signature. `epoch` is the one being voided: the DID's current epoch,
    /// as [`mux_admin_list`](Self::mux_admin_list) with `member` reports it.
    ///
    /// Naming an epoch that was already voided changes nothing
    /// (`epoch_advanced` is false). Naming a later one than the current is
    /// refused with `…:epochMismatch`, whose message gives the current
    /// epoch. A root administrator's DID is refused (`…:protectedAccount`)
    /// unless the requester is one, and a DID with no account with
    /// `…:unknownAccount`. Administrator accounts only.
    pub async fn mux_admin_revoke_all(
        &self,
        profile: &Arc<ATMProfile>,
        did: &str,
        epoch: u64,
    ) -> Result<mux_tasks::admin_revoke_all::v0_1::Response, ATMError> {
        let task = mux_task::<mux_tasks::admin_revoke_all::v0_1::Payload>(
            profile,
            mux_admin_revoke_all_payload(did, epoch),
        )?;
        let r: TrustTask<mux_tasks::admin_revoke_all::v0_1::Response> =
            self.exchange(profile, task).await?;
        Ok(r.payload)
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use trust_tasks_proof::affinidi::Verifier;
    use trust_tasks_rs::ProofVerifier;

    fn epoch_mismatch_document() -> Value {
        serde_json::json!({
            "id": "urn:uuid:00000000-0000-4000-8000-0000000000e1",
            "type": "https://trusttasks.org/spec/trust-task-error/0.6",
            "threadId": "urn:uuid:00000000-0000-4000-8000-0000000000a1",
            "payload": {
                "code": "messaging/mux/revoke-all:epochMismatch",
                "retryable": false,
                "message": "statement voids epoch 5, the DID's current epoch is 3",
                "inResponseTo": {
                    "typeUri": "https://trusttasks.org/spec/messaging/mux/revoke-all/0.1",
                    "id": "urn:uuid:00000000-0000-4000-8000-0000000000a1"
                },
                "details": { "currentEpoch": 3 }
            }
        })
    }

    /// The request `epoch_mismatch_document` refuses.
    fn refused_request() -> RequestIds {
        RequestIds::of(&serde_json::json!({
            "id": "urn:uuid:00000000-0000-4000-8000-0000000000a1"
        }))
    }

    #[test]
    fn a_trust_task_error_answer_is_a_typed_refusal() {
        let err =
            decode_reply::<Value>(&epoch_mismatch_document(), &refused_request()).unwrap_err();
        let refusal = err.trust_task_refusal().expect("a TrustTaskError");
        assert_eq!(refusal.code, "messaging/mux/revoke-all:epochMismatch");
        assert!(!refusal.retryable);
        assert_eq!(
            refusal.in_response_to.as_ref().map(|r| r.type_uri.as_str()),
            Some("https://trusttasks.org/spec/messaging/mux/revoke-all/0.1")
        );
        assert_eq!(
            refusal.thread_id.as_deref(),
            Some("urn:uuid:00000000-0000-4000-8000-0000000000a1")
        );
        assert_eq!(err.current_epoch(), Some(3));
        assert_eq!(
            err.refusal_code(),
            Some("messaging/mux/revoke-all:epochMismatch")
        );
    }

    #[test]
    fn a_trust_task_error_without_a_code_is_not_read_as_a_response() {
        let mut doc = epoch_mismatch_document();
        doc["payload"].as_object_mut().unwrap().remove("code");
        assert!(matches!(
            decode_reply::<Value>(&doc, &refused_request()),
            Err(ATMError::MsgReceiveError(_))
        ));
    }

    #[test]
    fn a_refusal_of_another_request_is_not_an_answer() {
        let other = RequestIds::of(&serde_json::json!({ "id": "urn:uuid:other" }));
        let err = decode_reply::<Value>(&epoch_mismatch_document(), &other).unwrap_err();
        assert!(matches!(err, ATMError::MsgReceiveError(_)), "{err}");
        assert!(err.trust_task_refusal().is_none());

        // Without threadId, inResponseTo.id alone ties it to the request.
        let mut doc = epoch_mismatch_document();
        doc.as_object_mut().unwrap().remove("threadId");
        assert!(
            decode_reply::<Value>(&doc, &refused_request())
                .unwrap_err()
                .trust_task_refusal()
                .is_some()
        );
        // With neither, it ties to nothing.
        doc["payload"]
            .as_object_mut()
            .unwrap()
            .remove("inResponseTo");
        assert!(matches!(
            decode_reply::<Value>(&doc, &refused_request()),
            Err(ATMError::MsgReceiveError(_))
        ));

        // A request that set its own threadId is answered on that thread.
        let mut doc = epoch_mismatch_document();
        doc["threadId"] = "urn:uuid:thread".into();
        doc["payload"]
            .as_object_mut()
            .unwrap()
            .remove("inResponseTo");
        let threaded = RequestIds::of(&serde_json::json!({
            "id": "urn:uuid:request", "threadId": "urn:uuid:thread"
        }));
        assert!(
            decode_reply::<Value>(&doc, &threaded)
                .unwrap_err()
                .trust_task_refusal()
                .is_some()
        );

        // Read as a plain response, a trust-task-error is never one.
        assert!(matches!(
            decode_body::<Value>(&epoch_mismatch_document()),
            Err(ATMError::MsgReceiveError(_))
        ));
    }

    /// The TSP inbox correlates every reply by `threadId` before reading it,
    /// so a refusal of another request is skipped there, not decoded.
    #[cfg(feature = "tsp")]
    #[test]
    fn the_tsp_inbox_takes_only_its_own_thread() {
        let doc = epoch_mismatch_document();
        assert!(answers_thread(
            &doc,
            "urn:uuid:00000000-0000-4000-8000-0000000000a1"
        ));
        assert!(!answers_thread(&doc, "urn:uuid:other"));
        let mut unthreaded = doc.clone();
        unthreaded.as_object_mut().unwrap().remove("threadId");
        assert!(!answers_thread(
            &unthreaded,
            "urn:uuid:00000000-0000-4000-8000-0000000000a1"
        ));
    }

    #[test]
    fn a_response_still_decodes() {
        let doc = serde_json::json!({
            "id": "urn:uuid:00000000-0000-4000-8000-0000000000e2",
            "type": "https://trusttasks.org/spec/messaging/mux/revoke-all/0.1#response",
            "payload": { "epoch": 4 }
        });
        assert_eq!(decode_body::<Value>(&doc).unwrap().payload["epoch"], 4);
    }

    #[test]
    fn every_request_asks_for_error_documents() {
        let mut doc = serde_json::json!({ "id": "x", "type": "t", "payload": {} });
        ask_for_error_documents(&mut doc);
        assert_eq!(doc[ERROR_FORMAT_MEMBER], ERROR_FORMAT_DOCUMENT);
        // A value set by the caller is kept.
        let mut doc = serde_json::json!({ ERROR_FORMAT_MEMBER: "other" });
        ask_for_error_documents(&mut doc);
        assert_eq!(doc[ERROR_FORMAT_MEMBER], "other");
    }

    #[test]
    fn an_unsupported_type_is_recognised_in_either_form() {
        use crate::protocols::trust_task_versions::is_unsupported_error;
        assert!(is_unsupported_error(&ATMError::ProblemReport(
            "e.p.protocol.trust_task.unsupported".into(),
            String::new(),
            "NONE".into(),
        )));
        let mut doc = epoch_mismatch_document();
        doc["payload"]["code"] = "unsupportedType".into();
        doc["payload"].as_object_mut().unwrap().remove("details");
        assert!(is_unsupported_error(
            &decode_reply::<Value>(&doc, &refused_request()).unwrap_err()
        ));
        assert!(!is_unsupported_error(
            &decode_reply::<Value>(&epoch_mismatch_document(), &refused_request()).unwrap_err()
        ));
    }

    /// An Ed25519 `did:key` secret whose `kid` is the DID's own verification
    /// method, so the stock `did:key` verifier can resolve it offline.
    fn did_key_secret() -> (String, Secret) {
        let seed = [7u8; 32];
        let mb = Secret::generate_ed25519(None, Some(&seed))
            .get_public_keymultibase()
            .expect("ed25519 multibase");
        let did = format!("did:key:{mb}");
        let secret = Secret::generate_ed25519(Some(&format!("{did}#{mb}")), Some(&seed));
        (did, secret)
    }

    fn monitor_message(ty: &str, event: Value) -> Message {
        Message::build(
            new_id(),
            ENVELOPE_TYPE.to_string(),
            serde_json::json!({
                "id": "urn:uuid:00000000-0000-4000-8000-000000000003",
                "type": ty,
                "payload": {
                    "subscriptionId": "s1",
                    "seq": 1,
                    "events": [event],
                    "dropped": 0,
                    "expiresAt": "2026-10-28T10:00:00Z",
                },
            }),
        )
        .finalize()
    }

    fn monitor_event(instant_member: &str) -> Value {
        serde_json::json!({
            instant_member: "2026-10-28T09:00:00.123Z",
            "direction": "inbound",
            "stage": "received",
            "channel": "websocket",
            "protocol": "didcomm",
        })
    }

    #[test]
    fn a_0_2_monitor_batch_decodes() {
        use trust_tasks_rs::Payload as _;
        let message = monitor_message(
            monitor::event::v0_2::Payload::TYPE_URI,
            monitor_event("occurredAt"),
        );
        let batch = decode_monitor_event(&message).expect("a 0.2 batch");
        assert_eq!(batch.payload.events.len(), 1);
    }

    #[test]
    fn a_0_1_monitor_batch_decodes_as_0_2() {
        let message = monitor_message(MONITOR_EVENT_V0_1, monitor_event("at"));
        let batch = decode_monitor_event(&message).expect("a 0.1 batch, converted");
        assert_eq!(
            batch.payload.events[0].occurred_at.to_rfc3339(),
            "2026-10-28T09:00:00.123+00:00"
        );
    }

    #[test]
    fn a_batch_with_a_malformed_event_is_refused() {
        // `at` that is not a date-time, in a 0.1 batch: refused whole, as at 0.1.
        let mut event = monitor_event("at");
        event["at"] = Value::String("yesterday".into());
        let message = monitor_message(MONITOR_EVENT_V0_1, event);
        assert!(decode_monitor_event(&message).is_none());
    }

    #[test]
    fn other_messages_are_not_monitor_batches() {
        let message = monitor_message(
            "https://trusttasks.org/spec/messaging/ping/0.2",
            monitor_event("occurredAt"),
        );
        assert!(decode_monitor_event(&message).is_none());
    }

    fn membership_event() -> Value {
        json!({
            "occurredAt": "2026-11-13T09:00:00.5Z",
            "change": "attached",
            "principal": "did:example:phone",
            "member": "did:example:work",
            "wire": "didcomm",
            "source": "grant",
            "reason": "connect",
            "sessionId": "sess-1",
        })
    }

    fn v0_3_message(membership: Option<Value>) -> Message {
        use trust_tasks_rs::Payload as _;
        let mut message = monitor_message(
            monitor::event::v0_3::Payload::TYPE_URI,
            monitor_event("occurredAt"),
        );
        if let Some(membership) = membership {
            message.body["payload"]["membership"] = json!([membership]);
            message.body["payload"]["membershipDropped"] = json!(2);
        }
        message
    }

    #[test]
    fn a_0_3_batch_with_membership_decodes() {
        let batch = decode_monitor_event_v0_3(&v0_3_message(Some(membership_event())))
            .expect("a 0.3 batch");
        assert_eq!(batch.payload.events.len(), 1);
        assert_eq!(batch.payload.membership.len(), 1);
        assert_eq!(batch.payload.membership_dropped, Some(2));
        let event = &batch.payload.membership[0];
        assert_eq!(
            event.change,
            monitor::event::v0_3::MembershipChange::Attached
        );
        assert_eq!(
            event.reason,
            monitor::event::v0_3::MemberChangeReason::Connect
        );
        assert!(event.session_id.is_some());
    }

    #[test]
    fn a_0_3_batch_without_membership_decodes() {
        let batch = decode_monitor_event_v0_3(&v0_3_message(None)).expect("a 0.3 batch");
        assert_eq!(batch.payload.events.len(), 1);
        assert!(batch.payload.membership.is_empty());
        assert_eq!(batch.payload.membership_dropped, None);
    }

    #[test]
    fn a_membership_only_0_3_batch_decodes() {
        let mut message = v0_3_message(Some(membership_event()));
        message.body["payload"]["events"] = json!([]);
        let batch = decode_monitor_event_v0_3(&message).expect("a 0.3 batch");
        assert!(batch.payload.events.is_empty());
        assert_eq!(batch.payload.membership.len(), 1);
    }

    #[test]
    fn older_batches_decode_as_0_3() {
        use trust_tasks_rs::Payload as _;
        let v0_2 = monitor_message(
            monitor::event::v0_2::Payload::TYPE_URI,
            monitor_event("occurredAt"),
        );
        let batch = decode_monitor_event_v0_3(&v0_2).expect("a 0.2 batch, as 0.3");
        assert_eq!(batch.payload.events.len(), 1);
        assert!(batch.payload.membership.is_empty());

        let v0_1 = monitor_message(MONITOR_EVENT_V0_1, monitor_event("at"));
        let batch = decode_monitor_event_v0_3(&v0_1).expect("a 0.1 batch, as 0.3");
        assert_eq!(
            batch.payload.events[0].occurred_at.to_rfc3339(),
            "2026-10-28T09:00:00.123+00:00"
        );
    }

    #[test]
    fn a_0_3_batch_decodes_as_0_2_without_its_membership() {
        let batch = decode_monitor_event(&v0_3_message(Some(membership_event())))
            .expect("a 0.3 batch, as 0.2");
        assert_eq!(batch.payload.events.len(), 1);
        assert_eq!(batch.payload.dropped, 0);
    }

    #[test]
    fn a_0_3_batch_with_a_malformed_membership_event_is_refused() {
        let mut event = membership_event();
        event["change"] = json!("moved");
        assert!(decode_monitor_event_v0_3(&v0_3_message(Some(event))).is_none());
    }

    #[test]
    fn other_messages_are_not_0_3_monitor_batches() {
        let message = monitor_message(
            "https://trusttasks.org/spec/messaging/ping/0.2",
            monitor_event("occurredAt"),
        );
        assert!(decode_monitor_event_v0_3(&message).is_none());
    }

    #[test]
    fn monitor_subscriptions_match_the_spec() {
        // The default reads as a 0.1 subscription: no traffic, no membership.
        let plain = serde_json::to_value(MonitorSubscription::new().payload().unwrap()).unwrap();
        assert_eq!(plain, json!({}));

        let membership = monitor::subscribe::v0_2::MembershipFilter::builder()
            .changes(Some(vec![
                monitor::subscribe::v0_2::MembershipChange::Detached,
            ]))
            .dids(Some(vec!["did:example:work".parse().unwrap()]));
        let membership: monitor::subscribe::v0_2::MembershipFilter = membership.try_into().unwrap();
        let only = MonitorSubscription::membership_only(membership.clone())
            .lease_seconds(60)
            .max_events_per_second(10)
            .renew("s1");
        let only = serde_json::to_value(only.payload().unwrap()).unwrap();
        assert_eq!(
            only,
            json!({ "traffic": false,
                    "membership": { "changes": ["detached"], "dids": ["did:example:work"] },
                    "leaseSeconds": 60, "maxEventsPerSecond": 10, "subscriptionId": "s1" })
        );
        serde_json::from_value::<monitor::subscribe::v0_2::Payload>(only).expect("spec payload");

        let both = MonitorSubscription::new()
            .filter(monitor::subscribe::v0_2::MonitorFilter::default())
            .membership(monitor::subscribe::v0_2::MembershipFilter::default());
        let both = serde_json::to_value(both.payload().unwrap()).unwrap();
        assert_eq!(both, json!({ "filter": {}, "membership": {} }));
        serde_json::from_value::<monitor::subscribe::v0_2::Payload>(both).expect("spec payload");

        // The spec forbids a traffic filter with traffic off.
        let refused = MonitorSubscription::membership_only(membership)
            .filter(monitor::subscribe::v0_2::MonitorFilter::default());
        assert!(refused.payload().is_err());
    }

    #[test]
    fn a_0_2_subscribe_response_decodes() {
        let response: monitor::subscribe::v0_2::Response = serde_json::from_value(json!({
            "subscriptionId": "s1",
            "expiresAt": "2026-11-13T09:05:00Z",
            "filter": {},
            "maxEventsPerSecond": 100,
            "traffic": false,
            "membership": { "wires": ["tsp"] },
        }))
        .expect("0.2 response");
        assert_eq!(response.traffic, Some(false));
        assert!(response.membership.is_some());
    }

    #[test]
    fn queue_purges_match_the_spec() {
        let plain = QueuePurge::new(queue::purge::v0_1::Queue::Receive);
        let plain = serde_json::to_value(plain.payload().unwrap()).unwrap();
        assert_eq!(plain, json!({ "queue": "receive", "dryRun": false }));

        let selected_at = chrono::DateTime::parse_from_rfc3339("2026-11-14T03:04:05.250Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let confirming = QueuePurge::new(queue::purge::v0_1::Queue::Send)
            .did_hash("account")
            .peer("did:example:peer")
            .older_than_seconds(60)
            .stored_before(selected_at);
        let confirming = serde_json::to_value(confirming.payload().unwrap()).unwrap();
        assert_eq!(
            confirming,
            json!({ "did": "account", "queue": "send", "peer": "did:example:peer",
                    "olderThanSeconds": 60, "storedBefore": "2026-11-14T03:04:05.250Z",
                    "dryRun": false })
        );
        let parsed: queue::purge::v0_1::Payload =
            serde_json::from_value(confirming).expect("spec payload");
        assert_eq!(parsed.stored_before, Some(selected_at));

        let refused = QueuePurge::new(queue::purge::v0_1::Queue::Receive).peer("");
        assert!(refused.payload().is_err());
    }

    #[test]
    fn a_queue_purge_response_carries_selected_at() {
        let response: queue::purge::v0_1::Response = serde_json::from_value(json!({
            "matched": 3,
            "matchedBytes": 1024,
            "purged": 0,
            "dryRun": true,
            "selectedAt": "2026-11-14T03:04:05.250Z",
        }))
        .expect("response with selectedAt");
        let selected_at = response.selected_at.expect("selectedAt");
        assert_eq!(
            selected_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "2026-11-14T03:04:05.250Z"
        );
        let confirming = QueuePurge::new(queue::purge::v0_1::Queue::Receive)
            .stored_before(selected_at)
            .payload()
            .unwrap();
        assert_eq!(confirming.stored_before, Some(selected_at));

        let without: queue::purge::v0_1::Response = serde_json::from_value(json!({
            "matched": 0, "purged": 0, "dryRun": false,
        }))
        .expect("response without selectedAt");
        assert!(without.selected_at.is_none());
    }

    #[tokio::test]
    async fn a_signed_task_survives_typed_parsing_and_verifies() {
        // The mediator re-reads every request as a typed `TrustTask<P>` before it
        // verifies, so the proof this SDK emits must round-trip through the typed
        // document — not merely verify as loose JSON.
        let (did, secret) = did_key_secret();
        let p: ping::v0_2::Payload =
            payload(ping::v0_2::Payload::builder().nonce(Some("n".into()))).unwrap();
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(did.clone());
        task.recipient = Some("did:web:mediator.example".into());
        task.issued_at = Some(chrono::Utc::now());

        let signed = sign_trust_task(
            &serde_json::to_value(&task).unwrap(),
            &secret,
            SignOptions::new(),
        )
        .await
        .expect("sign");
        let typed: TrustTask<ping::v0_2::Payload> =
            serde_json::from_value(signed).expect("signed document parses as typed");

        assert!(typed.proof.is_some());
        assert!(typed.issued_at.is_some());
        Verifier::for_did_key()
            .verify(&typed)
            .await
            .expect("stock verifier accepts the proof");
    }

    #[tokio::test]
    async fn a_tampered_payload_fails_verification() {
        let (did, secret) = did_key_secret();
        let p: ping::v0_2::Payload =
            payload(ping::v0_2::Payload::builder().nonce(Some("n".into()))).unwrap();
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(did);
        task.recipient = Some("did:web:mediator.example".into());

        let mut signed = sign_trust_task(
            &serde_json::to_value(&task).unwrap(),
            &secret,
            SignOptions::new(),
        )
        .await
        .expect("sign");
        signed["payload"]["nonce"] = Value::String("changed".into());
        let typed: TrustTask<ping::v0_2::Payload> = serde_json::from_value(signed).unwrap();

        assert!(Verifier::for_did_key().verify(&typed).await.is_err());
    }
}
