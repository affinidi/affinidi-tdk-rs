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

use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use affinidi_did_common::DocumentExt;
use affinidi_messaging_didcomm::message::Message;
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_secrets_resolver::secrets::{KeyType, Secret};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha256::digest;
use tracing::warn;
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::messaging::{
    access_list, account, acl, message, monitor, ping, queue, stats,
};
use trust_tasks_rs::specs::{audit, config};
use uuid::Uuid;

use crate::{ATM, errors::ATMError, profiles::ATMProfile, transports::SendMessageResponse};

/// DIDComm `type` URI of a Trust Tasks binding envelope.
pub const ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";

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
    ) -> Result<ping::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let p: ping::v0_1::Payload = payload(ping::v0_1::Payload::builder().nonce(nonce))?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<ping::v0_1::Response> = self.exchange(profile, task).await?;
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
    ) -> Result<account::get::v0_1::Account, ATMError> {
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
    ) -> Result<account::get::v0_1::Account, ATMError> {
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
    ) -> Result<account::get::v0_1::Account, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let target = did_hash.unwrap_or_else(|| digest(&profile.inner.did));

        let did = account::get::v0_1::Vid::from_str(&target)
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let p: account::get::v0_1::Payload = payload(
            account::get::v0_1::Payload::builder()
                .did(did)
                .include_activity(include_activity.then_some(true))
                .include_stats(include_stats.then_some(true)),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<account::get::v0_1::Response> =
            self.exchange(profile, task).await?;
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
        account_type: Option<account::list::v0_1::AccountType>,
    ) -> Result<account::list::v0_1::Response, ATMError> {
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
        account_type: Option<account::list::v0_1::AccountType>,
        include_activity: bool,
    ) -> Result<account::list::v0_1::Response, ATMError> {
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
        account_type: Option<account::list::v0_1::AccountType>,
        include_activity: bool,
        include_stats: bool,
    ) -> Result<account::list::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;

        let cursor = cursor
            .map(|c| account::list::v0_1::PayloadCursor::from_str(&c))
            .transpose()
            .map_err(|e| ATMError::MsgSendError(format!("invalid cursor: {e}")))?;
        let limit = limit.and_then(|l| std::num::NonZeroU64::new(l as u64));

        let p: account::list::v0_1::Payload = payload(
            account::list::v0_1::Payload::builder()
                .account_type(account_type)
                .cursor(cursor)
                .include_activity(include_activity.then_some(true))
                .include_stats(include_stats.then_some(true))
                .limit(limit),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<account::list::v0_1::Response> =
            self.exchange(profile, task).await?;
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
        account_type: Option<account::update::v0_1::AccountType>,
        acl: Option<account::update::v0_1::MediatorAcl>,
        queue_limits: Option<account::update::v0_1::QueueLimits>,
    ) -> Result<account::update::v0_1::Account, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let target = did_hash.unwrap_or_else(|| digest(&profile.inner.did));

        let did = account::update::v0_1::Vid::from_str(&target)
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let p: account::update::v0_1::Payload = payload(
            account::update::v0_1::Payload::builder()
                .account_type(account_type)
                .acl(acl)
                .did(did)
                .queue_limits(queue_limits),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<account::update::v0_1::Response> =
            self.exchange(profile, task).await?;
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
        account_type: account::add::v0_1::AccountType,
        acl: Option<account::add::v0_1::MediatorAcl>,
    ) -> Result<account::add::v0_1::Account, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;

        let did = account::add::v0_1::Vid::from_str(&did_hash)
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        // Initial queue limits are left unset so the mediator default applies;
        // adjust with `account_update` after creation.
        let p: account::add::v0_1::Payload = payload(
            account::add::v0_1::Payload::builder()
                .account_type(account_type)
                .acl(acl)
                .did(did),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<account::add::v0_1::Response> =
            self.exchange(profile, task).await?;
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
        page_size: Option<u32>,
    ) -> Result<audit::list::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        // Only the two members this method exposes are set; `action`, `actor`,
        // `contextId`, `from`, `outcome` and `to` are filters the builder leaves
        // unset, which is an unfiltered listing.
        let p: audit::list::v0_1::Payload = payload(
            audit::list::v0_1::Payload::builder()
                .cursor(cursor)
                .page_size(page_size.and_then(|l| std::num::NonZeroU64::new(l as u64))),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());
        let response: TrustTask<audit::list::v0_1::Response> = self.exchange(profile, task).await?;
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
    pub async fn queue_purge(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
        queue: queue::purge::v0_1::Queue,
        peer: Option<String>,
        older_than_seconds: Option<u64>,
        dry_run: bool,
    ) -> Result<queue::purge::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let vid = |v: String| {
            queue::purge::v0_1::Vid::from_str(&v)
                .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))
        };
        let did = did_hash.map(vid).transpose()?;
        let peer = peer.map(vid).transpose()?;

        let p: queue::purge::v0_1::Payload = payload(
            queue::purge::v0_1::Payload::builder()
                .did(did)
                .queue(queue)
                .peer(peer)
                .older_than_seconds(older_than_seconds)
                .dry_run(Some(dry_run)),
        )?;
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
        self.exchange_didcomm(profile, body).await
    }

    /// The DIDComm arm: the document rides the Trust Tasks envelope, and the
    /// mediator's reply comes back on the same request.
    async fn exchange_didcomm<R>(
        &self,
        profile: &Arc<ATMProfile>,
        body: Value,
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

        match atm
            .send_message(profile, &packed, &msg_id, true, true)
            .await?
        {
            SendMessageResponse::Message(response) => decode_body(&response.body),
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
        use affinidi_messaging_mediator_common::types::messages::MessageProtocol;

        use crate::messages::{DeleteMessageRequest, fetch::FetchOptions};

        let (_, mediator_did) = profile.dids()?;
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
                    if doc["threadId"].as_str() != Some(thread_id) {
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
                    return decode_body(&doc);
                }

                if cursor.is_none() || SystemTime::now() >= deadline {
                    break;
                }
            }

            if SystemTime::now() >= deadline {
                return Err(ATMError::MsgReceiveError(format!(
                    "no response from mediator for the Trust Task over TSP within {}s",
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
    async fn sign(&self, did: &str, doc: Value) -> Result<Value, ATMError> {
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

/// Recognise a `messaging/monitor/event` batch among live-stream messages.
///
/// Returns `None` for anything else, so a live-stream reader can route monitor
/// batches to its display and pass every other message on.
pub fn decode_monitor_event(message: &Message) -> Option<TrustTask<monitor::event::v0_1::Payload>> {
    use trust_tasks_rs::Payload as _;
    if message.typ != ENVELOPE_TYPE
        || message.body.get("type").and_then(Value::as_str)
            != Some(monitor::event::v0_1::Payload::TYPE_URI)
    {
        return None;
    }
    serde_json::from_value(message.body.clone()).ok()
}

fn new_id() -> String {
    format!("urn:uuid:{}", Uuid::new_v4())
}

/// How long a Trust Task sent over TSP waits for its reply.
#[cfg(feature = "tsp")]
const TSP_REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// How often the inbox is read while waiting for it.
#[cfg(feature = "tsp")]
const TSP_REPLY_POLL: std::time::Duration = std::time::Duration::from_millis(200);
/// How much of the inbox one read looks at.
#[cfg(feature = "tsp")]
const TSP_REPLY_PAGE: usize = 20;

fn decode_body<R: DeserializeOwned>(body: &Value) -> Result<TrustTask<R>, ATMError> {
    serde_json::from_value(body.clone()).map_err(|e| {
        ATMError::MsgReceiveError(format!("response is not a Trust Task document: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_tasks_proof::affinidi::Verifier;
    use trust_tasks_rs::ProofVerifier;

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

    #[tokio::test]
    async fn a_signed_task_survives_typed_parsing_and_verifies() {
        // The mediator re-reads every request as a typed `TrustTask<P>` before it
        // verifies, so the proof this SDK emits must round-trip through the typed
        // document — not merely verify as loose JSON.
        let (did, secret) = did_key_secret();
        let p: ping::v0_1::Payload =
            payload(ping::v0_1::Payload::builder().nonce(Some("n".into()))).unwrap();
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
        let typed: TrustTask<ping::v0_1::Payload> =
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
        let p: ping::v0_1::Payload =
            payload(ping::v0_1::Payload::builder().nonce(Some("n".into()))).unwrap();
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
        let typed: TrustTask<ping::v0_1::Payload> = serde_json::from_value(signed).unwrap();

        assert!(Verifier::for_did_key().verify(&typed).await.is_err());
    }
}
