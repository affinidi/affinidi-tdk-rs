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

use affinidi_messaging_didcomm::message::Message;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha256::digest;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::messaging::{access_list, account, acl, ping};
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

        let response: TrustTask<ping::v0_1::Response> = self.exchange(profile, &task).await?;
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
        let (profile_did, mediator_did) = profile.dids()?;
        let target = did_hash.unwrap_or_else(|| digest(&profile.inner.did));

        let did = account::get::v0_1::Vid::from_str(&target)
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let p: account::get::v0_1::Payload =
            payload(account::get::v0_1::Payload::builder().did(did))?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<account::get::v0_1::Response> =
            self.exchange(profile, &task).await?;
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
                .limit(limit),
        )?;
        let mut task = TrustTask::for_payload(new_id(), p);
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<account::list::v0_1::Response> =
            self.exchange(profile, &task).await?;
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
            self.exchange(profile, &task).await?;
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
            self.exchange(profile, &task).await?;
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

        let response: TrustTask<acl::get::v0_1::Response> = self.exchange(profile, &task).await?;
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
            self.exchange(profile, &task).await?;
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
            self.exchange(profile, &task).await?;
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
            self.exchange(profile, &task).await?;
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
        let response: TrustTask<audit::list::v0_1::Response> =
            self.exchange(profile, &task).await?;
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
            self.exchange(profile, &task).await?;
        Ok(response.payload)
    }

    /// Wrap a `TrustTask<P>` in the DIDComm binding envelope, authcrypt + send it
    /// to the mediator, and decode the reply's body as a `TrustTask<R>`.
    async fn exchange<P, R>(
        &self,
        profile: &Arc<ATMProfile>,
        task: &TrustTask<P>,
    ) -> Result<TrustTask<R>, ATMError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let atm = self.atm;
        let (profile_did, mediator_did) = profile.dids()?;

        let body = serde_json::to_value(task)
            .map_err(|e| ATMError::MsgSendError(format!("couldn't serialise Trust Task: {e}")))?;

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
}

fn new_id() -> String {
    format!("urn:uuid:{}", Uuid::new_v4())
}

fn decode_body<R: DeserializeOwned>(body: &Value) -> Result<TrustTask<R>, ATMError> {
    serde_json::from_value(body.clone()).map_err(|e| {
        ATMError::MsgReceiveError(format!("response is not a Trust Task document: {e}"))
    })
}
