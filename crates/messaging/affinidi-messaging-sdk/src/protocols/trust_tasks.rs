//! Trust Tasks client — send the messaging [Trust Tasks] to a mediator and get
//! the typed response.
//!
//! Accessed via [`crate::ATM::trust_tasks`]. Each task is a typed `TrustTask<P>`
//! document carried over the DIDComm binding envelope (a DIDComm message whose
//! `type` is the [`ENVELOPE_TYPE`] and whose `body` is the document). The mediator
//! consumes it through the Trust Tasks framework and returns a `TrustTask<R>`.
//!
//! This exposes `ping` and `account_get`; the rest of the account / acl /
//! access-list families follow, and the legacy `atm.mediator()` / `atm.trust_ping()`
//! methods will route through this same core.
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
use trust_tasks_rs::specs::messaging::{access_list, account, acl, admin, ping};
use uuid::Uuid;

use crate::{ATM, errors::ATMError, profiles::ATMProfile, transports::SendMessageResponse};

/// DIDComm `type` URI of a Trust Tasks binding envelope.
pub const ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";

/// Trust Tasks client operations, obtained from [`crate::ATM::trust_tasks`].
pub struct TrustTasksOps<'a> {
    pub(crate) atm: &'a ATM,
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
        let mut task = TrustTask::for_payload(
            new_id(),
            ping::v0_1::Payload { ext: None, nonce },
        );
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
        let mut task = TrustTask::for_payload(
            new_id(),
            account::get::v0_1::Payload { did, ext: None },
        );
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<account::get::v0_1::Response> = self.exchange(profile, &task).await?;
        Ok(response.payload.account)
    }

    /// Send a `messaging/account/list` Trust Task (admin only) and return one page
    /// of accounts plus an opaque `next_cursor` (present only when more remain).
    /// Pass the previous page's cursor to continue; `None` starts from the top.
    pub async fn account_list(
        &self,
        profile: &Arc<ATMProfile>,
        cursor: Option<String>,
        limit: Option<u32>,
    ) -> Result<account::list::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;

        let cursor = cursor
            .map(|c| account::list::v0_1::PayloadCursor::from_str(&c))
            .transpose()
            .map_err(|e| ATMError::MsgSendError(format!("invalid cursor: {e}")))?;
        let limit = limit.and_then(|l| std::num::NonZeroU64::new(l as u64));

        let mut task = TrustTask::for_payload(
            new_id(),
            account::list::v0_1::Payload {
                cursor,
                ext: None,
                limit,
            },
        );
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<account::list::v0_1::Response> =
            self.exchange(profile, &task).await?;
        Ok(response.payload)
    }

    /// Send a `messaging/account/change-queue-limits` Trust Task and return the
    /// updated account view. `did_hash` names the target; `None` is the caller's own
    /// account. Each limit is an `Option`: `Some(-1)` = unlimited, `Some(n)` = a cap,
    /// `None` = leave that limit unchanged. A standard account may only change limits
    /// it self-manages (others are silently left unchanged).
    pub async fn account_change_queue_limits(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
        send_queue_limit: Option<i64>,
        receive_queue_limit: Option<i64>,
    ) -> Result<account::change_queue_limits::v0_1::Account, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let target = did_hash.unwrap_or_else(|| digest(&profile.inner.did));

        let did = account::change_queue_limits::v0_1::Vid::from_str(&target)
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let mut task = TrustTask::for_payload(
            new_id(),
            account::change_queue_limits::v0_1::Payload {
                did,
                ext: None,
                queue_limits: account::change_queue_limits::v0_1::QueueLimits {
                    receive_queue_limit,
                    send_queue_limit,
                },
            },
        );
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<account::change_queue_limits::v0_1::Response> =
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
        let mut task = TrustTask::for_payload(
            new_id(),
            account::remove::v0_1::Payload { did, ext: None },
        );
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<account::remove::v0_1::Response> =
            self.exchange(profile, &task).await?;
        Ok(response.payload.removed)
    }

    /// Send a `messaging/account/change-type` Trust Task (admin only) and return the
    /// account's realized view after the role change. Only a root admin may assign the
    /// root-admin role or modify a root-admin account. `account_type` is the
    /// [`account::change_type::v0_1::AccountType`] to set.
    pub async fn account_change_type(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: String,
        account_type: account::change_type::v0_1::AccountType,
    ) -> Result<account::change_type::v0_1::Account, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;

        let did = account::change_type::v0_1::Vid::from_str(&did_hash)
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let mut task = TrustTask::for_payload(
            new_id(),
            account::change_type::v0_1::Payload {
                account_type,
                did,
                ext: None,
            },
        );
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<account::change_type::v0_1::Response> =
            self.exchange(profile, &task).await?;
        Ok(response.payload.account)
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
        let mut task =
            TrustTask::for_payload(new_id(), acl::get::v0_1::Payload { dids, ext: None });
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<acl::get::v0_1::Response> = self.exchange(profile, &task).await?;
        Ok(response.payload)
    }

    /// Send a `messaging/acl/set` Trust Task (admin only). The `acl` is applied as a
    /// partial update — flags present are set, flags absent are left unchanged — and
    /// the realized ACL is returned.
    pub async fn acl_set(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: String,
        acl: acl::set::v0_1::MediatorAcl,
    ) -> Result<acl::set::v0_1::MediatorAcl, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;

        let did = acl::set::v0_1::Vid::from_str(&did_hash)
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let mut task =
            TrustTask::for_payload(new_id(), acl::set::v0_1::Payload { acl, did, ext: None });
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<acl::set::v0_1::Response> = self.exchange(profile, &task).await?;
        Ok(response.payload.acl)
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
        let mut task = TrustTask::for_payload(
            new_id(),
            account::add::v0_1::Payload {
                account_type,
                acl,
                did,
                ext: None,
                // Initial queue limits use the mediator default; adjust with
                // `account_change_queue_limits` after creation.
                queue_limits: None,
            },
        );
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let response: TrustTask<account::add::v0_1::Response> =
            self.exchange(profile, &task).await?;
        Ok(response.payload.account)
    }

    /// `messaging/access-list/add` — add entries to an account's access list (self-or-
    /// admin; `None` = own list). Returns the inserted entries and the new count.
    pub async fn access_list_add(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
        entries: Vec<String>,
    ) -> Result<access_list::add::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let target = did_hash.unwrap_or_else(|| digest(&profile.inner.did));
        let did = access_list::add::v0_1::Vid::from_str(&target)
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let entries = entries
            .iter()
            .map(|e| access_list::add::v0_1::Vid::from_str(e))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ATMError::MsgSendError(format!("invalid access-list entry: {e}")))?;
        let mut task = TrustTask::for_payload(
            new_id(),
            access_list::add::v0_1::Payload { did, entries, ext: None },
        );
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());
        let response: TrustTask<access_list::add::v0_1::Response> =
            self.exchange(profile, &task).await?;
        Ok(response.payload)
    }

    /// `messaging/access-list/remove` — remove entries (self-or-admin; `None` = own
    /// list). Returns which of the requested entries were present (and so removed).
    pub async fn access_list_remove(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
        entries: Vec<String>,
    ) -> Result<access_list::remove::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let target = did_hash.unwrap_or_else(|| digest(&profile.inner.did));
        let did = access_list::remove::v0_1::Vid::from_str(&target)
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let entries = entries
            .iter()
            .map(|e| access_list::remove::v0_1::Vid::from_str(e))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ATMError::MsgSendError(format!("invalid access-list entry: {e}")))?;
        let mut task = TrustTask::for_payload(
            new_id(),
            access_list::remove::v0_1::Payload { did, entries, ext: None },
        );
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());
        let response: TrustTask<access_list::remove::v0_1::Response> =
            self.exchange(profile, &task).await?;
        Ok(response.payload)
    }

    /// `messaging/access-list/clear` — drop the entire access list (self-or-admin;
    /// `None` = own list).
    pub async fn access_list_clear(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
    ) -> Result<access_list::clear::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let target = did_hash.unwrap_or_else(|| digest(&profile.inner.did));
        let did = access_list::clear::v0_1::Vid::from_str(&target)
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let mut task = TrustTask::for_payload(
            new_id(),
            access_list::clear::v0_1::Payload { did, ext: None },
        );
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());
        let response: TrustTask<access_list::clear::v0_1::Response> =
            self.exchange(profile, &task).await?;
        Ok(response.payload)
    }

    /// `messaging/access-list/get` — partition the queried entries into those present
    /// in the list and those absent (self-or-admin; `None` = own list).
    pub async fn access_list_get(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
        entries: Vec<String>,
    ) -> Result<access_list::get::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let target = did_hash.unwrap_or_else(|| digest(&profile.inner.did));
        let did = access_list::get::v0_1::Vid::from_str(&target)
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let entries = entries
            .iter()
            .map(|e| access_list::get::v0_1::Vid::from_str(e))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ATMError::MsgSendError(format!("invalid access-list entry: {e}")))?;
        let mut task = TrustTask::for_payload(
            new_id(),
            access_list::get::v0_1::Payload { did, entries, ext: None },
        );
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());
        let response: TrustTask<access_list::get::v0_1::Response> =
            self.exchange(profile, &task).await?;
        Ok(response.payload)
    }

    /// `messaging/access-list/list` — page through an account's access list (self-or-
    /// admin; `None` = own list). Returns entries plus an opaque `next_cursor`.
    pub async fn access_list_list(
        &self,
        profile: &Arc<ATMProfile>,
        did_hash: Option<String>,
        cursor: Option<String>,
        limit: Option<u32>,
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
        let mut task = TrustTask::for_payload(
            new_id(),
            access_list::list::v0_1::Payload { cursor, did, ext: None, limit },
        );
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());
        let response: TrustTask<access_list::list::v0_1::Response> =
            self.exchange(profile, &task).await?;
        Ok(response.payload)
    }

    /// `messaging/admin/add` (admin only) — grant admin rights to the named accounts.
    /// Returns the now-admin account identifiers.
    pub async fn admin_add(
        &self,
        profile: &Arc<ATMProfile>,
        did_hashes: Vec<String>,
    ) -> Result<Vec<String>, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let dids = did_hashes
            .iter()
            .map(|d| admin::add::v0_1::Vid::from_str(d))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let mut task = TrustTask::for_payload(new_id(), admin::add::v0_1::Payload { dids, ext: None });
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());
        let response: TrustTask<admin::add::v0_1::Response> = self.exchange(profile, &task).await?;
        Ok(response.payload.admins.iter().map(|v| v.to_string()).collect())
    }

    /// `messaging/admin/strip` (admin only) — revoke admin rights from the named
    /// accounts. Returns the stripped account identifiers.
    pub async fn admin_strip(
        &self,
        profile: &Arc<ATMProfile>,
        did_hashes: Vec<String>,
    ) -> Result<Vec<String>, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let dids = did_hashes
            .iter()
            .map(|d| admin::strip::v0_1::Vid::from_str(d))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ATMError::MsgSendError(format!("invalid account identifier: {e}")))?;
        let mut task =
            TrustTask::for_payload(new_id(), admin::strip::v0_1::Payload { dids, ext: None });
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());
        let response: TrustTask<admin::strip::v0_1::Response> =
            self.exchange(profile, &task).await?;
        Ok(response.payload.stripped.iter().map(|v| v.to_string()).collect())
    }

    /// `messaging/admin/list` (admin only) — page the mediator's admin accounts.
    pub async fn admin_list(
        &self,
        profile: &Arc<ATMProfile>,
        cursor: Option<String>,
        limit: Option<u32>,
    ) -> Result<admin::list::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let cursor = cursor
            .map(|c| admin::list::v0_1::PayloadCursor::from_str(&c))
            .transpose()
            .map_err(|e| ATMError::MsgSendError(format!("invalid cursor: {e}")))?;
        let limit = limit.and_then(|l| std::num::NonZeroU64::new(l as u64));
        let mut task = TrustTask::for_payload(
            new_id(),
            admin::list::v0_1::Payload { cursor, ext: None, limit },
        );
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());
        let response: TrustTask<admin::list::v0_1::Response> = self.exchange(profile, &task).await?;
        Ok(response.payload)
    }

    /// `messaging/admin/audit-log` (admin only) — page the privileged-change log,
    /// newest first.
    pub async fn admin_audit_log(
        &self,
        profile: &Arc<ATMProfile>,
        cursor: Option<String>,
        limit: Option<u32>,
    ) -> Result<admin::audit_log::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let cursor = cursor
            .map(|c| admin::audit_log::v0_1::PayloadCursor::from_str(&c))
            .transpose()
            .map_err(|e| ATMError::MsgSendError(format!("invalid cursor: {e}")))?;
        let limit = limit.and_then(|l| std::num::NonZeroU64::new(l as u64));
        let mut task = TrustTask::for_payload(
            new_id(),
            admin::audit_log::v0_1::Payload { cursor, ext: None, limit },
        );
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());
        let response: TrustTask<admin::audit_log::v0_1::Response> =
            self.exchange(profile, &task).await?;
        Ok(response.payload)
    }

    /// `messaging/admin/config` (admin only) — read the mediator's version + config.
    pub async fn admin_config(
        &self,
        profile: &Arc<ATMProfile>,
    ) -> Result<admin::config::v0_1::Response, ATMError> {
        let (profile_did, mediator_did) = profile.dids()?;
        let mut task = TrustTask::for_payload(new_id(), admin::config::v0_1::Payload { ext: None });
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());
        let response: TrustTask<admin::config::v0_1::Response> =
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

        match atm.send_message(profile, &packed, &msg_id, true, true).await? {
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
    serde_json::from_value(body.clone())
        .map_err(|e| ATMError::MsgReceiveError(format!("response is not a Trust Task document: {e}")))
}
