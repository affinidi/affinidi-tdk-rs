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
use trust_tasks_rs::specs::messaging::{account, ping};
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
