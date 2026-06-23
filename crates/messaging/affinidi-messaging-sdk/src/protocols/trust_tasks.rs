//! Trust Tasks client — send the messaging [Trust Tasks] to a mediator and get
//! the typed response.
//!
//! Accessed via [`crate::ATM::trust_tasks`]. Each task is a typed `TrustTask<P>`
//! document carried over the DIDComm binding envelope (a DIDComm message whose
//! `type` is the [`ENVELOPE_TYPE`] and whose `body` is the document). The mediator
//! consumes it through the Trust Tasks framework and returns a `TrustTask<R>`.
//!
//! This first cut exposes `ping`; account / acl / access-list follow, and the
//! legacy `atm.mediator()` / `atm.trust_ping()` methods will route through this
//! same core.
//!
//! [Trust Tasks]: https://trusttasks.org

use std::sync::Arc;
use std::time::SystemTime;

use affinidi_messaging_didcomm::message::Message;
use trust_tasks_rs::TrustTask;
use trust_tasks_rs::specs::messaging::ping;
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
        let atm = self.atm;
        let (profile_did, mediator_did) = profile.dids()?;

        // Build the Trust Task document (in-band parties: me → the mediator).
        let mut task = TrustTask::for_payload(
            format!("urn:uuid:{}", Uuid::new_v4()),
            ping::v0_1::Payload { ext: None, nonce },
        );
        task.issuer = Some(profile_did.to_string());
        task.recipient = Some(mediator_did.to_string());

        let body = serde_json::to_value(&task)
            .map_err(|e| ATMError::MsgSendError(format!("couldn't serialise ping Trust Task: {e}")))?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Wrap it in the DIDComm binding envelope and authcrypt it to the mediator.
        let msg = Message::build(Uuid::new_v4().to_string(), ENVELOPE_TYPE.to_string(), body)
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
            .map_err(|e| ATMError::MsgSendError(format!("couldn't pack ping Trust Task: {e}")))?;

        match atm.send_message(profile, &packed, &msg_id, true, true).await? {
            SendMessageResponse::Message(response) => {
                let doc: TrustTask<ping::v0_1::Response> =
                    serde_json::from_value(response.body.clone()).map_err(|e| {
                        ATMError::MsgReceiveError(format!(
                            "ping response is not a Trust Task document: {e}"
                        ))
                    })?;
                Ok(doc.payload)
            }
            _ => Err(ATMError::MsgReceiveError(
                "no response from mediator for the ping Trust Task".to_owned(),
            )),
        }
    }
}
