use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_sdk::errors::ATMError;
use affinidi_messaging_sdk::protocols::mediator::acls::AccessListModeType;
use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};
use trust_tasks_rs::specs::messaging::acl;
use sha256::digest;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::listener::Listener;
use crate::error::{DIDCommServiceError, StartupError};
use crate::handler::DIDCommHandler;

const OFFLINE_SYNC_INTERVAL_SECS: u64 = 30;
/// Short retry used only when the very first drains can't run yet because the
/// websocket is still coming up right after connect — so the initial backlog is
/// fetched within a second or two instead of waiting a full interval.
const OFFLINE_SYNC_RETRY_SECS: u64 = 2;

impl Listener {
    pub(crate) async fn set_acl_mode(
        &self,
        acl_mode: &AccessListModeType,
    ) -> Result<(), DIDCommServiceError> {
        let atm = self.atm()?;
        let profile = self.profile()?;

        info!(acl_mode = ?acl_mode, "ACL mode configured");

        // A partial ACL update setting only the access-list mode; the mediator's
        // self-service gating applies it (the rest of the ACL is left unchanged).
        let mode = match acl_mode {
            AccessListModeType::ExplicitAllow => {
                acl::set::v0_1::MediatorAclAccessListMode::ExplicitAllow
            }
            AccessListModeType::ExplicitDeny => {
                acl::set::v0_1::MediatorAclAccessListMode::ExplicitDeny
            }
        };
        let acl = acl::set::v0_1::MediatorAcl {
            access_list_mode: Some(mode),
            ..Default::default()
        };
        atm.trust_tasks()
            .acl_set(profile, digest(&profile.inner.did), acl)
            .await
            .map_err(StartupError::AclApply)?;

        Ok(())
    }

    pub(crate) async fn run_periodic_offline_sync(
        listener_id: &str,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        handler: &Arc<dyn DIDCommHandler>,
        shutdown: &CancellationToken,
    ) {
        let profile_alias = profile.inner.alias.clone();
        loop {
            // Drain the offline/queued backlog at the TOP of the loop, so it runs
            // immediately on connect rather than only after the first interval.
            // Previously this slept `OFFLINE_SYNC_INTERVAL_SECS` *before* the
            // first sync, so a message delivered while this listener was offline
            // (e.g. a membership credential issued before the listener connected)
            // wasn't picked up for ~30s. Now it arrives in ~1s.
            let next_delay_secs = match Listener::sync_offline_messages(
                listener_id,
                atm,
                profile,
                handler,
            )
            .await
            {
                Ok(()) => OFFLINE_SYNC_INTERVAL_SECS,
                Err(e) => {
                    // A websocket reconnect (e.g. when the mediator closes the
                    // socket on access-token expiry) can land mid-poll and abort
                    // an in-flight request. That is expected and self-heals, so
                    // log it at debug rather than raising a misleading "sync
                    // failed" warning. Right after connect the socket may still be
                    // coming up — retry soon so the initial drain isn't delayed a
                    // whole interval; back off normally on any other error.
                    if matches!(
                        e.downcast_ref::<ATMError>(),
                        Some(ATMError::Disconnected(_))
                    ) {
                        debug!(profile = %profile_alias, "Offline sync skipped: websocket reconnecting");
                        OFFLINE_SYNC_RETRY_SECS
                    } else {
                        warn!(profile = %profile_alias, error = %e, "Offline sync failed");
                        OFFLINE_SYNC_INTERVAL_SECS
                    }
                }
            };

            tokio::select! {
                _ = shutdown.cancelled() => {
                    debug!(profile = %profile_alias, "Offline sync task shutting down");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(next_delay_secs)) => {}
            }
        }
    }

    async fn sync_offline_messages(
        listener_id: &str,
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        handler: &Arc<dyn DIDCommHandler>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let wait_for_response = true;
        let messages_limit = 100;

        let status_reply = atm
            .message_pickup()
            .send_status_request(profile, wait_for_response, None)
            .await?;

        let messages_count = status_reply.map(|m| m.message_count).unwrap_or(0);
        debug!(profile = %profile.inner.alias, count = messages_count, "Offline messages count");

        if messages_count == 0 {
            return Ok(());
        }

        let offline_messages = atm
            .message_pickup()
            .send_delivery_request(profile, Some(messages_limit), wait_for_response)
            .await?;

        let message_ids: Vec<_> = offline_messages.iter().map(|(m, _)| m.id.clone()).collect();

        debug!(profile = %profile.inner.alias, count = offline_messages.len(), "Retrieved offline messages");

        for (message, meta) in offline_messages {
            let meta = super::listener::convert_meta(meta);
            Listener::dispatch_message(listener_id, atm, profile, handler, message, meta).await;
        }

        let delete_result = atm
            .message_pickup()
            .send_messages_received(profile, &message_ids, wait_for_response)
            .await?;

        if delete_result.is_some() {
            debug!(profile = %profile.inner.alias, "Offline messages acknowledged and deleted");
        } else {
            warn!(profile = %profile.inner.alias, "No status reply for offline messages ack");
        }

        Ok(())
    }
}