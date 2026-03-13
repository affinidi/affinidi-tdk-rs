use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_sdk::protocols::mediator::acls::{AccessListModeType, MediatorACLSet};
use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};
use sha256::digest;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::listener::Listener;
use crate::error::{DIDCommServiceError, StartupError};

const OFFLINE_SYNC_INTERVAL_SECS: u64 = 30;

impl Listener {
    pub(crate) async fn set_acl_mode(
        &self,
        acl_mode: &AccessListModeType,
    ) -> Result<(), DIDCommServiceError> {
        let atm = self.atm()?;
        let profile = self.profile()?;

        let account_info = atm
            .mediator()
            .account_get(profile, None)
            .await
            .map_err(StartupError::AccountInfo)?
            .ok_or(StartupError::NoAccountInfo)?;

        let mut acls = MediatorACLSet::from_u64(account_info.acls);

        debug!("ACL_MODE: Configured to {:?}", acl_mode);

        acls.set_access_list_mode(acl_mode.clone(), true, false)
            .map_err(StartupError::AclMode)?;

        atm.mediator()
            .acls_set(profile, &digest(&profile.inner.did), &acls)
            .await
            .map_err(StartupError::AclApply)?;

        Ok(())
    }

    pub(crate) async fn run_periodic_offline_sync(
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        shutdown: &CancellationToken,
    ) {
        let profile_alias = profile.inner.alias.clone();
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    debug!("[profile = {}] Offline sync task shutting down", profile_alias);
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(OFFLINE_SYNC_INTERVAL_SECS)) => {
                    if let Err(e) = Listener::sync_offline_messages(atm, profile).await {
                        debug!(
                            "[profile = {}] Offline sync failed: {}",
                            profile_alias, e
                        );
                    }
                }
            }
        }
    }

    async fn sync_offline_messages(
        atm: &ATM,
        profile: &Arc<ATMProfile>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let wait_for_response = true;
        let messages_limit = 100;

        let status_reply = atm
            .message_pickup()
            .send_status_request(profile, wait_for_response, None)
            .await?;

        let messages_count = status_reply.map(|m| m.message_count).unwrap_or(0);
        debug!(
            "[profile = {}] Offline messages count: {}",
            profile.inner.alias, messages_count
        );

        if messages_count == 0 {
            return Ok(());
        }

        let offline_messages = atm
            .message_pickup()
            .send_delivery_request(profile, Some(messages_limit), wait_for_response)
            .await?;

        let message_ids: Vec<_> = offline_messages.iter().map(|(m, _)| m.id.clone()).collect();

        debug!(
            "[profile = {}] Retrieved {} offline messages",
            profile.inner.alias,
            offline_messages.len()
        );

        let delete_result = atm
            .message_pickup()
            .send_messages_received(profile, &message_ids, wait_for_response)
            .await?;

        if delete_result.is_some() {
            debug!(
                "[profile = {}] Offline messages acknowledged and deleted",
                profile.inner.alias
            );
        } else {
            debug!(
                "[profile = {}] No status reply for offline messages ack",
                profile.inner.alias
            );
        }

        Ok(())
    }
}
