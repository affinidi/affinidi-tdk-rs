use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_sdk::protocols::mediator::acls::MediatorACLSet;
use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};
use sha256::digest;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::listener::Listener;

const OFFLINE_SYNC_INTERVAL_SECS: u64 = 30;

impl Listener {
    pub(crate) async fn set_acl_mode(&self) {
        let atm = self.atm();
        let profile = self.profile();
        let acl_mode = &self.config.acl_mode;

        let account_result = atm.mediator().account_get(profile, None).await;

        let account_info = match account_result {
            Ok(Some(info)) => info,
            Ok(None) => {
                warn!(
                    "[profile = {}] Failed to get account info",
                    profile.inner.alias
                );
                return;
            }
            Err(e) => {
                warn!(
                    "[profile = {}] Failed to get account info: {}",
                    profile.inner.alias, e
                );
                return;
            }
        };

        let mut acls = MediatorACLSet::from_u64(account_info.acls);

        info!("ACL_MODE: Configured to {:?}", acl_mode);

        if let Err(e) = acls.set_access_list_mode(acl_mode.clone(), true, false) {
            warn!("Failed to set ACL mode: {}", e);
            return;
        }

        if let Err(e) = atm
            .mediator()
            .acls_set(profile, &digest(&profile.inner.did), &acls)
            .await
        {
            warn!("Failed to apply ACL settings: {}", e);
        }
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
                    info!("[profile = {}] Offline sync task shutting down", profile_alias);
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(OFFLINE_SYNC_INTERVAL_SECS)) => {
                    if let Err(e) = Listener::sync_offline_messages(atm, profile).await {
                        warn!(
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
        info!(
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
            info!(
                "[profile = {}] Offline messages acknowledged and deleted",
                profile.inner.alias
            );
        } else {
            warn!(
                "[profile = {}] No status reply for offline messages ack",
                profile.inner.alias
            );
        }

        Ok(())
    }
}
