use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_sdk::config::ATMConfigBuilder;
use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_tdk_common::TDKSharedState;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::config::ListenerConfig;
use crate::crypto::MessageCryptoProvider;
use crate::error::DIDCommServiceError;
use crate::handler::{DIDCommHandler, HandlerContext};
use crate::utils::{get_parent_thread_id, get_thread_id};

pub(crate) struct Listener {
    pub config: ListenerConfig,
    pub handler: Arc<dyn DIDCommHandler>,
    pub crypto_provider: Arc<dyn MessageCryptoProvider>,
    pub shutdown: CancellationToken,
    atm: Option<ATM>,
    profile: Option<Arc<ATMProfile>>,
}

impl Listener {
    pub fn new(
        config: ListenerConfig,
        handler: Arc<dyn DIDCommHandler>,
        crypto_provider: Arc<dyn MessageCryptoProvider>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            config,
            handler,
            crypto_provider,
            shutdown,
            atm: None,
            profile: None,
        }
    }

    pub fn atm(&self) -> &ATM {
        self.atm.as_ref().expect("Listener not connected")
    }

    pub fn profile(&self) -> &Arc<ATMProfile> {
        self.profile.as_ref().expect("Listener not connected")
    }

    pub async fn connect(&mut self) -> Result<(), DIDCommServiceError> {
        let shared_state = Arc::new(TDKSharedState::default().await);

        shared_state
            .secrets_resolver
            .insert_vec(&self.config.profile.secrets)
            .await;

        let atm_config = ATMConfigBuilder::default()
            .build()
            .map_err(|e| DIDCommServiceError::StartupFailed(e.to_string()))?;

        let atm = ATM::new(atm_config, shared_state)
            .await
            .map_err(|e| DIDCommServiceError::StartupFailed(e.to_string()))?;

        let atm_profile = ATMProfile::from_tdk_profile(&atm, &self.config.profile).await?;

        let profile_arc = match tokio::time::timeout(
            Duration::from_secs(10),
            atm.profile_add(&atm_profile, false),
        )
        .await
        {
            Ok(result) => result?,
            Err(e) => {
                error!(
                    "[profile = {}] Timeout adding profile: {}",
                    self.config.profile.alias, e
                );
                return Err(DIDCommServiceError::Timeout(e));
            }
        };

        self.atm = Some(atm);
        self.profile = Some(profile_arc);
        Ok(())
    }

    pub async fn listen(&self) -> Result<(), DIDCommServiceError> {
        self.set_acl_mode().await;

        self.atm()
            .profile_start_live_streaming(self.profile(), false, true)
            .await
            .map_err(|e| DIDCommServiceError::StartupFailed(e.to_string()))?;

        let shutdown_clone = self.shutdown.clone();
        let atm_clone = self.atm().clone();
        let profile_clone = self.profile().clone();
        tokio::spawn(async move {
            Listener::run_periodic_offline_sync(&atm_clone, &profile_clone, &shutdown_clone).await;
        });

        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    info!("[profile = {}] Listener received shutdown signal", self.profile().inner.alias);
                    return Ok(());
                }
                result = self.process_next_message() => {
                    if let Err(e) = result {
                        error!(
                            "[profile = {}] Error processing message: {}",
                            self.profile().inner.alias, e
                        );
                    }
                }
            }
        }
    }

    async fn process_next_message(&self) -> Result<(), DIDCommServiceError> {
        let wait_duration = Duration::from_secs(self.config.message_wait_duration_secs);
        let auto_delete = self.config.auto_delete;
        let atm = self.atm();
        let profile = self.profile();

        let packed = atm
            .message_pickup()
            .live_stream_next_packed(profile, Some(wait_duration), auto_delete)
            .await
            .map_err(DIDCommServiceError::ATM)?;

        if let Some(packed_message) = packed {
            let (message, meta) = self
                .crypto_provider
                .unpack(atm, profile, &packed_message)
                .await?;

            let sender_did = message.from.clone().unwrap_or_else(|| "anon".into());
            let thread_id = get_thread_id(&message).or_else(|| Some(message.id.clone()));
            let parent_thread_id = get_parent_thread_id(&message);

            let ctx = HandlerContext {
                atm: atm.clone(),
                profile: profile.clone(),
                sender_did,
                message_id: message.id.clone(),
                thread_id,
                parent_thread_id,
            };

            let handler = self.handler.clone();
            tokio::spawn(async move {
                let result = handler.handle(&ctx, message, meta).await;
                if let Err(e) = result {
                    error!(
                        "[profile = {}] Error handling message: {}",
                        ctx.profile.inner.alias, e
                    );
                }
            });
        }

        Ok(())
    }
}
