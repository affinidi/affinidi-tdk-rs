use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_sdk::config::ATMConfigBuilder;
use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};
use affinidi_secrets_resolver::SecretsResolver;
use affinidi_tdk_common::TDKSharedState;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::ListenerConfig;
use crate::error::{DIDCommServiceError, StartupError};
use crate::handler::{DIDCommHandler, HandlerContext};
use crate::response::DIDCommResponse;
use crate::transport;
use crate::utils::{get_parent_thread_id, get_thread_id};

/// Convert SDK compat UnpackMetadata to didcomm crate UnpackMetadata
pub(crate) fn convert_meta(
    sdk_meta: affinidi_messaging_sdk::messages::compat::UnpackMetadata,
) -> affinidi_messaging_didcomm::UnpackMetadata {
    affinidi_messaging_didcomm::UnpackMetadata {
        encrypted: sdk_meta.encrypted,
        authenticated: sdk_meta.authenticated,
        non_repudiation: sdk_meta.non_repudiation,
        anonymous_sender: sdk_meta.anonymous_sender,
        re_wrapped_in_forward: sdk_meta.re_wrapped_in_forward,
        encrypted_from_kid: sdk_meta.encrypted_from_kid,
        encrypted_to_kids: sdk_meta.encrypted_to_kids,
        sign_from: sdk_meta.sign_from,
    }
}

const ATM_OPERATION_TIMEOUT_SECS: u64 = 10;

pub(crate) struct Listener {
    pub config: ListenerConfig,
    pub handler: Arc<dyn DIDCommHandler>,
    pub shutdown: CancellationToken,
    atm: Option<ATM>,
    profile: Option<Arc<ATMProfile>>,
}

impl Listener {
    pub fn new(
        config: ListenerConfig,
        handler: Arc<dyn DIDCommHandler>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            config,
            handler,
            shutdown,
            atm: None,
            profile: None,
        }
    }

    pub(crate) fn atm(&self) -> Result<&ATM, DIDCommServiceError> {
        self.atm
            .as_ref()
            .ok_or_else(|| DIDCommServiceError::Internal("Listener not connected".into()))
    }

    pub(crate) fn profile(&self) -> Result<&Arc<ATMProfile>, DIDCommServiceError> {
        self.profile
            .as_ref()
            .ok_or_else(|| DIDCommServiceError::Internal("Listener not connected".into()))
    }

    pub async fn connect(&mut self) -> Result<(), DIDCommServiceError> {
        let shared_state = Arc::new(TDKSharedState::default().await);

        shared_state
            .secrets_resolver
            .insert_vec(&self.config.profile.secrets)
            .await;

        let atm_config = ATMConfigBuilder::default()
            .build()
            .map_err(StartupError::Config)?;

        let atm = ATM::new(atm_config, shared_state)
            .await
            .map_err(StartupError::Init)?;

        let atm_profile = ATMProfile::from_tdk_profile(&atm, &self.config.profile).await?;

        let profile_arc = match tokio::time::timeout(
            Duration::from_secs(ATM_OPERATION_TIMEOUT_SECS),
            atm.profile_add(&atm_profile, true),
        )
        .await
        {
            Ok(result) => result?,
            Err(e) => {
                warn!(profile = %self.config.profile.alias, error = %e, "Timeout adding profile");
                return Err(DIDCommServiceError::Timeout(e));
            }
        };

        self.atm = Some(atm);
        self.profile = Some(profile_arc);
        Ok(())
    }

    pub async fn listen(&self) -> Result<(), DIDCommServiceError> {
        if let Some(ref acl_mode) = self.config.acl_mode {
            self.set_acl_mode(acl_mode).await?;
        }

        let atm = self.atm()?;
        let profile = self.profile()?;

        let mut tasks = JoinSet::new();

        // Spawn offline sync as a tracked task
        let shutdown_clone = self.shutdown.clone();
        let atm_clone = atm.clone();
        let profile_clone = profile.clone();
        let handler_clone = self.handler.clone();
        tasks.spawn(async move {
            Listener::run_periodic_offline_sync(
                &atm_clone,
                &profile_clone,
                &handler_clone,
                &shutdown_clone,
            )
            .await;
        });

        loop {
            // Reap completed tasks and log panics
            while let Some(result) = tasks.try_join_next() {
                if let Err(e) = result
                    && e.is_panic()
                {
                    error!(profile = %profile.inner.alias, error = %e, "Handler task panicked");
                }
            }

            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    info!(profile = %profile.inner.alias, "Listener received shutdown signal");
                    break;
                }
                result = self.process_next_message(&mut tasks) => {
                    if let Err(e) = result {
                        warn!(profile = %profile.inner.alias, error = %e, "Error processing message");
                    }
                }
            }
        }

        // Drain in-flight tasks on shutdown
        info!(profile = %profile.inner.alias, count = tasks.len(), "Waiting for in-flight tasks to complete");
        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result
                && e.is_panic()
            {
                error!(profile = %profile.inner.alias, error = %e, "Handler task panicked during shutdown");
            }
        }

        Ok(())
    }

    async fn process_next_message(
        &self,
        tasks: &mut JoinSet<()>,
    ) -> Result<(), DIDCommServiceError> {
        let wait_duration = Duration::from_secs(self.config.message_wait_duration_secs);
        let auto_delete = self.config.auto_delete;
        let atm = self.atm()?;
        let profile = self.profile()?;

        let next = atm
            .message_pickup()
            .live_stream_next(profile, Some(wait_duration), auto_delete)
            .await
            .map_err(DIDCommServiceError::ATM)?;

        if let Some((message, meta)) = next {
            let meta = convert_meta(*meta);
            let atm = atm.clone();
            let profile = profile.clone();
            let handler = self.handler.clone();
            tasks.spawn(async move {
                Self::dispatch_message(&atm, &profile, &handler, message, meta).await;
            });
        }

        Ok(())
    }

    pub(crate) async fn dispatch_message(
        atm: &ATM,
        profile: &Arc<ATMProfile>,
        handler: &Arc<dyn DIDCommHandler>,
        message: affinidi_messaging_didcomm::Message,
        meta: affinidi_messaging_didcomm::UnpackMetadata,
    ) {
        let sender_did = message.from.clone();
        let thread_id = get_thread_id(&message);
        let parent_thread_id = get_parent_thread_id(&message, false);

        let ctx = HandlerContext {
            atm: atm.clone(),
            profile: profile.clone(),
            sender_did,
            message_id: message.id.clone(),
            thread_id,
            parent_thread_id,
        };

        let profile_alias = ctx.profile.inner.alias.clone();
        match handler.handle(ctx.clone(), message, meta).await {
            Ok(Some(response)) => {
                if let Err(e) = Self::send_response(&ctx, response).await {
                    warn!(profile = %profile_alias, error = %e, "Failed to send response");
                }
            }
            Ok(None) => {}
            Err(e) => {
                warn!(profile = %profile_alias, error = %e, "Unhandled handler error");
            }
        }
    }

    pub(crate) async fn send_response(
        ctx: &HandlerContext,
        response: DIDCommResponse,
    ) -> Result<(), DIDCommServiceError> {
        let message = response.into_message(ctx)?;
        transport::send_response(ctx, message).await
    }
}
