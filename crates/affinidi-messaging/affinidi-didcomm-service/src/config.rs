use std::sync::Arc;

use affinidi_messaging_sdk::protocols::mediator::acls::AccessListModeType;
use affinidi_tdk_common::profiles::TDKProfile;

use crate::crypto::MessageCryptoProvider;

pub struct DIDCommServiceConfig {
    pub listeners: Vec<ListenerConfig>,
    pub retry: RetryConfig,
}

pub struct ListenerConfig {
    pub id: String,
    pub profile: TDKProfile,
    pub acl_mode: AccessListModeType,
    pub restart_policy: RestartPolicy,
    pub crypto_provider: Option<Arc<dyn MessageCryptoProvider>>,
    pub message_wait_duration_secs: u64,
    pub auto_delete: bool,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            profile: TDKProfile::default(),
            acl_mode: AccessListModeType::ExplicitDeny,
            restart_policy: RestartPolicy::default(),
            crypto_provider: None,
            message_wait_duration_secs: 5,
            auto_delete: true,
        }
    }
}

#[derive(Clone, Default)]
pub enum RestartPolicy {
    #[default]
    Never,
    OnFailure {
        max_retries: Option<u32>,
        backoff: RetryConfig,
    },
    Always {
        backoff: RetryConfig,
    },
}

#[derive(Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay_secs: u64,
    pub max_delay_secs: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_delay_secs: 2,
            max_delay_secs: 60,
        }
    }
}
