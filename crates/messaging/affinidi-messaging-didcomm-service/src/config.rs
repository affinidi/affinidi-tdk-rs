use affinidi_messaging_sdk::protocols::mediator::acls::AccessListModeType;
use affinidi_tdk_common::{config::TDKConfig, profiles::TDKProfile};

#[derive(Debug)]
pub struct DIDCommServiceConfig {
    pub listeners: Vec<ListenerConfig>,
}

pub struct ListenerConfig {
    pub id: String,
    pub profile: TDKProfile,
    pub acl_mode: Option<AccessListModeType>,
    pub restart_policy: RestartPolicy,
    pub message_wait_duration_secs: u64,
    pub auto_delete: bool,
    pub tdk_config: Option<TDKConfig>,
}

impl std::fmt::Debug for ListenerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListenerConfig")
            .field("id", &self.id)
            .field("profile", &self.profile.alias)
            .field("restart_policy", &self.restart_policy)
            .field(
                "message_wait_duration_secs",
                &self.message_wait_duration_secs,
            )
            .field("auto_delete", &self.auto_delete)
            .field("tdk_config", &self.tdk_config.as_ref().map(|_| "..."))
            .finish()
    }
}

impl ListenerConfig {
    /// Create a new listener config with the required fields.
    /// Optional fields use sensible defaults (restart: Never, wait: 5s, auto_delete: true).
    pub fn new(id: impl Into<String>, profile: TDKProfile) -> Self {
        Self {
            id: id.into(),
            profile,
            ..Default::default()
        }
    }
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            profile: TDKProfile::default(),
            acl_mode: None,
            restart_policy: RestartPolicy::default(),
            message_wait_duration_secs: 5,
            auto_delete: true,
            tdk_config: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
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

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub initial_delay_secs: u64,
    pub max_delay_secs: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            initial_delay_secs: 2,
            max_delay_secs: 60,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_config_defaults() {
        let lc = ListenerConfig::default();
        assert!(lc.id.is_empty());
        assert_eq!(lc.message_wait_duration_secs, 5);
        assert!(lc.auto_delete);
        assert!(lc.acl_mode.is_none());
        assert!(matches!(lc.restart_policy, RestartPolicy::Never));
        assert!(lc.tdk_config.is_none());
    }

    #[test]
    fn retry_config_defaults() {
        let rc = RetryConfig::default();
        assert_eq!(rc.initial_delay_secs, 2);
        assert_eq!(rc.max_delay_secs, 60);
    }

    #[test]
    fn restart_policy_default_is_never() {
        let rp = RestartPolicy::default();
        assert!(matches!(rp, RestartPolicy::Never));
    }

    #[test]
    fn restart_policy_on_failure_variant() {
        let rp = RestartPolicy::OnFailure {
            max_retries: Some(3),
            backoff: RetryConfig::default(),
        };
        if let RestartPolicy::OnFailure {
            max_retries,
            backoff,
        } = rp
        {
            assert_eq!(max_retries, Some(3));
            assert_eq!(backoff.initial_delay_secs, 2);
        } else {
            panic!("expected OnFailure");
        }
    }

    #[test]
    fn restart_policy_always_variant() {
        let rp = RestartPolicy::Always {
            backoff: RetryConfig {
                initial_delay_secs: 1,
                max_delay_secs: 30,
            },
        };
        if let RestartPolicy::Always { backoff } = rp {
            assert_eq!(backoff.initial_delay_secs, 1);
            assert_eq!(backoff.max_delay_secs, 30);
        } else {
            panic!("expected Always");
        }
    }
}
