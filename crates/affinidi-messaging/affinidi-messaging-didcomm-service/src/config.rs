use affinidi_messaging_sdk::protocols::mediator::acls::AccessListModeType;
use affinidi_tdk_common::profiles::TDKProfile;

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
