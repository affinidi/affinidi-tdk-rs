use affinidi_messaging_sdk::protocols::mediator::acls::AccessListModeType;
use std::time::Duration;

use affinidi_tdk_common::{config::TDKConfig, profiles::TDKProfile};

use crate::error::ConfigError;

#[derive(Debug)]
pub struct DIDCommServiceConfig {
    pub listeners: Vec<ListenerConfig>,
}

/// Which transport protocols a message service handles on its single per-DID
/// websocket.
///
/// The mediator allows one websocket per DID, so a node speaking both protocols
/// multiplexes them on the same socket rather than opening a second one. At
/// least one protocol must be enabled — an empty set is rejected at
/// construction ([`ConfigError::NoProtocolEnabled`]). The fields are private
/// so the empty set cannot be built at all; read them with
/// [`didcomm`](Self::didcomm) and [`tsp`](Self::tsp).
///
/// Both flags are enforced on receipt: a listener with `didcomm` off drops
/// (and acks) DIDComm frames instead of handing them to the
/// [`DIDCommHandler`](crate::DIDCommHandler), and one with `tsp` off drops TSP
/// frames, live and in the offline drain. `tsp` requires this crate's `tsp`
/// feature; a listener asking for it in a build without the feature is refused
/// with [`ConfigError::TspFeatureDisabled`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protocols {
    didcomm: bool,
    tsp: bool,
}

impl Protocols {
    /// DIDComm only — the historical `DIDCommService` behaviour (and the
    /// [`Default`]).
    pub const DIDCOMM_ONLY: Protocols = Protocols {
        didcomm: true,
        tsp: false,
    };
    /// TSP only — a node with no DIDComm pickup; the socket carries only TSP.
    pub const TSP_ONLY: Protocols = Protocols {
        didcomm: false,
        tsp: true,
    };
    /// Both protocols multiplexed on one socket.
    pub const BOTH: Protocols = Protocols {
        didcomm: true,
        tsp: true,
    };

    /// Construct from flags, rejecting the empty set.
    pub fn new(didcomm: bool, tsp: bool) -> Result<Self, ConfigError> {
        if !didcomm && !tsp {
            return Err(ConfigError::NoProtocolEnabled);
        }
        Ok(Self { didcomm, tsp })
    }

    /// Whether DIDComm frames are handled.
    pub const fn didcomm(&self) -> bool {
        self.didcomm
    }

    /// Whether TSP frames are handled.
    pub const fn tsp(&self) -> bool {
        self.tsp
    }
}

impl Default for Protocols {
    /// DIDComm-only, so existing `ListenerConfig` consumers keep their behaviour.
    fn default() -> Self {
        Protocols::DIDCOMM_ONLY
    }
}

pub struct ListenerConfig {
    pub id: String,
    pub profile: TDKProfile,
    pub acl_mode: Option<AccessListModeType>,
    pub restart_policy: RestartPolicy,
    pub message_wait_duration_secs: u64,
    pub auto_delete: bool,
    pub tdk_config: Option<TDKConfig>,
    /// Which protocols this listener handles on its socket. Defaults to
    /// [`Protocols::DIDCOMM_ONLY`].
    pub protocols: Protocols,
    /// Optional durable relationship store for this listener's ATM (spec Rev 3
    /// §7.2.2). `None` (the default) uses the SDK's ephemeral in-memory store,
    /// wiped on restart — after which the framework drops a peer's traffic until
    /// each re-handshakes. Inject a `PersistentRelationshipStore` (over a
    /// `RelationshipKv` backend) to persist relationships across restarts.
    #[cfg(feature = "tsp")]
    pub relationship_store: Option<std::sync::Arc<dyn affinidi_messaging_sdk::RelationshipStore>>,
    /// Most handler invocations this listener runs at once, across the live
    /// stream and the offline drain. When all are busy the listener stops
    /// pulling from the mediator until one finishes (the mediator keeps the
    /// rest queued). Must be at least 1. Default
    /// [`DEFAULT_MAX_CONCURRENT_HANDLERS`].
    pub max_concurrent_handlers: usize,
    /// How long a stopping listener (shutdown, `remove_listener`, or a lost
    /// transport) waits for running handlers before aborting them. An aborted
    /// handler's message was not acked, so the mediator redelivers it. Default
    /// [`DEFAULT_SHUTDOWN_DRAIN_TIMEOUT`].
    pub shutdown_drain_timeout: Duration,
}

/// Default for [`ListenerConfig::max_concurrent_handlers`].
pub const DEFAULT_MAX_CONCURRENT_HANDLERS: usize = 64;
/// Default for [`ListenerConfig::shutdown_drain_timeout`].
pub const DEFAULT_SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

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
            .field("protocols", &self.protocols)
            .field("max_concurrent_handlers", &self.max_concurrent_handlers)
            .field("shutdown_drain_timeout", &self.shutdown_drain_timeout)
            .finish()
    }
}

impl ListenerConfig {
    /// Create a new listener config with the required fields.
    /// Optional fields use the [`Default`] values: restart
    /// `OnFailure` with unlimited retries and the default backoff, wait 5s,
    /// `auto_delete` on, DIDComm only, 64 concurrent handlers, 10s drain.
    pub fn new(id: impl Into<String>, profile: TDKProfile) -> Self {
        Self {
            id: id.into(),
            profile,
            ..Default::default()
        }
    }

    /// Persist this listener's TSP relationships across restarts by injecting a
    /// durable [`affinidi_messaging_sdk::RelationshipStore`] (spec Rev 3 §7.2.2).
    /// Without it the listener uses the SDK's ephemeral in-memory store.
    #[cfg(feature = "tsp")]
    pub fn with_relationship_store(
        mut self,
        store: std::sync::Arc<dyn affinidi_messaging_sdk::RelationshipStore>,
    ) -> Self {
        self.relationship_store = Some(store);
        self
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
            protocols: Protocols::default(),
            #[cfg(feature = "tsp")]
            relationship_store: None,
            max_concurrent_handlers: DEFAULT_MAX_CONCURRENT_HANDLERS,
            shutdown_drain_timeout: DEFAULT_SHUTDOWN_DRAIN_TIMEOUT,
        }
    }
}

impl ListenerConfig {
    /// Check the settings that cannot be enforced by construction. Called by
    /// `AffinidiMessageService::start*` and `add_listener` before anything is
    /// spawned.
    pub fn validate(&self) -> Result<(), ConfigError> {
        #[cfg(not(feature = "tsp"))]
        if self.protocols.tsp() {
            return Err(ConfigError::TspFeatureDisabled {
                listener_id: self.id.clone(),
            });
        }
        if self.max_concurrent_handlers == 0 {
            return Err(ConfigError::ZeroHandlerConcurrency {
                listener_id: self.id.clone(),
            });
        }
        Ok(())
    }
}

/// What a listener does when its connection attempt or receive loop fails.
///
/// The default is `OnFailure` with unlimited retries and the default
/// [`RetryConfig`] backoff, so a mediator that is briefly unreachable at boot
/// does not end the listener for good. (It was `Never` before 0.35.)
#[derive(Debug, Clone)]
pub enum RestartPolicy {
    /// Stop after the first failure. The listener then reports
    /// [`ListenerState::Failed`](crate::ListenerState::Failed).
    Never,
    OnFailure {
        max_retries: Option<u32>,
        backoff: RetryConfig,
    },
    Always {
        backoff: RetryConfig,
    },
}

impl Default for RestartPolicy {
    fn default() -> Self {
        RestartPolicy::OnFailure {
            max_retries: None,
            backoff: RetryConfig::default(),
        }
    }
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
        assert!(matches!(
            lc.restart_policy,
            RestartPolicy::OnFailure {
                max_retries: None,
                ..
            }
        ));
        assert!(lc.tdk_config.is_none());
        assert_eq!(lc.max_concurrent_handlers, DEFAULT_MAX_CONCURRENT_HANDLERS);
        assert_eq!(lc.shutdown_drain_timeout, DEFAULT_SHUTDOWN_DRAIN_TIMEOUT);
        assert!(lc.validate().is_ok());
        // Back-compat: a listener defaults to DIDComm-only.
        assert_eq!(lc.protocols, Protocols::DIDCOMM_ONLY);
    }

    #[test]
    fn protocols_default_is_didcomm_only() {
        assert_eq!(Protocols::default(), Protocols::DIDCOMM_ONLY);
        assert!(Protocols::default().didcomm());
        assert!(!Protocols::default().tsp());
    }

    #[cfg(feature = "tsp")]
    #[test]
    fn with_relationship_store_sets_the_field() {
        use affinidi_messaging_sdk::InMemoryRelationshipStore;
        // Default: no store (ephemeral).
        assert!(ListenerConfig::default().relationship_store.is_none());
        // Injected: present.
        let lc = ListenerConfig::default()
            .with_relationship_store(std::sync::Arc::new(InMemoryRelationshipStore::default()));
        assert!(lc.relationship_store.is_some());
    }

    #[test]
    fn protocols_new_rejects_empty_set() {
        let err = Protocols::new(false, false).unwrap_err();
        assert!(matches!(err, ConfigError::NoProtocolEnabled));
    }

    #[test]
    fn protocols_new_accepts_each_non_empty_combination() {
        assert_eq!(
            Protocols::new(true, false).unwrap(),
            Protocols::DIDCOMM_ONLY
        );
        assert_eq!(Protocols::new(false, true).unwrap(), Protocols::TSP_ONLY);
        assert_eq!(Protocols::new(true, true).unwrap(), Protocols::BOTH);
    }

    #[test]
    fn retry_config_defaults() {
        let rc = RetryConfig::default();
        assert_eq!(rc.initial_delay_secs, 2);
        assert_eq!(rc.max_delay_secs, 60);
    }

    #[test]
    fn restart_policy_default_retries_on_failure() {
        let rp = RestartPolicy::default();
        assert!(matches!(
            rp,
            RestartPolicy::OnFailure {
                max_retries: None,
                ..
            }
        ));
    }

    #[test]
    fn zero_handler_concurrency_is_refused() {
        let lc = ListenerConfig {
            id: "l".into(),
            max_concurrent_handlers: 0,
            ..Default::default()
        };
        assert!(matches!(
            lc.validate(),
            Err(ConfigError::ZeroHandlerConcurrency { ref listener_id }) if listener_id == "l"
        ));
    }

    #[test]
    fn tsp_without_the_feature_is_refused() {
        let lc = ListenerConfig {
            id: "l".into(),
            protocols: Protocols::BOTH,
            ..Default::default()
        };
        #[cfg(not(feature = "tsp"))]
        assert!(matches!(
            lc.validate(),
            Err(ConfigError::TspFeatureDisabled { ref listener_id }) if listener_id == "l"
        ));
        #[cfg(feature = "tsp")]
        assert!(lc.validate().is_ok());
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
