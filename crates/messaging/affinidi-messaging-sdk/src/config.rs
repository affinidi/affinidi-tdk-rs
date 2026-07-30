use crate::{
    errors::ATMError, protocols::discover_features::DiscoverFeatures,
    transports::websockets::WebSocketResponses,
};
use affinidi_crypto::jose::key_agreement::Curve;
use affinidi_messaging_mediator_common::types::clock::{Clock, SystemClock};
use rustls::pki_types::CertificateDer;
use std::{fs::File, io::BufReader, sync::Arc, time::Duration};
use tokio::sync::{RwLock, broadcast::Sender};
use tracing::error;

pub use crate::messages::wrapping::MessageWrappingType;

/// Policy applied to every received envelope — by both [`crate::ATM::unpack`]
/// and the message-pickup delivery drain — to enforce which envelope *wrapping
/// types* are accepted and whether message-layer addressing consistency is
/// enforced.
///
/// The [`Default`] is the DIDComm v2 secure baseline — accept only
/// authenticated encryption (every accepted wrapping carries an authcrypt layer
/// that binds the sender): `authcrypt(plaintext)`, `authcrypt(sign(plaintext))`,
/// and `anoncrypt(authcrypt(plaintext))` (which additionally hides the sender
/// key id from intermediaries) — and enforce addressing consistency, so an app
/// that simply calls `atm.unpack` is protected against envelope-downgrade and
/// forged-sender (`from` ≠ authcrypt `skid`) attacks without any extra code.
/// Relax it explicitly via [`ATMConfigBuilder::with_unpack_policy`] when a
/// protocol legitimately expects an unauthenticated wrapping (e.g. anoncrypt
/// receipts or signed-only notifications).
#[derive(Debug, Clone)]
pub struct UnpackPolicy {
    /// Exactly which wrapping types `unpack` accepts. A message classified
    /// outside this set is rejected. No presets — list precisely what your
    /// protocol expects.
    pub expected: Vec<MessageWrappingType>,
    /// Enforce message-layer addressing consistency across the unwrapped
    /// layers: the inner `from` DID must equal the authcrypt `skid` DID (when
    /// encrypted) and a verified signer's DID (when signed). Disable only for
    /// debugging in trusted environments.
    pub validate_addressing_consistency: bool,
    /// Maximum number of signatures accepted on a signed message, enforced
    /// *before* any signer DID is resolved — so it doubles as the guard
    /// against resolution-amplification DoS. Every signature within the cap is
    /// verified; a message carrying more is rejected without resolving any key.
    /// Defaults to `5` (enough for co-signed / multi-signer messages); raise it
    /// to any value your protocol expects — there is no absolute ceiling above
    /// your configured policy.
    pub max_signatures: usize,
    /// Maximum number of recipients a single JWE (encryption) layer may address
    /// before it is rejected. Unlike [`Self::max_signatures`], the secure
    /// default is **permissive** (`100`, the absolute hard cap): a receiver is
    /// legitimately only one of several recipients, so a restrictive default
    /// would reject ordinary group/broadcast messages. Decrypting runs the key
    /// agreement once (for the matched recipient), so this bounds parse /
    /// allocation cost, not asymmetric-crypto work. Lower it for stricter
    /// (e.g. one-to-one only) deployments.
    pub max_recipients: usize,
}

impl Default for UnpackPolicy {
    fn default() -> Self {
        UnpackPolicy {
            expected: vec![
                MessageWrappingType::AuthcryptPlaintext,
                MessageWrappingType::AuthcryptSignPlaintext,
                MessageWrappingType::AnoncryptAuthcryptPlaintext,
            ],
            validate_addressing_consistency: true,
            max_signatures: crate::messages::unpack::DEFAULT_MAX_SIGNATURES,
            max_recipients: crate::messages::unpack::DEFAULT_MAX_RECIPIENTS,
        }
    }
}

impl UnpackPolicy {
    /// True when `wrapping` is accepted by this policy.
    pub fn accepts(&self, wrapping: MessageWrappingType) -> bool {
        self.expected.contains(&wrapping)
    }
}

/// Configuration for the Affinidi Trusted Messaging (ATM) Service
/// You need to use the `builder()` method to create a new instance of `ATMConfig`
/// Example:
/// ```
/// use affinidi_messaging_sdk::config::ATMConfig;
///
/// let config = ATMConfig::builder().build();
/// ```
#[derive(Clone)]
pub struct ATMConfig {
    pub(crate) ssl_certificates: Vec<CertificateDer<'static>>,
    pub(crate) fetch_cache_limit_count: u32,
    pub(crate) fetch_cache_limit_bytes: u64,

    /// If you want to aggregate inbound messages from the SDK to a channel to be used by the client
    pub(crate) inbound_message_channel: Option<Sender<WebSocketResponses>>,

    /// Optional broadcast channel that receives a
    /// [`crate::protocols::message_pickup::PoisonMessage`] for every
    /// undeliverable pickup attachment *before* the drain purges it, so a
    /// consumer can retain/quarantine it. `None` (default) = poison messages are
    /// only logged and purged.
    pub(crate) poison_message_channel:
        Option<Sender<crate::protocols::message_pickup::PoisonMessage>>,

    /// Should we auto unpack forwarded messages?
    pub(crate) unpack_forwards: bool,

    /// Policy enforced on every received envelope — both [`crate::ATM::unpack`]
    /// and the message-pickup delivery drain — governing which wrapping types
    /// are accepted and whether addressing consistency is enforced. Defaults to
    /// the secure authenticated-encryption baseline, so messages pulled via
    /// pickup get the same guarantees as a direct `unpack`.
    pub(crate) unpack_policy: UnpackPolicy,

    /// Can configure any protocol discoverable information here
    pub(crate) discover_features: Arc<RwLock<DiscoverFeatures>>,

    /// Optional override for the key-agreement curve preference used when
    /// packing encrypted messages. `None` uses
    /// [`affinidi_did_common::key_negotiation::DEFAULT_CURVE_PREFERENCE`]
    /// (`X25519 > P-256 > P-384 > P-521 > secp256k1`). Set a custom order to
    /// force a specific policy, e.g. P-256 first for a FIPS deployment.
    pub(crate) curve_preference: Option<Vec<Curve>>,

    /// Per-request timeout for mediator REST calls (delete/list/get). Bounded
    /// so an unreachable mediator surfaces a `TransportError` in seconds
    /// rather than blocking on the OS-level TCP RTO. Default: 15s.
    pub(crate) request_timeout: Duration,

    /// Source of the current time for the SDK's expiry / TTL decisions
    /// (forwarded-message expiry, the WebSocket token-refresh deadline).
    /// Defaults to the real [`SystemClock`]; tests inject a `TestClock` via
    /// [`ATMConfigBuilder::with_clock`] to drive those reads deterministically.
    pub(crate) clock: Arc<dyn Clock>,

    /// Pluggable backing store for TSP relationship state (the FSM behind
    /// `atm.tsp().form_relationship` / `accept_relationship` / etc.). Defaults
    /// to an ephemeral [`crate::protocols::tsp::InMemoryRelationshipStore`];
    /// inject a durable implementation via
    /// [`ATMConfigBuilder::with_relationship_store`].
    #[cfg(feature = "tsp")]
    pub(crate) relationship_store: Arc<dyn crate::protocols::tsp::RelationshipStore>,

    /// Protocol-selection policy for [`crate::ATM::send_to`]. Defaults to
    /// [`TspPolicy::Off`] — send_to sends DIDComm and never picks TSP — so
    /// enabling the `tsp` feature alone changes no behaviour. Set
    /// [`TspPolicy::Preferred`] / [`TspPolicy::Required`] via
    /// [`ATMConfigBuilder::with_tsp_policy`] to opt in.
    #[cfg(feature = "tsp")]
    pub(crate) tsp_policy: crate::protocols::tsp::TspPolicy,

    /// How long a learned per-peer TSP capability stays fresh before it is
    /// re-derived. `None` (default) = never expires. Measured against the
    /// injected [`clock`](Self::clock).
    #[cfg(feature = "tsp")]
    pub(crate) tsp_capability_ttl: Option<Duration>,
}

impl ATMConfig {
    /// The configured key-agreement curve preference, if any. `None` means
    /// the negotiator's built-in default order is used.
    pub fn get_curve_preference(&self) -> Option<&[Curve]> {
        self.curve_preference.as_deref()
    }

    /// The per-request timeout applied to mediator REST calls.
    pub fn get_request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// The policy [`crate::ATM::unpack`] enforces on received envelopes.
    pub fn unpack_policy(&self) -> &UnpackPolicy {
        &self.unpack_policy
    }

    /// The clock backing the SDK's expiry / TTL decisions.
    pub(crate) fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// The pluggable store backing TSP relationship state.
    #[cfg(feature = "tsp")]
    pub(crate) fn relationship_store(&self) -> &Arc<dyn crate::protocols::tsp::RelationshipStore> {
        &self.relationship_store
    }

    /// The protocol-selection policy for [`crate::ATM::send_to`].
    #[cfg(feature = "tsp")]
    pub(crate) fn tsp_policy(&self) -> crate::protocols::tsp::TspPolicy {
        self.tsp_policy
    }

    /// The freshness window for a learned per-peer TSP capability (`None` =
    /// never expires).
    #[cfg(feature = "tsp")]
    pub(crate) fn tsp_capability_ttl(&self) -> Option<Duration> {
        self.tsp_capability_ttl
    }

    /// Returns a builder for `ATMConfig`
    /// Example:
    /// ```
    /// use affinidi_messaging_sdk::config::ATMConfig;
    ///
    /// let config = ATMConfig::builder().build();
    /// ```
    pub fn builder() -> ATMConfigBuilder {
        ATMConfigBuilder::default()
    }

    pub fn get_ssl_certificates(&'_ self) -> &'_ Vec<CertificateDer<'_>> {
        &self.ssl_certificates
    }
}

/// Builder for `ATMConfig`.
/// Example:
/// ```
/// use affinidi_messaging_sdk::config::ATMConfig;
///
/// // Create a new `ATMConfig` with defaults
/// let config = ATMConfig::builder().build();
/// ```
pub struct ATMConfigBuilder {
    ssl_certificates: Vec<String>,
    fetch_cache_limit_count: u32,
    fetch_cache_limit_bytes: u64,
    inbound_message_channel: Option<Sender<WebSocketResponses>>,
    poison_message_channel: Option<Sender<crate::protocols::message_pickup::PoisonMessage>>,
    unpack_forwards: bool,
    unpack_policy: UnpackPolicy,
    discover_features: DiscoverFeatures,
    curve_preference: Option<Vec<Curve>>,
    request_timeout: Duration,
    clock: Option<Arc<dyn Clock>>,
    #[cfg(feature = "tsp")]
    relationship_store: Option<Arc<dyn crate::protocols::tsp::RelationshipStore>>,
    #[cfg(feature = "tsp")]
    tsp_policy: crate::protocols::tsp::TspPolicy,
    #[cfg(feature = "tsp")]
    tsp_capability_ttl: Option<Duration>,
}

impl Default for ATMConfigBuilder {
    fn default() -> Self {
        ATMConfigBuilder {
            ssl_certificates: vec![],
            fetch_cache_limit_count: 100,
            fetch_cache_limit_bytes: 1024 * 1024 * 10, // Defaults to 10MB Cache
            inbound_message_channel: None,
            poison_message_channel: None,
            unpack_forwards: true,
            unpack_policy: UnpackPolicy::default(),
            discover_features: DiscoverFeatures::default(),
            curve_preference: None,
            request_timeout: Duration::from_secs(15),
            clock: None,
            #[cfg(feature = "tsp")]
            relationship_store: None,
            #[cfg(feature = "tsp")]
            tsp_policy: crate::protocols::tsp::TspPolicy::Off,
            #[cfg(feature = "tsp")]
            tsp_capability_ttl: None,
        }
    }
}

impl ATMConfigBuilder {
    /// Default starting constructor for `ATMConfigBuilder`
    pub fn new() -> ATMConfigBuilder {
        ATMConfigBuilder::default()
    }

    /// Add a list of SSL certificates to the configuration
    /// Each certificate should be a file path to a PEM encoded certificate
    pub fn with_ssl_certificates(mut self, ssl_certificates: &mut Vec<String>) -> Self {
        self.ssl_certificates.append(ssl_certificates);
        self
    }

    /// Set the maximum number of messages to cache in the fetch task
    /// This is per profile
    /// Default: 100
    pub fn with_fetch_cache_limit_count(mut self, count: u32) -> Self {
        self.fetch_cache_limit_count = count;
        self
    }

    /// Set the maximum total size of messages to cache in the fetch task in bytes
    /// This is per profile
    /// Default: 10MB (1024*1024*10)
    pub fn with_fetch_cache_limit_bytes(mut self, count: u64) -> Self {
        self.fetch_cache_limit_bytes = count;
        self
    }

    /// Create an optional broadcast (MPMC) channel to send inbound messages from websockets to
    /// This is useful if you want to aggregate inbound messages to the SDK to a single channel to be used by the client
    pub fn with_inbound_message_channel(mut self, capacity: usize) -> Self {
        let (inbound_message_channel, _) = tokio::sync::broadcast::channel(capacity);
        self.inbound_message_channel = Some(inbound_message_channel);
        self
    }

    /// Enable a broadcast channel that receives a
    /// [`crate::protocols::message_pickup::PoisonMessage`] for every
    /// undeliverable pickup attachment *before* it is purged from the mediator.
    /// Subscribe with [`crate::ATM::get_poison_channel`] to retain or quarantine
    /// poison messages instead of silently dropping them. `capacity` bounds the
    /// broadcast buffer.
    pub fn with_poison_message_channel(mut self, capacity: usize) -> Self {
        let (poison_message_channel, _) = tokio::sync::broadcast::channel(capacity);
        self.poison_message_channel = Some(poison_message_channel);
        self
    }

    /// When unpacking a message, if it is of type forward, try and unpack the forwarded message
    /// and return the innermost message instead of the forward message
    /// Default: true (will unpack the forward message)
    pub fn with_unpack_forwards(mut self, unpack_forwards: bool) -> Self {
        self.unpack_forwards = unpack_forwards;
        self
    }

    /// Set the policy [`crate::ATM::unpack`] enforces on received envelopes:
    /// which wrapping types are accepted and whether addressing consistency is
    /// checked. Defaults to the secure authcrypt-only baseline
    /// ([`UnpackPolicy::default`]); relax it when a protocol expects other
    /// wrappings.
    ///
    /// ```
    /// use affinidi_messaging_sdk::config::{ATMConfig, MessageWrappingType, UnpackPolicy};
    ///
    /// let config = ATMConfig::builder()
    ///     .with_unpack_policy(UnpackPolicy {
    ///         expected: vec![
    ///             MessageWrappingType::AuthcryptPlaintext,
    ///             MessageWrappingType::AnoncryptAuthcryptPlaintext,
    ///         ],
    ///         validate_addressing_consistency: true,
    ///         max_signatures: 2,
    ///         max_recipients: 100,
    ///     })
    ///     .build();
    /// ```
    pub fn with_unpack_policy(mut self, policy: UnpackPolicy) -> Self {
        self.unpack_policy = policy;
        self
    }

    /// You can specificy protocol information that can be discovered by others using the Dicover
    /// Features Protocol here. This is useful for things like indicating support for certain
    /// message types, transports, etc.
    /// Default: None (No discoverable information)
    pub fn with_discovery_features(mut self, features: DiscoverFeatures) -> Self {
        self.discover_features = features;
        self
    }

    /// Override the key-agreement curve preference used when packing
    /// encrypted messages. Curves are tried most-preferred first; the first
    /// curve both sender and recipient offer is chosen. Omit to use the
    /// default order (`X25519 > P-256 > P-384 > P-521 > secp256k1`).
    ///
    /// Example — prefer the NIST P-256 curve first (FIPS-leaning):
    /// ```no_run
    /// use affinidi_messaging_sdk::config::ATMConfig;
    /// use affinidi_crypto::jose::key_agreement::Curve;
    ///
    /// let config = ATMConfig::builder()
    ///     .with_curve_preference(vec![Curve::P256, Curve::P384, Curve::P521, Curve::X25519, Curve::K256])
    ///     .build();
    /// ```
    pub fn with_curve_preference(mut self, preference: Vec<Curve>) -> Self {
        self.curve_preference = Some(preference);
        self
    }

    /// Override the per-request timeout for mediator REST calls
    /// (delete/list/get). Lower it for snappier failure on flaky links;
    /// raise it for high-latency mediators. Default: 15s.
    ///
    /// ```
    /// use affinidi_messaging_sdk::config::ATMConfig;
    /// use std::time::Duration;
    ///
    /// let config = ATMConfig::builder()
    ///     .with_request_timeout(Duration::from_secs(30))
    ///     .build();
    /// ```
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Inject the clock the SDK uses for expiry / TTL decisions
    /// (forwarded-message expiry, the WebSocket token-refresh deadline).
    /// Defaults to the real [`SystemClock`]; pass a `TestClock` to drive those
    /// reads deterministically in tests.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Inject a pluggable backing store for TSP relationship state.
    ///
    /// Defaults to an ephemeral
    /// [`crate::protocols::tsp::InMemoryRelationshipStore`] (wiped on process
    /// restart); pass a durable implementation of
    /// [`crate::protocols::tsp::RelationshipStore`] to persist relationship
    /// state across restarts.
    #[cfg(feature = "tsp")]
    pub fn with_relationship_store(
        mut self,
        store: Arc<dyn crate::protocols::tsp::RelationshipStore>,
    ) -> Self {
        self.relationship_store = Some(store);
        self
    }

    /// Set the protocol-selection policy for [`crate::ATM::send_to`].
    ///
    /// Defaults to [`crate::protocols::tsp::TspPolicy::Off`] (send_to always
    /// sends DIDComm). [`Preferred`](crate::protocols::tsp::TspPolicy::Preferred)
    /// picks TSP when the peer is known/derivable to speak it and falls back to
    /// DIDComm otherwise; [`Required`](crate::protocols::tsp::TspPolicy::Required)
    /// errors instead of falling back.
    #[cfg(feature = "tsp")]
    pub fn with_tsp_policy(mut self, policy: crate::protocols::tsp::TspPolicy) -> Self {
        self.tsp_policy = policy;
        self
    }

    /// Set how long a learned per-peer TSP capability stays fresh before it is
    /// re-derived. Defaults to `None` (never expires). Measured against the
    /// injected [`clock`](ATMConfigBuilder::with_clock).
    #[cfg(feature = "tsp")]
    pub fn with_tsp_capability_ttl(mut self, ttl: Duration) -> Self {
        self.tsp_capability_ttl = Some(ttl);
        self
    }

    pub fn build(self) -> Result<ATMConfig, ATMError> {
        // Process any custom SSL certificates
        let mut certs = vec![];
        let mut failed_certs = false;
        for cert in &self.ssl_certificates {
            let file = File::open(cert).map_err(|e| {
                ATMError::SSLError(format!(
                    "Couldn't open SSL certificate file ({cert})! Reason: {e}"
                ))
            })?;
            let mut reader = BufReader::new(file);

            for cert in rustls_pemfile::certs(&mut reader) {
                match cert {
                    Ok(cert) => certs.push(cert.into_owned()),
                    Err(e) => {
                        failed_certs = true;
                        error!("Couldn't parse SSL certificate! Reason: {}", e)
                    }
                }
            }
        }
        if failed_certs {
            return Err(ATMError::SSLError(
                "Couldn't parse all SSL certificates!".to_owned(),
            ));
        }

        // When TSP protocol selection is enabled, advertise the TSP capability
        // URI in Discover Features 2.0 so peers can discover it proactively
        // (symmetric with `send_to` preferring TSP for peers known to support it).
        #[cfg(feature = "tsp")]
        let discover_features = {
            let mut df = self.discover_features;
            if self.tsp_policy != crate::protocols::tsp::TspPolicy::Off
                && !df
                    .protocols
                    .iter()
                    .any(|p| p == crate::protocols::tsp::TSP_DISCOVER_FEATURE_URI)
            {
                df.protocols
                    .push(crate::protocols::tsp::TSP_DISCOVER_FEATURE_URI.to_string());
            }
            df
        };
        #[cfg(not(feature = "tsp"))]
        let discover_features = self.discover_features;

        Ok(ATMConfig {
            ssl_certificates: certs,
            fetch_cache_limit_count: self.fetch_cache_limit_count,
            fetch_cache_limit_bytes: self.fetch_cache_limit_bytes,
            inbound_message_channel: self.inbound_message_channel,
            poison_message_channel: self.poison_message_channel,
            unpack_forwards: self.unpack_forwards,
            unpack_policy: self.unpack_policy,
            discover_features: Arc::new(RwLock::new(discover_features)),
            curve_preference: self.curve_preference,
            request_timeout: self.request_timeout,
            clock: self.clock.unwrap_or_else(|| Arc::new(SystemClock)),
            #[cfg(feature = "tsp")]
            relationship_store: self.relationship_store.unwrap_or_else(|| {
                Arc::new(crate::protocols::tsp::InMemoryRelationshipStore::default())
            }),
            #[cfg(feature = "tsp")]
            tsp_policy: self.tsp_policy,
            #[cfg(feature = "tsp")]
            tsp_capability_ttl: self.tsp_capability_ttl,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clock fixed at a chosen instant — proves an injected clock flows
    /// through to the SDK's time reads without pulling the `test-clock` feature.
    #[derive(Debug)]
    struct FixedClock(u64);
    impl Clock for FixedClock {
        fn unix_secs(&self) -> u64 {
            self.0
        }
        fn unix_millis(&self) -> u128 {
            self.0 as u128 * 1_000
        }
    }

    #[test]
    fn defaults_to_a_live_system_clock() {
        let config = ATMConfig::builder().build().unwrap();
        assert!(
            config.clock().unix_secs() > 0,
            "default is the system clock"
        );
    }

    #[test]
    fn injected_clock_is_used() {
        let config = ATMConfig::builder()
            .with_clock(Arc::new(FixedClock(1_234)))
            .build()
            .unwrap();
        assert_eq!(config.clock().unix_secs(), 1_234);
    }
}
