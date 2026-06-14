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

    /// Should we auto unpack forwarded messages?
    pub(crate) unpack_forwards: bool,

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

    /// The clock backing the SDK's expiry / TTL decisions.
    pub(crate) fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
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
    unpack_forwards: bool,
    discover_features: DiscoverFeatures,
    curve_preference: Option<Vec<Curve>>,
    request_timeout: Duration,
    clock: Option<Arc<dyn Clock>>,
}

impl Default for ATMConfigBuilder {
    fn default() -> Self {
        ATMConfigBuilder {
            ssl_certificates: vec![],
            fetch_cache_limit_count: 100,
            fetch_cache_limit_bytes: 1024 * 1024 * 10, // Defaults to 10MB Cache
            inbound_message_channel: None,
            unpack_forwards: true,
            discover_features: DiscoverFeatures::default(),
            curve_preference: None,
            request_timeout: Duration::from_secs(15),
            clock: None,
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

    /// When unpacking a message, if it is of type forward, try and unpack the forwarded message
    /// and return the innermost message instead of the forward message
    /// Default: true (will unpack the forward message)
    pub fn with_unpack_forwards(mut self, unpack_forwards: bool) -> Self {
        self.unpack_forwards = unpack_forwards;
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

        Ok(ATMConfig {
            ssl_certificates: certs,
            fetch_cache_limit_count: self.fetch_cache_limit_count,
            fetch_cache_limit_bytes: self.fetch_cache_limit_bytes,
            inbound_message_channel: self.inbound_message_channel,
            unpack_forwards: self.unpack_forwards,
            discover_features: Arc::new(RwLock::new(self.discover_features)),
            curve_preference: self.curve_preference,
            request_timeout: self.request_timeout,
            clock: self.clock.unwrap_or_else(|| Arc::new(SystemClock)),
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
