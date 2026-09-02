use crate::{
    errors::ATMError, protocols::discover_features::DiscoverFeatures,
    transports::websockets::WebSocketResponses,
};
use affinidi_crypto::jose::key_agreement::Curve;
use affinidi_messaging_mediator_common::types::clock::{Clock, SystemClock};
use rustls::pki_types::{CertificateDer, pem::PemObject};
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
    /// encrypted) and a verified signer's DID (when signed). An **authenticated**
    /// message (signed or authcrypt) with **no** `from` is therefore rejected —
    /// it has an authenticated identity but nothing to bind it to, so `msg.from`
    /// could not be trusted; a pure `anoncrypt` message is anonymous and may
    /// omit `from`. Disable only for debugging in trusted environments.
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
    /// default is **permissive** (`100`): a receiver is legitimately only one of
    /// several recipients, so a restrictive default would reject ordinary
    /// group/broadcast messages. Like `max_signatures`, this is a default, not
    /// an absolute ceiling — raise it to any value your protocol expects (or
    /// lower it for stricter, e.g. one-to-one, deployments). Decrypting runs the
    /// key agreement once (for the matched recipient), so this bounds parse /
    /// allocation cost, not asymmetric-crypto work.
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

    /// Optional broadcast channel that receives an
    /// [`crate::protocols::message_pickup::UnprocessableMessage`] for every
    /// inbound message the SDK can't process — malformed base64/UTF-8, an
    /// unpack/verification failure, or a policy rejection — *before* the drain
    /// deletes/drops it, so a consumer can observe or quarantine it. `None`
    /// (default) = unprocessable messages are only logged.
    pub(crate) unprocessable_message_channel:
        Option<Sender<crate::protocols::message_pickup::UnprocessableMessage>>,

    /// Whether the message-pickup drain deletes a message the *`unpack_policy`*
    /// rejected — a disallowed wrapping (`UnexpectedEnvelope`) or an addressing
    /// mismatch (`AddressingMismatch`). `true` (default) **deletes** it: the
    /// mediator's per-recipient queue is bounded (a fixed message limit), and a
    /// retained reject is redelivered every pickup, so it would accumulate and
    /// eventually fill the queue, blocking new inbound messages. Set `false` to
    /// *retain* such messages instead — e.g. for a bounded window during an
    /// `unpack_policy` tightening/upgrade, so a message rejected only by the
    /// stricter policy can be recovered by relaxing the policy — accepting that
    /// retained rejects count against the queue limit until processed or expired.
    ///
    /// This flag does **not** govern non-recoverable input — malformed
    /// base64/UTF-8, an unsupported attachment type, or a cryptographically
    /// invalid signature (`VerificationFailed`). Those can never become
    /// processable regardless of policy and are *always* deleted so they can't
    /// be redelivered every pickup and fill the bounded queue.
    pub(crate) purge_policy_rejected_messages: bool,

    /// When a signed message carries multiple signatures, whether to tolerate
    /// non-authoritative ones that don't verify. `false` (default) fails the
    /// whole unpack if *any* signature is missing a `kid`, has an unresolvable
    /// signer DID, uses an unsupported curve, or is invalid. `true` records such
    /// signatures in [`crate::messages::compat::UnpackMetadata::unverified_signers`]
    /// and keeps unpacking — the authoritative (`from`-matching) signature must
    /// still verify under `unpack_policy.validate_addressing_consistency`, so
    /// this only relaxes *supplementary* co-signatures (e.g. a notary using a
    /// curve this build can't resolve).
    pub(crate) allow_invalid_signatures: bool,

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
    /// Whether inbound TSP application messages are gated on an existing
    /// relationship (Rev 3 §7.2.2). Defaults to true, which is what the
    /// specification asks of an endpoint; a node that is not an endpoint in
    /// that sense — an intermediary relaying for others — sets it false.
    #[cfg(feature = "tsp")]
    pub(crate) tsp_relationship_gating: bool,
    /// How this endpoint keeps a peer's TSP key state fresh (spec Rev 3
    /// §7.4.2). Defaults to resolving for itself, with a day's
    /// re-verification threshold and a minute's resolution rate limit.
    #[cfg(feature = "tsp")]
    pub(crate) tsp_key_state_policy: affinidi_tsp::KeyStatePolicy,
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

    /// Whether the message-pickup drain deletes a policy-rejected message
    /// (`UnexpectedEnvelope` / `AddressingMismatch`) from the mediator queue.
    /// Default `true` (delete — the mediator queue is bounded, so retained
    /// rejects redelivered every pickup would accumulate and fill it). Set
    /// `false` to retain. Non-recoverable input (malformed base64/UTF-8,
    /// unsupported type, invalid signature) is always deleted regardless of this
    /// flag.
    pub fn purge_policy_rejected_messages(&self) -> bool {
        self.purge_policy_rejected_messages
    }

    /// Whether unpack tolerates non-authoritative signatures that don't verify
    /// (recording them in
    /// [`crate::messages::compat::UnpackMetadata::unverified_signers`]).
    /// Default `false`.
    pub fn allow_invalid_signatures(&self) -> bool {
        self.allow_invalid_signatures
    }

    /// The clock backing the SDK's expiry / TTL decisions.
    pub(crate) fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// The pluggable store backing TSP relationship state.
    /// The TSP relationship store this config was built with.
    ///
    /// Public so a caller can reach the same store the SDK is using — a test
    /// seeding a relationship, or an application sharing one across ATMs.
    #[cfg(feature = "tsp")]
    pub fn relationship_store(&self) -> &Arc<dyn crate::protocols::tsp::RelationshipStore> {
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

    /// Whether inbound TSP application messages are gated on an existing
    /// relationship (spec Rev 3 §7.2.2).
    #[cfg(feature = "tsp")]
    pub(crate) fn tsp_relationship_gating(&self) -> bool {
        self.tsp_relationship_gating
    }

    /// How this endpoint keeps a peer's TSP key state fresh (Rev 3 §7.4.2).
    #[cfg(feature = "tsp")]
    pub(crate) fn tsp_key_state_policy(&self) -> affinidi_tsp::KeyStatePolicy {
        self.tsp_key_state_policy
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
    unprocessable_message_channel:
        Option<Sender<crate::protocols::message_pickup::UnprocessableMessage>>,
    purge_policy_rejected_messages: bool,
    allow_invalid_signatures: bool,
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
    #[cfg(feature = "tsp")]
    tsp_relationship_gating: bool,
    #[cfg(feature = "tsp")]
    tsp_key_state_policy: affinidi_tsp::KeyStatePolicy,
}

impl Default for ATMConfigBuilder {
    fn default() -> Self {
        ATMConfigBuilder {
            ssl_certificates: vec![],
            fetch_cache_limit_count: 100,
            fetch_cache_limit_bytes: 1024 * 1024 * 10, // Defaults to 10MB Cache
            inbound_message_channel: None,
            unprocessable_message_channel: None,
            purge_policy_rejected_messages: true,
            allow_invalid_signatures: false,
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
            tsp_relationship_gating: true,
            tsp_key_state_policy: affinidi_tsp::KeyStatePolicy::default(),
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

    /// Enable a broadcast channel that receives an
    /// [`crate::protocols::message_pickup::UnprocessableMessage`] for every
    /// inbound message the SDK can't process *before* it is deleted/dropped.
    /// Subscribe with [`crate::ATM::get_unprocessable_message_channel`] to
    /// observe or quarantine such messages instead of losing them to a log line.
    /// `capacity` bounds the broadcast buffer.
    pub fn with_unprocessable_message_channel(mut self, capacity: usize) -> Self {
        let (unprocessable_message_channel, _) = tokio::sync::broadcast::channel(capacity);
        self.unprocessable_message_channel = Some(unprocessable_message_channel);
        self
    }

    /// Control whether the message-pickup drain **deletes** a message that the
    /// configured `unpack_policy` rejected — a disallowed wrapping
    /// (`UnexpectedEnvelope`) or an addressing mismatch (`AddressingMismatch`).
    /// Default `true`: such messages are **deleted**, because the mediator's
    /// per-recipient queue is bounded (a fixed message limit) and a retained
    /// reject is redelivered every pickup, so it would accumulate and eventually
    /// fill the queue and block new inbound messages. Set `false` to **retain**
    /// them instead — e.g. for a bounded window during an `unpack_policy`
    /// tightening/upgrade, so a message rejected only by the stricter policy can
    /// be recovered by relaxing the policy — accepting that retained rejects
    /// count against the queue limit until processed or expired. Pair with
    /// [`Self::with_unprocessable_message_channel`] to observe what is affected.
    ///
    /// Non-recoverable input — malformed base64/UTF-8, an unsupported attachment
    /// type, or a cryptographically invalid signature (`VerificationFailed`) —
    /// is **always** deleted (it can never become processable), independent of
    /// this flag.
    pub fn with_purge_policy_rejected_messages(mut self, purge: bool) -> Self {
        self.purge_policy_rejected_messages = purge;
        self
    }

    /// Tolerate non-authoritative signatures that fail to verify when a signed
    /// message carries more than one signature. Default `false` (strict: any
    /// signature that is missing a `kid`, has an unresolvable/unsupported signer
    /// key, or is invalid fails the whole unpack). Set `true` to keep unpacking
    /// and record the offending signatures in
    /// [`UnpackMetadata::unverified_signers`](crate::messages::compat::UnpackMetadata)
    /// instead — the authoritative (`from`-matching) signature must still verify
    /// under `validate_addressing_consistency`, so this relaxes only
    /// supplementary co-signatures (e.g. a third-party notary using a curve this
    /// build can't resolve).
    pub fn with_allow_invalid_signatures(mut self, allow: bool) -> Self {
        self.allow_invalid_signatures = allow;
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

    /// Whether inbound TSP application messages are gated on an existing
    /// relationship (Rev 3 §7.2.2).
    ///
    /// Defaults to `true`, which is what the specification asks of an endpoint.
    /// Set `false` for a node that is not an endpoint in that sense — an
    /// intermediary, which by §5 handles messages for relationships it is not a
    /// party to and would otherwise drop all of them.
    #[cfg(feature = "tsp")]
    pub fn with_tsp_relationship_gating(mut self, gated: bool) -> Self {
        self.tsp_relationship_gating = gated;
        self
    }

    /// How this endpoint keeps a peer's TSP key state fresh (Rev 3 §7.4.2):
    /// whether it resolves key state for itself, how long a silence must be
    /// before a peer's VID is re-resolved, and how often any one peer may be
    /// resolved.
    ///
    /// Defaults to resolving for itself with a day's threshold and a minute's
    /// rate limit. Set `self_resolving` false where the VID implementation
    /// maintains key state and delivers changes without being asked (§7.4.1),
    /// in which case the endpoint takes no action of its own.
    #[cfg(feature = "tsp")]
    pub fn with_tsp_key_state_policy(mut self, policy: affinidi_tsp::KeyStatePolicy) -> Self {
        self.tsp_key_state_policy = policy;
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

            for cert in CertificateDer::pem_reader_iter(&mut reader) {
                match cert {
                    Ok(cert) => certs.push(cert),
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
            unprocessable_message_channel: self.unprocessable_message_channel,
            purge_policy_rejected_messages: self.purge_policy_rejected_messages,
            allow_invalid_signatures: self.allow_invalid_signatures,
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
            tsp_relationship_gating: self.tsp_relationship_gating,
            tsp_key_state_policy: self.tsp_key_state_policy,
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

    /// Rev 3 §7.2.2 asks an endpoint to gate application messages on an
    /// existing relationship, so that is the default. An intermediary turns it
    /// off: by §5 it handles messages for relationships it is not a party to,
    /// and would otherwise drop every one of them.
    #[test]
    #[cfg(feature = "tsp")]
    fn relationship_gating_defaults_on_and_can_be_turned_off() {
        let config = ATMConfig::builder().build().unwrap();
        assert!(config.tsp_relationship_gating());

        let config = ATMConfig::builder()
            .with_tsp_relationship_gating(false)
            .build()
            .unwrap();
        assert!(!config.tsp_relationship_gating());
    }

    /// The key-state policy defaults to resolving for oneself (Rev 3 §7.4.2)
    /// with a day's re-verification threshold and a minute's rate limit, and
    /// can be replaced wholesale — including turning the rules off for a
    /// deployment where the VID implementation maintains key state itself.
    #[test]
    #[cfg(feature = "tsp")]
    fn key_state_policy_defaults_and_overrides() {
        let config = ATMConfig::builder().build().unwrap();
        let policy = config.tsp_key_state_policy();
        assert!(policy.self_resolving);
        assert_eq!(
            policy.reverification_threshold,
            std::time::Duration::from_secs(60 * 60 * 24)
        );
        assert_eq!(
            policy.resolution_rate_limit,
            std::time::Duration::from_secs(60)
        );

        let config = ATMConfig::builder()
            .with_tsp_key_state_policy(affinidi_tsp::KeyStatePolicy {
                self_resolving: false,
                reverification_threshold: std::time::Duration::from_secs(1),
                resolution_rate_limit: std::time::Duration::from_secs(2),
            })
            .build()
            .unwrap();
        let policy = config.tsp_key_state_policy();
        assert!(!policy.self_resolving);
        assert_eq!(policy.reverification_threshold, std::time::Duration::from_secs(1));
        assert_eq!(policy.resolution_rate_limit, std::time::Duration::from_secs(2));
    }

    /// Policy-rejected pickup messages are **deleted by default** — the
    /// mediator queue is bounded, so a retained reject redelivered every pickup
    /// would accumulate and fill it. Operators opt into retention explicitly.
    #[test]
    fn policy_rejected_messages_are_deleted_by_default() {
        let config = ATMConfig::builder().build().unwrap();
        assert!(
            config.purge_policy_rejected_messages(),
            "the default deletes policy-rejected messages (bounded mediator queue)"
        );

        let retained = ATMConfig::builder()
            .with_purge_policy_rejected_messages(false)
            .build()
            .unwrap();
        assert!(
            !retained.purge_policy_rejected_messages(),
            "opting out retains policy-rejected messages"
        );
    }
}
