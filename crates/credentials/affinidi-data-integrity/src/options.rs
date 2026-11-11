//! Options passed to [`crate::DataIntegrityProof::sign`] and
//! [`crate::DataIntegrityProof::verify_with_public_key`].
//!
//! Both types are plain value structs with a hand-rolled `with_*` builder.
//! No procedural macros, no extra dependencies. The builder style was
//! chosen over `typed-builder` / `bon` to keep the public-facing
//! production-grade dependency footprint minimal.
//!
//! # Example
//!
//! ```ignore
//! use affinidi_data_integrity::{SignOptions, crypto_suites::CryptoSuite};
//!
//! let opts = SignOptions::new()
//!     .with_context(vec!["https://www.w3.org/ns/credentials/v2".into()])
//!     .with_cryptosuite(CryptoSuite::MlDsa44Jcs2024)
//!     .with_proof_purpose("authentication");
//! ```

use chrono::{DateTime, Utc};

use crate::StringOrList;
use crate::crypto_suites::CryptoSuite;

/// Options for signing a Data Integrity proof.
///
/// Construct via [`SignOptions::new`] (or [`SignOptions::default`]) then
/// chain `with_*` methods. All fields default to `None` / empty; the
/// library fills in spec-compliant defaults (current time for `created`,
/// `"assertionMethod"` for `proof_purpose`, the signer's declared
/// cryptosuite) where they are not overridden here.
///
/// `SignOptions` is `#[non_exhaustive]` from the outside: construct it
/// only via the provided methods, not struct-literal syntax.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct SignOptions {
    /// JSON-LD `@context` values to place on the proof. If `None`, the
    /// document's own `@context` is used (for RDFC canonicalization) or no
    /// context is emitted (for JCS).
    pub context: Option<Vec<String>>,

    /// Proof creation timestamp. If `None`, `Utc::now()` is used.
    pub created: Option<DateTime<Utc>>,

    /// Overrides the signer's declared cryptosuite. If `None`, the
    /// library uses `signer.cryptosuite()`.
    pub cryptosuite: Option<CryptoSuite>,

    /// Value of `proofPurpose`. Defaults to `"assertionMethod"`.
    pub proof_purpose: Option<String>,

    /// Proof `expires`. If `None`, the proof does not expire.
    pub expires: Option<DateTime<Utc>>,

    /// Proof `domain`. If `None`, no domain is set.
    pub domain: Option<StringOrList>,

    /// Proof `challenge`. If `None`, no challenge is set.
    pub challenge: Option<String>,

    /// Proof `nonce`. If `None`, no nonce is set.
    pub nonce: Option<String>,

    /// Proof `id`. If `None`, the proof has no `id`.
    pub id: Option<String>,

    /// Proof `previousProof`. If `None`, the proof does not chain from
    /// another.
    pub previous_proof: Option<StringOrList>,
}

impl SignOptions {
    /// Constructs an empty `SignOptions`. Equivalent to
    /// [`SignOptions::default`].
    #[must_use = "constructed options must be passed to sign/verify to take effect"]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the `@context` value placed on the emitted proof.
    #[must_use = "chained builder call returns self; assign or chain further"]
    pub fn with_context(mut self, context: Vec<String>) -> Self {
        self.context = Some(context);
        self
    }

    /// Sets the `created` timestamp. Takes a typed `DateTime<Utc>`; the
    /// library serialises it to ISO-8601 (seconds precision, `Z`-suffix)
    /// at the serde boundary.
    #[must_use = "chained builder call returns self; assign or chain further"]
    pub fn with_created(mut self, created: DateTime<Utc>) -> Self {
        self.created = Some(created);
        self
    }

    /// Overrides the cryptosuite that would otherwise be chosen by the
    /// signer's default ([`crate::signer::Signer::cryptosuite`]).
    #[must_use = "chained builder call returns self; assign or chain further"]
    pub fn with_cryptosuite(mut self, suite: CryptoSuite) -> Self {
        self.cryptosuite = Some(suite);
        self
    }

    /// Overrides `proofPurpose`. The default is `"assertionMethod"`.
    #[must_use = "chained builder call returns self; assign or chain further"]
    pub fn with_proof_purpose(mut self, purpose: impl Into<String>) -> Self {
        self.proof_purpose = Some(purpose.into());
        self
    }

    /// Sets `expires`, after which verifiers refuse the proof. Serialised
    /// like `created`: seconds precision, `Z`-suffix, so any sub-second
    /// part is dropped.
    #[must_use = "chained builder call returns self; assign or chain further"]
    pub fn with_expires(mut self, expires: DateTime<Utc>) -> Self {
        self.expires = Some(expires);
        self
    }

    /// Sets `domain`: one string, or a list of strings.
    #[must_use = "chained builder call returns self; assign or chain further"]
    pub fn with_domain(mut self, domain: impl Into<StringOrList>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Sets `challenge`, normally a value the verifier issued.
    #[must_use = "chained builder call returns self; assign or chain further"]
    pub fn with_challenge(mut self, challenge: impl Into<String>) -> Self {
        self.challenge = Some(challenge.into());
        self
    }

    /// Sets `nonce`.
    #[must_use = "chained builder call returns self; assign or chain further"]
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Sets the proof's `id`. [`DataIntegrityProof::sign_multi`] gives every
    /// proof the same options, so sign individually to give each proof its
    /// own `id`.
    ///
    /// [`DataIntegrityProof::sign_multi`]: crate::DataIntegrityProof::sign_multi
    #[must_use = "chained builder call returns self; assign or chain further"]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Sets `previousProof`: the `id` of one proof, or a list of them.
    #[must_use = "chained builder call returns self; assign or chain further"]
    pub fn with_previous_proof(mut self, previous_proof: impl Into<StringOrList>) -> Self {
        self.previous_proof = Some(previous_proof.into());
        self
    }
}

/// Default tolerance applied to a proof's `created` timestamp when it
/// sits in the verifier's future: 60 seconds.
///
/// `created` is stamped by the *signer's* clock and checked against the
/// *verifier's*. With zero tolerance, acceptance of an otherwise-valid
/// proof becomes a race between clock skew and delivery latency — the
/// same signed request is accepted or rejected depending on how quickly
/// it arrives. 60s matches the leeway conventionally applied to JWT
/// `iat`/`nbf` (and `jsonwebtoken`'s own default), so a signer skewed
/// further than this generally fails bearer-token validation anyway.
///
/// The same allowance applies after a proof's `expires`: a proof is refused
/// once the verification time is more than this far past it.
///
/// It is not a freshness window: this library does not reject old proofs
/// that carry no `expires`, so replay protection must come from the
/// surrounding protocol (or from `expires`, `challenge` and `domain`).
pub const DEFAULT_CLOCK_SKEW: chrono::TimeDelta = chrono::TimeDelta::seconds(60);

/// Options for verifying a Data Integrity proof.
///
/// Carries the document's externally-supplied `@context` (for comparison
/// with the proof's declared context), an optional allowlist of acceptable
/// cryptosuites, the clock-skew tolerance applied to `created` and
/// `expires`, the time to verify at, and an optional expected `domain` and
/// `challenge`. More fields will be added as the library grows —
/// `#[non_exhaustive]` ensures future additions do not break callers.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct VerifyOptions {
    /// Expected `@context` of the signed document. When `Some`, the
    /// verifier enforces that the proof's `@context` matches.
    pub expected_context: Option<Vec<String>>,

    /// If non-empty, the proof's `cryptosuite` must appear in this list.
    /// Use to reject proofs produced by suites your policy does not
    /// accept (e.g. refuse `bbs-2023` in a context that requires full
    /// disclosure).
    pub allowed_suites: Vec<CryptoSuite>,

    /// How far into the verifier's future a proof's `created` may sit
    /// before it is rejected as non-conformant, and how far past a proof's
    /// `expires` the verifier may be before the proof is refused as
    /// expired. Defaults to [`DEFAULT_CLOCK_SKEW`]; set to zero for strict
    /// comparison. Negative values are treated as zero.
    pub clock_skew: chrono::TimeDelta,

    /// The time `created` and `expires` are compared against. `None` (the
    /// default) means the current time. Set it to verify as of a fixed
    /// instant, for tests or for checking a proof at the time it was
    /// received.
    pub verification_time: Option<DateTime<Utc>>,

    /// When `Some`, the proof's `domain` must be, or must include, this
    /// value. A proof with no `domain` is then refused.
    pub expected_domain: Option<String>,

    /// When `Some`, the proof's `challenge` must equal this value. A proof
    /// with no `challenge` is then refused.
    pub expected_challenge: Option<String>,
}

impl Default for VerifyOptions {
    /// All checks off except a [`DEFAULT_CLOCK_SKEW`] allowance on
    /// `created` — deliberately *not* `#[derive]`d, which would mean zero
    /// tolerance and make verification skew-sensitive by default.
    fn default() -> Self {
        Self {
            expected_context: None,
            allowed_suites: Vec::new(),
            clock_skew: DEFAULT_CLOCK_SKEW,
            verification_time: None,
            expected_domain: None,
            expected_challenge: None,
        }
    }
}

impl VerifyOptions {
    /// Constructs a `VerifyOptions` with no context or cryptosuite
    /// restrictions and the default clock-skew allowance. Equivalent to
    /// [`VerifyOptions::default`].
    #[must_use = "constructed options must be passed to sign/verify to take effect"]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the expected document `@context`.
    #[must_use = "chained builder call returns self; assign or chain further"]
    pub fn with_expected_context(mut self, ctx: Vec<String>) -> Self {
        self.expected_context = Some(ctx);
        self
    }

    /// Restricts the set of cryptosuites the verifier will accept.
    #[must_use = "chained builder call returns self; assign or chain further"]
    pub fn with_allowed_suites(mut self, suites: Vec<CryptoSuite>) -> Self {
        self.allowed_suites = suites;
        self
    }

    /// Overrides the tolerance for a `created` timestamp in the
    /// verifier's future. Pass [`chrono::TimeDelta::zero`] to reject any
    /// future timestamp outright.
    #[must_use = "chained builder call returns self; assign or chain further"]
    pub fn with_clock_skew(mut self, skew: chrono::TimeDelta) -> Self {
        self.clock_skew = skew;
        self
    }

    /// Verifies as of `time` instead of the current time.
    #[must_use = "chained builder call returns self; assign or chain further"]
    pub fn with_verification_time(mut self, time: DateTime<Utc>) -> Self {
        self.verification_time = Some(time);
        self
    }

    /// Requires the proof's `domain` to be, or to include, `domain`.
    #[must_use = "chained builder call returns self; assign or chain further"]
    pub fn with_expected_domain(mut self, domain: impl Into<String>) -> Self {
        self.expected_domain = Some(domain.into());
        self
    }

    /// Requires the proof's `challenge` to equal `challenge`.
    #[must_use = "chained builder call returns self; assign or chain further"]
    pub fn with_expected_challenge(mut self, challenge: impl Into<String>) -> Self {
        self.expected_challenge = Some(challenge.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_options_builder_chains() {
        let opts = SignOptions::new()
            .with_context(vec!["https://example/ctx".into()])
            .with_proof_purpose("authentication");
        assert_eq!(
            opts.context.as_deref(),
            Some(&["https://example/ctx".to_string()][..])
        );
        assert_eq!(opts.proof_purpose.as_deref(), Some("authentication"));
        assert!(opts.created.is_none());
    }

    #[test]
    fn verify_options_builder_chains() {
        let opts = VerifyOptions::new()
            .with_expected_context(vec!["a".into()])
            .with_allowed_suites(vec![]);
        assert_eq!(
            opts.expected_context.as_deref(),
            Some(&["a".to_string()][..])
        );
        assert!(opts.allowed_suites.is_empty());
    }
}
