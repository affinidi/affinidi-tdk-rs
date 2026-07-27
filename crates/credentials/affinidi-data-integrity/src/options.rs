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
/// This governs only how far *ahead* `created` may be. It is not a
/// freshness window: this library does not reject old proofs, so replay
/// protection must come from the surrounding protocol.
pub const DEFAULT_CLOCK_SKEW: chrono::TimeDelta = chrono::TimeDelta::seconds(60);

/// Options for verifying a Data Integrity proof.
///
/// Currently carries the document's externally-supplied `@context` (for
/// comparison with the proof's declared context), an optional allowlist
/// of acceptable cryptosuites, and the tolerance applied to a future
/// `created` timestamp. More fields will be added as the library grows —
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
    /// before it is rejected as non-conformant. Defaults to
    /// [`DEFAULT_CLOCK_SKEW`]; set to zero for strict rejection of any
    /// future timestamp. Negative values are treated as zero.
    pub clock_skew: chrono::TimeDelta,
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
