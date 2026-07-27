//! Spec-shape conformance checking for Data Integrity proofs.
//!
//! [`verify_conformance`] enforces the structural requirements of the
//! W3C Data Integrity spec *before* any cryptographic verification
//! happens. A proof that is signed correctly but violates the spec's
//! structural rules (missing `proofPurpose`, wrong `type`, non-
//! RFC-3339 `created`, unexpected `proofValue` encoding) still gets
//! rejected.
//!
//! Use this to catch cross-implementation bugs where a signer emits
//! cryptographically valid but spec-non-conformant proofs — a common
//! failure mode when different implementations interpret the spec
//! slightly differently.

use crate::crypto_suites::CryptoSuite;
use crate::options::DEFAULT_CLOCK_SKEW;
use crate::{DataIntegrityError, DataIntegrityProof};

/// Checks that `proof` conforms to the W3C Data Integrity spec.
///
/// Currently checks:
///
/// 1. `type` is exactly `"DataIntegrityProof"`.
/// 2. `cryptosuite` matches `expected` (callers pick the suite they
///    were expecting for this context).
/// 3. `proofPurpose` is present and non-empty.
/// 4. `verificationMethod` is present and non-empty.
/// 5. `proofValue` is present and multibase-decodable.
/// 6. `created`, if present, parses as RFC 3339 and is no further into
///    the future than [`DEFAULT_CLOCK_SKEW`] (the signer's clock is not
///    the verifier's; see [`verify_conformance_with_skew`] to choose the
///    allowance).
///
/// Returns `Ok(())` if all structural checks pass. The cryptographic
/// signature is **not** verified here — use
/// [`DataIntegrityProof::verify_with_public_key`] or
/// [`DataIntegrityProof::verify`] for that.
///
/// Returns [`DataIntegrityError::Conformance`] on the first failure.
pub fn verify_conformance(
    proof: &DataIntegrityProof,
    expected: CryptoSuite,
) -> Result<(), DataIntegrityError> {
    verify_conformance_with_skew(proof, expected, DEFAULT_CLOCK_SKEW)
}

/// [`verify_conformance`], with an explicit tolerance for a `created`
/// timestamp in the verifier's future.
///
/// Pass [`chrono::TimeDelta::zero`] to reject any future timestamp
/// outright. Negative values are treated as zero.
pub fn verify_conformance_with_skew(
    proof: &DataIntegrityProof,
    expected: CryptoSuite,
    clock_skew: chrono::TimeDelta,
) -> Result<(), DataIntegrityError> {
    if proof.type_ != "DataIntegrityProof" {
        return Err(DataIntegrityError::Conformance(format!(
            "expected type \"DataIntegrityProof\", got {:?}",
            proof.type_
        )));
    }

    if proof.cryptosuite != expected {
        return Err(DataIntegrityError::Conformance(format!(
            "expected cryptosuite {}, got {}",
            expected, proof.cryptosuite
        )));
    }

    if proof.proof_purpose.is_empty() {
        return Err(DataIntegrityError::Conformance(
            "proofPurpose is missing or empty".into(),
        ));
    }

    if proof.verification_method.is_empty() {
        return Err(DataIntegrityError::Conformance(
            "verificationMethod is missing or empty".into(),
        ));
    }

    let Some(proof_value) = &proof.proof_value else {
        return Err(DataIntegrityError::Conformance(
            "proofValue is missing".into(),
        ));
    };
    multibase::decode(proof_value).map_err(|e| {
        DataIntegrityError::Conformance(format!("proofValue is not valid multibase: {e}"))
    })?;

    if let Some(created) = &proof.created {
        use chrono::{DateTime, TimeDelta, Utc};
        let parsed: DateTime<Utc> = created.parse().map_err(|e| {
            DataIntegrityError::Conformance(format!(
                "created does not parse as RFC 3339 ({e}): {created}"
            ))
        })?;
        let skew = clock_skew.max(TimeDelta::zero());
        let horizon = Utc::now()
            .checked_add_signed(skew)
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        if parsed > horizon {
            return Err(DataIntegrityError::Conformance(format!(
                "created timestamp is in the future (beyond the {}s clock-skew allowance)",
                skew.num_seconds()
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DataIntegrityProof, SignOptions};
    use affinidi_secrets_resolver::secrets::Secret;
    use serde_json::json;

    async fn sample_proof() -> DataIntegrityProof {
        let secret = Secret::generate_ed25519(None, Some(&[1u8; 32]));
        DataIntegrityProof::sign(&json!({"x": 1}), &secret, SignOptions::new())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn conformance_accepts_valid_proof() {
        let p = sample_proof().await;
        verify_conformance(&p, CryptoSuite::EddsaJcs2022).unwrap();
    }

    #[tokio::test]
    async fn conformance_rejects_wrong_type() {
        let mut p = sample_proof().await;
        p.type_ = "NotADataIntegrityProof".into();
        let err = verify_conformance(&p, CryptoSuite::EddsaJcs2022).unwrap_err();
        assert!(matches!(err, DataIntegrityError::Conformance(_)));
    }

    #[tokio::test]
    async fn conformance_rejects_wrong_suite() {
        let p = sample_proof().await;
        let err = verify_conformance(&p, CryptoSuite::EddsaRdfc2022).unwrap_err();
        assert!(matches!(err, DataIntegrityError::Conformance(_)));
    }

    #[tokio::test]
    async fn conformance_rejects_empty_proof_purpose() {
        let mut p = sample_proof().await;
        p.proof_purpose = String::new();
        let err = verify_conformance(&p, CryptoSuite::EddsaJcs2022).unwrap_err();
        assert!(matches!(err, DataIntegrityError::Conformance(_)));
    }

    #[tokio::test]
    async fn conformance_rejects_missing_proof_value() {
        let mut p = sample_proof().await;
        p.proof_value = None;
        let err = verify_conformance(&p, CryptoSuite::EddsaJcs2022).unwrap_err();
        assert!(matches!(err, DataIntegrityError::Conformance(_)));
    }

    #[tokio::test]
    async fn conformance_rejects_future_created() {
        let mut p = sample_proof().await;
        p.created = Some("3000-01-01T00:00:00Z".to_string());
        let err = verify_conformance(&p, CryptoSuite::EddsaJcs2022).unwrap_err();
        assert!(matches!(err, DataIntegrityError::Conformance(_)));
    }

    /// Ordinary signer-vs-verifier clock skew is not a conformance
    /// failure — only a `created` beyond the allowance is.
    #[tokio::test]
    async fn conformance_tolerates_default_clock_skew() {
        use chrono::{TimeDelta, Utc};
        let mut p = sample_proof().await;
        p.created = Some((Utc::now() + TimeDelta::seconds(5)).to_rfc3339());
        verify_conformance(&p, CryptoSuite::EddsaJcs2022)
            .expect("5s ahead is inside the default 60s allowance");
    }

    /// Zero skew restores the strict behaviour for callers that want it.
    #[tokio::test]
    async fn conformance_zero_skew_rejects_any_future_created() {
        use chrono::{TimeDelta, Utc};
        let mut p = sample_proof().await;
        p.created = Some((Utc::now() + TimeDelta::seconds(5)).to_rfc3339());
        let err =
            verify_conformance_with_skew(&p, CryptoSuite::EddsaJcs2022, TimeDelta::zero())
                .unwrap_err();
        assert!(matches!(err, DataIntegrityError::Conformance(_)));
    }

    #[tokio::test]
    async fn conformance_rejects_missing_verification_method() {
        let mut p = sample_proof().await;
        p.verification_method = String::new();
        let err = verify_conformance(&p, CryptoSuite::EddsaJcs2022).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("verificationMethod"), "got: {msg}");
    }

    #[tokio::test]
    async fn conformance_rejects_malformed_proof_value() {
        let mut p = sample_proof().await;
        // Valid base64 but invalid multibase — no base prefix character.
        p.proof_value = Some("AABB".to_string());
        let err = verify_conformance(&p, CryptoSuite::EddsaJcs2022).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("multibase"), "got: {msg}");
    }

    #[tokio::test]
    async fn conformance_rejects_malformed_created_timestamp() {
        let mut p = sample_proof().await;
        p.created = Some("not-a-timestamp".to_string());
        let err = verify_conformance(&p, CryptoSuite::EddsaJcs2022).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("RFC 3339") || msg.contains("created"),
            "got: {msg}"
        );
    }
}
