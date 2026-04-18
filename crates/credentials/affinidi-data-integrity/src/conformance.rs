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
/// 6. `created`, if present, parses as RFC 3339 and is not in the
///    future.
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
        use chrono::{DateTime, Utc};
        let parsed: DateTime<Utc> = created.parse().map_err(|e| {
            DataIntegrityError::Conformance(format!(
                "created does not parse as RFC 3339 ({e}): {created}"
            ))
        })?;
        if parsed > Utc::now() {
            return Err(DataIntegrityError::Conformance(
                "created timestamp is in the future".into(),
            ));
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
}
