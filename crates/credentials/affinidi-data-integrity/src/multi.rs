//! Multi-proof signing and verification.
//!
//! The W3C Data Integrity spec allows more than one proof on a single
//! document. This module provides first-class ergonomics for two key
//! use cases:
//!
//! - **Hybrid / PQC migration.** Attach both an Ed25519 proof and an
//!   ML-DSA-44 proof to the same credential so classical and
//!   post-quantum verifiers can each verify their preferred suite,
//!   during the (multi-year) transition period.
//! - **Witness / threshold schemes.** Collect signatures from N
//!   witnesses, accept the document if at least `t` of them verify —
//!   e.g. did:webvh-style update logs.
//!
//! # sign_multi semantics
//!
//! [`DataIntegrityProof::sign_multi`] is **fail-fast**: if any signer
//! errors, no proofs are emitted and the error bubbles up. This matches
//! the typical "issuer wants the credential fully signed or not at all"
//! model. Callers who want best-effort semantics can loop
//! [`DataIntegrityProof::sign`] themselves and collect results.
//!
//! # verify_multi semantics
//!
//! Configurable via [`VerifyPolicy`]. The library returns a
//! [`MultiVerifyResult`] that lists which proofs passed, which failed
//! (with per-proof structured errors), and whether the overall policy
//! was satisfied. Callers can log the full audit trail while only
//! needing to check one bool for the go/no-go decision.

use serde::Serialize;

use crate::{
    DataIntegrityError, DataIntegrityProof, SignOptions, VerificationMethodResolver, VerifyOptions,
    signer::Signer,
};

/// Acceptance rule for [`verify_multi`].
///
/// # Examples
///
/// ```ignore
/// use affinidi_data_integrity::multi::VerifyPolicy;
///
/// // Every proof must verify:
/// let strict = VerifyPolicy::RequireAll;
///
/// // At least three of N witnesses must verify:
/// let quorum = VerifyPolicy::RequireThreshold(3);
///
/// // Hybrid classical+PQC: accept if *any* proof verifies (client picks
/// // the strongest proof it understands):
/// let hybrid = VerifyPolicy::RequireAny;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyPolicy {
    /// Every proof in the set must verify. The set must be non-empty.
    RequireAll,
    /// At least one proof must verify.
    RequireAny,
    /// At least `n` proofs must verify. A threshold of zero is treated
    /// as [`RequireAll`] (the degenerate case is a user error —
    /// callers should pick a meaningful threshold).
    ///
    /// [`RequireAll`]: VerifyPolicy::RequireAll
    RequireThreshold(usize),
}

/// Per-proof verification outcome and the overall policy decision.
#[derive(Debug)]
#[non_exhaustive]
pub struct MultiVerifyResult<'a> {
    /// Proofs that verified successfully.
    pub passed: Vec<&'a DataIntegrityProof>,
    /// Proofs that failed, paired with the structured error returned by
    /// the verifier.
    pub failed: Vec<(&'a DataIntegrityProof, DataIntegrityError)>,
    /// Did the combination satisfy the requested policy?
    pub policy_satisfied: bool,
}

impl MultiVerifyResult<'_> {
    /// Returns `Err(MultiProofPolicyFailed)` if the policy was not
    /// satisfied, otherwise `Ok(())`. Use this when you want a single
    /// `?`-propagatable result instead of inspecting the struct.
    pub fn into_result(self) -> Result<(), DataIntegrityError> {
        if self.policy_satisfied {
            Ok(())
        } else {
            Err(DataIntegrityError::Conformance(format!(
                "multi-proof policy not satisfied ({} passed, {} failed)",
                self.passed.len(),
                self.failed.len()
            )))
        }
    }
}

impl DataIntegrityProof {
    /// Signs `data_doc` with every signer in `signers`, producing one
    /// [`DataIntegrityProof`] per signer.
    ///
    /// **Fail-fast**: if any signer errors, no proofs are emitted and
    /// the error is returned immediately.
    ///
    /// All signers share the same [`SignOptions`] — the per-signer
    /// cryptosuite still defaults via [`Signer::cryptosuite`], so a
    /// heterogeneous list of signers (Ed25519 + ML-DSA-44) produces one
    /// proof per suite automatically.
    pub async fn sign_multi<S>(
        data_doc: &S,
        signers: &[&dyn Signer],
        options: SignOptions,
    ) -> Result<Vec<DataIntegrityProof>, DataIntegrityError>
    where
        S: Serialize,
    {
        if signers.is_empty() {
            return Err(DataIntegrityError::MalformedProof(
                "sign_multi called with no signers".to_string(),
            ));
        }

        // Pin `created` once for the whole batch so every emitted proof
        // carries an identical timestamp. Without this, the first signer
        // might run at t0 and the last at t0+~ms, producing proofs with
        // different `created` fields — surprising for callers that do
        // byte-exact interop.
        let mut options = options;
        if options.created.is_none() {
            options.created = Some(chrono::Utc::now());
        }

        let mut proofs = Vec::with_capacity(signers.len());
        for signer in signers {
            let proof = DataIntegrityProof::sign(data_doc, *signer, options.clone()).await?;
            proofs.push(proof);
        }
        Ok(proofs)
    }
}

/// Verifies multiple proofs against the same document, enforcing
/// [`VerifyPolicy`].
///
/// Every proof is verified independently via
/// [`DataIntegrityProof::verify`] (i.e. the `verificationMethod` of each
/// proof is resolved through `resolver`). The returned
/// [`MultiVerifyResult`] lists per-proof outcomes plus the policy
/// decision.
pub async fn verify_multi<'a, S, R>(
    proofs: &'a [DataIntegrityProof],
    data_doc: &S,
    resolver: &R,
    options: VerifyOptions,
    policy: VerifyPolicy,
) -> MultiVerifyResult<'a>
where
    S: Serialize + Sync,
    R: VerificationMethodResolver + ?Sized,
{
    let mut passed = Vec::new();
    let mut failed = Vec::new();

    for proof in proofs {
        match proof.verify(data_doc, resolver, options.clone()).await {
            Ok(()) => passed.push(proof),
            Err(e) => failed.push((proof, e)),
        }
    }

    let policy_satisfied = match policy {
        VerifyPolicy::RequireAll => !proofs.is_empty() && failed.is_empty(),
        VerifyPolicy::RequireAny => !passed.is_empty(),
        VerifyPolicy::RequireThreshold(n) => {
            if n == 0 {
                !proofs.is_empty() && failed.is_empty()
            } else {
                passed.len() >= n
            }
        }
    };

    MultiVerifyResult {
        passed,
        failed,
        policy_satisfied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DidKeyResolver;
    use affinidi_secrets_resolver::secrets::Secret;
    use serde_json::json;

    fn make_signer(kind: &str, seed: u8) -> Secret {
        let secret = match kind {
            "ed25519" => Secret::generate_ed25519(None, Some(&[seed; 32])),
            #[cfg(feature = "ml-dsa")]
            "ml-dsa-44" => Secret::generate_ml_dsa_44(None, Some(&[seed; 32])),
            _ => panic!("unknown kind {kind}"),
        };
        let pk_mb = secret.get_public_keymultibase().unwrap();
        let mut s = secret.clone();
        s.id = format!("did:key:{pk_mb}#{pk_mb}");
        s
    }

    #[tokio::test]
    async fn sign_multi_pins_created_across_batch() {
        // Without an explicit `created` in options, sign_multi still
        // emits the same timestamp on every proof. Guards against
        // timestamp drift from sequential Utc::now() calls.
        let a = make_signer("ed25519", 10);
        let b = make_signer("ed25519", 11);
        let signers: Vec<&dyn Signer> = vec![&a, &b];
        let doc = json!({"pin": "created"});
        let proofs = DataIntegrityProof::sign_multi(&doc, &signers, SignOptions::new())
            .await
            .unwrap();
        assert_eq!(proofs.len(), 2);
        assert_eq!(proofs[0].created, proofs[1].created);
    }

    #[tokio::test]
    async fn sign_multi_emits_one_proof_per_signer() {
        let a = make_signer("ed25519", 1);
        let b = make_signer("ed25519", 2);
        let signers: Vec<&dyn Signer> = vec![&a, &b];
        let doc = json!({"multi": true});
        let proofs = DataIntegrityProof::sign_multi(&doc, &signers, SignOptions::new())
            .await
            .unwrap();
        assert_eq!(proofs.len(), 2);
    }

    #[cfg(feature = "ml-dsa")]
    #[tokio::test]
    async fn sign_multi_hybrid_classical_and_pqc() {
        // Ed25519 + ML-DSA-44 proofs on the same document — the PQC
        // migration use case.
        let classical = make_signer("ed25519", 9);
        let pqc = make_signer("ml-dsa-44", 9);
        let signers: Vec<&dyn Signer> = vec![&classical, &pqc];
        let doc = json!({"hybrid": "yes"});

        let proofs = DataIntegrityProof::sign_multi(&doc, &signers, SignOptions::new())
            .await
            .unwrap();
        assert_eq!(proofs.len(), 2);
        assert_eq!(
            proofs[0].cryptosuite,
            crate::crypto_suites::CryptoSuite::EddsaJcs2022
        );
        assert_eq!(
            proofs[1].cryptosuite,
            crate::crypto_suites::CryptoSuite::MlDsa44Jcs2024
        );

        // RequireAll: both must verify.
        let result = verify_multi(
            &proofs,
            &doc,
            &DidKeyResolver,
            VerifyOptions::new(),
            VerifyPolicy::RequireAll,
        )
        .await;
        assert!(result.policy_satisfied);
        assert_eq!(result.passed.len(), 2);
        assert!(result.failed.is_empty());
    }

    #[tokio::test]
    async fn verify_multi_require_any_tolerates_one_bad_proof() {
        let good = make_signer("ed25519", 3);
        let signers: Vec<&dyn Signer> = vec![&good];
        let doc = json!({"x": 1});
        let mut proofs = DataIntegrityProof::sign_multi(&doc, &signers, SignOptions::new())
            .await
            .unwrap();

        // Corrupt a clone of the real proof so it fails verification.
        let mut bad = proofs[0].clone();
        let pv = bad.proof_value.take().unwrap();
        let mut raw = multibase::decode(&pv).unwrap().1;
        raw[0] ^= 0xff;
        bad.proof_value = Some(multibase::encode(multibase::Base::Base58Btc, raw));
        proofs.push(bad);

        // RequireAny: one valid proof is enough.
        let result = verify_multi(
            &proofs,
            &doc,
            &DidKeyResolver,
            VerifyOptions::new(),
            VerifyPolicy::RequireAny,
        )
        .await;
        assert!(result.policy_satisfied);
        assert_eq!(result.passed.len(), 1);
        assert_eq!(result.failed.len(), 1);

        // RequireAll would fail on the same input.
        let result = verify_multi(
            &proofs,
            &doc,
            &DidKeyResolver,
            VerifyOptions::new(),
            VerifyPolicy::RequireAll,
        )
        .await;
        assert!(!result.policy_satisfied);
    }

    #[tokio::test]
    async fn verify_multi_threshold() {
        let a = make_signer("ed25519", 1);
        let b = make_signer("ed25519", 2);
        let c = make_signer("ed25519", 3);
        let signers: Vec<&dyn Signer> = vec![&a, &b, &c];
        let doc = json!({"witnesses": 3});
        let proofs = DataIntegrityProof::sign_multi(&doc, &signers, SignOptions::new())
            .await
            .unwrap();

        let result = verify_multi(
            &proofs,
            &doc,
            &DidKeyResolver,
            VerifyOptions::new(),
            VerifyPolicy::RequireThreshold(2),
        )
        .await;
        assert!(result.policy_satisfied);
        assert_eq!(result.passed.len(), 3);
    }

    /// `RequireThreshold(0)` must behave identically to `RequireAll` so
    /// the degenerate case (caller accidentally passing 0) doesn't
    /// silently accept every empty-proof set.
    #[tokio::test]
    async fn verify_multi_threshold_zero_equals_require_all() {
        let a = make_signer("ed25519", 1);
        let signers: Vec<&dyn Signer> = vec![&a];
        let doc = json!({"t": 0});
        let proofs = DataIntegrityProof::sign_multi(&doc, &signers, SignOptions::new())
            .await
            .unwrap();

        let require_all = verify_multi(
            &proofs,
            &doc,
            &DidKeyResolver,
            VerifyOptions::new(),
            VerifyPolicy::RequireAll,
        )
        .await;
        let threshold_zero = verify_multi(
            &proofs,
            &doc,
            &DidKeyResolver,
            VerifyOptions::new(),
            VerifyPolicy::RequireThreshold(0),
        )
        .await;
        assert_eq!(
            require_all.policy_satisfied,
            threshold_zero.policy_satisfied
        );
        assert_eq!(require_all.passed.len(), threshold_zero.passed.len());

        // Also: both must fail on an empty proof set.
        let empty: Vec<DataIntegrityProof> = vec![];
        let r = verify_multi(
            &empty,
            &doc,
            &DidKeyResolver,
            VerifyOptions::new(),
            VerifyPolicy::RequireThreshold(0),
        )
        .await;
        assert!(!r.policy_satisfied);
    }

    #[tokio::test]
    async fn sign_multi_empty_signer_list_is_error() {
        let doc = json!({});
        let err = DataIntegrityProof::sign_multi(&doc, &[], SignOptions::new())
            .await
            .unwrap_err();
        assert!(matches!(err, DataIntegrityError::MalformedProof(_)));
    }
}
