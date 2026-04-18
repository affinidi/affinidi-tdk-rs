//! Hybrid classical + post-quantum signing on one credential.
//!
//! Attach both an Ed25519 proof and an ML-DSA-44 proof to the same
//! credential. Verifiers that only understand classical Ed25519 can
//! accept the credential via the Ed25519 proof; verifiers that require
//! PQC can reject the Ed25519 proof and accept the ML-DSA one. This is
//! the intended migration pattern for the multi-year PQC transition.
//!
//! Run:
//! `cargo run --example sign_multi_hybrid -p affinidi-data-integrity --features post-quantum`

#![cfg(feature = "ml-dsa")]

use affinidi_data_integrity::{
    DataIntegrityProof, DidKeyResolver, SignOptions, VerifyOptions, VerifyPolicy, signer::Signer,
    verify_multi,
};
use affinidi_secrets_resolver::secrets::Secret;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Two independent keys, one per algorithm. In production these
    // would come from a KMS or HSM (see examples/remote_signer_*.rs).
    let classical = build_signer_with_did_key(Secret::generate_ed25519(None, Some(&[1u8; 32])))?;
    let pqc = build_signer_with_did_key(Secret::generate_ml_dsa_44(None, Some(&[2u8; 32])))?;

    let credential = json!({
        "@context": "https://www.w3.org/ns/credentials/v2",
        "id": "urn:hybrid:1",
        "type": ["VerifiableCredential"],
        "issuer": classical.verification_method(),
        "credentialSubject": { "id": "did:example:dana", "name": "Dana" },
    });

    // Produce both proofs in one call — fail-fast on any signer error.
    let signers: Vec<&dyn Signer> = vec![&classical, &pqc];
    let proofs = DataIntegrityProof::sign_multi(&credential, &signers, SignOptions::new()).await?;
    println!("Emitted {} proofs:", proofs.len());
    for p in &proofs {
        println!("  {} via {}", p.cryptosuite, p.verification_method);
    }

    // Classical-only verifier: accept if Ed25519 proof verifies. They
    // don't understand ML-DSA proofs, so RequireAny matches either one
    // and the ML-DSA proof simply doesn't get to contribute.
    //
    // Here we verify both proofs with a single DidKeyResolver — a real
    // classical-only verifier would only verify the Ed25519 proof and
    // ignore the PQC one.
    let result = verify_multi(
        &proofs,
        &credential,
        &DidKeyResolver,
        VerifyOptions::new(),
        VerifyPolicy::RequireAny,
    )
    .await;
    println!(
        "RequireAny: {} passed, {} failed, policy_satisfied={}",
        result.passed.len(),
        result.failed.len(),
        result.policy_satisfied
    );

    // PQC-strict verifier: require ALL proofs to verify (belt + braces)
    // so the credential can't be forged by breaking Ed25519 alone.
    let result = verify_multi(
        &proofs,
        &credential,
        &DidKeyResolver,
        VerifyOptions::new(),
        VerifyPolicy::RequireAll,
    )
    .await;
    println!(
        "RequireAll: {} passed, {} failed, policy_satisfied={}",
        result.passed.len(),
        result.failed.len(),
        result.policy_satisfied
    );
    result.into_result()?;
    println!("Credential accepted under belt-and-braces PQC+classical policy.");

    Ok(())
}

fn build_signer_with_did_key(mut secret: Secret) -> Result<Secret, Box<dyn std::error::Error>> {
    let pk_mb = secret.get_public_keymultibase()?;
    secret.id = format!("did:key:{pk_mb}#{pk_mb}");
    Ok(secret)
}
