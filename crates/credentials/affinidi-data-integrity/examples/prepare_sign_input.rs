//! Remote signing with `prepare_sign_input`.
//!
//! A common remote-signer protocol looks like this:
//!
//! 1. Client prepares the document + proof config.
//! 2. Client computes the "sign-over bytes" locally, without calling
//!    the remote service yet (there might be an approval step, or the
//!    client might cache the bytes to retry against a failover service).
//! 3. Client submits just those bytes to the remote signer.
//! 4. Client assembles the final proof from the returned signature.
//!
//! [`affinidi_data_integrity::prepare_sign_input`] gives you step 2
//! directly — the exact bytes that [`Signer::sign`] would receive if you
//! were using the built-in pipeline. This keeps the canonicalization and
//! hashing in the library (one place to audit) even when the signature
//! happens elsewhere.
//!
//! Run:
//! `cargo run --example prepare_sign_input -p affinidi-data-integrity`

use affinidi_data_integrity::{
    DataIntegrityProof, SignOptions, VerifyOptions, crypto_suites::CryptoSuite, prepare_sign_input,
};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::Utc;
use multibase::Base;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ---- 1. Set up keys and the document to sign ---------------------
    let mut backend_key = Secret::generate_ed25519(None, Some(&[42u8; 32]));
    let pk_mb = backend_key.get_public_keymultibase()?;
    let vm = format!("did:key:{pk_mb}#{pk_mb}");
    // Align the Secret's id with the proof's verificationMethod so the
    // built-in Signer::verification_method() matches our proof_config.
    backend_key.id = vm.clone();
    let public_key = backend_key.get_public_bytes().to_vec();

    let credential = json!({
        "@context": "https://www.w3.org/ns/credentials/v2",
        "id": "urn:fixture:prepare-sign-input",
        "type": ["VerifiableCredential"],
        "issuer": vm,
        "credentialSubject": { "id": "did:example:carol", "name": "Carol" },
    });

    // ---- 2. Build the proof configuration (everything except the signature)
    let suite = CryptoSuite::EddsaJcs2022;
    let created = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let proof_config = DataIntegrityProof {
        type_: "DataIntegrityProof".into(),
        cryptosuite: suite,
        created: Some(created),
        verification_method: vm.clone(),
        proof_purpose: "assertionMethod".into(),
        proof_value: None,
        context: None,
    };

    // ---- 3. Compute the exact bytes a remote signer would receive ---
    //
    // These are the 64 bytes (`SHA-256(proof_config) || SHA-256(doc)`)
    // that the library would pass to `Signer::sign`. Submit this payload
    // to your KMS / HSM / remote signing service.
    let sign_input = prepare_sign_input(&credential, &proof_config, suite)?;
    println!("sign_input: {} bytes", sign_input.len());

    // ---- 4. Stand-in for the remote service: sign locally with the key
    //
    // In production, replace this block with your KMS call. The returned
    // signature is raw bytes in the cryptosuite's expected format.
    let signature = simulate_remote_sign(&backend_key, &sign_input).await?;

    // ---- 5. Assemble the final proof --------------------------------
    let proof = DataIntegrityProof {
        proof_value: Some(multibase::encode(Base::Base58Btc, &signature)),
        ..proof_config
    };

    // ---- 6. Sanity-check: verify against the same public key --------
    proof.verify_with_public_key(&credential, &public_key, VerifyOptions::new())?;
    println!(
        "Proof verified. proofValue = {} chars",
        proof.proof_value.as_deref().unwrap_or("").len()
    );

    // ---- Optional: confirm bit-for-bit equivalence with the built-in path
    //
    // The library's `DataIntegrityProof::sign(...)` produces the same
    // bytes. Deterministic signing (Ed25519, ML-DSA, SLH-DSA are all
    // deterministic here) means the proofValue must match when the
    // `created` timestamp is pinned.
    let options = SignOptions::new()
        .with_cryptosuite(suite)
        .with_created(proof.created.as_deref().unwrap().parse()?);
    let builtin_proof = DataIntegrityProof::sign(&credential, &backend_key, options).await?;
    assert_eq!(
        proof.proof_value, builtin_proof.proof_value,
        "prepare_sign_input output should match the built-in sign pipeline"
    );
    println!("prepare_sign_input output matches built-in sign() output exactly.");

    Ok(())
}

async fn simulate_remote_sign(
    key: &Secret,
    payload: &[u8],
) -> Result<Vec<u8>, affinidi_data_integrity::DataIntegrityError> {
    // In a real remote signer, this would be an HTTP call to AWS KMS,
    // Azure Key Vault, or similar. Here we simulate by signing locally.
    use affinidi_data_integrity::signer::Signer;
    key.sign(payload).await
}
