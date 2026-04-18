//! Remote Ed25519 signer — shows how to implement [`Signer`] for a
//! backend that holds the private key somewhere else (KMS, HSM,
//! network service).
//!
//! This example uses an in-process mock to keep the example self-contained
//! and runnable without cloud credentials, but the trait shape is exactly
//! what a real AWS KMS / Azure Key Vault / GCP KMS integration would use:
//!
//! - `sign` is async — delegate to your SDK there.
//! - Errors from the remote side get wrapped with
//!   [`DataIntegrityError::signing`] so the source chain survives.
//! - The bytes you receive are already canonicalised — just submit them
//!   as the sign request payload.
//!
//! Run with: `cargo run --example remote_signer_ed25519 -p affinidi-data-integrity`

use affinidi_data_integrity::{
    DataIntegrityError, DataIntegrityProof, SignOptions, VerifyOptions, signer::Signer,
};
use affinidi_secrets_resolver::secrets::{KeyType, Secret};
use async_trait::async_trait;
use serde_json::json;
use tokio::sync::oneshot;

/// A mock "remote" signer that talks to a signing service over a channel.
/// In production this would be e.g. `aws_sdk_kms::Client::sign()`.
struct RemoteEd25519Signer {
    /// Verification-method URI exposed in the emitted proof.
    vm: String,
    /// The "backend" — normally held by some other process/machine.
    backend: tokio::sync::mpsc::Sender<SignRequest>,
}

struct SignRequest {
    payload: Vec<u8>,
    response: oneshot::Sender<Result<Vec<u8>, String>>,
}

#[async_trait]
impl Signer for RemoteEd25519Signer {
    fn key_type(&self) -> KeyType {
        KeyType::Ed25519
    }
    fn verification_method(&self) -> &str {
        &self.vm
    }
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, DataIntegrityError> {
        let (tx, rx) = oneshot::channel();
        self.backend
            .send(SignRequest {
                payload: data.to_vec(),
                response: tx,
            })
            .await
            .map_err(|e| DataIntegrityError::signing(std::io::Error::other(e.to_string())))?;
        rx.await
            .map_err(|e| DataIntegrityError::signing(std::io::Error::other(e.to_string())))?
            .map_err(|e| DataIntegrityError::signing(std::io::Error::other(e)))
    }
}

/// Spawns a "remote signing service" task holding the key material.
fn spawn_backend(secret: Secret) -> tokio::sync::mpsc::Sender<SignRequest> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SignRequest>(16);
    tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            let result = secret.sign(&req.payload).await.map_err(|e| e.to_string());
            let _ = req.response.send(result);
        }
    });
    tx
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up the "remote" backend with an Ed25519 key it holds privately.
    let backend_secret = Secret::generate_ed25519(None, Some(&[42u8; 32]));
    let pk_mb = backend_secret.get_public_keymultibase()?;
    let vm = format!("did:key:{pk_mb}#{pk_mb}");
    let public_key_bytes = backend_secret.get_public_bytes().to_vec();
    let backend = spawn_backend(backend_secret);

    // The client side only keeps the public key and the handle.
    let remote = RemoteEd25519Signer {
        vm: vm.clone(),
        backend,
    };

    // Produce a Data Integrity proof — exactly the same API as a local signer.
    let credential = json!({
        "@context": "https://www.w3.org/ns/credentials/v2",
        "id": "https://example.com/credentials/1",
        "type": ["VerifiableCredential"],
        "issuer": vm,
        "credentialSubject": { "id": "did:example:alice", "name": "Alice" },
    });

    let proof = DataIntegrityProof::sign(
        &credential,
        &remote,
        SignOptions::new().with_proof_purpose("assertionMethod"),
    )
    .await?;

    println!("Produced proof with cryptosuite: {}", proof.cryptosuite);
    println!(
        "proofValue length: {} bytes",
        proof.proof_value.as_ref().map(String::len).unwrap_or(0)
    );

    // Verify locally to confirm the remote signer produced a valid proof.
    proof.verify_with_public_key(&credential, &public_key_bytes, VerifyOptions::new())?;
    println!("Verified OK.");

    Ok(())
}
