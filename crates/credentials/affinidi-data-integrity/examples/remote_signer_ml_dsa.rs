//! Remote ML-DSA-44 signer — shows how the same `Signer` trait handles
//! post-quantum keys held by a remote backend.
//!
//! **Cloud KMS support status (as of this commit):** no major cloud KMS
//! provider (AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault transit)
//! exposes ML-DSA today. This example uses an in-process mock to stand in
//! for whatever PQC-capable signing service becomes available — the
//! client-side trait impl below is exactly what a real integration would
//! look like once the upstream APIs exist.
//!
//! Build with the `post-quantum` feature:
//! `cargo run --example remote_signer_ml_dsa -p affinidi-data-integrity --features post-quantum`

use affinidi_data_integrity::{
    DataIntegrityError, DataIntegrityProof, SignOptions, VerifyOptions, signer::Signer,
};
use affinidi_secrets_resolver::secrets::{KeyType, Secret};
use async_trait::async_trait;
use serde_json::json;
use tokio::sync::oneshot;

struct RemoteMlDsa44Signer {
    vm: String,
    backend: tokio::sync::mpsc::Sender<SignRequest>,
}

struct SignRequest {
    payload: Vec<u8>,
    response: oneshot::Sender<Result<Vec<u8>, String>>,
}

#[async_trait]
impl Signer for RemoteMlDsa44Signer {
    fn key_type(&self) -> KeyType {
        KeyType::MlDsa44
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
    let backend_secret = Secret::generate_ml_dsa_44(None, Some(&[88u8; 32]));
    let pk_mb = backend_secret.get_public_keymultibase()?;
    let vm = format!("did:key:{pk_mb}#{pk_mb}");
    let public_key_bytes = backend_secret.get_public_bytes().to_vec();
    let backend = spawn_backend(backend_secret);

    let remote = RemoteMlDsa44Signer {
        vm: vm.clone(),
        backend,
    };

    let credential = json!({
        "@context": "https://www.w3.org/ns/credentials/v2",
        "id": "https://example.com/credentials/pqc-1",
        "type": ["VerifiableCredential"],
        "issuer": vm,
        "credentialSubject": { "id": "did:example:bob", "name": "Bob" },
    });

    let proof = DataIntegrityProof::sign(&credential, &remote, SignOptions::new()).await?;
    println!("Produced proof with cryptosuite: {}", proof.cryptosuite);
    println!(
        "proofValue length: {} bytes (ML-DSA-44 signatures are ~2420 bytes raw; the multibase-encoded representation is larger)",
        proof.proof_value.as_ref().map(String::len).unwrap_or(0)
    );

    proof.verify_with_public_key(&credential, &public_key_bytes, VerifyOptions::new())?;
    println!("Verified OK.");

    Ok(())
}
