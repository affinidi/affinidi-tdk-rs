/*!
 * EdDSA (Ed25519) COSE signer and verifier for mdoc.
 *
 * Production implementation of the `CoseSigner`/`CoseVerifier` traits
 * using Ed25519. EdDSA provides fast, compact signatures and is used
 * in some eIDAS deployments and DID-based identity systems.
 *
 * Enabled via the `eddsa` feature flag.
 *
 * # Algorithm Details
 *
 * - **COSE Algorithm**: EdDSA (`-8`)
 * - **Curve**: Ed25519
 * - **Key size**: 32 bytes private, 32 bytes public
 * - **Signature size**: 64 bytes
 * - **Hash**: SHA-512 (internal to Ed25519)
 */

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::cose::{CoseSigner, CoseVerifier};
use crate::error::{MdocError, Result};

/// EdDSA COSE signer using an Ed25519 private key.
pub struct EdDsaCoseSigner {
    signing_key: SigningKey,
    x5chain: Option<Vec<Vec<u8>>>,
    kid: Option<Vec<u8>>,
}

impl EdDsaCoseSigner {
    /// Create a signer from raw Ed25519 private key bytes (32 bytes).
    pub fn from_bytes(private_key: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            MdocError::Cose(format!(
                "Ed25519 key must be 32 bytes, got {}",
                private_key.len()
            ))
        })?;
        let signing_key = SigningKey::from_bytes(&bytes);
        Ok(Self {
            signing_key,
            x5chain: None,
            kid: None,
        })
    }

    /// Generate a new random Ed25519 key pair for signing.
    pub fn generate() -> Self {
        // Generate 32 random bytes and construct the key, avoiding
        // rand_core version conflicts (ed25519-dalek uses 0.6, rand uses 0.9).
        let mut rng = rand::rng();
        let mut bytes = [0u8; 32];
        rand::Fill::fill(&mut bytes, &mut rng);
        let signing_key = SigningKey::from_bytes(&bytes);
        Self {
            signing_key,
            x5chain: None,
            kid: None,
        }
    }

    /// Set the X.509 certificate chain (DER-encoded).
    pub fn with_x5chain(mut self, chain: Vec<Vec<u8>>) -> Self {
        self.x5chain = Some(chain);
        self
    }

    /// Set the key identifier.
    pub fn with_kid(mut self, kid: Vec<u8>) -> Self {
        self.kid = Some(kid);
        self
    }

    /// Get the public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }
}

impl CoseSigner for EdDsaCoseSigner {
    fn algorithm(&self) -> coset::iana::Algorithm {
        coset::iana::Algorithm::EdDSA
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signature = self.signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    fn x5chain(&self) -> Option<Vec<Vec<u8>>> {
        self.x5chain.clone()
    }

    fn kid(&self) -> Option<Vec<u8>> {
        self.kid.clone()
    }
}

/// EdDSA COSE verifier using an Ed25519 public key.
pub struct EdDsaCoseVerifier {
    verifying_key: VerifyingKey,
}

impl EdDsaCoseVerifier {
    /// Create a verifier from Ed25519 public key bytes (32 bytes).
    pub fn from_bytes(public_key: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = public_key.try_into().map_err(|_| {
            MdocError::Cose(format!(
                "Ed25519 public key must be 32 bytes, got {}",
                public_key.len()
            ))
        })?;
        let verifying_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| MdocError::Cose(format!("invalid Ed25519 public key: {e}")))?;
        Ok(Self { verifying_key })
    }
}

impl CoseVerifier for EdDsaCoseVerifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let sig = Signature::from_slice(signature)
            .map_err(|e| MdocError::Cose(format!("invalid EdDSA signature: {e}")))?;

        match self.verifying_key.verify(data, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::{sign_mso, verify_issuer_auth};
    use crate::issuer_signed_item::IssuerSignedItem;
    use crate::mso::{MobileSecurityObject, ValidityInfo};
    use std::collections::BTreeMap;

    fn test_mso() -> MobileSecurityObject {
        let mut namespaces = BTreeMap::new();
        namespaces.insert(
            "test".to_string(),
            vec![IssuerSignedItem::new(
                0,
                "name",
                ciborium::Value::Text("Alice".into()),
            )],
        );

        MobileSecurityObject::create(
            "test.doctype",
            "SHA-256",
            &namespaces,
            ciborium::Value::Map(vec![]),
            ValidityInfo {
                signed: "2024-01-01T00:00:00Z".to_string(),
                valid_from: "2024-01-01T00:00:00Z".to_string(),
                valid_until: "2025-01-01T00:00:00Z".to_string(),
            },
            0,
        )
        .unwrap()
    }

    #[test]
    fn eddsa_sign_and_verify() {
        let signer = EdDsaCoseSigner::generate();
        let verifier = EdDsaCoseVerifier::from_bytes(&signer.public_key_bytes()).unwrap();

        let mso = test_mso();
        let sign1 = sign_mso(&mso, &signer).unwrap();

        let decoded = verify_issuer_auth(&sign1, &verifier).unwrap();
        assert_eq!(decoded.doc_type, "test.doctype");
    }

    #[test]
    fn eddsa_wrong_key_fails() {
        let signer = EdDsaCoseSigner::generate();
        let wrong = EdDsaCoseSigner::generate();
        let verifier = EdDsaCoseVerifier::from_bytes(&wrong.public_key_bytes()).unwrap();

        let mso = test_mso();
        let sign1 = sign_mso(&mso, &signer).unwrap();

        assert!(verify_issuer_auth(&sign1, &verifier).is_err());
    }

    #[test]
    fn eddsa_cbor_roundtrip() {
        use coset::CborSerializable;

        let signer = EdDsaCoseSigner::generate();
        let verifier = EdDsaCoseVerifier::from_bytes(&signer.public_key_bytes()).unwrap();

        let mso = test_mso();
        let sign1 = sign_mso(&mso, &signer).unwrap();

        let bytes = sign1.to_vec().unwrap();
        let parsed = coset::CoseSign1::from_slice(&bytes).unwrap();

        let decoded = verify_issuer_auth(&parsed, &verifier).unwrap();
        assert_eq!(decoded.doc_type, "test.doctype");
    }

    #[test]
    fn eddsa_signature_is_64_bytes() {
        let signer = EdDsaCoseSigner::generate();
        let sig = signer.sign(b"test data").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn eddsa_public_key_is_32_bytes() {
        let signer = EdDsaCoseSigner::generate();
        assert_eq!(signer.public_key_bytes().len(), 32);
    }

    #[test]
    fn eddsa_from_bytes_roundtrip() {
        let signer = EdDsaCoseSigner::generate();
        let private_bytes = signer.signing_key.to_bytes();
        let restored = EdDsaCoseSigner::from_bytes(&private_bytes).unwrap();
        assert_eq!(signer.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn eddsa_with_kid() {
        let signer = EdDsaCoseSigner::generate().with_kid(b"key-ed25519".to_vec());
        assert_eq!(signer.kid(), Some(b"key-ed25519".to_vec()));
    }
}
