/*!
 * ES256 (ECDSA P-256) COSE signer and verifier for mdoc.
 *
 * Production-ready implementation of the `CoseSigner`/`CoseVerifier` traits
 * using P-256 ECDSA. This is the mandatory signing algorithm for eIDAS mdoc.
 *
 * Enabled via the `es256` feature flag.
 */

use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier};

use crate::cose::{CoseSigner, CoseVerifier};
use crate::error::{MdocError, Result};

/// ES256 COSE signer using a P-256 private key.
///
/// For production mdoc issuance. Produces real ECDSA signatures
/// compatible with ISO 18013-5 and eIDAS 2.0.
pub struct Es256CoseSigner {
    signing_key: SigningKey,
    x5chain: Option<Vec<Vec<u8>>>,
    kid: Option<Vec<u8>>,
}

impl Es256CoseSigner {
    /// Create a signer from raw P-256 private key bytes (32 bytes).
    pub fn from_bytes(private_key: &[u8]) -> Result<Self> {
        let signing_key = SigningKey::from_slice(private_key)
            .map_err(|e| MdocError::Cose(format!("invalid P-256 key: {e}")))?;
        Ok(Self {
            signing_key,
            x5chain: None,
            kid: None,
        })
    }

    /// Generate a new random P-256 key pair for signing.
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
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

    /// Get the public key as uncompressed SEC1 bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        VerifyingKey::from(&self.signing_key)
            .to_encoded_point(false)
            .to_bytes()
            .to_vec()
    }
}

impl CoseSigner for Es256CoseSigner {
    fn algorithm(&self) -> coset::iana::Algorithm {
        coset::iana::Algorithm::ES256
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signature: Signature = self.signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    fn x5chain(&self) -> Option<Vec<Vec<u8>>> {
        self.x5chain.clone()
    }

    fn kid(&self) -> Option<Vec<u8>> {
        self.kid.clone()
    }
}

/// ES256 COSE verifier using a P-256 public key.
pub struct Es256CoseVerifier {
    verifying_key: VerifyingKey,
}

impl Es256CoseVerifier {
    /// Create a verifier from uncompressed or compressed SEC1 public key bytes.
    pub fn from_bytes(public_key: &[u8]) -> Result<Self> {
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|e| MdocError::Cose(format!("invalid P-256 public key: {e}")))?;
        Ok(Self { verifying_key })
    }
}

impl CoseVerifier for Es256CoseVerifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let sig = Signature::from_slice(signature)
            .map_err(|e| MdocError::Cose(format!("invalid signature: {e}")))?;

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
    fn es256_cose_sign_and_verify() {
        let signer = Es256CoseSigner::generate();
        let verifier = Es256CoseVerifier::from_bytes(&signer.public_key_bytes()).unwrap();

        let mso = test_mso();
        let sign1 = sign_mso(&mso, &signer).unwrap();

        let decoded = verify_issuer_auth(&sign1, &verifier).unwrap();
        assert_eq!(decoded.doc_type, "test.doctype");
    }

    #[test]
    fn es256_cose_wrong_key_fails() {
        let signer = Es256CoseSigner::generate();
        let wrong_signer = Es256CoseSigner::generate();
        let verifier = Es256CoseVerifier::from_bytes(&wrong_signer.public_key_bytes()).unwrap();

        let mso = test_mso();
        let sign1 = sign_mso(&mso, &signer).unwrap();

        assert!(verify_issuer_auth(&sign1, &verifier).is_err());
    }

    #[test]
    fn es256_cose_cbor_roundtrip() {
        use coset::CborSerializable;

        let signer = Es256CoseSigner::generate();
        let verifier = Es256CoseVerifier::from_bytes(&signer.public_key_bytes()).unwrap();

        let mso = test_mso();
        let sign1 = sign_mso(&mso, &signer).unwrap();

        // Serialize to CBOR
        let bytes = sign1.to_vec().unwrap();

        // Deserialize
        let parsed = coset::CoseSign1::from_slice(&bytes).unwrap();

        // Verify
        let decoded = verify_issuer_auth(&parsed, &verifier).unwrap();
        assert_eq!(decoded.doc_type, "test.doctype");
    }
}
