/*!
 * ES384 (ECDSA P-384) COSE signer and verifier for mdoc.
 *
 * Production implementation of the `CoseSigner`/`CoseVerifier` traits
 * using P-384 ECDSA. P-384 provides a higher security level than P-256
 * and is recommended for higher-assurance eIDAS deployments.
 *
 * Enabled via the `es384` feature flag.
 *
 * # Algorithm Details
 *
 * - **COSE Algorithm**: ES384 (`-35`)
 * - **Curve**: P-384 (secp384r1)
 * - **Key size**: 48 bytes private, 97 bytes public (uncompressed)
 * - **Signature size**: 96 bytes (r || s, 48 bytes each)
 * - **Hash**: SHA-384
 */

use p384::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier};

use crate::cose::{CoseSigner, CoseVerifier};
use crate::error::{MdocError, Result};

/// ES384 COSE signer using a P-384 private key.
pub struct Es384CoseSigner {
    signing_key: SigningKey,
    x5chain: Option<Vec<Vec<u8>>>,
    kid: Option<Vec<u8>>,
}

impl Es384CoseSigner {
    /// Create a signer from raw P-384 private key bytes (48 bytes).
    pub fn from_bytes(private_key: &[u8]) -> Result<Self> {
        let signing_key = SigningKey::from_slice(private_key)
            .map_err(|e| MdocError::Cose(format!("invalid P-384 key: {e}")))?;
        Ok(Self {
            signing_key,
            x5chain: None,
            kid: None,
        })
    }

    /// Generate a new random P-384 key pair for signing.
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut p384::elliptic_curve::rand_core::OsRng);
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

    /// Get the public key as uncompressed SEC1 bytes (97 bytes).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        VerifyingKey::from(&self.signing_key)
            .to_encoded_point(false)
            .to_bytes()
            .to_vec()
    }
}

impl CoseSigner for Es384CoseSigner {
    fn algorithm(&self) -> coset::iana::Algorithm {
        coset::iana::Algorithm::ES384
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

/// ES384 COSE verifier using a P-384 public key.
pub struct Es384CoseVerifier {
    verifying_key: VerifyingKey,
}

impl Es384CoseVerifier {
    /// Create a verifier from uncompressed or compressed SEC1 public key bytes.
    pub fn from_bytes(public_key: &[u8]) -> Result<Self> {
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|e| MdocError::Cose(format!("invalid P-384 public key: {e}")))?;
        Ok(Self { verifying_key })
    }
}

impl CoseVerifier for Es384CoseVerifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let sig = Signature::from_slice(signature)
            .map_err(|e| MdocError::Cose(format!("invalid ES384 signature: {e}")))?;

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
            "SHA-384",
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
    fn es384_sign_and_verify() {
        let signer = Es384CoseSigner::generate();
        let verifier = Es384CoseVerifier::from_bytes(&signer.public_key_bytes()).unwrap();

        let mso = test_mso();
        let sign1 = sign_mso(&mso, &signer).unwrap();

        let decoded = verify_issuer_auth(&sign1, &verifier).unwrap();
        assert_eq!(decoded.doc_type, "test.doctype");
        assert_eq!(decoded.digest_algorithm, "SHA-384");
    }

    #[test]
    fn es384_wrong_key_fails() {
        let signer = Es384CoseSigner::generate();
        let wrong = Es384CoseSigner::generate();
        let verifier = Es384CoseVerifier::from_bytes(&wrong.public_key_bytes()).unwrap();

        let mso = test_mso();
        let sign1 = sign_mso(&mso, &signer).unwrap();

        assert!(verify_issuer_auth(&sign1, &verifier).is_err());
    }

    #[test]
    fn es384_cbor_roundtrip() {
        use coset::CborSerializable;

        let signer = Es384CoseSigner::generate();
        let verifier = Es384CoseVerifier::from_bytes(&signer.public_key_bytes()).unwrap();

        let mso = test_mso();
        let sign1 = sign_mso(&mso, &signer).unwrap();

        let bytes = sign1.to_vec().unwrap();
        let parsed = coset::CoseSign1::from_slice(&bytes).unwrap();

        let decoded = verify_issuer_auth(&parsed, &verifier).unwrap();
        assert_eq!(decoded.doc_type, "test.doctype");
    }

    #[test]
    fn es384_signature_is_96_bytes() {
        let signer = Es384CoseSigner::generate();
        let sig = signer.sign(b"test data").unwrap();
        assert_eq!(sig.len(), 96);
    }

    #[test]
    fn es384_public_key_is_97_bytes() {
        let signer = Es384CoseSigner::generate();
        let pk = signer.public_key_bytes();
        assert_eq!(pk.len(), 97); // 0x04 || x(48) || y(48)
    }

    #[test]
    fn es384_with_kid() {
        let signer = Es384CoseSigner::generate()
            .with_kid(b"key-id-384".to_vec());
        assert_eq!(signer.kid(), Some(b"key-id-384".to_vec()));
    }
}
