/*!
 * COSE operations for mdoc signing and verification.
 *
 * Uses COSE_Sign1 (single signer) per ISO 18013-5.
 * The MSO is the detached payload of the COSE_Sign1 structure.
 */

use coset::{CoseSign1, CoseSign1Builder, HeaderBuilder};

use crate::error::{MdocError, Result};
use crate::mso::MobileSecurityObject;
use crate::tag24::Tag24;

/// Trait for signing COSE payloads.
///
/// Implementations can use local keys, HSM, or WSCD.
///
/// # Supported Algorithms
///
/// | Algorithm | COSE ID | Curve | Feature |
/// |-----------|---------|-------|---------|
/// | ES256 | -7 | P-256 | `es256` |
/// | ES384 | -35 | P-384 | `es384` |
/// | EdDSA | -8 | Ed25519 | `eddsa` |
pub trait CoseSigner: Send + Sync {
    /// The COSE algorithm identifier (e.g., -7 for ES256, -35 for ES384).
    fn algorithm(&self) -> coset::iana::Algorithm;

    /// Sign the data and return the raw signature bytes.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Optional X.509 certificate chain (DER-encoded).
    /// The first certificate is the signing certificate (Document Signer).
    fn x5chain(&self) -> Option<Vec<Vec<u8>>> {
        None
    }

    /// Optional key identifier (kid).
    /// Used to identify which key was used for signing.
    fn kid(&self) -> Option<Vec<u8>> {
        None
    }
}

/// Trait for verifying COSE signatures.
pub trait CoseVerifier: Send + Sync {
    /// Verify the signature over the data. Returns `Ok(true)` if valid.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool>;
}

/// Sign an MSO with COSE_Sign1, producing the `issuerAuth` structure.
///
/// Per ISO 18013-5, the MSO is Tag24-wrapped and used as the
/// payload of COSE_Sign1. The X.509 certificate chain (if provided)
/// is included in the unprotected header as `x5chain` (label 33).
pub fn sign_mso(mso: &MobileSecurityObject, signer: &dyn CoseSigner) -> Result<CoseSign1> {
    let mso_tagged = mso.to_tagged()?;
    let mso_bytes = mso_tagged.to_tagged_bytes()?;

    // Build protected header
    let protected = HeaderBuilder::new().algorithm(signer.algorithm()).build();

    // Build unprotected header with x5chain and kid if available
    let mut unprotected_builder = HeaderBuilder::new();
    if let Some(chain) = signer.x5chain() {
        if chain.len() == 1 {
            // Single cert: bstr
            unprotected_builder =
                unprotected_builder.value(33, coset::cbor::Value::Bytes(chain[0].clone()));
        } else if chain.len() > 1 {
            // Chain: array of bstr
            let certs: Vec<coset::cbor::Value> =
                chain.into_iter().map(coset::cbor::Value::Bytes).collect();
            unprotected_builder = unprotected_builder.value(33, coset::cbor::Value::Array(certs));
        }
    }
    if let Some(kid) = signer.kid() {
        unprotected_builder = unprotected_builder.key_id(kid);
    }
    let unprotected = unprotected_builder.build();

    // Build COSE_Sign1
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(mso_bytes)
        .try_create_signature(&[], |data| signer.sign(data))
        .map_err(|e| MdocError::Cose(format!("signing failed: {e}")))?
        .build();

    Ok(sign1)
}

/// Extract and verify the MSO from a COSE_Sign1 `issuerAuth`.
///
/// Returns the decoded MSO if the signature verification succeeds.
pub fn verify_issuer_auth(
    sign1: &CoseSign1,
    verifier: &dyn CoseVerifier,
) -> Result<MobileSecurityObject> {
    // Verify the signature
    // Note: coset passes (signature, tbs_data) — signature first, then data
    sign1
        .verify_signature(&[], |signature, tbs_data| {
            match verifier.verify(tbs_data, signature) {
                Ok(true) => Ok(()),
                Ok(false) => Err(MdocError::Cose("signature invalid".into())),
                Err(e) => Err(e),
            }
        })
        .map_err(|e| MdocError::Cose(format!("verification failed: {e}")))?;

    // Extract the MSO from the payload
    let payload = sign1
        .payload
        .as_ref()
        .ok_or_else(|| MdocError::Cose("COSE_Sign1 has no payload".into()))?;

    // Payload is Tag24<MSO> bytes — decode
    let tagged: Tag24<MobileSecurityObject> = ciborium::from_reader(&payload[..])
        .map_err(|e| MdocError::Cbor(format!("MSO decode: {e}")))?;

    Ok(tagged.inner)
}

/// Verify a COSE_Sign1 issuerAuth with algorithm verification.
///
/// Same as `verify_issuer_auth` but also checks that the algorithm
/// in the protected header matches the expected algorithm.
pub fn verify_issuer_auth_with_alg(
    sign1: &CoseSign1,
    verifier: &dyn CoseVerifier,
    expected_alg: coset::iana::Algorithm,
) -> Result<MobileSecurityObject> {
    // Check the algorithm in protected header
    let alg = &sign1.protected.header.alg;
    let expected = coset::RegisteredLabelWithPrivate::Assigned(expected_alg);
    if alg.as_ref() != Some(&expected) {
        return Err(MdocError::Cose(format!(
            "algorithm mismatch: expected {expected:?}, got {alg:?}"
        )));
    }

    verify_issuer_auth(sign1, verifier)
}

/// Extract the key ID (kid) from a COSE_Sign1 unprotected header.
pub fn extract_kid(sign1: &CoseSign1) -> Option<&[u8]> {
    let kid = &sign1.unprotected.key_id;
    if kid.is_empty() { None } else { Some(kid) }
}

/// Extract the algorithm from a COSE_Sign1 protected header.
pub fn extract_algorithm(
    sign1: &CoseSign1,
) -> Option<&coset::RegisteredLabelWithPrivate<coset::iana::Algorithm>> {
    sign1.protected.header.alg.as_ref()
}

#[cfg(any(test, feature = "_test-utils"))]
pub mod test_utils {
    use super::*;

    /// A test-only signer that produces a fixed "signature" (NOT cryptographically secure).
    ///
    /// For testing structure and encoding only. NOT for production.
    pub struct TestSigner {
        pub key: Vec<u8>,
    }

    impl TestSigner {
        pub fn new(key: &[u8]) -> Self {
            Self { key: key.to_vec() }
        }
    }

    impl CoseSigner for TestSigner {
        fn algorithm(&self) -> coset::iana::Algorithm {
            coset::iana::Algorithm::ES256
        }

        fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
            // Simple HMAC-like test signature (NOT real ECDSA)
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&self.key);
            hasher.update(data);
            // ES256 signature is 64 bytes (r || s)
            let hash = hasher.finalize();
            let mut sig = hash.to_vec();
            sig.extend_from_slice(&hash);
            Ok(sig)
        }
    }

    /// A test-only verifier matching TestSigner.
    pub struct TestVerifier {
        signer: TestSigner,
    }

    impl TestVerifier {
        pub fn new(key: &[u8]) -> Self {
            Self {
                signer: TestSigner::new(key),
            }
        }
    }

    impl CoseVerifier for TestVerifier {
        fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
            let expected = self.signer.sign(data)?;
            Ok(expected == signature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer_signed_item::IssuerSignedItem;
    use crate::mso::ValidityInfo;
    use coset::CborSerializable;
    use std::collections::BTreeMap;
    use test_utils::{TestSigner, TestVerifier};

    fn test_mso() -> MobileSecurityObject {
        let mut namespaces = BTreeMap::new();
        namespaces.insert(
            "test".to_string(),
            vec![
                IssuerSignedItem::new(0, "name", ciborium::Value::Text("Alice".into())),
                IssuerSignedItem::new(1, "age", ciborium::Value::Integer(30.into())),
            ],
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
    fn sign_and_verify_mso() {
        let key = b"test-signing-key-for-cose-tests!";
        let signer = TestSigner::new(key);
        let verifier = TestVerifier::new(key);

        let mso = test_mso();
        let sign1 = sign_mso(&mso, &signer).unwrap();

        // Payload should be present
        assert!(sign1.payload.is_some());

        // Verify
        let decoded_mso = verify_issuer_auth(&sign1, &verifier).unwrap();
        assert_eq!(decoded_mso.doc_type, "test.doctype");
        assert_eq!(decoded_mso.version, "1.0");
    }

    #[test]
    fn wrong_key_fails_verification() {
        let signer = TestSigner::new(b"correct-key-for-signing-test!!");
        let wrong_verifier = TestVerifier::new(b"wrong-key-should-fail-verify!!");

        let mso = test_mso();
        let sign1 = sign_mso(&mso, &signer).unwrap();

        let result = verify_issuer_auth(&sign1, &wrong_verifier);
        assert!(result.is_err());
    }

    #[test]
    fn cose_sign1_cbor_roundtrip() {
        let signer = TestSigner::new(b"roundtrip-key-for-cose-tests!!");
        let verifier = TestVerifier::new(b"roundtrip-key-for-cose-tests!!");

        let mso = test_mso();
        let sign1 = sign_mso(&mso, &signer).unwrap();

        // Serialize to CBOR
        let bytes = sign1.to_vec().unwrap();

        // Deserialize back
        let parsed = CoseSign1::from_slice(&bytes).unwrap();

        // Verify the deserialized structure
        let decoded = verify_issuer_auth(&parsed, &verifier).unwrap();
        assert_eq!(decoded.doc_type, "test.doctype");
    }

    #[test]
    fn protected_header_has_algorithm() {
        let signer = TestSigner::new(b"header-test-key-for-cose-algo!");

        let mso = test_mso();
        let sign1 = sign_mso(&mso, &signer).unwrap();

        let protected = sign1.protected.header;
        assert_eq!(
            protected.alg,
            Some(coset::RegisteredLabelWithPrivate::Assigned(
                coset::iana::Algorithm::ES256
            ))
        );
    }
}
