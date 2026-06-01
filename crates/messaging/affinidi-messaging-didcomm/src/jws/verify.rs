//! JWS verification — verify DIDComm signed messages.

use base64ct::{Base64UrlUnpadded, Encoding};

use crate::error::DIDCommError;
use crate::jws::envelope::*;
use affinidi_crypto::jose::signing;

/// Result of verifying a JWS.
pub struct VerifiedJws {
    /// The raw payload bytes.
    pub payload: Vec<u8>,
    /// The signer KID, taken from the protected header if present,
    /// otherwise from the per-signature unprotected header (issue #323).
    pub signer_kid: Option<String>,
}

/// Verify a JWS string using an Ed25519 public key.
///
/// # Arguments
/// * `jws_str` - The JWS JSON string
/// * `public_key` - The signer's Ed25519 public key (32 bytes)
pub fn verify_ed25519(jws_str: &str, public_key: &[u8; 32]) -> Result<VerifiedJws, DIDCommError> {
    let jws: Jws = serde_json::from_str(jws_str)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid JWS JSON: {e}")))?;

    if jws.signatures.is_empty() {
        return Err(DIDCommError::InvalidMessage("no signatures in JWS".into()));
    }

    // Verify the first signature
    let sig_entry = &jws.signatures[0];

    // Parse protected header
    let header_bytes = Base64UrlUnpadded::decode_vec(&sig_entry.protected)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid protected header: {e}")))?;
    let header: JwsProtectedHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid header JSON: {e}")))?;

    if header.alg != "EdDSA" {
        return Err(DIDCommError::UnsupportedAlgorithm(format!(
            "expected EdDSA, got {}",
            header.alg
        )));
    }

    // Decode signature
    let sig_bytes = Base64UrlUnpadded::decode_vec(&sig_entry.signature)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid signature base64: {e}")))?;
    let sig: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| DIDCommError::InvalidMessage("signature must be 64 bytes".into()))?;

    // Reconstruct signing input
    let signing_input = format!("{}.{}", sig_entry.protected, jws.payload);
    signing::verify(signing_input.as_bytes(), &sig, public_key)?;

    // Decode payload
    let payload = Base64UrlUnpadded::decode_vec(&jws.payload)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid payload base64: {e}")))?;

    // Signer kid: prefer the protected header, fall back to the
    // per-signature unprotected header (where DIDComm / credo-ts /
    // didcomm-python place it). Verification itself doesn't depend on
    // kid — the caller supplies the key — but attribution does.
    let signer_kid = header
        .kid
        .or_else(|| sig_entry.header.as_ref().and_then(|h| h.kid.clone()));

    Ok(VerifiedJws {
        payload,
        signer_kid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws::sign;

    #[test]
    fn sign_verify_roundtrip() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pk = sk.verifying_key().to_bytes();

        let payload = b"{\"type\":\"test\",\"body\":{}}";
        let jws_str =
            sign::sign_ed25519(payload, "did:example:alice#key-1", &sk.to_bytes()).unwrap();

        let result = verify_ed25519(&jws_str, &pk).unwrap();
        assert_eq!(result.payload, payload);
        assert_eq!(
            result.signer_kid.as_deref(),
            Some("did:example:alice#key-1")
        );
    }

    #[test]
    fn wrong_key_fails() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let wrong_pk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng)
            .verifying_key()
            .to_bytes();

        let jws_str =
            sign::sign_ed25519(b"test", "did:example:alice#key-1", &sk.to_bytes()).unwrap();

        assert!(verify_ed25519(&jws_str, &wrong_pk).is_err());
    }

    /// #323: a credo-ts / didcomm-python style JWS carries `kid` in the
    /// per-signature *unprotected* header (the protected header has only
    /// `typ`/`alg`). Verification must succeed AND attribute the signer
    /// from the unprotected header.
    #[test]
    fn signer_kid_from_unprotected_header() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pk = sk.verifying_key().to_bytes();
        let payload = b"{\"type\":\"test\",\"body\":{}}";

        // Protected header WITHOUT kid (only typ + alg).
        let protected = JwsProtectedHeader {
            typ: Some("application/didcomm-signed+json".into()),
            alg: "EdDSA".into(),
            kid: None,
            jwk: None,
        };
        let protected_b64 =
            Base64UrlUnpadded::encode_string(serde_json::to_string(&protected).unwrap().as_bytes());
        let payload_b64 = Base64UrlUnpadded::encode_string(payload);
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig =
            affinidi_crypto::jose::signing::sign(signing_input.as_bytes(), &sk.to_bytes()).unwrap();

        let jws = Jws {
            payload: payload_b64,
            signatures: vec![JwsSignature {
                protected: protected_b64,
                header: Some(JwsUnprotectedHeader {
                    kid: Some("did:example:alice#key-1".into()),
                }),
                signature: Base64UrlUnpadded::encode_string(&sig),
            }],
        };
        let jws_str = serde_json::to_string(&jws).unwrap();

        let result = verify_ed25519(&jws_str, &pk).unwrap();
        assert_eq!(result.payload, payload);
        assert_eq!(
            result.signer_kid.as_deref(),
            Some("did:example:alice#key-1"),
            "signer_kid must come from the unprotected header when absent from protected"
        );
    }

    /// When kid is present in BOTH headers, the protected one wins
    /// (it's integrity-protected).
    #[test]
    fn protected_kid_takes_precedence_over_unprotected() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pk = sk.verifying_key().to_bytes();

        // sign_ed25519 puts kid in the protected header.
        let jws_str =
            sign::sign_ed25519(b"x", "did:example:alice#protected", &sk.to_bytes()).unwrap();
        let mut jws: Jws = serde_json::from_str(&jws_str).unwrap();
        jws.signatures[0].header = Some(JwsUnprotectedHeader {
            kid: Some("did:example:mallory#unprotected".into()),
        });
        let jws_str = serde_json::to_string(&jws).unwrap();

        let result = verify_ed25519(&jws_str, &pk).unwrap();
        assert_eq!(
            result.signer_kid.as_deref(),
            Some("did:example:alice#protected")
        );
    }
}
