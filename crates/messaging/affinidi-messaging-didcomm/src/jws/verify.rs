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

/// Shared JWS verification skeleton (General JSON Serialization): parse the
/// envelope, enforce the expected `alg` on the first signature's protected
/// header, reconstruct the signing input, and delegate the signature check to
/// `verify`. Only the first signature is verified (DIDComm envelopes are
/// single-signer). `alg_expected` names the accepted alg(s) in error messages.
fn verify_jws(
    jws_str: &str,
    alg_accepted: impl Fn(&str) -> bool,
    alg_expected: &str,
    verify: impl FnOnce(&[u8], &[u8; 64]) -> Result<(), DIDCommError>,
) -> Result<VerifiedJws, DIDCommError> {
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

    if !alg_accepted(&header.alg) {
        return Err(DIDCommError::UnsupportedAlgorithm(format!(
            "expected {alg_expected}, got {}",
            header.alg
        )));
    }

    // Decode signature (raw r || s for ECDSA, R || S for Ed25519 — 64 bytes
    // either way)
    let sig_bytes = Base64UrlUnpadded::decode_vec(&sig_entry.signature)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid signature base64: {e}")))?;
    let sig: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        DIDCommError::InvalidMessage(format!("{alg_expected} signature must be 64 bytes"))
    })?;

    // Reconstruct signing input
    let signing_input = format!("{}.{}", sig_entry.protected, jws.payload);
    verify(signing_input.as_bytes(), &sig)?;

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

/// Verify a JWS string using an Ed25519 public key.
///
/// Accepts either the polymorphic `EdDSA` alg (RFC 8037) or the fully-specified
/// `Ed25519` alg (draft-ietf-jose-fully-specified-algorithms) — both denote
/// Ed25519 signatures.
///
/// # Arguments
/// * `jws_str` - The JWS JSON string
/// * `public_key` - The signer's Ed25519 public key (32 bytes)
pub fn verify_ed25519(jws_str: &str, public_key: &[u8; 32]) -> Result<VerifiedJws, DIDCommError> {
    verify_jws(
        jws_str,
        |alg| alg == "EdDSA" || alg == "Ed25519",
        "EdDSA or Ed25519",
        |input, sig| signing::verify(input, sig, public_key).map_err(DIDCommError::from),
    )
}

/// Verify a JWS string using an ECDSA P-256 (ES256) public key.
///
/// # Arguments
/// * `jws_str` - The JWS JSON string
/// * `public_key` - The signer's SEC1-encoded P-256 public key (compressed 33 bytes or uncompressed 65 bytes)
pub fn verify_p256(jws_str: &str, public_key: &[u8]) -> Result<VerifiedJws, DIDCommError> {
    verify_jws(
        jws_str,
        |alg| alg == "ES256",
        "ES256",
        |input, sig| signing::verify_p256(input, sig, public_key).map_err(DIDCommError::from),
    )
}

/// Verify a JWS string using an ECDSA secp256k1 (ES256K) public key.
///
/// # Arguments
/// * `jws_str` - The JWS JSON string
/// * `public_key` - The signer's SEC1-encoded secp256k1 public key (compressed 33 bytes or uncompressed 65 bytes)
pub fn verify_secp256k1(jws_str: &str, public_key: &[u8]) -> Result<VerifiedJws, DIDCommError> {
    verify_jws(
        jws_str,
        |alg| alg == "ES256K",
        "ES256K",
        |input, sig| signing::verify_secp256k1(input, sig, public_key).map_err(DIDCommError::from),
    )
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

    /// A credo-ts / didcomm-python style JWS carries `kid` in the
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

    // ─── ES256 / ECDSA P-256 ────────────────────────────────────────────────
    use p256::ecdsa::{SigningKey as P256SigningKey, signature::Signer as _};

    /// Build an ES256 JWS (General JSON Serialization) over `payload`, placing
    /// `kid` in the protected header (or omitting it when `None`).
    fn build_es256_jws(payload: &[u8], kid: Option<&str>, sk: &P256SigningKey) -> String {
        let protected = JwsProtectedHeader {
            typ: Some("application/didcomm-signed+json".into()),
            alg: "ES256".into(),
            kid: kid.map(|k| k.to_string()),
            jwk: None,
        };
        let protected_b64 =
            Base64UrlUnpadded::encode_string(serde_json::to_string(&protected).unwrap().as_bytes());
        let payload_b64 = Base64UrlUnpadded::encode_string(payload);
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig: p256::ecdsa::Signature = sk.sign(signing_input.as_bytes());
        let sig_bytes: [u8; 64] = sig.to_bytes().into();
        let jws = Jws {
            payload: payload_b64,
            signatures: vec![JwsSignature {
                protected: protected_b64,
                header: None,
                signature: Base64UrlUnpadded::encode_string(&sig_bytes),
            }],
        };
        serde_json::to_string(&jws).unwrap()
    }

    fn p256_pub_sec1(sk: &P256SigningKey) -> Vec<u8> {
        sk.verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn es256_sign_verify_roundtrip() {
        let sk = P256SigningKey::random(&mut rand_core::OsRng);
        let payload = b"{\"type\":\"test\",\"body\":{}}";
        let jws_str = build_es256_jws(payload, Some("did:example:alice#p256-1"), &sk);

        let result = verify_p256(&jws_str, &p256_pub_sec1(&sk)).unwrap();
        assert_eq!(result.payload, payload);
        assert_eq!(
            result.signer_kid.as_deref(),
            Some("did:example:alice#p256-1")
        );
    }

    #[test]
    fn es256_wrong_key_fails() {
        let sk = P256SigningKey::random(&mut rand_core::OsRng);
        let other = P256SigningKey::random(&mut rand_core::OsRng);
        let jws_str = build_es256_jws(b"test", Some("did:example:alice#p256-1"), &sk);

        assert!(verify_p256(&jws_str, &p256_pub_sec1(&other)).is_err());
    }

    /// The ES256 verifier must reject a JWS that declares a different `alg`
    /// (here EdDSA) before touching the signature — guards against an
    /// algorithm-confusion attempt.
    #[test]
    fn es256_rejects_eddsa_alg() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let jws_str = sign::sign_ed25519(b"x", "did:example:alice#key-1", &sk.to_bytes()).unwrap();

        let dummy_pub = [0x04u8; 65];
        let result = verify_p256(&jws_str, &dummy_pub);
        assert!(matches!(result, Err(DIDCommError::UnsupportedAlgorithm(_))));
    }

    /// Symmetric guard: the Ed25519 verifier must reject an ES256 JWS.
    #[test]
    fn ed25519_rejects_es256_alg() {
        let sk = P256SigningKey::random(&mut rand_core::OsRng);
        let jws_str = build_es256_jws(b"x", Some("did:example:alice#p256-1"), &sk);

        let dummy_pub = [0u8; 32];
        let result = verify_ed25519(&jws_str, &dummy_pub);
        assert!(matches!(result, Err(DIDCommError::UnsupportedAlgorithm(_))));
    }

    /// ES256 counterpart of `signer_kid_from_unprotected_header`: when the
    /// signer `kid` lives only in the per-signature unprotected header, it
    /// must still be attributed.
    #[test]
    fn es256_signer_kid_from_unprotected_header() {
        let sk = P256SigningKey::random(&mut rand_core::OsRng);
        let payload = b"{\"type\":\"test\"}";

        let protected = JwsProtectedHeader {
            typ: Some("application/didcomm-signed+json".into()),
            alg: "ES256".into(),
            kid: None,
            jwk: None,
        };
        let protected_b64 =
            Base64UrlUnpadded::encode_string(serde_json::to_string(&protected).unwrap().as_bytes());
        let payload_b64 = Base64UrlUnpadded::encode_string(payload);
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig: p256::ecdsa::Signature = sk.sign(signing_input.as_bytes());
        let sig_bytes: [u8; 64] = sig.to_bytes().into();

        let jws = Jws {
            payload: payload_b64,
            signatures: vec![JwsSignature {
                protected: protected_b64,
                header: Some(JwsUnprotectedHeader {
                    kid: Some("did:example:alice#p256-1".into()),
                }),
                signature: Base64UrlUnpadded::encode_string(&sig_bytes),
            }],
        };
        let jws_str = serde_json::to_string(&jws).unwrap();

        let result = verify_p256(&jws_str, &p256_pub_sec1(&sk)).unwrap();
        assert_eq!(result.payload, payload);
        assert_eq!(
            result.signer_kid.as_deref(),
            Some("did:example:alice#p256-1")
        );
    }

    /// The fully-specified `Ed25519` alg
    /// (draft-ietf-jose-fully-specified-algorithms) must verify identically to
    /// the polymorphic `EdDSA`.
    #[test]
    fn ed25519_alg_accepted_alongside_eddsa() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pk = sk.verifying_key().to_bytes();
        let payload = b"{\"type\":\"test\"}";

        let protected = JwsProtectedHeader {
            typ: Some("application/didcomm-signed+json".into()),
            alg: "Ed25519".into(),
            kid: Some("did:example:alice#key-1".into()),
            jwk: None,
        };
        let protected_b64 =
            Base64UrlUnpadded::encode_string(serde_json::to_string(&protected).unwrap().as_bytes());
        let payload_b64 = Base64UrlUnpadded::encode_string(payload);
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig = signing::sign(signing_input.as_bytes(), &sk.to_bytes()).unwrap();

        let jws = Jws {
            payload: payload_b64,
            signatures: vec![JwsSignature {
                protected: protected_b64,
                header: None,
                signature: Base64UrlUnpadded::encode_string(&sig),
            }],
        };
        let jws_str = serde_json::to_string(&jws).unwrap();

        let result = verify_ed25519(&jws_str, &pk).unwrap();
        assert_eq!(result.payload, payload);
        assert_eq!(
            result.signer_kid.as_deref(),
            Some("did:example:alice#key-1")
        );
    }

    // ─── ES256K / ECDSA secp256k1 ───────────────────────────────────────────
    // `signature::Signer` is already in scope from the ES256 block above (both
    // curves re-export the same `signature` crate trait).
    use k256::ecdsa::SigningKey as K256SigningKey;

    /// Build an ES256K JWS (General JSON Serialization) over `payload`. `kid`
    /// is placed in the protected header when `Some`, otherwise omitted.
    fn build_es256k_jws(payload: &[u8], kid: Option<&str>, sk: &K256SigningKey) -> String {
        let protected = JwsProtectedHeader {
            typ: Some("application/didcomm-signed+json".into()),
            alg: "ES256K".into(),
            kid: kid.map(|k| k.to_string()),
            jwk: None,
        };
        let protected_b64 =
            Base64UrlUnpadded::encode_string(serde_json::to_string(&protected).unwrap().as_bytes());
        let payload_b64 = Base64UrlUnpadded::encode_string(payload);
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig: k256::ecdsa::Signature = sk.sign(signing_input.as_bytes());
        let sig_bytes: [u8; 64] = sig.to_bytes().into();
        let jws = Jws {
            payload: payload_b64,
            signatures: vec![JwsSignature {
                protected: protected_b64,
                header: None,
                signature: Base64UrlUnpadded::encode_string(&sig_bytes),
            }],
        };
        serde_json::to_string(&jws).unwrap()
    }

    fn k256_pub_sec1(sk: &K256SigningKey) -> Vec<u8> {
        sk.verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn es256k_sign_verify_roundtrip() {
        let sk = K256SigningKey::random(&mut rand_core::OsRng);
        let payload = b"{\"type\":\"test\",\"body\":{}}";
        let jws_str = build_es256k_jws(payload, Some("did:example:alice#k256-1"), &sk);

        let result = verify_secp256k1(&jws_str, &k256_pub_sec1(&sk)).unwrap();
        assert_eq!(result.payload, payload);
        assert_eq!(
            result.signer_kid.as_deref(),
            Some("did:example:alice#k256-1")
        );
    }

    #[test]
    fn es256k_wrong_key_fails() {
        let sk = K256SigningKey::random(&mut rand_core::OsRng);
        let other = K256SigningKey::random(&mut rand_core::OsRng);
        let jws_str = build_es256k_jws(b"test", Some("did:example:alice#k256-1"), &sk);

        assert!(verify_secp256k1(&jws_str, &k256_pub_sec1(&other)).is_err());
    }

    /// The ES256K verifier must reject a JWS that declares a different `alg`
    /// (here ES256) before touching the signature — guards against an
    /// algorithm-confusion attempt across the two ECDSA curves.
    #[test]
    fn es256k_rejects_es256_alg() {
        let sk = P256SigningKey::random(&mut rand_core::OsRng);
        let jws_str = build_es256_jws(b"x", Some("did:example:alice#p256-1"), &sk);

        let dummy_pub = [0x04u8; 65];
        let result = verify_secp256k1(&jws_str, &dummy_pub);
        assert!(matches!(result, Err(DIDCommError::UnsupportedAlgorithm(_))));
    }

    /// Symmetric guard: the ES256 verifier must reject an ES256K JWS.
    #[test]
    fn es256_rejects_es256k_alg() {
        let sk = K256SigningKey::random(&mut rand_core::OsRng);
        let jws_str = build_es256k_jws(b"x", Some("did:example:alice#k256-1"), &sk);

        let dummy_pub = [0x04u8; 65];
        let result = verify_p256(&jws_str, &dummy_pub);
        assert!(matches!(result, Err(DIDCommError::UnsupportedAlgorithm(_))));
    }

    /// ES256K counterpart of `es256_signer_kid_from_unprotected_header`: when
    /// the signer `kid` lives only in the per-signature unprotected header, it
    /// must still be attributed.
    #[test]
    fn es256k_signer_kid_from_unprotected_header() {
        let sk = K256SigningKey::random(&mut rand_core::OsRng);
        let payload = b"{\"type\":\"test\"}";

        let protected = JwsProtectedHeader {
            typ: Some("application/didcomm-signed+json".into()),
            alg: "ES256K".into(),
            kid: None,
            jwk: None,
        };
        let protected_b64 =
            Base64UrlUnpadded::encode_string(serde_json::to_string(&protected).unwrap().as_bytes());
        let payload_b64 = Base64UrlUnpadded::encode_string(payload);
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig: k256::ecdsa::Signature = sk.sign(signing_input.as_bytes());
        let sig_bytes: [u8; 64] = sig.to_bytes().into();

        let jws = Jws {
            payload: payload_b64,
            signatures: vec![JwsSignature {
                protected: protected_b64,
                header: Some(JwsUnprotectedHeader {
                    kid: Some("did:example:alice#k256-1".into()),
                }),
                signature: Base64UrlUnpadded::encode_string(&sig_bytes),
            }],
        };
        let jws_str = serde_json::to_string(&jws).unwrap();

        let result = verify_secp256k1(&jws_str, &k256_pub_sec1(&sk)).unwrap();
        assert_eq!(result.payload, payload);
        assert_eq!(
            result.signer_kid.as_deref(),
            Some("did:example:alice#k256-1")
        );
    }
}
