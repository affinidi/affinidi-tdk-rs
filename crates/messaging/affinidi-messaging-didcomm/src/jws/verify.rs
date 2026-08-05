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
    //
    // SECURITY: an unprotected-header kid is not integrity-protected; here it
    // only attributes an *already-verified* signature (the key was supplied by
    // the caller), so it can't steer verification. The riskier case — a kid read
    // *before* verification, to choose which DID to resolve — is in `parse_jws`;
    // see its `SECURITY` note.
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

/// A single signature entry parsed from a JWS but **not yet verified**.
///
/// The multi-signature flow ([`parse_jws`] + [`verify_parsed_signature`])
/// splits parsing from verification so an async caller (the SDK) can resolve
/// each signer's key from its DID document between the two steps. The legacy
/// single-signature helpers ([`verify_ed25519`] etc.) remain for callers that
/// already hold the key.
#[non_exhaustive]
pub struct ParsedSignature {
    /// Signer KID — protected header preferred, then the per-signature
    /// unprotected header (RFC 7515 §7.2.1, where DIDComm / credo-ts /
    /// didcomm-python place it). Attribution only; verification uses the
    /// caller-resolved key.
    pub kid: Option<String>,
    /// Whether [`Self::kid`] came from the **protected** (integrity-protected)
    /// header. `false` means it came from the per-signature *unprotected*
    /// header, i.e. it is attacker-controllable on an untrusted JWS and is read
    /// *before* verification.
    ///
    /// A caller that turns a `kid` into a **network** operation (resolving a
    /// `did:web` signer DID is an outbound HTTPS fetch) must branch on this: an
    /// unprotected `kid` lets an attacker choose the host that gets contacted —
    /// an SSRF vector — on a message that will ultimately fail verification
    /// anyway. `true` for a `kid` absent from both headers is meaningless, so
    /// this is `false` whenever `kid` is `None`.
    pub kid_from_protected: bool,
    /// JWS `alg` from this signature's protected header (`EdDSA`/`Ed25519`,
    /// `ES256`, or `ES256K`).
    pub alg: String,
    /// ASCII signing input: `BASE64URL(protected) || '.' || BASE64URL(payload)`.
    pub signing_input: Vec<u8>,
    /// Raw 64-byte signature (`R||S` for Ed25519, `r||s` for ECDSA).
    pub signature: [u8; 64],
}

/// A JWS parsed into its decoded payload plus every (unverified) signature.
pub struct ParsedJws {
    /// The decoded JWS payload bytes (the signed DIDComm message).
    pub payload: Vec<u8>,
    /// Every signature entry, in wire order.
    pub signatures: Vec<ParsedSignature>,
}

/// Resolved public-key material, tagged by curve family so
/// [`verify_parsed_signature`] can enforce that the key matches the
/// signature's `alg`.
pub enum VerifyKey {
    /// Ed25519 verifying key (32 octets).
    Ed25519([u8; 32]),
    /// SEC1-encoded P-256 verifying key (compressed 33 / uncompressed 65).
    P256(Vec<u8>),
    /// SEC1-encoded secp256k1 verifying key (compressed 33 / uncompressed 65).
    Secp256k1(Vec<u8>),
}

/// Parse a JWS (General JSON Serialization) into its payload and **all**
/// signature entries, without verifying any of them.
///
/// Unlike [`verify_jws`] (which only touches `signatures[0]`), this preserves
/// every signature so the caller can verify each one. Errors only on
/// structural / base64 problems; an empty `signatures` array is rejected.
pub fn parse_jws(jws_str: &str) -> Result<ParsedJws, DIDCommError> {
    let jws: Jws = serde_json::from_str(jws_str)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid JWS JSON: {e}")))?;

    if jws.signatures.is_empty() {
        return Err(DIDCommError::InvalidMessage("no signatures in JWS".into()));
    }

    let mut signatures = Vec::with_capacity(jws.signatures.len());
    for sig_entry in &jws.signatures {
        let header_bytes = Base64UrlUnpadded::decode_vec(&sig_entry.protected)
            .map_err(|e| DIDCommError::InvalidMessage(format!("invalid protected header: {e}")))?;
        let header: JwsProtectedHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| DIDCommError::InvalidMessage(format!("invalid header JSON: {e}")))?;

        let sig_bytes = Base64UrlUnpadded::decode_vec(&sig_entry.signature)
            .map_err(|e| DIDCommError::InvalidMessage(format!("invalid signature base64: {e}")))?;
        let signature: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| DIDCommError::InvalidMessage("signature must be 64 bytes".into()))?;

        // Signing input never includes the unprotected header (it is not
        // integrity-protected), so reconstruct from protected + payload only.
        let signing_input = format!("{}.{}", sig_entry.protected, jws.payload).into_bytes();

        // Signer kid: prefer the protected header, else fall back to the
        // per-signature *unprotected* header (interop with credo-ts /
        // didcomm-python, issue #323).
        //
        // SECURITY: a kid taken from the unprotected header is *not* covered by
        // the signature, and this kid is read *before* verification runs, so on
        // an untrusted JWS it names an attacker-chosen DID to resolve — an
        // outbound `did:web` fetch. Worse, because the unprotected header is
        // outside the signing input, *any intermediary* (a mediator, a relay)
        // can rewrite it in transit without invalidating the signature, so the
        // host contacted is not even the original sender's choice.
        //
        // Verification itself never trusts this kid (the caller supplies the
        // verifying key — only attribution uses it), but a caller that turns it
        // into a network operation MUST constrain it. `kid_from_protected`
        // below reports the provenance so the caller can: the SDK only resolves
        // an unprotected kid whose DID matches the signed payload's `from`,
        // which is inside the signing input and therefore not rewritable in
        // transit. See `verify_all_signatures` in `affinidi-messaging-sdk`.
        let kid_from_protected = header.kid.is_some();
        let kid = header
            .kid
            .or_else(|| sig_entry.header.as_ref().and_then(|h| h.kid.clone()));

        signatures.push(ParsedSignature {
            kid_from_protected: kid_from_protected && kid.is_some(),
            kid,
            alg: header.alg,
            signing_input,
            signature,
        });
    }

    let payload = Base64UrlUnpadded::decode_vec(&jws.payload)
        .map_err(|e| DIDCommError::InvalidMessage(format!("invalid payload base64: {e}")))?;

    Ok(ParsedJws {
        payload,
        signatures,
    })
}

/// Verify one [`ParsedSignature`] against resolved key material.
///
/// The key family must match the signature's `alg`
/// (`EdDSA`/`Ed25519` → [`VerifyKey::Ed25519`], `ES256` → [`VerifyKey::P256`],
/// `ES256K` → [`VerifyKey::Secp256k1`]); a mismatch is an error so a message
/// cannot smuggle a signature verified under an unexpected key type.
pub fn verify_parsed_signature(sig: &ParsedSignature, key: &VerifyKey) -> Result<(), DIDCommError> {
    match (sig.alg.as_str(), key) {
        ("EdDSA" | "Ed25519", VerifyKey::Ed25519(pk)) => {
            signing::verify(&sig.signing_input, &sig.signature, pk).map_err(DIDCommError::from)
        }
        ("ES256", VerifyKey::P256(pk)) => {
            signing::verify_p256(&sig.signing_input, &sig.signature, pk).map_err(DIDCommError::from)
        }
        ("ES256K", VerifyKey::Secp256k1(pk)) => {
            signing::verify_secp256k1(&sig.signing_input, &sig.signature, pk)
                .map_err(DIDCommError::from)
        }
        (alg, _) => Err(DIDCommError::UnsupportedAlgorithm(format!(
            "signature alg '{alg}' does not match the resolved key type"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws::sign;

    #[test]
    fn sign_verify_roundtrip() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_10::rng());
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
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_10::rng());
        let wrong_pk = ed25519_dalek::SigningKey::generate(&mut rand_10::rng())
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
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_10::rng());
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
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_10::rng());
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
    use p256::elliptic_curve::Generate as _;

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
        sk.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }

    #[test]
    fn es256_sign_verify_roundtrip() {
        let sk = P256SigningKey::generate();
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
        let sk = P256SigningKey::generate();
        let other = P256SigningKey::generate();
        let jws_str = build_es256_jws(b"test", Some("did:example:alice#p256-1"), &sk);

        assert!(verify_p256(&jws_str, &p256_pub_sec1(&other)).is_err());
    }

    /// The ES256 verifier must reject a JWS that declares a different `alg`
    /// (here EdDSA) before touching the signature — guards against an
    /// algorithm-confusion attempt.
    #[test]
    fn es256_rejects_eddsa_alg() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_10::rng());
        let jws_str = sign::sign_ed25519(b"x", "did:example:alice#key-1", &sk.to_bytes()).unwrap();

        let dummy_pub = [0x04u8; 65];
        let result = verify_p256(&jws_str, &dummy_pub);
        assert!(matches!(result, Err(DIDCommError::UnsupportedAlgorithm(_))));
    }

    /// Symmetric guard: the Ed25519 verifier must reject an ES256 JWS.
    #[test]
    fn ed25519_rejects_es256_alg() {
        let sk = P256SigningKey::generate();
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
        let sk = P256SigningKey::generate();
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
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_10::rng());
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
        sk.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }

    #[test]
    fn es256k_sign_verify_roundtrip() {
        let sk = K256SigningKey::generate();
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
        let sk = K256SigningKey::generate();
        let other = K256SigningKey::generate();
        let jws_str = build_es256k_jws(b"test", Some("did:example:alice#k256-1"), &sk);

        assert!(verify_secp256k1(&jws_str, &k256_pub_sec1(&other)).is_err());
    }

    /// The ES256K verifier must reject a JWS that declares a different `alg`
    /// (here ES256) before touching the signature — guards against an
    /// algorithm-confusion attempt across the two ECDSA curves.
    #[test]
    fn es256k_rejects_es256_alg() {
        let sk = P256SigningKey::generate();
        let jws_str = build_es256_jws(b"x", Some("did:example:alice#p256-1"), &sk);

        let dummy_pub = [0x04u8; 65];
        let result = verify_secp256k1(&jws_str, &dummy_pub);
        assert!(matches!(result, Err(DIDCommError::UnsupportedAlgorithm(_))));
    }

    /// Symmetric guard: the ES256 verifier must reject an ES256K JWS.
    #[test]
    fn es256_rejects_es256k_alg() {
        let sk = K256SigningKey::generate();
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
        let sk = K256SigningKey::generate();
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

    // ─── Multi-signature (parse_jws + verify_parsed_signature) ──────────────

    /// `kid_from_protected` reports the *provenance* of the signer kid, which
    /// callers rely on to decide whether the kid may steer a network operation:
    /// a protected kid is inside the signing input, an unprotected one can be
    /// rewritten in transit by any intermediary. `sign_multi` writes both, so
    /// the flag is `true`; strip the protected copy and it must flip to `false`.
    #[test]
    fn parse_jws_reports_kid_provenance() {
        use crate::jws::sign::{JwsSigner, sign_multi};
        use base64ct::{Base64UrlUnpadded, Encoding};

        let ed = ed25519_dalek::SigningKey::generate(&mut rand_10::rng());
        let jws_str = sign_multi(
            b"{\"from\":\"did:example:alice\"}",
            &[JwsSigner::Ed25519 {
                kid: "did:example:alice#key-1",
                private: &ed.to_bytes(),
            }],
        )
        .unwrap();

        let parsed = parse_jws(&jws_str).unwrap();
        assert_eq!(
            parsed.signatures[0].kid.as_deref(),
            Some("did:example:alice#key-1")
        );
        assert!(
            parsed.signatures[0].kid_from_protected,
            "sign_multi writes kid to the protected header, so provenance is protected"
        );

        // Remove the protected `kid`, leaving only the unprotected copy — the
        // in-transit rewrite an intermediary can perform.
        let mut v: serde_json::Value = serde_json::from_str(&jws_str).unwrap();
        let protected_b64 = v["signatures"][0]["protected"]
            .as_str()
            .unwrap()
            .to_string();
        let mut protected: serde_json::Value =
            serde_json::from_slice(&Base64UrlUnpadded::decode_vec(&protected_b64).unwrap())
                .unwrap();
        protected.as_object_mut().unwrap().remove("kid");
        v["signatures"][0]["protected"] = serde_json::Value::String(
            Base64UrlUnpadded::encode_string(&serde_json::to_vec(&protected).unwrap()),
        );
        let stripped = serde_json::to_string(&v).unwrap();

        let parsed = parse_jws(&stripped).unwrap();
        assert_eq!(
            parsed.signatures[0].kid.as_deref(),
            Some("did:example:alice#key-1"),
            "the unprotected header still supplies the kid (interop fallback)"
        );
        assert!(
            !parsed.signatures[0].kid_from_protected,
            "with no protected kid the provenance must be reported as unprotected"
        );
    }

    /// A JWS carrying three signatures over the same payload (Ed25519, P-256,
    /// secp256k1) parses into three entries, each of which verifies against
    /// its own resolved key with the correct `alg`/kid attribution.
    #[test]
    fn multi_signature_all_verify() {
        use crate::jws::sign::{JwsSigner, sign_multi};

        let ed = ed25519_dalek::SigningKey::generate(&mut rand_10::rng());
        let p256 = P256SigningKey::generate();
        let k256 = K256SigningKey::generate();

        let payload = b"{\"type\":\"test\",\"from\":\"did:example:alice\"}";
        let jws_str = sign_multi(
            payload,
            &[
                JwsSigner::Ed25519 {
                    kid: "did:example:alice#ed",
                    private: &ed.to_bytes(),
                },
                JwsSigner::P256 {
                    kid: "did:example:alice#p256",
                    private: &p256.to_bytes().into(),
                },
                JwsSigner::Secp256k1 {
                    kid: "did:example:alice#k256",
                    private: &k256.to_bytes().into(),
                },
            ],
        )
        .unwrap();

        let parsed = parse_jws(&jws_str).unwrap();
        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.signatures.len(), 3);

        let keys = [
            VerifyKey::Ed25519(ed.verifying_key().to_bytes()),
            VerifyKey::P256(p256_pub_sec1(&p256)),
            VerifyKey::Secp256k1(k256_pub_sec1(&k256)),
        ];
        for (sig, key) in parsed.signatures.iter().zip(keys.iter()) {
            verify_parsed_signature(sig, key).expect("each signature verifies");
        }

        let kids: Vec<_> = parsed
            .signatures
            .iter()
            .filter_map(|s| s.kid.clone())
            .collect();
        assert!(kids.contains(&"did:example:alice#ed".to_string()));
        assert!(kids.contains(&"did:example:alice#p256".to_string()));
        assert!(kids.contains(&"did:example:alice#k256".to_string()));
    }

    /// A signature whose resolved key family does not match its declared `alg`
    /// must be rejected (algorithm/key confusion guard for the multi-sig path).
    #[test]
    fn verify_parsed_rejects_key_type_mismatch() {
        use crate::jws::sign::{JwsSigner, sign_multi};

        let ed = ed25519_dalek::SigningKey::generate(&mut rand_10::rng());
        let jws_str = sign_multi(
            b"x",
            &[JwsSigner::Ed25519 {
                kid: "did:example:alice#ed",
                private: &ed.to_bytes(),
            }],
        )
        .unwrap();

        let parsed = parse_jws(&jws_str).unwrap();
        // Feed a P-256 key to an EdDSA signature.
        let wrong = VerifyKey::P256(vec![0x04u8; 65]);
        assert!(matches!(
            verify_parsed_signature(&parsed.signatures[0], &wrong),
            Err(DIDCommError::UnsupportedAlgorithm(_))
        ));
    }

    /// One bad signature in an otherwise-valid multi-sig JWS is detectable —
    /// the caller's strict "all must verify" policy relies on this.
    #[test]
    fn multi_signature_detects_one_bad() {
        use crate::jws::sign::{JwsSigner, sign_multi};

        let ed = ed25519_dalek::SigningKey::generate(&mut rand_10::rng());
        let p256 = P256SigningKey::generate();
        let other_p256 = P256SigningKey::generate();

        let jws_str = sign_multi(
            b"payload",
            &[
                JwsSigner::Ed25519 {
                    kid: "did:example:alice#ed",
                    private: &ed.to_bytes(),
                },
                JwsSigner::P256 {
                    kid: "did:example:alice#p256",
                    private: &p256.to_bytes().into(),
                },
            ],
        )
        .unwrap();

        let parsed = parse_jws(&jws_str).unwrap();
        // Ed25519 sig verifies, but the P-256 sig checked against the WRONG key fails.
        verify_parsed_signature(
            &parsed.signatures[0],
            &VerifyKey::Ed25519(ed.verifying_key().to_bytes()),
        )
        .expect("ed25519 ok");
        assert!(
            verify_parsed_signature(
                &parsed.signatures[1],
                &VerifyKey::P256(p256_pub_sec1(&other_p256))
            )
            .is_err(),
            "wrong P-256 key must fail"
        );
    }
}
