//! JWS signing — create DIDComm signed messages.

use base64ct::{Base64UrlUnpadded, Encoding};

use crate::error::DIDCommError;
use crate::jws::envelope::*;
use affinidi_crypto::jose::signing;

/// Sign a payload using Ed25519 (EdDSA), producing a JWS General JSON string.
///
/// # Arguments
/// * `payload` - The raw payload bytes (typically a serialized DIDComm message)
/// * `signer_kid` - The signer's key ID (DID URL)
/// * `private_key` - The signer's Ed25519 private key (32 bytes)
pub fn sign_ed25519(
    payload: &[u8],
    signer_kid: &str,
    private_key: &[u8; 32],
) -> Result<String, DIDCommError> {
    let header = JwsProtectedHeader {
        typ: Some("application/didcomm-signed+json".into()),
        alg: "EdDSA".into(),
        kid: Some(signer_kid.to_string()),
        jwk: None,
    };

    let header_json = serde_json::to_string(&header)
        .map_err(|e| DIDCommError::Serialization(format!("JWS header: {e}")))?;
    let header_b64 = Base64UrlUnpadded::encode_string(header_json.as_bytes());
    let payload_b64 = Base64UrlUnpadded::encode_string(payload);

    // JWS signing input: ASCII(BASE64URL(header) || '.' || BASE64URL(payload))
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = signing::sign(signing_input.as_bytes(), private_key)?;

    let jws = Jws {
        payload: payload_b64,
        signatures: vec![JwsSignature {
            protected: header_b64,
            // `kid` in BOTH headers: protected (integrity-protected; JOSE
            // key-selection best practice + spec §5.2.2) and unprotected
            // (what DIDComm test-vector verifiers read). Verify prefers the
            // protected copy, falling back to this one.
            header: Some(JwsUnprotectedHeader {
                kid: Some(signer_kid.to_string()),
            }),
            signature: Base64UrlUnpadded::encode_string(&sig),
        }],
    };

    serde_json::to_string(&jws).map_err(|e| DIDCommError::Serialization(format!("JWS: {e}")))
}

/// A signer for [`sign_multi`], tagging the private key with its curve so the
/// correct JWS `alg` and signature algorithm are used.
pub enum JwsSigner<'a> {
    /// Ed25519 (`alg: EdDSA`). 32-byte seed.
    Ed25519 { kid: &'a str, private: &'a [u8; 32] },
    /// ECDSA P-256 (`alg: ES256`). 32-byte scalar.
    P256 { kid: &'a str, private: &'a [u8; 32] },
    /// ECDSA secp256k1 (`alg: ES256K`). 32-byte scalar.
    Secp256k1 { kid: &'a str, private: &'a [u8; 32] },
}

/// Build one signature entry (protected header + signature) over
/// `BASE64URL(protected) || '.' || payload_b64`.
fn build_signature(
    payload_b64: &str,
    alg: &str,
    kid: &str,
    sign: impl FnOnce(&[u8]) -> Result<[u8; 64], DIDCommError>,
) -> Result<JwsSignature, DIDCommError> {
    let header = JwsProtectedHeader {
        typ: Some("application/didcomm-signed+json".into()),
        alg: alg.into(),
        kid: Some(kid.to_string()),
        jwk: None,
    };
    let header_json = serde_json::to_string(&header)
        .map_err(|e| DIDCommError::Serialization(format!("JWS header: {e}")))?;
    let header_b64 = Base64UrlUnpadded::encode_string(header_json.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = sign(signing_input.as_bytes())?;
    Ok(JwsSignature {
        protected: header_b64,
        // `kid` in both headers (see `sign_ed25519` for the rationale).
        header: Some(JwsUnprotectedHeader {
            kid: Some(kid.to_string()),
        }),
        signature: Base64UrlUnpadded::encode_string(&sig),
    })
}

fn sign_ecdsa_p256(input: &[u8], private: &[u8; 32]) -> Result<[u8; 64], DIDCommError> {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    let sk = SigningKey::from_slice(private)
        .map_err(|e| DIDCommError::Signing(format!("invalid P-256 signing key: {e}")))?;
    let sig: Signature = sk.sign(input);
    <[u8; 64]>::try_from(sig.to_bytes().as_slice())
        .map_err(|_| DIDCommError::Signing("P-256 signature not 64 bytes".into()))
}

fn sign_ecdsa_secp256k1(input: &[u8], private: &[u8; 32]) -> Result<[u8; 64], DIDCommError> {
    use k256::ecdsa::{Signature, SigningKey, signature::Signer};
    let sk = SigningKey::from_slice(private)
        .map_err(|e| DIDCommError::Signing(format!("invalid secp256k1 signing key: {e}")))?;
    let sig: Signature = sk.sign(input);
    <[u8; 64]>::try_from(sig.to_bytes().as_slice())
        .map_err(|_| DIDCommError::Signing("secp256k1 signature not 64 bytes".into()))
}

/// Sign a payload with one or more signers, producing a JWS General JSON
/// string carrying every signature over the same payload. Used to build
/// multi-signature DIDComm messages (each signer's `kid`/`alg` in its own
/// protected header).
pub fn sign_multi(payload: &[u8], signers: &[JwsSigner]) -> Result<String, DIDCommError> {
    if signers.is_empty() {
        return Err(DIDCommError::InvalidMessage(
            "at least one signer is required".into(),
        ));
    }
    let payload_b64 = Base64UrlUnpadded::encode_string(payload);
    let mut signatures = Vec::with_capacity(signers.len());
    for signer in signers {
        let entry = match signer {
            JwsSigner::Ed25519 { kid, private } => build_signature(&payload_b64, "EdDSA", kid, {
                let private = *private;
                move |input| signing::sign(input, private).map_err(DIDCommError::from)
            })?,
            JwsSigner::P256 { kid, private } => build_signature(&payload_b64, "ES256", kid, {
                let private = *private;
                move |input| sign_ecdsa_p256(input, private)
            })?,
            JwsSigner::Secp256k1 { kid, private } => {
                build_signature(&payload_b64, "ES256K", kid, {
                    let private = *private;
                    move |input| sign_ecdsa_secp256k1(input, private)
                })?
            }
        };
        signatures.push(entry);
    }
    let jws = Jws {
        payload: payload_b64,
        signatures,
    };
    serde_json::to_string(&jws).map_err(|e| DIDCommError::Serialization(format!("JWS: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_produces_valid_jws() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_10::rng());

        let jws_str = sign_ed25519(
            b"{\"type\":\"test\"}",
            "did:example:alice#key-1",
            &sk.to_bytes(),
        )
        .unwrap();

        let jws: Jws = serde_json::from_str(&jws_str).unwrap();
        assert_eq!(jws.signatures.len(), 1);

        // Verify header
        let header_json = Base64UrlUnpadded::decode_vec(&jws.signatures[0].protected).unwrap();
        let header: JwsProtectedHeader = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header.alg, "EdDSA");
        assert_eq!(header.kid.as_deref(), Some("did:example:alice#key-1"));

        // `kid` is also mirrored in the unprotected per-signature header so
        // DIDComm test-vector verifiers (which read only `header.kid`) can
        // attribute the signer.
        assert_eq!(
            jws.signatures[0]
                .header
                .as_ref()
                .and_then(|h| h.kid.as_deref()),
            Some("did:example:alice#key-1")
        );
    }

    #[test]
    fn sign_multi_emits_kid_in_both_headers() {
        use k256::ecdsa::SigningKey as K256SigningKey;
        use p256::ecdsa::SigningKey as P256SigningKey;

        // Every curve routes through `build_signature`, so EdDSA, ES256 and
        // ES256K signatures must all carry `kid` in both headers.
        let ed = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let p256 = P256SigningKey::random(&mut rand_core::OsRng);
        let k256 = K256SigningKey::random(&mut rand_core::OsRng);

        let jws_str = sign_multi(
            b"{\"type\":\"test\"}",
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

        let jws: Jws = serde_json::from_str(&jws_str).unwrap();
        assert_eq!(jws.signatures.len(), 3);

        for (sig, kid) in jws.signatures.iter().zip([
            "did:example:alice#ed",
            "did:example:alice#p256",
            "did:example:alice#k256",
        ]) {
            // Protected header carries kid (integrity-protected)...
            let header_json = Base64UrlUnpadded::decode_vec(&sig.protected).unwrap();
            let header: JwsProtectedHeader = serde_json::from_slice(&header_json).unwrap();
            assert_eq!(header.kid.as_deref(), Some(kid), "protected kid for {kid}");

            // ...and so does the unprotected header (for test-vector verifiers).
            assert_eq!(
                sig.header.as_ref().and_then(|h| h.kid.as_deref()),
                Some(kid),
                "unprotected kid for {kid}"
            );
        }
    }
}
