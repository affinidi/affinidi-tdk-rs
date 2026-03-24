//! JWS signing — create DIDComm signed messages.

use base64ct::{Base64UrlUnpadded, Encoding};

use crate::crypto::signing;
use crate::error::DIDCommError;
use crate::jws::envelope::*;

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
            signature: Base64UrlUnpadded::encode_string(&sig),
        }],
    };

    serde_json::to_string(&jws).map_err(|e| DIDCommError::Serialization(format!("JWS: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_produces_valid_jws() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

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
    }
}
