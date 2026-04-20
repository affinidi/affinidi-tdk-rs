//! Ed25519 and X25519 key operations

use affinidi_encoding::{ED25519_PUB, MultiEncoded, MultiEncodedBuf, X25519_PUB};
use base58::{FromBase58, ToBase58};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{CryptoError, JWK, KeyType, OctectParams, Params, error::Result};

/// Generated key pair with raw bytes and JWK representation
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub key_type: KeyType,
    pub private_bytes: Vec<u8>,
    pub public_bytes: Vec<u8>,
    pub jwk: JWK,
}

/// Generates a random Ed25519 signing key pair
pub fn generate(seed: Option<&[u8; 32]>) -> KeyPair {
    let signing_key = match seed {
        Some(seed) => SigningKey::from_bytes(seed),
        None => SigningKey::generate(&mut OsRng),
    };

    let private_bytes = signing_key.to_bytes().to_vec();
    let public_bytes = signing_key.verifying_key().to_bytes().to_vec();

    KeyPair {
        key_type: KeyType::Ed25519,
        private_bytes: private_bytes.clone(),
        public_bytes: public_bytes.clone(),
        jwk: JWK {
            key_id: None,
            params: Params::OKP(OctectParams {
                curve: "Ed25519".to_string(),
                x: BASE64_URL_SAFE_NO_PAD.encode(&public_bytes),
                d: Some(BASE64_URL_SAFE_NO_PAD.encode(&private_bytes)),
            }),
        },
    }
}

/// Generates a random X25519 encryption key pair
pub fn generate_x25519(seed: Option<&[u8; 32]>) -> KeyPair {
    let secret = match seed {
        Some(seed) => StaticSecret::from(*seed),
        None => {
            // Generate from random ed25519 key
            let ed_key = generate(None);
            let x_seed = ed25519_private_to_x25519(&ed_key.private_bytes[..32].try_into().unwrap());
            StaticSecret::from(x_seed)
        }
    };

    let public: PublicKey = PublicKey::from(&secret);
    let private_bytes = secret.to_bytes().to_vec();
    let public_bytes = public.to_bytes().to_vec();

    KeyPair {
        key_type: KeyType::X25519,
        private_bytes: private_bytes.clone(),
        public_bytes: public_bytes.clone(),
        jwk: JWK {
            key_id: None,
            params: Params::OKP(OctectParams {
                curve: "X25519".to_string(),
                x: BASE64_URL_SAFE_NO_PAD.encode(&public_bytes),
                d: Some(BASE64_URL_SAFE_NO_PAD.encode(&private_bytes)),
            }),
        },
    }
}

/// Converts an Ed25519 private key to an X25519 private key
pub fn ed25519_private_to_x25519(secret: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha512::digest(secret);

    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;

    let mut result = [0u8; 32];
    result.copy_from_slice(&h[..32]);
    result
}

/// Converts an Ed25519 multikey public key to an X25519 multikey public key
/// Returns the multicodec String and the raw public bytes
pub fn ed25519_public_to_x25519(ed25519_multikey: &str) -> Result<(String, Vec<u8>)> {
    if !ed25519_multikey.starts_with('z') {
        return Err(CryptoError::Decoding(
            "Expected multibase encoded string starting with 'z' prefix".into(),
        ));
    }

    let decoded = ed25519_multikey[1..]
        .from_base58()
        .map_err(|_| CryptoError::Decoding("Couldn't decode base58".into()))?;

    let multicodec = MultiEncoded::new(decoded.as_slice())?;

    if multicodec.codec() != ED25519_PUB {
        return Err(CryptoError::KeyError(format!(
            "Expected ED25519 public key, instead received codec 0x{:x}",
            multicodec.codec()
        )));
    }
    if multicodec.data().len() != 32 {
        return Err(CryptoError::KeyError(format!(
            "Invalid public key byte length: expected 32, got {}",
            multicodec.data().len()
        )));
    }

    let vk = VerifyingKey::try_from(multicodec.data())
        .map_err(|e| CryptoError::KeyError(format!("Couldn't create ED25519 VerifyingKey: {e}")))?;

    let x25519 = vk.to_montgomery().to_bytes();

    Ok((
        format!(
            "z{}",
            MultiEncodedBuf::encode_bytes(X25519_PUB, &x25519)
                .into_bytes()
                .to_base58()
        ),
        x25519.to_vec(),
    ))
}

/// Generates a public JWK from Ed25519 raw bytes
pub fn public_jwk(data: &[u8]) -> Result<JWK> {
    Ok(JWK {
        key_id: None,
        params: Params::OKP(OctectParams {
            curve: "Ed25519".to_string(),
            x: BASE64_URL_SAFE_NO_PAD.encode(data),
            d: None,
        }),
    })
}

/// Generates a public JWK from X25519 raw bytes
pub fn x25519_public_jwk(data: &[u8]) -> Result<JWK> {
    Ok(JWK {
        key_id: None,
        params: Params::OKP(OctectParams {
            curve: "X25519".to_string(),
            x: BASE64_URL_SAFE_NO_PAD.encode(data),
            d: None,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_SK: [u8; 32] = [
        202, 104, 239, 81, 53, 110, 80, 252, 198, 23, 155, 162, 215, 98, 223, 173, 227, 188, 110,
        54, 127, 45, 185, 206, 174, 29, 44, 147, 76, 66, 196, 195,
    ];
    const CURVE25519_SK: [u8; 32] = [
        200, 255, 64, 61, 17, 52, 112, 33, 205, 71, 186, 13, 131, 12, 241, 136, 223, 5, 152, 40,
        95, 187, 83, 168, 142, 10, 234, 215, 70, 210, 148, 104,
    ];

    #[test]
    fn ed25519_to_x25519_conversion() {
        assert_eq!(ed25519_private_to_x25519(&ED25519_SK), CURVE25519_SK);
    }

    #[test]
    fn generate_ed25519_from_seed() {
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode("X20biMbNG8QUQDnBv4RrZzkS3Civfc2zWHcDkeUeS9g")
            .unwrap();

        let mut seed: [u8; 32] = [0; 32];
        seed.copy_from_slice(&bytes[0..32]);

        let keypair = generate(Some(&seed));

        assert_eq!(
            keypair.public_bytes,
            BASE64_URL_SAFE_NO_PAD
                .decode("yb2ttOBWPH2qO-oTrFGs8mgw3cu0nCfjnPt-q9dag7E")
                .unwrap()
        );
    }

    #[test]
    fn generate_x25519_from_seed() {
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode("_wYeKm00KWi8H861TsQLVkbAwWOVe0-T9n5Pa80VwTs")
            .unwrap();

        let mut seed: [u8; 32] = [0; 32];
        seed.copy_from_slice(&bytes[0..32]);

        let keypair = generate_x25519(Some(&seed));

        assert_eq!(
            keypair.public_bytes,
            BASE64_URL_SAFE_NO_PAD
                .decode("ozI6dU2afJs4eyCXxs1FB-rNbn5UgPSHKHRNLRUlLnU")
                .unwrap()
        );
    }

    // Helper: encode an Ed25519 public key as a multikey string
    // (multicodec 0xed, base58btc with `z` prefix). Mirrors the encoding
    // expected by `ed25519_public_to_x25519` without pulling in `did_key`.
    fn ed25519_multikey(pubkey: &[u8]) -> String {
        format!(
            "z{}",
            MultiEncodedBuf::encode_bytes(ED25519_PUB, pubkey)
                .into_bytes()
                .to_base58()
        )
    }

    #[test]
    fn multikey_and_bytes_x25519_agree() {
        // The multikey-string `ed25519_public_to_x25519` and the bytes
        // `did_key::ed25519_pub_to_x25519_bytes` helpers must produce the
        // same X25519 public key for the same Ed25519 input.
        let kp = generate(None);
        let pub_bytes: [u8; 32] = kp.public_bytes.as_slice().try_into().unwrap();

        let (_, from_multikey) = ed25519_public_to_x25519(&ed25519_multikey(&pub_bytes)).unwrap();
        let from_bytes = crate::did_key::ed25519_pub_to_x25519_bytes(&pub_bytes).unwrap();

        assert_eq!(from_multikey.as_slice(), from_bytes.as_slice());
        assert_eq!(from_bytes.len(), 32);
    }

    #[test]
    fn ed25519_public_to_x25519_rejects_missing_z_prefix() {
        // Valid base58 payload but no multibase `z` prefix.
        let raw = MultiEncodedBuf::encode_bytes(ED25519_PUB, &[0u8; 32])
            .into_bytes()
            .to_base58();
        let err = ed25519_public_to_x25519(&raw).unwrap_err();
        assert!(
            matches!(err, CryptoError::Decoding(ref m) if m.contains('z')),
            "got {err:?}"
        );
    }

    #[test]
    fn ed25519_public_to_x25519_rejects_wrong_codec() {
        // X25519 multicodec (0xec) where Ed25519 (0xed) is expected.
        let multikey = format!(
            "z{}",
            MultiEncodedBuf::encode_bytes(X25519_PUB, &[0u8; 32])
                .into_bytes()
                .to_base58()
        );
        let err = ed25519_public_to_x25519(&multikey).unwrap_err();
        assert!(
            matches!(err, CryptoError::KeyError(ref m) if m.contains("codec")),
            "got {err:?}"
        );
    }

    #[test]
    fn ed25519_public_to_x25519_rejects_wrong_length() {
        // Ed25519 multicodec with a 16-byte payload.
        let multikey = ed25519_multikey(&[0u8; 16]);
        let err = ed25519_public_to_x25519(&multikey).unwrap_err();
        assert!(
            matches!(err, CryptoError::KeyError(ref m) if m.contains("length") || m.contains("32")),
            "got {err:?}"
        );
    }
}
