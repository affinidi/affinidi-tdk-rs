use crate::{
    errors::SecretsResolverError,
    jwk::{JWK, OctectParams, Params},
    multicodec::{ED25519_PUB, MultiEncoded, MultiEncodedBuf, X25519_PUB},
    secrets::{KeyType, Secret, SecretMaterial, SecretType},
};
use base58::{FromBase58, ToBase58};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

impl Secret {
    /// Creates a random ed25519 signing key pair
    /// kid: Key ID, if none specified then a random value is assigned
    pub fn generate_ed25519(kid: Option<&str>, seed: Option<&[u8; 32]>) -> Self {
        let mut csprng = OsRng;

        let signing_key = if let Some(seed) = seed {
            SigningKey::from_bytes(seed)
        } else {
            SigningKey::generate(&mut csprng)
        };

        let kid = if let Some(kid) = kid {
            kid.to_string()
        } else {
            BASE64_URL_SAFE_NO_PAD.encode(csprng.next_u64().to_ne_bytes())
        };

        Secret {
            id: kid,
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK(JWK {
                key_id: None,
                params: Params::OKP(OctectParams {
                    curve: "Ed25519".to_string(),
                    x: BASE64_URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
                    d: Some(BASE64_URL_SAFE_NO_PAD.encode(signing_key.to_bytes())),
                }),
            }),
            private_bytes: signing_key.to_bytes().to_vec(),
            public_bytes: signing_key.verifying_key().to_bytes().to_vec(),
            key_type: KeyType::Ed25519,
        }
    }

    /// Creates a random x25519 encryption key pair
    /// kid: Key ID, if none specified then a random value is assigned
    /// seed: Optional seed the x25519 key is derived from
    pub fn generate_x25519(
        kid: Option<&str>,
        seed: Option<&[u8; 32]>,
    ) -> Result<Self, SecretsResolverError> {
        let seed = if let Some(seed) = seed {
            *seed
        } else {
            let mut csprng = OsRng;
            let mut bytes: [u8; 32] = [0; 32];
            csprng.fill_bytes(&mut bytes);
            bytes
            // to_x25519(&Secret::generate_ed25519(kid, None).private_bytes)
        };

        let x25519 = StaticSecret::from(seed);
        let x25519_public: PublicKey = PublicKey::from(&x25519);

        Ok(Secret {
            id: kid.unwrap_or("x25519").to_string(),
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK(JWK {
                key_id: None,
                params: Params::OKP(OctectParams {
                    curve: "X25519".to_string(),
                    x: BASE64_URL_SAFE_NO_PAD.encode(x25519_public.as_bytes()),
                    d: Some(BASE64_URL_SAFE_NO_PAD.encode(x25519.as_bytes())),
                }),
            }),
            private_bytes: x25519.as_bytes().to_vec(),
            public_bytes: x25519_public.as_bytes().to_vec(),
            key_type: KeyType::X25519,
        })
    }

    /// Generates a Public JWK from a multikey value
    pub fn ed25519_public_jwk(data: &[u8]) -> Result<JWK, SecretsResolverError> {
        let params = OctectParams {
            curve: "Ed25519".to_string(),
            d: None,
            x: BASE64_URL_SAFE_NO_PAD.encode(data),
        };

        Ok(JWK {
            key_id: None,
            params: Params::OKP(params),
        })
    }

    /// Generates a Public JWK from a multikey value
    pub fn x25519_public_jwk(data: &[u8]) -> Result<JWK, SecretsResolverError> {
        let params = OctectParams {
            curve: "X25519".to_string(),
            d: None,
            x: BASE64_URL_SAFE_NO_PAD.encode(data),
        };

        Ok(JWK {
            key_id: None,
            params: Params::OKP(params),
        })
    }
}

/// Converts an ed25519 secret to a x25519 secret
pub fn ed25519_private_to_x25519_private_key(secret: &Vec<u8>) -> [u8; 32] {
    let mut bytes = Sha512::digest(secret);

    bytes[0] &= 0xF8;
    bytes[31] |= 0x80;
    bytes[31] &= 0x7F;

    let mut a: [u8; 32] = [0; 32]; // Initialize with zeros

    a.copy_from_slice(&bytes[0..32]);
    a
}

/// Converts a ed25519 multi_encoded public key to a x25519 multi_encoded key
/// Returns the multicodec String and the raw public bytes
pub fn ed25519_public_to_x25519_public_key(
    ed25519_public: &str,
) -> Result<(String, Vec<u8>), SecretsResolverError> {
    if !ed25519_public.starts_with('z') {
        return Err(SecretsResolverError::Decoding(
            "Expected multibase encoded string starting with a z prefix".to_string(),
        ));
    }

    let decoded = ed25519_public[1..]
        .from_base58()
        .map_err(|_| SecretsResolverError::Decoding("Couldn't decode base58".to_string()))?;

    let multicodec = MultiEncoded::new(decoded.as_slice())
        .map_err(|_| SecretsResolverError::Decoding("Unknown multicodec value".to_string()))?;

    if multicodec.codec() != ED25519_PUB {
        return Err(SecretsResolverError::KeyError(format!(
            "Expected ED25519 Public key, instead received {}",
            multicodec.codec()
        )));
    }
    if multicodec.data().len() != 32 {
        return Err(SecretsResolverError::KeyError(format!(
            "Invalid public key byte length. expected 32, instead have ({})",
            multicodec.data().len()
        )));
    }

    let vk = VerifyingKey::try_from(multicodec.data()).map_err(|e| {
        SecretsResolverError::KeyError(format!("Couldn't created ED25519 Verifying Key: {e}"))
    })?;

    let x25519 = vk.to_montgomery().to_bytes();

    Ok((
        [
            "z",
            &MultiEncodedBuf::encode_bytes(X25519_PUB, &x25519)
                .into_bytes()
                .to_base58(),
        ]
        .concat(),
        x25519.to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

    use crate::{crypto::ed25519::ed25519_private_to_x25519_private_key, secrets::Secret};

    const ED25519_SK: [u8; 32] = [
        202, 104, 239, 81, 53, 110, 80, 252, 198, 23, 155, 162, 215, 98, 223, 173, 227, 188, 110,
        54, 127, 45, 185, 206, 174, 29, 44, 147, 76, 66, 196, 195,
    ];
    const CURVE25519_SK: [u8; 32] = [
        200, 255, 64, 61, 17, 52, 112, 33, 205, 71, 186, 13, 131, 12, 241, 136, 223, 5, 152, 40,
        95, 187, 83, 168, 142, 10, 234, 215, 70, 210, 148, 104,
    ];

    #[test]
    fn check_ed25519_to_x25519_key_conversion() {
        assert_eq!(
            ed25519_private_to_x25519_private_key(&ED25519_SK.to_vec()),
            CURVE25519_SK
        );
    }

    #[test]
    fn check_x25519_from_seed() {
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode("_wYeKm00KWi8H861TsQLVkbAwWOVe0-T9n5Pa80VwTs")
            .unwrap();

        let mut a: [u8; 32] = [0; 32];
        a.copy_from_slice(&bytes[0..32]);

        let x25519 = Secret::generate_x25519(None, Some(&a)).unwrap();

        assert_eq!(
            x25519.get_public_bytes(),
            BASE64_URL_SAFE_NO_PAD
                .decode("ozI6dU2afJs4eyCXxs1FB-rNbn5UgPSHKHRNLRUlLnU")
                .unwrap()
        );
    }

    #[test]
    fn check_ed25519_from_seed() {
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode("X20biMbNG8QUQDnBv4RrZzkS3Civfc2zWHcDkeUeS9g")
            .unwrap();

        let mut a: [u8; 32] = [0; 32];
        a.copy_from_slice(&bytes[0..32]);

        let ed25519 = Secret::generate_ed25519(None, Some(&a));

        assert_eq!(
            ed25519.get_public_bytes(),
            BASE64_URL_SAFE_NO_PAD
                .decode("yb2ttOBWPH2qO-oTrFGs8mgw3cu0nCfjnPt-q9dag7E")
                .unwrap()
        );
    }
}
