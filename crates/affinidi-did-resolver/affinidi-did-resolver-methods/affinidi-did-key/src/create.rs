use affinidi_secrets_resolver::{
    errors::SecretsResolverError,
    secrets::{KeyType, Secret},
};

use crate::{DIDKey, errors::Error};

impl DIDKey {
    pub fn generate<'a>(key_type: KeyType) -> Result<(String, Secret), Error<'a>> {
        let mut secret = match key_type {
            KeyType::Ed25519 => Secret::generate_ed25519(None, None),
            KeyType::X25519 => Secret::generate_x25519(None, None)?,
            KeyType::P256 => Secret::generate_p256(None, None)?,
            KeyType::P384 => Secret::generate_p256(None, None)?,
            KeyType::Secp256k1 => Secret::generate_secp256k1(None, None)?,
            _ => {
                return Err(Error::GenerateError(
                    SecretsResolverError::UnsupportedKeyType(key_type.to_string()),
                ));
            }
        };

        secret.id = [
            "did:key:",
            &secret.get_public_keymultibase()?,
            "#",
            &secret.get_public_keymultibase()?,
        ]
        .concat();
        Ok((
            ["did:key:", &secret.get_public_keymultibase()?].concat(),
            secret,
        ))
    }
}

#[cfg(test)]
mod tests {
    use affinidi_secrets_resolver::{jwk::JWK, secrets::KeyType};

    use crate::DIDKey;

    #[test]
    fn check_generate() {
        let (did, secret) =
            DIDKey::generate(KeyType::P256).expect("COuldn't generate P256 DID Key");

        assert_eq!(
            [
                &did,
                "#",
                &secret
                    .get_public_keymultibase()
                    .expect("Couldn't get multibase key")
            ]
            .concat(),
            secret.id
        );

        assert!(JWK::from_multikey(did.trim_start_matches("did:key:")).is_ok());
    }
}
