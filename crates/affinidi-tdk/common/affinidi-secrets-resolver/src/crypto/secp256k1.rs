use affinidi_crypto::KeyType;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

use crate::{
    errors::SecretsResolverError,
    secrets::{Secret, SecretMaterial, SecretType},
};

impl Secret {
    /// Creates a secp256k1 key pair
    /// kid: Key ID, if none specified then a random value is assigned
    /// secret: Generate from secret bytes if known, otherwise random key is generated
    pub fn generate_secp256k1(
        kid: Option<&str>,
        secret: Option<&[u8]>,
    ) -> Result<Self, SecretsResolverError> {
        let keypair = affinidi_crypto::secp256k1::generate(secret)?;

        let kid = kid
            .map(|k| k.to_string())
            .unwrap_or_else(|| {
                use rand::{RngCore, rngs::OsRng};
                BASE64_URL_SAFE_NO_PAD.encode(OsRng.next_u64().to_ne_bytes())
            });

        Ok(Secret {
            id: kid,
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK(keypair.jwk.clone()),
            private_bytes: keypair.private_bytes,
            public_bytes: keypair.public_bytes,
            key_type: KeyType::Secp256k1,
        })
    }
}

#[cfg(test)]
mod tests {
    use affinidi_crypto::Params;
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

    use crate::secrets::{Secret, SecretMaterial};

    #[test]
    fn check_secp256k1_encoding() {
        let d = "mD9ssK9cdYw7hW9cT6rSSi67urjBz-7fce3Q6bAka-E";
        let x = "S_caroUAnHCypb9QTfWkCpB2Yx792O3uw_6eDNbGQLo";
        let y = "k-FA2c2UBoH4D_PWZ7LPiRDr5WPbahMi8duNOU1Lcdc";
        let secret_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(d)
            .expect("Couldn't decode secret bytes");

        let mut public_bytes: Vec<u8> = vec![4]; // Leading byte '4' denotes uncompressed
        public_bytes.append(&mut BASE64_URL_SAFE_NO_PAD.decode(x).expect("Couldn't decode X"));
        public_bytes.append(&mut BASE64_URL_SAFE_NO_PAD.decode(y).expect("Couldn't decode Y"));

        let secp256k1_secret = Secret::generate_secp256k1(None, Some(&secret_bytes))
            .expect("Couldn't create secp256k1 secret");

        if let SecretMaterial::JWK(jwk) = &secp256k1_secret.secret_material
            && let Params::EC(params) = &jwk.params
        {
            if let Some(params_d) = &params.d {
                assert_eq!(params_d, d);
            } else {
                panic!("No private key material for secp256k1 secret")
            }
            assert_eq!(params.x, x);
            assert_eq!(params.y, y);
        } else {
            panic!("No secret JWK");
        }

        assert_eq!(secp256k1_secret.private_bytes, secret_bytes);
        assert_eq!(secp256k1_secret.public_bytes, public_bytes);
    }
}
