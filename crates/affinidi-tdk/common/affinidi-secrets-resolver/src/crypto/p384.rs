use affinidi_crypto::KeyType;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

use crate::{
    errors::SecretsResolverError,
    secrets::{Secret, SecretMaterial, SecretType},
};

impl Secret {
    /// Creates a p384 key pair
    /// kid: Key ID, if none specified then a random value is assigned
    /// secret: Generate from secret bytes if known, otherwise random key is generated
    pub fn generate_p384(
        kid: Option<&str>,
        secret: Option<&[u8]>,
    ) -> Result<Self, SecretsResolverError> {
        let keypair = affinidi_crypto::p384::generate(secret)?;

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
            key_type: KeyType::P384,
        })
    }
}

#[cfg(test)]
mod tests {
    use affinidi_crypto::Params;
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

    use crate::secrets::{Secret, SecretMaterial};

    #[test]
    fn check_p384_encoding() {
        let d = "sbb1acpuGPO2P3-aAchoUO5Ghs9Iyecm52HgcvVWR58Pmd-uvKZd-38OhCNCiaNd";
        let x = "zBTXJl2R0sjxCYxvq6_eQovQWTyZUlv5wMWV857GNvYT39h7AMCPCVRrH9l6qVfb";
        let y = "meSAqJ1ycBRzuA2FwKjHWDT6BaDufqxADi6GMSqbCTvZzb0qxgHKdXCXHcbl1EPv";

        let secret_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(d)
            .expect("Couldn't decode secret bytes");

        let mut public_bytes: Vec<u8> = vec![4]; // Leading byte '4' denotes uncompressed
        public_bytes.append(&mut BASE64_URL_SAFE_NO_PAD.decode(x).expect("Couldn't decode X"));
        public_bytes.append(&mut BASE64_URL_SAFE_NO_PAD.decode(y).expect("Couldn't decode Y"));

        let p384_secret =
            Secret::generate_p384(None, Some(&secret_bytes)).expect("Couldn't create P384 secret");

        if let SecretMaterial::JWK(jwk) = &p384_secret.secret_material
            && let Params::EC(params) = &jwk.params
        {
            if let Some(params_d) = &params.d {
                assert_eq!(params_d, d);
            } else {
                panic!("No private key material for P384 secret")
            }
            assert_eq!(params.x, x);
            assert_eq!(params.y, y);
        } else {
            panic!("No secret JWK");
        }

        assert_eq!(p384_secret.private_bytes, secret_bytes);
        assert_eq!(p384_secret.public_bytes, public_bytes);
    }
}
