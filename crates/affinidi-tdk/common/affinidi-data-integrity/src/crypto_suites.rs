/*!
*   Recognized crypto suites
*/

use affinidi_tdk_common::secrets_resolver::secrets::{KeyType, Secret};
use ed25519_dalek::{SigningKey, ed25519::signature::SignerMut};
use serde::{Deserialize, Serialize};

use crate::DataIntegrityError;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum CryptoSuite {
    /// EDDSA JCS 2022 spec
    /// https://www.w3.org/TR/vc-di-eddsa/
    #[serde(rename = "eddsa-jcs-2022")]
    EddsaJcs2022,
}

impl TryFrom<&str> for CryptoSuite {
    type Error = DataIntegrityError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "eddsa-jcs-2022" => Ok(CryptoSuite::EddsaJcs2022),
            _ => Err(DataIntegrityError::InputDataError(format!(
                "Unsupported crypto suite: {}",
                value
            ))),
        }
    }
}

impl TryFrom<String> for CryptoSuite {
    type Error = DataIntegrityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<CryptoSuite> for String {
    type Error = DataIntegrityError;

    fn try_from(value: CryptoSuite) -> Result<Self, Self::Error> {
        match value {
            CryptoSuite::EddsaJcs2022 => Ok("eddsa-jcs-2022".to_string()),
        }
    }
}

impl TryFrom<KeyType> for CryptoSuite {
    type Error = DataIntegrityError;

    fn try_from(value: KeyType) -> Result<Self, Self::Error> {
        match value {
            KeyType::Ed25519 => Ok(CryptoSuite::EddsaJcs2022),
            _ => Err(DataIntegrityError::InputDataError(format!(
                "Unsupported key type: {:?}",
                value
            ))),
        }
    }
}

impl CryptoSuite {
    pub fn sign(&self, secret: &Secret, data: &[u8]) -> Result<Vec<u8>, DataIntegrityError> {
        match self {
            CryptoSuite::EddsaJcs2022 => {
                let mut signing_key =
                    SigningKey::from_bytes(secret.get_private_bytes().try_into().unwrap());
                Ok(signing_key.sign(data).to_vec())
            }
        }
    }
}
