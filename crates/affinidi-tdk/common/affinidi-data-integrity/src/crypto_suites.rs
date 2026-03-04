/*!
*   Recognized crypto suites
*/

use affinidi_secrets_resolver::secrets::{KeyType, Secret};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, ed25519::signature::SignerMut};
use serde::{Deserialize, Serialize};

use crate::DataIntegrityError;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub enum CryptoSuite {
    /// EDDSA JCS 2022 spec
    /// https://www.w3.org/TR/vc-di-eddsa/
    #[serde(rename = "eddsa-jcs-2022")]
    EddsaJcs2022,
    /// EDDSA RDFC 2022 spec
    /// https://www.w3.org/TR/vc-di-eddsa/
    #[serde(rename = "eddsa-rdfc-2022")]
    EddsaRdfc2022,
}

impl TryFrom<&str> for CryptoSuite {
    type Error = DataIntegrityError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "eddsa-jcs-2022" => Ok(CryptoSuite::EddsaJcs2022),
            "eddsa-rdfc-2022" => Ok(CryptoSuite::EddsaRdfc2022),
            _ => Err(DataIntegrityError::InputDataError(format!(
                "Unsupported crypto suite: {value}",
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
            CryptoSuite::EddsaRdfc2022 => Ok("eddsa-rdfc-2022".to_string()),
        }
    }
}

impl CryptoSuite {
    /// Validates that the given key type is compatible with this cryptosuite.
    pub fn validate_key_type(&self, key_type: KeyType) -> Result<(), DataIntegrityError> {
        match self {
            CryptoSuite::EddsaJcs2022 | CryptoSuite::EddsaRdfc2022 => match key_type {
                KeyType::Ed25519 => Ok(()),
                _ => Err(DataIntegrityError::InputDataError(format!(
                    "Unsupported key type {key_type:?} for cryptosuite {}",
                    String::try_from(*self).unwrap_or_default()
                ))),
            },
        }
    }

    pub fn sign(&self, secret: &Secret, data: &[u8]) -> Result<Vec<u8>, DataIntegrityError> {
        match self {
            CryptoSuite::EddsaJcs2022 | CryptoSuite::EddsaRdfc2022 => {
                let mut signing_key =
                    SigningKey::from_bytes(secret.get_private_bytes().try_into().unwrap());
                Ok(signing_key.sign(data).to_vec())
            }
        }
    }

    pub fn verify(
        &self,
        key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), DataIntegrityError> {
        match self {
            CryptoSuite::EddsaJcs2022 | CryptoSuite::EddsaRdfc2022 => {
                let verifying_key = VerifyingKey::try_from(key).map_err(|_| {
                    DataIntegrityError::CryptoError("Invalid public key bytes".to_string())
                })?;
                let signature = Signature::from_slice(signature).map_err(|_| {
                    DataIntegrityError::VerificationError("Invalid signature format".to_string())
                })?;
                Ok(verifying_key.verify_strict(data, &signature).map_err(|_| {
                    DataIntegrityError::VerificationError(
                        "Signature verification failed".to_string(),
                    )
                })?)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use affinidi_crypto::KeyType;

    use super::CryptoSuite;

    #[test]
    fn try_from_str_bad() {
        assert!(CryptoSuite::try_from("bad-suite").is_err());
    }

    #[test]
    fn try_from_string_bad() {
        assert!(CryptoSuite::try_from("bad-suite".to_string()).is_err());
    }

    #[test]
    fn try_from_str_good_jcs() {
        assert!(CryptoSuite::try_from("eddsa-jcs-2022").is_ok());
    }

    #[test]
    fn try_from_str_good_rdfc() {
        assert!(CryptoSuite::try_from("eddsa-rdfc-2022").is_ok());
    }

    #[test]
    fn try_from_string_good_jcs() {
        assert!(CryptoSuite::try_from("eddsa-jcs-2022".to_string()).is_ok());
    }

    #[test]
    fn try_from_string_good_rdfc() {
        assert!(CryptoSuite::try_from("eddsa-rdfc-2022".to_string()).is_ok());
    }

    #[test]
    fn try_from_cryptosuite_good_jcs() {
        assert!(String::try_from(CryptoSuite::EddsaJcs2022).is_ok());
    }

    #[test]
    fn try_from_cryptosuite_good_rdfc() {
        assert_eq!(
            String::try_from(CryptoSuite::EddsaRdfc2022).unwrap(),
            "eddsa-rdfc-2022"
        );
    }

    #[test]
    fn validate_key_type_ed25519_jcs() {
        assert!(
            CryptoSuite::EddsaJcs2022
                .validate_key_type(KeyType::Ed25519)
                .is_ok()
        );
    }

    #[test]
    fn validate_key_type_ed25519_rdfc() {
        assert!(
            CryptoSuite::EddsaRdfc2022
                .validate_key_type(KeyType::Ed25519)
                .is_ok()
        );
    }

    #[test]
    fn validate_key_type_bad() {
        assert!(
            CryptoSuite::EddsaJcs2022
                .validate_key_type(KeyType::P521)
                .is_err()
        );
        assert!(
            CryptoSuite::EddsaRdfc2022
                .validate_key_type(KeyType::P521)
                .is_err()
        );
    }
}
