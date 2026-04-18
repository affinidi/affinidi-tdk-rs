/*!
*   Recognized crypto suites
*/

use affinidi_secrets_resolver::secrets::KeyType;
use ed25519_dalek::{Signature, VerifyingKey};
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
    /// BBS 2023 spec — BBS signatures with zero-knowledge selective disclosure
    /// https://www.w3.org/TR/vc-di-bbs/
    #[cfg(feature = "bbs-2023")]
    #[serde(rename = "bbs-2023")]
    Bbs2023,
    /// ML-DSA-44 with JCS canonicalization — W3C `di-quantum-safe` v0.3 (experimental).
    #[cfg(feature = "ml-dsa")]
    #[serde(rename = "mldsa44-jcs-2024")]
    MlDsa44Jcs2024,
    /// ML-DSA-44 with RDFC canonicalization — W3C `di-quantum-safe` v0.3 (experimental).
    #[cfg(feature = "ml-dsa")]
    #[serde(rename = "mldsa44-rdfc-2024")]
    MlDsa44Rdfc2024,
    /// SLH-DSA-SHA2-128s with JCS canonicalization — W3C `di-quantum-safe` v0.3 (experimental).
    #[cfg(feature = "slh-dsa")]
    #[serde(rename = "slhdsa128-jcs-2024")]
    SlhDsa128Jcs2024,
    /// SLH-DSA-SHA2-128s with RDFC canonicalization — W3C `di-quantum-safe` v0.3 (experimental).
    #[cfg(feature = "slh-dsa")]
    #[serde(rename = "slhdsa128-rdfc-2024")]
    SlhDsa128Rdfc2024,
}

impl TryFrom<&str> for CryptoSuite {
    type Error = DataIntegrityError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "eddsa-jcs-2022" => Ok(CryptoSuite::EddsaJcs2022),
            "eddsa-rdfc-2022" => Ok(CryptoSuite::EddsaRdfc2022),
            #[cfg(feature = "bbs-2023")]
            "bbs-2023" => Ok(CryptoSuite::Bbs2023),
            #[cfg(feature = "ml-dsa")]
            "mldsa44-jcs-2024" => Ok(CryptoSuite::MlDsa44Jcs2024),
            #[cfg(feature = "ml-dsa")]
            "mldsa44-rdfc-2024" => Ok(CryptoSuite::MlDsa44Rdfc2024),
            #[cfg(feature = "slh-dsa")]
            "slhdsa128-jcs-2024" => Ok(CryptoSuite::SlhDsa128Jcs2024),
            #[cfg(feature = "slh-dsa")]
            "slhdsa128-rdfc-2024" => Ok(CryptoSuite::SlhDsa128Rdfc2024),
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
            #[cfg(feature = "bbs-2023")]
            CryptoSuite::Bbs2023 => Ok("bbs-2023".to_string()),
            #[cfg(feature = "ml-dsa")]
            CryptoSuite::MlDsa44Jcs2024 => Ok("mldsa44-jcs-2024".to_string()),
            #[cfg(feature = "ml-dsa")]
            CryptoSuite::MlDsa44Rdfc2024 => Ok("mldsa44-rdfc-2024".to_string()),
            #[cfg(feature = "slh-dsa")]
            CryptoSuite::SlhDsa128Jcs2024 => Ok("slhdsa128-jcs-2024".to_string()),
            #[cfg(feature = "slh-dsa")]
            CryptoSuite::SlhDsa128Rdfc2024 => Ok("slhdsa128-rdfc-2024".to_string()),
        }
    }
}

impl CryptoSuite {
    /// Validates that the given key type is compatible with this cryptosuite.
    pub fn validate_key_type(&self, key_type: KeyType) -> Result<(), DataIntegrityError> {
        let bad = |expected: &str| {
            DataIntegrityError::InputDataError(format!(
                "Unsupported key type {key_type:?} for cryptosuite {} (expected {expected})",
                String::try_from(*self).unwrap_or_default()
            ))
        };
        match self {
            CryptoSuite::EddsaJcs2022 | CryptoSuite::EddsaRdfc2022 => match key_type {
                KeyType::Ed25519 => Ok(()),
                _ => Err(bad("Ed25519")),
            },
            // BBS-2023 uses BLS12-381 keys, not traditional key types
            #[cfg(feature = "bbs-2023")]
            CryptoSuite::Bbs2023 => Ok(()),
            #[cfg(feature = "ml-dsa")]
            CryptoSuite::MlDsa44Jcs2024 | CryptoSuite::MlDsa44Rdfc2024 => match key_type {
                KeyType::MlDsa44 => Ok(()),
                _ => Err(bad("ML-DSA-44")),
            },
            #[cfg(feature = "slh-dsa")]
            CryptoSuite::SlhDsa128Jcs2024 | CryptoSuite::SlhDsa128Rdfc2024 => match key_type {
                KeyType::SlhDsaSha2_128s => Ok(()),
                _ => Err(bad("SLH-DSA-SHA2-128s")),
            },
        }
    }

    /// Returns `true` if this cryptosuite uses RDFC canonicalization,
    /// `false` for JCS.
    pub fn is_rdfc(&self) -> bool {
        match self {
            CryptoSuite::EddsaJcs2022 => false,
            CryptoSuite::EddsaRdfc2022 => true,
            #[cfg(feature = "bbs-2023")]
            CryptoSuite::Bbs2023 => false,
            #[cfg(feature = "ml-dsa")]
            CryptoSuite::MlDsa44Jcs2024 => false,
            #[cfg(feature = "ml-dsa")]
            CryptoSuite::MlDsa44Rdfc2024 => true,
            #[cfg(feature = "slh-dsa")]
            CryptoSuite::SlhDsa128Jcs2024 => false,
            #[cfg(feature = "slh-dsa")]
            CryptoSuite::SlhDsa128Rdfc2024 => true,
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
            // BBS-2023 verification is handled separately via the bbs_2023 module
            #[cfg(feature = "bbs-2023")]
            CryptoSuite::Bbs2023 => Err(DataIntegrityError::InputDataError(
                "BBS-2023 verification uses bbs_2023::verify_proof, not CryptoSuite::verify".into(),
            )),
            #[cfg(feature = "ml-dsa")]
            CryptoSuite::MlDsa44Jcs2024 | CryptoSuite::MlDsa44Rdfc2024 => {
                affinidi_crypto::ml_dsa::verify_ml_dsa_44(key, data, signature).map_err(|e| {
                    DataIntegrityError::VerificationError(format!(
                        "ML-DSA-44 verification failed: {e}"
                    ))
                })
            }
            #[cfg(feature = "slh-dsa")]
            CryptoSuite::SlhDsa128Jcs2024 | CryptoSuite::SlhDsa128Rdfc2024 => {
                affinidi_crypto::slh_dsa::verify_slh_dsa_sha2_128s(key, data, signature).map_err(
                    |e| {
                        DataIntegrityError::VerificationError(format!(
                            "SLH-DSA-SHA2-128s verification failed: {e}"
                        ))
                    },
                )
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
