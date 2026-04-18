/*!
*   Recognized crypto suites
*/

use affinidi_secrets_resolver::secrets::KeyType;
use serde::{Deserialize, Serialize};

use crate::DataIntegrityError;
use crate::suite_ops::{self, Canonicalization, CryptoSuiteOps};

/// Supported Data Integrity cryptosuites.
///
/// This enum is `#[non_exhaustive]`: new cryptosuites (future W3C specs,
/// vendor extensions) are added in minor releases without breaking
/// downstream match-all arms. Always include a wildcard arm when matching.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[non_exhaustive]
pub enum CryptoSuite {
    /// EDDSA JCS 2022 spec
    ///
    /// <https://www.w3.org/TR/vc-di-eddsa/>
    #[serde(rename = "eddsa-jcs-2022")]
    EddsaJcs2022,
    /// EDDSA RDFC 2022 spec
    ///
    /// <https://www.w3.org/TR/vc-di-eddsa/>
    #[serde(rename = "eddsa-rdfc-2022")]
    EddsaRdfc2022,
    /// BBS 2023 spec — BBS signatures with zero-knowledge selective disclosure.
    ///
    /// <https://www.w3.org/TR/vc-di-bbs/>
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
            _ => Err(DataIntegrityError::UnsupportedCryptoSuite {
                name: value.to_string(),
            }),
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
        Ok(value.ops().name().to_string())
    }
}

impl std::fmt::Display for CryptoSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.ops().name())
    }
}

impl CryptoSuite {
    /// Returns the `CryptoSuiteOps` implementation for this variant.
    /// All enum methods delegate through this — adding a new cryptosuite
    /// is one impl in [`crate::suite_ops`] + one new arm here.
    pub fn ops(&self) -> &'static dyn CryptoSuiteOps {
        match self {
            CryptoSuite::EddsaJcs2022 => &suite_ops::EddsaJcs2022,
            CryptoSuite::EddsaRdfc2022 => &suite_ops::EddsaRdfc2022,
            #[cfg(feature = "bbs-2023")]
            CryptoSuite::Bbs2023 => &suite_ops::Bbs2023,
            #[cfg(feature = "ml-dsa")]
            CryptoSuite::MlDsa44Jcs2024 => &suite_ops::MlDsa44Jcs2024,
            #[cfg(feature = "ml-dsa")]
            CryptoSuite::MlDsa44Rdfc2024 => &suite_ops::MlDsa44Rdfc2024,
            #[cfg(feature = "slh-dsa")]
            CryptoSuite::SlhDsa128Jcs2024 => &suite_ops::SlhDsa128Jcs2024,
            #[cfg(feature = "slh-dsa")]
            CryptoSuite::SlhDsa128Rdfc2024 => &suite_ops::SlhDsa128Rdfc2024,
        }
    }

    /// Validates that the given key type is compatible with this cryptosuite.
    pub fn validate_key_type(&self, key_type: KeyType) -> Result<(), DataIntegrityError> {
        let compatible = self.ops().compatible_key_types();
        // Empty list = "any key type" (BBS-2023). Otherwise must match.
        if compatible.is_empty() || compatible.contains(&key_type) {
            Ok(())
        } else {
            Err(DataIntegrityError::KeyTypeMismatch {
                expected: compatible.first().copied().unwrap_or_default(),
                actual: key_type,
                suite: *self,
            })
        }
    }

    /// Returns the set of [`KeyType`] values compatible with this
    /// cryptosuite. Always non-empty except for BBS-2023, which uses
    /// BLS12-381 keys not modelled by [`KeyType`].
    ///
    /// Downstream code building key-generation flows or verification-method
    /// compatibility UI should use this instead of re-matching on the
    /// cryptosuite name.
    pub fn compatible_key_types(&self) -> &'static [KeyType] {
        self.ops().compatible_key_types()
    }

    /// Returns the recommended default cryptosuite for a given key type.
    ///
    /// Policy: prefer the **JCS** canonicalization variant where a choice
    /// exists — JCS produces smaller proofs, has no RDF canonicalization
    /// dependency, and is the W3C-recommended default for interop.
    /// Returns `None` if the key type has no compatible suite compiled in.
    pub fn default_for_key_type(key_type: KeyType) -> Option<Self> {
        match key_type {
            KeyType::Ed25519 => Some(CryptoSuite::EddsaJcs2022),
            #[cfg(feature = "ml-dsa")]
            KeyType::MlDsa44 => Some(CryptoSuite::MlDsa44Jcs2024),
            #[cfg(feature = "slh-dsa")]
            KeyType::SlhDsaSha2_128s => Some(CryptoSuite::SlhDsa128Jcs2024),
            _ => None,
        }
    }

    /// Returns `true` if this cryptosuite uses RDFC canonicalization,
    /// `false` for JCS or a custom scheme.
    pub fn is_rdfc(&self) -> bool {
        matches!(self.ops().canonicalization(), Canonicalization::Rdfc)
    }

    /// Verifies a signature against the data using this cryptosuite.
    pub fn verify(
        &self,
        key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), DataIntegrityError> {
        self.ops().verify(key, data, signature)
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
