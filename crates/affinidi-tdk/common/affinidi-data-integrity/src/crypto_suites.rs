/*!
*   Recognized crypto suites
*/

use serde::{Deserialize, Serialize};

use crate::DataIntegrityError;

#[derive(Debug, Deserialize, Serialize)]
pub enum CryptoSuite {
    /// EDDSA JCS 2022 spec
    /// https://www.w3.org/TR/vc-di-eddsa/
    EddsaJcs2022,
}

impl TryFrom<&str> for CryptoSuite {
    type Error = DataIntegrityError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "EddsaJcs2022" => Ok(CryptoSuite::EddsaJcs2022),
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
            CryptoSuite::EddsaJcs2022 => Ok("EddsaJcs2022".to_string()),
        }
    }
}
