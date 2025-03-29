/*!
 * Meeting Place minimum vcard spec based on RFC 6350
 * https://www.rfc-editor.org/rfc/rfc6350
 */

use crate::errors::{MeetingPlaceError, Result};
use base64::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Vcard {
    #[serde(rename = "n")]
    name: VcardName,
    email: Option<VcardType>,
    tel: Option<VcardType>,
}

impl Default for Vcard {
    fn default() -> Self {
        Self {
            name: VcardName {
                surname: None,
                given: None,
            },
            email: None,
            tel: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VcardName {
    surname: Option<String>,
    given: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcardType {
    pub r#type: VcardTypes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum VcardTypes {
    #[serde(rename = "work")]
    Work(String),
    #[serde(rename = "cell")]
    Cell(String),
}

impl Vcard {
    /// Create a new Vcard
    /// # Arguments
    /// * `given` - Given name
    /// * `surname` - Surname
    /// * `email` - Email address
    /// * `tel` - Telephone number
    pub fn new(
        given: Option<String>,
        surname: Option<String>,
        email: Option<String>,
        tel: Option<String>,
    ) -> Self {
        Self {
            name: VcardName { surname, given },
            email: email.map(|e| VcardType {
                r#type: VcardTypes::Work(e),
            }),
            tel: tel.map(|t| VcardType {
                r#type: VcardTypes::Cell(t),
            }),
        }
    }

    /// Convert the Vcard to a base64 encoded string
    pub fn to_base64(&self) -> Result<String> {
        Ok(
            BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_string(self).map_err(|e| {
                MeetingPlaceError::Serialization(format!("Couldn't serialize vcard: {}", e))
            })?),
        )
    }
}
