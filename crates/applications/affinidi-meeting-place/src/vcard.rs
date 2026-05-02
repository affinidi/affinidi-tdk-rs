/*!
 * Minimum vCard payload accepted by Meeting Place, modelled on RFC 6350.
 *
 * The Meeting Place API only consumes a small subset (name + one email +
 * one phone), and ships it as a base64-encoded JSON blob alongside the
 * registered offer. See [`Vcard::to_base64`].
 */

use crate::errors::{MeetingPlaceError, Result};
use base64::prelude::*;
use serde::{Deserialize, Serialize};

/// Minimal vCard payload.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Vcard {
    #[serde(rename = "n")]
    name: VcardName,
    email: Option<VcardType>,
    tel: Option<VcardType>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VcardName {
    surname: Option<String>,
    given: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcardType {
    #[serde(rename = "type")]
    pub kind: VcardTypes,
}

/// Tagged value: an enum carrying the contact-method label as the JSON tag
/// (`"work"` for email, `"cell"` for phone) and the value as the inner
/// string.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum VcardTypes {
    #[serde(rename = "work")]
    Work(String),
    #[serde(rename = "cell")]
    Cell(String),
}

impl Vcard {
    /// Build a new vCard. All four fields are optional.
    pub fn new(
        given: Option<String>,
        surname: Option<String>,
        email: Option<String>,
        tel: Option<String>,
    ) -> Self {
        Self {
            name: VcardName { surname, given },
            email: email.map(|e| VcardType {
                kind: VcardTypes::Work(e),
            }),
            tel: tel.map(|t| VcardType {
                kind: VcardTypes::Cell(t),
            }),
        }
    }

    /// Serialise to JSON and base64 (URL-safe, no padding) — the wire
    /// format Meeting Place expects in `RegisterOffer.vcard`.
    pub fn to_base64(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self).map_err(|e| {
            MeetingPlaceError::Serialization(format!("Couldn't serialise vcard: {e}"))
        })?;
        Ok(BASE64_URL_SAFE_NO_PAD.encode(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty() {
        let v = Vcard::default();
        assert!(v.name.given.is_none());
        assert!(v.name.surname.is_none());
        assert!(v.email.is_none());
        assert!(v.tel.is_none());
    }

    #[test]
    fn new_populates_provided_fields() {
        let v = Vcard::new(
            Some("Alice".to_string()),
            Some("Smith".to_string()),
            Some("alice@example.com".to_string()),
            Some("+15551234".to_string()),
        );
        assert_eq!(v.name.given.as_deref(), Some("Alice"));
        assert_eq!(v.name.surname.as_deref(), Some("Smith"));
        assert!(matches!(
            v.email.as_ref().unwrap().kind,
            VcardTypes::Work(ref s) if s == "alice@example.com"
        ));
        assert!(matches!(
            v.tel.as_ref().unwrap().kind,
            VcardTypes::Cell(ref s) if s == "+15551234"
        ));
    }

    #[test]
    fn to_base64_decodes_back_to_serializable_json() {
        let v = Vcard::new(Some("A".into()), None, None, None);
        let b64 = v.to_base64().unwrap();
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(b64.as_bytes()).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["n"]["given"], "A");
    }

    #[test]
    fn json_field_renames_match_wire_contract() {
        let v = Vcard::new(None, None, Some("e@x.com".into()), Some("+1".into()));
        let s = serde_json::to_string(&v).unwrap();
        // `n` not `name`; `email` and `tel` carry a `type` discriminator.
        assert!(s.contains("\"n\":"), "expected `n` field, got {s}");
        assert!(s.contains("\"type\":"), "expected `type` field, got {s}");
        assert!(s.contains("\"work\":"), "expected `work` tag, got {s}");
        assert!(s.contains("\"cell\":"), "expected `cell` tag, got {s}");
    }
}
