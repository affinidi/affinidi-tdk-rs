/*!
 * mDL schema validation per ISO 18013-5 Table 5.
 *
 * Validates that an IssuerSigned mdoc contains all mandatory data elements
 * for the mDL document type.
 */

use crate::issuer_signed::IssuerSigned;
use crate::namespace::MDL_NAMESPACE;

/// ISO 18013-5 mandatory mDL data elements (Table 5).
pub const MANDATORY_MDL_FIELDS: &[&str] = &[
    "family_name",
    "given_name",
    "birth_date",
    "issue_date",
    "expiry_date",
    "issuing_country",
    "issuing_authority",
    "document_number",
    "portrait",
    "driving_privileges",
    "un_distinguishing_sign",
];

/// ISO 18013-5 optional mDL data elements (Table 5).
pub const OPTIONAL_MDL_FIELDS: &[&str] = &[
    "family_name_national_character",
    "given_name_national_character",
    "birth_place",
    "resident_address",
    "resident_city",
    "resident_state",
    "resident_postal_code",
    "resident_country",
    "portrait_capture_date",
    "age_in_years",
    "age_birth_year",
    "age_over_18",
    "age_over_21",
    "sex",
    "height",
    "weight",
    "eye_colour",
    "hair_colour",
    "nationality",
    "administrative_number",
];

/// mDL document type.
pub const MDL_DOC_TYPE: &str = "org.iso.18013.5.1.mDL";

/// mDL attribute name constants.
pub mod mdl_attributes {
    pub const FAMILY_NAME: &str = "family_name";
    pub const GIVEN_NAME: &str = "given_name";
    pub const BIRTH_DATE: &str = "birth_date";
    pub const ISSUE_DATE: &str = "issue_date";
    pub const EXPIRY_DATE: &str = "expiry_date";
    pub const ISSUING_COUNTRY: &str = "issuing_country";
    pub const ISSUING_AUTHORITY: &str = "issuing_authority";
    pub const DOCUMENT_NUMBER: &str = "document_number";
    pub const PORTRAIT: &str = "portrait";
    pub const DRIVING_PRIVILEGES: &str = "driving_privileges";
    pub const UN_DISTINGUISHING_SIGN: &str = "un_distinguishing_sign";
    pub const AGE_OVER_18: &str = "age_over_18";
    pub const AGE_OVER_21: &str = "age_over_21";
    pub const AGE_IN_YEARS: &str = "age_in_years";
    pub const AGE_BIRTH_YEAR: &str = "age_birth_year";
    pub const SEX: &str = "sex";
    pub const HEIGHT: &str = "height";
    pub const WEIGHT: &str = "weight";
    pub const NATIONALITY: &str = "nationality";
}

/// Result of mDL schema validation.
#[derive(Debug, Clone)]
pub struct MdlValidationReport {
    /// Whether the document passes validation (all mandatory fields present, correct docType).
    pub valid: bool,
    /// Mandatory fields that are missing.
    pub missing_mandatory: Vec<String>,
    /// Mandatory fields that are present.
    pub present_mandatory: Vec<String>,
    /// Optional (known) fields that are present.
    pub present_optional: Vec<String>,
    /// Fields not recognized as standard mDL fields.
    pub unknown_fields: Vec<String>,
}

/// Validate that an IssuerSigned mdoc conforms to the mDL schema.
///
/// Checks:
/// 1. `doc_type` is `"org.iso.18013.5.1.mDL"`
/// 2. All mandatory fields from ISO 18013-5 Table 5 are present in the mDL namespace
/// 3. Reports unknown fields (not in mandatory or optional lists)
pub fn validate_mdl(issuer_signed: &IssuerSigned) -> MdlValidationReport {
    let present_names = issuer_signed.attribute_names(MDL_NAMESPACE);

    let mut missing_mandatory = Vec::new();
    let mut present_mandatory = Vec::new();

    for &field in MANDATORY_MDL_FIELDS {
        if present_names.contains(&field) {
            present_mandatory.push(field.to_string());
        } else {
            missing_mandatory.push(field.to_string());
        }
    }

    let mut present_optional = Vec::new();
    let mut unknown_fields = Vec::new();

    for name in &present_names {
        if MANDATORY_MDL_FIELDS.contains(name) {
            // Already tracked
        } else if OPTIONAL_MDL_FIELDS.contains(name) {
            present_optional.push(name.to_string());
        } else {
            unknown_fields.push(name.to_string());
        }
    }

    let valid = issuer_signed.doc_type == MDL_DOC_TYPE && missing_mandatory.is_empty();

    MdlValidationReport {
        valid,
        missing_mandatory,
        present_mandatory,
        present_optional,
        unknown_fields,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::test_utils::TestSigner;
    use crate::issuer_signed::MdocBuilder;
    use crate::mso::ValidityInfo;

    fn test_validity() -> ValidityInfo {
        ValidityInfo {
            signed: "2024-01-01T00:00:00Z".to_string(),
            valid_from: "2024-01-01T00:00:00Z".to_string(),
            valid_until: "2025-01-01T00:00:00Z".to_string(),
        }
    }

    fn build_complete_mdl(signer: &TestSigner) -> IssuerSigned {
        MdocBuilder::new(MDL_DOC_TYPE)
            .validity(test_validity())
            .add_attribute(
                MDL_NAMESPACE,
                "family_name",
                ciborium::Value::Text("Doe".into()),
            )
            .add_attribute(
                MDL_NAMESPACE,
                "given_name",
                ciborium::Value::Text("John".into()),
            )
            .add_attribute(
                MDL_NAMESPACE,
                "birth_date",
                ciborium::Value::Text("1990-01-01".into()),
            )
            .add_attribute(
                MDL_NAMESPACE,
                "issue_date",
                ciborium::Value::Text("2024-01-01".into()),
            )
            .add_attribute(
                MDL_NAMESPACE,
                "expiry_date",
                ciborium::Value::Text("2029-01-01".into()),
            )
            .add_attribute(
                MDL_NAMESPACE,
                "issuing_country",
                ciborium::Value::Text("US".into()),
            )
            .add_attribute(
                MDL_NAMESPACE,
                "issuing_authority",
                ciborium::Value::Text("State DMV".into()),
            )
            .add_attribute(
                MDL_NAMESPACE,
                "document_number",
                ciborium::Value::Text("DL12345".into()),
            )
            .add_attribute(
                MDL_NAMESPACE,
                "portrait",
                ciborium::Value::Bytes(vec![0xFF, 0xD8]),
            )
            .add_attribute(
                MDL_NAMESPACE,
                "driving_privileges",
                ciborium::Value::Array(vec![]),
            )
            .add_attribute(
                MDL_NAMESPACE,
                "un_distinguishing_sign",
                ciborium::Value::Text("USA".into()),
            )
            .build(signer)
            .unwrap()
    }

    #[test]
    fn validate_complete_mdl() {
        let signer = TestSigner::new(b"test-signing-key-for-mdl-tests!");
        let mdoc = build_complete_mdl(&signer);
        let report = validate_mdl(&mdoc);

        assert!(report.valid);
        assert!(report.missing_mandatory.is_empty());
        assert_eq!(report.present_mandatory.len(), MANDATORY_MDL_FIELDS.len());
    }

    #[test]
    fn validate_incomplete_mdl() {
        let signer = TestSigner::new(b"test-signing-key-for-mdl-tests!");
        let mdoc = MdocBuilder::new(MDL_DOC_TYPE)
            .validity(test_validity())
            .add_attribute(
                MDL_NAMESPACE,
                "family_name",
                ciborium::Value::Text("Doe".into()),
            )
            .add_attribute(
                MDL_NAMESPACE,
                "given_name",
                ciborium::Value::Text("John".into()),
            )
            .build(&signer)
            .unwrap();

        let report = validate_mdl(&mdoc);
        assert!(!report.valid);
        assert!(report.missing_mandatory.contains(&"birth_date".to_string()));
        assert!(report.missing_mandatory.contains(&"portrait".to_string()));
        assert_eq!(report.present_mandatory.len(), 2);
    }

    #[test]
    fn validate_wrong_doc_type() {
        let signer = TestSigner::new(b"test-signing-key-for-mdl-tests!");
        // Build with PID doc type instead of mDL
        let mdoc = MdocBuilder::new("eu.europa.ec.eudi.pid.1")
            .validity(test_validity())
            .add_attribute(
                MDL_NAMESPACE,
                "family_name",
                ciborium::Value::Text("Doe".into()),
            )
            .build(&signer)
            .unwrap();

        let report = validate_mdl(&mdoc);
        assert!(!report.valid); // Wrong doc type
    }

    #[test]
    fn validate_with_optional_fields() {
        let signer = TestSigner::new(b"test-signing-key-for-mdl-tests!");
        let mdoc = MdocBuilder::new(MDL_DOC_TYPE)
            .validity(test_validity())
            .add_attribute(
                MDL_NAMESPACE,
                "family_name",
                ciborium::Value::Text("Doe".into()),
            )
            .add_attribute(
                MDL_NAMESPACE,
                "nationality",
                ciborium::Value::Text("US".into()),
            )
            .add_attribute(
                MDL_NAMESPACE,
                "height",
                ciborium::Value::Integer(180.into()),
            )
            .build(&signer)
            .unwrap();

        let report = validate_mdl(&mdoc);
        assert!(!report.valid); // Missing mandatory fields
        assert!(report.present_optional.contains(&"nationality".to_string()));
        assert!(report.present_optional.contains(&"height".to_string()));
    }

    #[test]
    fn validate_with_unknown_fields() {
        let signer = TestSigner::new(b"test-signing-key-for-mdl-tests!");
        let mdoc = MdocBuilder::new(MDL_DOC_TYPE)
            .validity(test_validity())
            .add_attribute(
                MDL_NAMESPACE,
                "family_name",
                ciborium::Value::Text("Doe".into()),
            )
            .add_attribute(
                MDL_NAMESPACE,
                "custom_field",
                ciborium::Value::Text("value".into()),
            )
            .build(&signer)
            .unwrap();

        let report = validate_mdl(&mdoc);
        assert!(report.unknown_fields.contains(&"custom_field".to_string()));
    }
}
