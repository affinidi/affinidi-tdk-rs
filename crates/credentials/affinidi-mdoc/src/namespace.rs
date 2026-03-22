/*!
 * mdoc namespace definitions.
 *
 * In ISO 18013-5, attributes are organized into namespaces.
 * Each namespace groups related attributes (e.g., PID attributes,
 * driving licence attributes).
 */

/// eIDAS PID namespace for Person Identification Data.
pub const EIDAS_PID_NAMESPACE: &str = "eu.europa.ec.eudi.pid.1";

/// ISO 18013-5 mDL namespace for mobile driving licences.
pub const MDL_NAMESPACE: &str = "org.iso.18013.5.1";

/// Standard eIDAS PID attribute names.
pub mod pid_attributes {
    pub const FAMILY_NAME: &str = "family_name";
    pub const GIVEN_NAME: &str = "given_name";
    pub const BIRTH_DATE: &str = "birth_date";
    pub const AGE_OVER_18: &str = "age_over_18";
    pub const AGE_IN_YEARS: &str = "age_in_years";
    pub const AGE_BIRTH_YEAR: &str = "age_birth_year";
    pub const FAMILY_NAME_BIRTH: &str = "family_name_birth";
    pub const GIVEN_NAME_BIRTH: &str = "given_name_birth";
    pub const BIRTH_PLACE: &str = "birth_place";
    pub const BIRTH_COUNTRY: &str = "birth_country";
    pub const BIRTH_STATE: &str = "birth_state";
    pub const BIRTH_CITY: &str = "birth_city";
    pub const RESIDENT_ADDRESS: &str = "resident_address";
    pub const RESIDENT_COUNTRY: &str = "resident_country";
    pub const RESIDENT_STATE: &str = "resident_state";
    pub const RESIDENT_CITY: &str = "resident_city";
    pub const RESIDENT_POSTAL_CODE: &str = "resident_postal_code";
    pub const RESIDENT_STREET: &str = "resident_street";
    pub const RESIDENT_HOUSE_NUMBER: &str = "resident_house_number";
    pub const GENDER: &str = "gender";
    pub const NATIONALITY: &str = "nationality";
    pub const ISSUANCE_DATE: &str = "issuance_date";
    pub const EXPIRY_DATE: &str = "expiry_date";
    pub const ISSUING_AUTHORITY: &str = "issuing_authority";
    pub const ISSUING_COUNTRY: &str = "issuing_country";
    pub const DOCUMENT_NUMBER: &str = "document_number";
}
