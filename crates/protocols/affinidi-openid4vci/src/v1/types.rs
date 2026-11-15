/*!
 * OpenID4VCI **1.0 Final** wire types.
 *
 * Every type cites the section of
 * [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * (Final, 16 September 2025) it models. Field names, optionality and nesting
 * follow the spec text; where the spec says "additional parameters MAY be
 * defined and used" the type carries an `additional` map so unknown members
 * survive a round trip (the spec requires the receiver to ignore them, not
 * reject them).
 */

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// Unrecognised members of an extensible JSON object.
pub type Additional = BTreeMap<String, Value>;

// ── String-valued enums with an open fallback ───────────────────────────────

/// Defines a string-valued wire enum whose unknown values deserialize into
/// `Other(String)` instead of failing (the spec registers these values in
/// IANA registries, so new ones appear without a spec revision).
macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident => $value:literal, )+
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )+
            /// A value this crate does not model, kept verbatim.
            Other(String),
        }

        impl $name {
            /// The wire string.
            pub fn as_str(&self) -> &str {
                match self {
                    $( Self::$variant => $value, )+
                    Self::Other(s) => s,
                }
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                match s {
                    $( $value => Self::$variant, )+
                    other => Self::Other(other.to_string()),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                String::deserialize(d).map(|s| Self::from(s.as_str()))
            }
        }
    };
}

// ── Identifiers and constants ───────────────────────────────────────────────

/// SD-JWT VC Credential Format Identifier (Appendix A.3.1). Draft 13 used
/// `vc+sd-jwt` ([`crate::types::FORMAT_SD_JWT_VC`]).
pub const FORMAT_DC_SD_JWT: &str = "dc+sd-jwt";
/// ISO mdoc Credential Format Identifier (Appendix A.2.1).
pub const FORMAT_MSO_MDOC: &str = "mso_mdoc";
/// W3C VC signed as a JWT, not using JSON-LD (Appendix A.1.1.1).
pub const FORMAT_JWT_VC_JSON: &str = "jwt_vc_json";
/// W3C VC secured with Data Integrity, using JSON-LD (Appendix A.1.2.1).
pub const FORMAT_LDP_VC: &str = "ldp_vc";
/// W3C VC signed as a JWT, using JSON-LD (Appendix A.1.3.1).
pub const FORMAT_JWT_VC_JSON_LD: &str = "jwt_vc_json-ld";

/// The Pre-Authorized Code grant type (§4.1.1, Appendix G.1.1).
pub const GRANT_TYPE_PRE_AUTHORIZED_CODE: &str =
    "urn:ietf:params:oauth:grant-type:pre-authorized_code";
/// The OAuth 2.0 authorization code grant type (§4.1.1, RFC 6749).
pub const GRANT_TYPE_AUTHORIZATION_CODE: &str = "authorization_code";

/// Authorization details type for credential issuance (§5.1.1).
pub const AUTHORIZATION_DETAILS_TYPE_OPENID_CREDENTIAL: &str = "openid_credential";

/// `jwt` proof type (Appendix F.1).
pub const PROOF_TYPE_JWT: &str = "jwt";
/// `di_vp` proof type (Appendix F.2).
pub const PROOF_TYPE_DI_VP: &str = "di_vp";
/// `attestation` proof type (Appendix F.3).
pub const PROOF_TYPE_ATTESTATION: &str = "attestation";

/// `typ` of a key attestation JWT (Appendix D.1).
pub const KEY_ATTESTATION_TYP: &str = "key-attestation+jwt";
/// `typ` of signed Credential Issuer Metadata (§12.2.3). Note the spec's
/// spelling: `openidvci`, not `openid4vci`.
pub const ISSUER_METADATA_JWT_TYP: &str = "openidvci-issuer-metadata+jwt";

/// Well-known path segment for Credential Issuer Metadata (§12.2.2).
pub const WELL_KNOWN_CREDENTIAL_ISSUER: &str = "/.well-known/openid-credential-issuer";
/// Custom URL scheme of the Wallet's Credential Offer Endpoint (§12.1.1).
pub const CREDENTIAL_OFFER_SCHEME: &str = "openid-credential-offer";

/// Maximum length of [`TxCode::description`] (§4.1.1).
pub const TX_CODE_DESCRIPTION_MAX_CHARS: usize = 300;

// ── Credential Issuer Metadata (§12.2.4) ────────────────────────────────────

/// Credential Issuer Metadata (§12.2.4).
///
/// Retrieved from the issuer's well-known location (§12.2.2; see
/// [`crate::v1::wallet::metadata_url`]). Draft 13's `batch_credential_endpoint`
/// is gone; `nonce_endpoint`, `notification_endpoint` and
/// `batch_credential_issuance` are new.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialIssuerMetadata {
    /// The Credential Issuer Identifier (§12.2.1). REQUIRED.
    pub credential_issuer: String,

    /// Identifiers of the OAuth 2.0 Authorization Servers the issuer relies
    /// on. OPTIONAL; absent means the issuer is its own AS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<Vec<String>>,

    /// URL of the Credential Endpoint (§8). REQUIRED.
    pub credential_endpoint: String,

    /// URL of the Nonce Endpoint (§7). OPTIONAL; absent means the issuer
    /// does not require `c_nonce`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<String>,

    /// URL of the Deferred Credential Endpoint (§9). OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deferred_credential_endpoint: Option<String>,

    /// URL of the Notification Endpoint (§11). OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_endpoint: Option<String>,

    /// Support for encrypted Credential Requests (§10). OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_request_encryption: Option<CredentialRequestEncryptionMetadata>,

    /// Support for encrypted Credential Responses (§10). OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryptionMetadata>,

    /// Batch issuance support (more than one key proof per request). OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_credential_issuance: Option<BatchCredentialIssuance>,

    /// Display properties of the issuer, one per language. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<IssuerDisplay>>,

    /// Supported Credential Configurations keyed by
    /// `credential_configuration_id`. REQUIRED.
    pub credential_configurations_supported: BTreeMap<String, CredentialConfiguration>,

    /// Additional metadata parameters.
    #[serde(flatten)]
    pub additional: Additional,
}

/// `credential_request_encryption` issuer metadata (§12.2.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialRequestEncryptionMetadata {
    /// Public keys for encrypting Credential Requests. REQUIRED.
    pub jwks: EncryptionJwks,
    /// Supported JWE `enc` values. REQUIRED, non-empty.
    pub enc_values_supported: Vec<String>,
    /// Supported JWE `zip` values. OPTIONAL; absent = no compression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zip_values_supported: Option<Vec<String>>,
    /// Whether every Credential Request must be encrypted. REQUIRED.
    pub encryption_required: bool,
}

/// The `jwks` member of [`CredentialRequestEncryptionMetadata`].
///
/// §12.2.4 says "a JSON Web Key Set, as defined in RFC 7591" (an object
/// `{"keys": [...]}`) but the spec's own example (Appendix I.1) is a bare
/// array of JWKs. Both shapes are accepted and re-serialized as received.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EncryptionJwks {
    /// A JWK Set object, `{"keys": [...]}`.
    Set {
        /// The keys.
        keys: Vec<Value>,
    },
    /// A bare array of JWKs (the form in the spec's Appendix I.1 example).
    List(Vec<Value>),
}

impl EncryptionJwks {
    /// The JWKs, whichever shape they arrived in.
    pub fn keys(&self) -> &[Value] {
        match self {
            Self::Set { keys } | Self::List(keys) => keys,
        }
    }
}

/// `credential_response_encryption` issuer metadata (§12.2.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialResponseEncryptionMetadata {
    /// Supported JWE `alg` values. REQUIRED, non-empty.
    pub alg_values_supported: Vec<String>,
    /// Supported JWE `enc` values. REQUIRED, non-empty.
    pub enc_values_supported: Vec<String>,
    /// Supported JWE `zip` values. OPTIONAL; absent = no compression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zip_values_supported: Option<Vec<String>>,
    /// Whether every Credential Response must be encrypted (and so every
    /// request must carry `credential_response_encryption`). REQUIRED.
    pub encryption_required: bool,
}

/// `batch_credential_issuance` issuer metadata (§12.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchCredentialIssuance {
    /// Maximum number of key proofs in one Credential Request. REQUIRED,
    /// MUST be 2 or greater.
    pub batch_size: u32,
}

/// Issuer `display` entry (§12.2.4).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IssuerDisplay {
    /// Display name of the issuer. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// BCP47 language tag. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Issuer logo. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<Logo>,
    /// Other display parameters (the list is non-exhaustive).
    #[serde(flatten)]
    pub additional: Additional,
}

/// A `logo` object (§12.2.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Logo {
    /// Where the Wallet can obtain the logo (`https:`, `data:`, …). REQUIRED.
    pub uri: String,
    /// Alternative text. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
    /// Other logo parameters.
    #[serde(flatten)]
    pub additional: Additional,
}

/// One entry of `credential_configurations_supported` (§12.2.4 plus the
/// format-specific members of Appendix A).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialConfiguration {
    /// Credential Format Identifier, e.g. [`FORMAT_DC_SD_JWT`]. REQUIRED.
    pub format: String,

    /// OAuth scope value for this configuration (§5.1.2). OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Algorithms the issuer signs this credential with. JOSE names for the
    /// JWT-based formats; numeric COSE identifiers for `mso_mdoc`
    /// (Appendix A.2.2), hence [`AlgorithmIdentifier`]. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_signing_alg_values_supported: Option<Vec<AlgorithmIdentifier>>,

    /// Key-binding representations (`jwk`, `cose_key`, `did:<method>`).
    /// OPTIONAL; present iff Cryptographic Key Binding is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,

    /// Supported key proof types keyed by proof type (Appendix F).
    /// OPTIONAL; when present, Credential Requests MUST carry `proofs` (§8.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_types_supported: Option<BTreeMap<String, ProofTypeMetadata>>,

    /// Display and claims metadata. OPTIONAL. (Draft 13 had `display` and
    /// `claims` directly on the configuration; 1.0 nests them here.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_metadata: Option<CredentialMetadata>,

    /// SD-JWT VC type (Appendix A.3.2). REQUIRED for [`FORMAT_DC_SD_JWT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,

    /// mdoc document type (Appendix A.2.2). REQUIRED for [`FORMAT_MSO_MDOC`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,

    /// W3C VC type description (Appendices A.1.1.2, A.1.2.2, A.1.3.2).
    /// REQUIRED for the W3C VC formats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_definition: Option<CredentialDefinition>,

    /// Other (format-specific or extension) parameters.
    #[serde(flatten)]
    pub additional: Additional,
}

/// A credential signing algorithm identifier: a JOSE/LD suite name or a
/// numeric COSE algorithm identifier (Appendix A.2.2, e.g. `-7`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AlgorithmIdentifier {
    /// A named algorithm (`ES256`, `Ed25519Signature2018`, …).
    Name(String),
    /// A numeric COSE algorithm identifier.
    Cose(i64),
}

/// Metadata for one proof type in `proof_types_supported` (§12.2.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofTypeMetadata {
    /// Algorithms the issuer accepts for this proof type. REQUIRED, non-empty.
    pub proof_signing_alg_values_supported: Vec<String>,
    /// Key attestation requirements (Appendix D). OPTIONAL; present (even
    /// empty) means a key attestation is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_attestations_required: Option<KeyAttestationsRequired>,
    /// Other parameters.
    #[serde(flatten)]
    pub additional: Additional,
}

/// `key_attestations_required` (§12.2.4, values from Appendix D.2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAttestationsRequired {
    /// Accepted key storage attack-potential-resistance levels. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_storage: Option<Vec<String>>,
    /// Accepted user authentication attack-potential-resistance levels.
    /// OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_authentication: Option<Vec<String>>,
}

/// `credential_metadata` of a Credential Configuration (§12.2.4).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CredentialMetadata {
    /// Display properties, one per language. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<CredentialDisplay>>,
    /// Claims description objects (Appendix B.2). OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimsDescription>>,
    /// Other parameters (the list is non-exhaustive).
    #[serde(flatten)]
    pub additional: Additional,
}

/// Credential `display` entry inside `credential_metadata` (§12.2.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialDisplay {
    /// Display name of the credential. REQUIRED.
    pub name: String,
    /// BCP47 language tag. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Credential logo. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo: Option<Logo>,
    /// Description of the credential. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// CSS background colour. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    /// Background image. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_image: Option<BackgroundImage>,
    /// CSS text colour. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
    /// Other display parameters.
    #[serde(flatten)]
    pub additional: Additional,
}

/// `background_image` of a [`CredentialDisplay`] (§12.2.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackgroundImage {
    /// Where the Wallet can obtain the image. REQUIRED.
    pub uri: String,
    /// Other parameters.
    #[serde(flatten)]
    pub additional: Additional,
}

/// A claims description object (Appendix B.1 for authorization details,
/// B.2 for issuer metadata; `display` is only meaningful in metadata).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimsDescription {
    /// Claims path pointer (Appendix C). REQUIRED, non-empty.
    pub path: Vec<ClaimPathElement>,
    /// Whether the claim is always included (B.2) / must be included (B.1).
    /// OPTIONAL, default `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mandatory: Option<bool>,
    /// Display properties of the claim per language (B.2). OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<ClaimDisplay>>,
    /// Other keys ("other keys MAY also be used").
    #[serde(flatten)]
    pub additional: Additional,
}

/// One element of a claims path pointer (Appendix C).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClaimPathElement {
    /// Select an object member by name.
    Name(String),
    /// Select an array element by (non-negative) index.
    Index(u64),
    /// `null`: select all elements of an array.
    All,
}

/// `display` entry of a [`ClaimsDescription`] (Appendix B.2).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClaimDisplay {
    /// Display name of the claim. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// BCP47 language tag. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Other parameters.
    #[serde(flatten)]
    pub additional: Additional,
}

/// `credential_definition` for the W3C VC formats (Appendix A.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialDefinition {
    /// JSON-LD `@context` — REQUIRED for `ldp_vc` / `jwt_vc_json-ld`
    /// (A.1.2.2), absent for `jwt_vc_json`.
    #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<Value>>,
    /// VC types. REQUIRED.
    #[serde(rename = "type")]
    pub types: Vec<String>,
    /// Other parameters.
    #[serde(flatten)]
    pub additional: Additional,
}

// ── Credential Offer (§4.1) ─────────────────────────────────────────────────

/// Credential Offer object (§4.1.1).
///
/// Sent by value in the `credential_offer` parameter or by reference via
/// `credential_offer_uri` (§4.1.2, §4.1.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialOffer {
    /// The Credential Issuer Identifier. REQUIRED.
    pub credential_issuer: String,
    /// Offered configuration ids (keys of
    /// `credential_configurations_supported`). REQUIRED, non-empty, unique.
    pub credential_configuration_ids: Vec<String>,
    /// Grant types the AS will accept for this offer. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<Grants>,
    /// Additional offer parameters.
    #[serde(flatten)]
    pub additional: Additional,
}

/// The `grants` object of a Credential Offer (§4.1.1).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Grants {
    /// `authorization_code` grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_code: Option<AuthorizationCodeGrant>,
    /// `urn:ietf:params:oauth:grant-type:pre-authorized_code` grant.
    #[serde(
        rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
    /// Other grant types.
    #[serde(flatten)]
    pub additional: Additional,
}

/// `authorization_code` grant parameters (§4.1.1).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationCodeGrant {
    /// Opaque value the Wallet echoes as `issuer_state` in the Authorization
    /// Request. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,
    /// Which of the metadata's `authorization_servers` to use. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}

/// Pre-Authorized Code grant parameters (§4.1.1).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PreAuthorizedCodeGrant {
    /// The short-lived, single-use Pre-Authorized Code. REQUIRED.
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    /// Present (even as `{}`) iff the Token Request must carry a Transaction
    /// Code. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<TxCode>,
    /// Which of the metadata's `authorization_servers` to use. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}

impl fmt::Debug for PreAuthorizedCodeGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The pre-authorized code is a bearer credential redeemable at the
        // token endpoint (§3.5) — never let it land in logs.
        f.debug_struct("PreAuthorizedCodeGrant")
            .field("pre_authorized_code", &"[REDACTED]")
            .field("tx_code", &self.tx_code)
            .field("authorization_server", &self.authorization_server)
            .finish()
    }
}

/// Transaction Code requirements (`tx_code` object, §4.1.1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxCode {
    /// Input character set. OPTIONAL, default [`TxCodeInputMode::Numeric`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_mode: Option<TxCodeInputMode>,
    /// Length of the code. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    /// Guidance on how to obtain the code; at most 300 characters. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl TxCode {
    /// The effective input mode (`numeric` when absent, §4.1.1).
    pub fn effective_input_mode(&self) -> TxCodeInputMode {
        self.input_mode.clone().unwrap_or(TxCodeInputMode::Numeric)
    }
}

string_enum! {
    /// `tx_code.input_mode` values (§4.1.1).
    pub enum TxCodeInputMode {
        /// Digits only (the default).
        Numeric => "numeric",
        /// Any characters.
        Text => "text",
    }
}

// ── Authorization details (§5.1.1, §6.2) ────────────────────────────────────

/// An RFC 9396 authorization details object of type `openid_credential`
/// (§5.1.1), as sent in the Authorization / Token Request and returned —
/// with `credential_identifiers` — in the Token Response (§6.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationDetail {
    /// Authorization details type; [`AUTHORIZATION_DETAILS_TYPE_OPENID_CREDENTIAL`].
    #[serde(rename = "type")]
    pub detail_type: String,
    /// The requested configuration. REQUIRED.
    pub credential_configuration_id: String,
    /// Requested claims (Appendix B.1). OPTIONAL, non-empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimsDescription>>,
    /// RFC 9396 `locations`; MUST name the Credential Issuer when the
    /// metadata lists `authorization_servers`. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<String>>,
    /// Token Response only (§6.2): the Credential Dataset identifiers the
    /// Wallet uses as `credential_identifier` in Credential Requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_identifiers: Option<Vec<String>>,
    /// Other data fields.
    #[serde(flatten)]
    pub additional: Additional,
}

impl AuthorizationDetail {
    /// An `openid_credential` authorization detail for one configuration.
    pub fn openid_credential(credential_configuration_id: impl Into<String>) -> Self {
        Self {
            detail_type: AUTHORIZATION_DETAILS_TYPE_OPENID_CREDENTIAL.to_string(),
            credential_configuration_id: credential_configuration_id.into(),
            claims: None,
            locations: None,
            credential_identifiers: None,
            additional: Additional::new(),
        }
    }
}

// ── Token Endpoint (§6) ─────────────────────────────────────────────────────

/// A Token Request (§6.1): RFC 6749 §4.1.3 plus the Pre-Authorized Code
/// extension parameters.
///
/// Token Requests are `application/x-www-form-urlencoded`, not JSON — use
/// [`TokenRequest::to_form_urlencoded`] / [`TokenRequest::from_form_urlencoded`].
/// `authorization_details` travels as a JSON-encoded form value.
#[derive(Clone, Default, PartialEq)]
pub struct TokenRequest {
    /// `grant_type`. REQUIRED.
    pub grant_type: String,
    /// `code` (authorization code grant).
    pub code: Option<String>,
    /// `redirect_uri` (authorization code grant).
    pub redirect_uri: Option<String>,
    /// `code_verifier` (PKCE, RFC 7636).
    pub code_verifier: Option<String>,
    /// `client_id`. OPTIONAL for the pre-authorized code grant (§6.1).
    pub client_id: Option<String>,
    /// `pre-authorized_code`. REQUIRED for the pre-authorized code grant.
    pub pre_authorized_code: Option<String>,
    /// `tx_code` — the Transaction Code value. REQUIRED iff the offer carried
    /// a `tx_code` object (even an empty one); only valid with the
    /// pre-authorized code grant.
    pub tx_code: Option<String>,
    /// `scope`.
    pub scope: Option<String>,
    /// `resource` (RFC 8707), RECOMMENDED with a credential `scope` when the
    /// issuer uses separate authorization servers.
    pub resource: Option<String>,
    /// `authorization_details` (§6.1.1), JSON-encoded on the wire.
    pub authorization_details: Option<Vec<AuthorizationDetail>>,
    /// Other parameters (client authentication assertions etc.).
    pub additional: BTreeMap<String, String>,
}

impl fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn redact(v: &Option<String>) -> Option<&'static str> {
            v.as_ref().map(|_| "[REDACTED]")
        }
        f.debug_struct("TokenRequest")
            .field("grant_type", &self.grant_type)
            .field("code", &redact(&self.code))
            .field("redirect_uri", &self.redirect_uri)
            .field("code_verifier", &redact(&self.code_verifier))
            .field("client_id", &self.client_id)
            .field("pre_authorized_code", &redact(&self.pre_authorized_code))
            .field("tx_code", &redact(&self.tx_code))
            .field("scope", &self.scope)
            .field("resource", &self.resource)
            .field("authorization_details", &self.authorization_details)
            .field(
                "additional",
                &self.additional.keys().collect::<Vec<&String>>(),
            )
            .finish()
    }
}

impl TokenRequest {
    /// Encode as an `application/x-www-form-urlencoded` body.
    pub fn to_form_urlencoded(&self) -> String {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", &self.grant_type);
        let optional = [
            ("code", &self.code),
            ("redirect_uri", &self.redirect_uri),
            ("code_verifier", &self.code_verifier),
            ("client_id", &self.client_id),
            ("pre-authorized_code", &self.pre_authorized_code),
            ("tx_code", &self.tx_code),
            ("scope", &self.scope),
            ("resource", &self.resource),
        ];
        for (name, value) in optional {
            if let Some(v) = value {
                form.append_pair(name, v);
            }
        }
        if let Some(details) = &self.authorization_details {
            // Serializing plain data structs to JSON cannot fail.
            let json = serde_json::to_string(details).unwrap_or_default();
            form.append_pair("authorization_details", &json);
        }
        for (name, value) in &self.additional {
            form.append_pair(name, value);
        }
        form.finish()
    }

    /// Decode an `application/x-www-form-urlencoded` body.
    ///
    /// Fails with `invalid_request` (RFC 6749 §5.2) when `grant_type` is
    /// missing, a parameter is repeated, or `authorization_details` is not a
    /// JSON array of authorization details.
    pub fn from_form_urlencoded(body: &str) -> Result<Self, TokenErrorResponse> {
        let invalid = |msg: String| {
            TokenErrorResponse::new(TokenErrorCode::InvalidRequest).with_description(msg)
        };
        let mut req = TokenRequest::default();
        let mut grant_type = None;
        let mut seen = std::collections::BTreeSet::new();
        for (name, value) in url::form_urlencoded::parse(body.as_bytes()) {
            if !seen.insert(name.to_string()) {
                return Err(invalid(format!("parameter `{name}` is repeated")));
            }
            let value = value.into_owned();
            match name.as_ref() {
                "grant_type" => grant_type = Some(value),
                "code" => req.code = Some(value),
                "redirect_uri" => req.redirect_uri = Some(value),
                "code_verifier" => req.code_verifier = Some(value),
                "client_id" => req.client_id = Some(value),
                "pre-authorized_code" => req.pre_authorized_code = Some(value),
                "tx_code" => req.tx_code = Some(value),
                "scope" => req.scope = Some(value),
                "resource" => req.resource = Some(value),
                "authorization_details" => {
                    let details = serde_json::from_str(&value)
                        .map_err(|e| invalid(format!("authorization_details is not valid: {e}")))?;
                    req.authorization_details = Some(details);
                }
                other => {
                    req.additional.insert(other.to_string(), value);
                }
            }
        }
        req.grant_type = grant_type.ok_or_else(|| invalid("grant_type is required".into()))?;
        Ok(req)
    }
}

/// A successful Token Response (§6.2, RFC 6749 §5.1).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token. REQUIRED.
    pub access_token: String,
    /// Token type, e.g. `Bearer` or `DPoP`. REQUIRED.
    pub token_type: String,
    /// Lifetime in seconds. RECOMMENDED.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// Refresh token. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Granted scope. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Authorized credentials with their `credential_identifiers` (§6.2).
    /// REQUIRED when `authorization_details` was used in the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<AuthorizationDetail>>,
    /// Other response parameters.
    #[serde(flatten)]
    pub additional: Additional,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("scope", &self.scope)
            .field("authorization_details", &self.authorization_details)
            .finish()
    }
}

// ── Nonce Endpoint (§7) ─────────────────────────────────────────────────────

/// Nonce Response (§7.2). The Nonce Request (§7.1) is an empty-bodied
/// `POST` to `nonce_endpoint`, so it has no type. Serve the response with
/// `Cache-Control: no-store`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceResponse {
    /// Fresh, unpredictable challenge for key proofs. REQUIRED.
    pub c_nonce: String,
}

// ── Credential Endpoint (§8) ────────────────────────────────────────────────

/// A Credential Request (§8.2).
///
/// Exactly one of `credential_identifier` (when the Token Response returned
/// `credential_identifiers`) or `credential_configuration_id` is present.
/// There is no `format` member any more (draft 13), and key proofs travel in
/// `proofs` (an array per proof type) rather than a single `proof`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// Credential Dataset identifier from the Token Response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_identifier: Option<String>,
    /// Key of `credential_configurations_supported`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_configuration_id: Option<String>,
    /// Key proofs. OPTIONAL in general, REQUIRED when the configuration lists
    /// `proof_types_supported`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proofs: Option<Proofs>,
    /// Response encryption parameters. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
    /// Additional request parameters.
    #[serde(flatten)]
    pub additional: Additional,
}

/// The `proofs` object of a Credential Request (§8.2, Appendix F).
///
/// The spec requires **exactly one** member, named after the proof type,
/// whose value is a non-empty array; [`Proofs::single`] checks that.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Proofs {
    /// `jwt` proofs (Appendix F.1): compact `openid4vci-proof+jwt` JWTs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<Vec<String>>,
    /// `di_vp` proofs (Appendix F.2): Data Integrity–secured W3C VPs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub di_vp: Option<Vec<Value>>,
    /// `attestation` proofs (Appendix F.3): exactly one key attestation JWT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<Vec<String>>,
    /// Other proof types (arrays of proofs).
    #[serde(flatten)]
    pub other: BTreeMap<String, Vec<Value>>,
}

impl Proofs {
    /// `jwt` proofs.
    pub fn jwt(jwts: Vec<String>) -> Self {
        Self {
            jwt: Some(jwts),
            ..Self::default()
        }
    }

    /// `attestation` proof (a single key attestation JWT, Appendix F.3).
    pub fn attestation(key_attestation_jwt: String) -> Self {
        Self {
            attestation: Some(vec![key_attestation_jwt]),
            ..Self::default()
        }
    }

    /// The single proof type present and its number of proofs, or `None`
    /// when zero or several proof types are present.
    pub fn single(&self) -> Option<(&str, usize)> {
        let mut present = Vec::with_capacity(1);
        if let Some(v) = &self.jwt {
            present.push((PROOF_TYPE_JWT, v.len()));
        }
        if let Some(v) = &self.di_vp {
            present.push((PROOF_TYPE_DI_VP, v.len()));
        }
        if let Some(v) = &self.attestation {
            present.push((PROOF_TYPE_ATTESTATION, v.len()));
        }
        for (k, v) in &self.other {
            present.push((k.as_str(), v.len()));
        }
        match present.as_slice() {
            [one] => Some(*one),
            _ => None,
        }
    }
}

/// `credential_response_encryption` request parameter (§8.2, also used by
/// the Deferred Credential Request, §9.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialResponseEncryption {
    /// Public JWK to encrypt the response to; carries `alg` (§10). REQUIRED.
    pub jwk: Value,
    /// JWE `enc` algorithm. REQUIRED.
    pub enc: String,
    /// JWE `zip` algorithm. OPTIONAL; absent = no compression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zip: Option<String>,
}

/// A Credential Response (§8.3), also the Deferred Credential Response
/// (§9.2).
///
/// Immediate issuance (HTTP 200): `credentials` (+ optional
/// `notification_id`). Deferred (HTTP 202): `transaction_id` + `interval`.
/// [`CredentialResponse::check`] enforces the exclusivity rules. There is no
/// `c_nonce` any more — nonces come from the Nonce Endpoint (§7).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CredentialResponse {
    /// The issued credentials (one per accepted key proof). OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<IssuedCredential>>,
    /// Deferred issuance transaction. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    /// Minimum seconds to wait before polling the Deferred Credential
    /// Endpoint. REQUIRED with `transaction_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    /// Identifier for the Notification Endpoint (§11). Only with
    /// `credentials`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_id: Option<String>,
    /// Additional response parameters.
    #[serde(flatten)]
    pub additional: Additional,
}

/// The Deferred Credential Response has the Credential Response shape (§9.2).
pub type DeferredCredentialResponse = CredentialResponse;

impl CredentialResponse {
    /// Immediate issuance (HTTP 200).
    pub fn issued(credentials: Vec<Value>, notification_id: Option<String>) -> Self {
        Self {
            credentials: Some(credentials.into_iter().map(IssuedCredential::new).collect()),
            notification_id,
            ..Self::default()
        }
    }

    /// Deferred issuance (HTTP 202).
    pub fn deferred(transaction_id: impl Into<String>, interval: u64) -> Self {
        Self {
            transaction_id: Some(transaction_id.into()),
            interval: Some(interval),
            ..Self::default()
        }
    }

    /// Whether this is a deferral (`transaction_id` present → HTTP 202).
    pub fn is_deferred(&self) -> bool {
        self.transaction_id.is_some()
    }

    /// Check the §8.3 member rules: exactly one of `credentials` (non-empty)
    /// or `transaction_id`; `interval` (positive) iff `transaction_id`;
    /// `notification_id` only with `credentials`.
    pub fn check(&self) -> Result<(), &'static str> {
        match (&self.credentials, &self.transaction_id) {
            (Some(_), Some(_)) => Err("credentials and transaction_id are mutually exclusive"),
            (None, None) => Err("one of credentials or transaction_id is required"),
            (Some(c), None) => {
                if c.is_empty() {
                    Err("credentials must not be empty")
                } else if self.interval.is_some() {
                    Err("interval must not be used with credentials")
                } else {
                    Ok(())
                }
            }
            (None, Some(_)) => match self.interval {
                None => Err("interval is required with transaction_id"),
                Some(0) => Err("interval must be positive"),
                Some(_) if self.notification_id.is_some() => {
                    Err("notification_id must not be used without credentials")
                }
                Some(_) => Ok(()),
            },
        }
    }
}

/// One element of the `credentials` array (§8.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IssuedCredential {
    /// One issued credential: a string (JWT / SD-JWT / base64url CBOR) or an
    /// object (e.g. `ldp_vc`), per the format profile (Appendix A). REQUIRED.
    pub credential: Value,
    /// Other parameters.
    #[serde(flatten)]
    pub additional: Additional,
}

impl IssuedCredential {
    /// Wrap one credential.
    pub fn new(credential: Value) -> Self {
        Self {
            credential,
            additional: Additional::new(),
        }
    }
}

// ── Deferred Credential Endpoint (§9) ───────────────────────────────────────

/// A Deferred Credential Request (§9.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeferredCredentialRequest {
    /// The deferred issuance transaction. REQUIRED.
    pub transaction_id: String,
    /// Response encryption parameters (§8.2); replaces whatever the original
    /// request sent. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
    /// Additional request parameters.
    #[serde(flatten)]
    pub additional: Additional,
}

// ── Notification Endpoint (§11) ─────────────────────────────────────────────

/// A Notification Request (§11.1). A successful response is an empty 2xx
/// (204 recommended, §11.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotificationRequest {
    /// From the (Deferred) Credential Response. REQUIRED.
    pub notification_id: String,
    /// The event. REQUIRED.
    pub event: NotificationEvent,
    /// Human-readable ASCII description. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_description: Option<String>,
    /// Additional request parameters.
    #[serde(flatten)]
    pub additional: Additional,
}

string_enum! {
    /// Notification `event` values (§11.1). Case sensitive.
    pub enum NotificationEvent {
        /// The credentials were stored in the Wallet.
        CredentialAccepted => "credential_accepted",
        /// Issuance failed for a reason other than a user action.
        CredentialFailure => "credential_failure",
        /// Issuance failed because of a user action (e.g. deletion).
        CredentialDeleted => "credential_deleted",
    }
}

// ── Error responses (§6.3, §8.3.1, §9.3, §11.3) ─────────────────────────────

/// A JSON error response body: `error` plus optional `error_description`
/// (and `error_uri` for the RFC 6749 token endpoint).
///
/// Use the aliases [`TokenErrorResponse`], [`CredentialErrorResponse`] and
/// [`NotificationErrorResponse`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponse<C> {
    /// The error code. REQUIRED.
    pub error: C,
    /// Human-readable ASCII description. OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// URI of a human-readable error page (RFC 6749 §5.2). OPTIONAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
}

impl<C> ErrorResponse<C> {
    /// An error response with just a code.
    pub fn new(error: C) -> Self {
        Self {
            error,
            error_description: None,
            error_uri: None,
        }
    }

    /// Attach an `error_description`. Characters outside the permitted set
    /// (`%x20-21 / %x23-5B / %x5D-7E`, §8.3.1.2 / RFC 6749 §5.2 — printable
    /// ASCII except `"` and `\`) are replaced with `?`.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        let sanitized = description
            .into()
            .chars()
            .map(|c| match c {
                '\x20'..='\x21' | '\x23'..='\x5B' | '\x5D'..='\x7E' => c,
                _ => '?',
            })
            .collect();
        self.error_description = Some(sanitized);
        self
    }
}

impl<C: fmt::Display> fmt::Display for ErrorResponse<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.error_description {
            Some(d) => write!(f, "{}: {d}", self.error),
            None => write!(f, "{}", self.error),
        }
    }
}

impl<C: fmt::Display + fmt::Debug> std::error::Error for ErrorResponse<C> {}

string_enum! {
    /// Token Endpoint error codes (§6.3; RFC 6749 §5.2 and RFC 9396 §5).
    pub enum TokenErrorCode {
        /// Malformed request; also a missing or unexpected `tx_code` (§6.3).
        InvalidRequest => "invalid_request",
        /// Client authentication failed; also an anonymous pre-authorized
        /// code request the AS does not allow (§6.3).
        InvalidClient => "invalid_client",
        /// Wrong / expired pre-authorized code or wrong `tx_code` (§6.3).
        InvalidGrant => "invalid_grant",
        /// The client may not use this grant type.
        UnauthorizedClient => "unauthorized_client",
        /// The grant type is not supported.
        UnsupportedGrantType => "unsupported_grant_type",
        /// The requested scope is invalid.
        InvalidScope => "invalid_scope",
        /// The `authorization_details` are invalid (RFC 9396 §5).
        InvalidAuthorizationDetails => "invalid_authorization_details",
    }
}

string_enum! {
    /// Credential and Deferred Credential Endpoint error codes (§8.3.1.2, §9.3).
    pub enum CredentialErrorCode {
        /// Missing / unsupported / repeated parameter, or malformed request.
        InvalidCredentialRequest => "invalid_credential_request",
        /// Requested Credential Configuration is unknown.
        UnknownCredentialConfiguration => "unknown_credential_configuration",
        /// Requested Credential identifier is unknown.
        UnknownCredentialIdentifier => "unknown_credential_identifier",
        /// `proofs` missing, a key proof invalid, or a key proof lacks the
        /// `c_nonce`.
        InvalidProof => "invalid_proof",
        /// A key proof carries an invalid `c_nonce`; fetch a new one.
        InvalidNonce => "invalid_nonce",
        /// Encryption parameters invalid, or missing while required.
        InvalidEncryptionParameters => "invalid_encryption_parameters",
        /// The request was not accepted; unrecoverable.
        CredentialRequestDenied => "credential_request_denied",
        /// Deferred endpoint only (§9.3): unknown or already used
        /// `transaction_id`.
        InvalidTransactionId => "invalid_transaction_id",
    }
}

string_enum! {
    /// Notification Endpoint error codes (§11.3).
    pub enum NotificationErrorCode {
        /// The `notification_id` was invalid.
        InvalidNotificationId => "invalid_notification_id",
        /// Missing / unsupported / repeated parameter, or malformed request.
        InvalidNotificationRequest => "invalid_notification_request",
    }
}

/// Token Endpoint error response (§6.3).
pub type TokenErrorResponse = ErrorResponse<TokenErrorCode>;
/// Credential / Deferred Credential Endpoint error response (§8.3.1.2, §9.3).
pub type CredentialErrorResponse = ErrorResponse<CredentialErrorCode>;
/// Notification Endpoint error response (§11.3).
pub type NotificationErrorResponse = ErrorResponse<NotificationErrorCode>;
