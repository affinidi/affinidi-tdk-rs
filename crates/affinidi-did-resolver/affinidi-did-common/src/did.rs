/*!
 * DID (Decentralized Identifier) type definitions per W3C DID Core 1.0
 *
 * Provides a structured representation of DIDs with parsing, validation,
 * and component access.
 *
 * # W3C DID Grammar (ABNF)
 * ```abnf
 * did                = "did:" method-name ":" method-specific-id
 * method-name        = 1*method-char
 * method-char        = %x61-7A / DIGIT  ; lowercase + digits
 * method-specific-id = *( *idchar ":" ) 1*idchar
 * did-url            = did [ "/" path ] [ "?" query ] [ "#" fragment ]
 * ```
 */

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

use crate::did_method::{DIDMethod, parse::parse_method};

/// A validated Decentralized Identifier (DID) or DID URL
///
/// DIDs are parsed and validated at construction time according to W3C DID Core 1.0.
/// Invalid DIDs are rejected immediately, ensuring type-level guarantees.
///
/// # Examples
///
/// ```
/// use affinidi_did_common::DID;
///
/// // Parse a basic DID
/// let did: DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".parse().unwrap();
/// assert_eq!(did.method().to_string(), "key");
///
/// // Parse a DID URL with fragment
/// let did_url: DID = "did:example:123#key-1".parse().unwrap();
/// assert_eq!(did_url.fragment(), Some("key-1".to_string()));
///
/// // Create programmatically
/// let did = DID::new_key("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DID {
    method: DIDMethod,
    path: Option<String>,
    query: Option<String>,
    fragment: Option<String>,
    /// Pre-parsed URL representation (guaranteed valid at construction)
    url: url::Url,
}

/// Errors that can occur when parsing or constructing a DID
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DIDError {
    /// DID string does not start with "did:"
    MissingPrefix,
    /// Method name is invalid (empty or contains invalid characters)
    InvalidMethod(String),
    /// Method-specific identifier is invalid
    InvalidMethodSpecificId(String),
    /// Path component is invalid per RFC 3986
    InvalidPath(String),
    /// Query component is invalid per RFC 3986
    InvalidQuery(String),
    /// Fragment component is invalid per RFC 3986
    InvalidFragment(String),
    /// DID is not a valid URL (WHATWG URL Standard)
    InvalidUrl(String),
}

impl std::error::Error for DIDError {}

impl fmt::Display for DIDError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DIDError::MissingPrefix => write!(f, "DID must start with 'did:'"),
            DIDError::InvalidMethod(m) => write!(f, "Invalid DID method: {m}"),
            DIDError::InvalidMethodSpecificId(id) => {
                write!(f, "Invalid method-specific ID: {id}")
            }
            DIDError::InvalidPath(msg) => write!(f, "Invalid path: {msg}"),
            DIDError::InvalidQuery(msg) => write!(f, "Invalid query: {msg}"),
            DIDError::InvalidFragment(msg) => write!(f, "Invalid fragment: {msg}"),
            DIDError::InvalidUrl(msg) => write!(f, "Invalid URL: {msg}"),
        }
    }
}

impl FromStr for DID {
    type Err = DIDError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s.strip_prefix("did:").ok_or(DIDError::MissingPrefix)?;

        let (method_name, rest) = rest
            .split_once(':')
            .ok_or_else(|| DIDError::InvalidMethod("missing method".into()))?;

        // Validate method name: must be non-empty, lowercase letters and digits only
        if method_name.is_empty()
            || !method_name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            return Err(DIDError::InvalidMethod(method_name.into()));
        }

        let components = parse_did_url_components(rest)?;

        // Parse and validate method-specific identifier, returns rich DIDMethod
        let method = parse_method(method_name, &components.method_specific_id)?;

        DID::build(
            method,
            components.path,
            components.query,
            components.fragment,
        )
    }
}

/// Parsed components from a DID URL string
struct DIDUrlComponents {
    method_specific_id: String,
    path: Option<String>,
    query: Option<String>,
    fragment: Option<String>,
}

/// Check if a character is an `unreserved` char per RFC 3986
/// `unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"`
fn is_unreserved(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')
}

/// Check if a character is a `sub-delims` char per RFC 3986
/// `sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="`
fn is_sub_delims(c: char) -> bool {
    matches!(
        c,
        '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '='
    )
}

/// Check if a character is a `pchar` per RFC 3986 (excluding pct-encoded)
/// `pchar = unreserved / sub-delims / ":" / "@"`
fn is_pchar(c: char) -> bool {
    is_unreserved(c) || is_sub_delims(c) || matches!(c, ':' | '@')
}

/// Validate a string as RFC 3986 pchar sequence (with pct-encoded support)
fn validate_pchar_sequence(s: &str, allow_slash_question: bool) -> Result<(), String> {
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if is_pchar(c) {
            continue;
        }
        if allow_slash_question && matches!(c, '/' | '?') {
            continue;
        }
        // pct-encoded = "%" HEXDIG HEXDIG
        if c == '%' {
            match (chars.next(), chars.next()) {
                (Some(h1), Some(h2)) if h1.is_ascii_hexdigit() && h2.is_ascii_hexdigit() => {
                    continue;
                }
                _ => return Err("invalid percent-encoding".into()),
            }
        }
        return Err(format!("invalid character '{c}'"));
    }
    Ok(())
}

/// Validate path per RFC 3986
/// `path = *( "/" segment )` where `segment = *pchar`
fn validate_path(s: &str) -> Result<(), DIDError> {
    // Path segments are separated by "/", each segment is *pchar
    for segment in s.split('/') {
        validate_pchar_sequence(segment, false).map_err(DIDError::InvalidPath)?;
    }
    Ok(())
}

/// Validate query per RFC 3986
/// `query = *( pchar / "/" / "?" )`
fn validate_query(s: &str) -> Result<(), DIDError> {
    validate_pchar_sequence(s, true).map_err(DIDError::InvalidQuery)
}

/// Validate fragment per RFC 3986
/// `fragment = *( pchar / "/" / "?" )`
fn validate_fragment(s: &str) -> Result<(), DIDError> {
    validate_pchar_sequence(s, true).map_err(DIDError::InvalidFragment)
}

/// Normalize empty strings to None
fn none_if_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

/// Parse DID URL components (path, query, fragment) from the remainder after "did:method:"
fn parse_did_url_components(s: &str) -> Result<DIDUrlComponents, DIDError> {
    let path_start = s.find('/');
    let query_start = s.find('?');
    let fragment_start = s.find('#');

    // Find where the method-specific-id ends
    let id_end = [path_start, query_start, fragment_start]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(s.len());

    let method_specific_id = s[..id_end].to_string();
    let remainder = &s[id_end..];

    if remainder.is_empty() {
        return Ok(DIDUrlComponents {
            method_specific_id,
            path: None,
            query: None,
            fragment: None,
        });
    }

    let mut path = None;
    let mut query = None;
    let mut fragment = None;

    // Parse path, query, fragment in order (empty values normalized to None)
    if let Some(stripped) = remainder.strip_prefix('/') {
        let end = stripped.find(['?', '#']).unwrap_or(stripped.len());
        path = none_if_empty(stripped[..end].to_string());
        let remainder = &stripped[end..];

        if let Some(stripped) = remainder.strip_prefix('?') {
            let end = stripped.find('#').unwrap_or(stripped.len());
            query = none_if_empty(stripped[..end].to_string());
            if let Some(stripped) = stripped[end..].strip_prefix('#') {
                fragment = none_if_empty(stripped.to_string());
            }
        } else if let Some(stripped) = remainder.strip_prefix('#') {
            fragment = none_if_empty(stripped.to_string());
        }
    } else if let Some(stripped) = remainder.strip_prefix('?') {
        let end = stripped.find('#').unwrap_or(stripped.len());
        query = none_if_empty(stripped[..end].to_string());
        if let Some(frag) = stripped[end..].strip_prefix('#') {
            fragment = none_if_empty(frag.to_string());
        }
    } else if let Some(stripped) = remainder.strip_prefix('#') {
        fragment = none_if_empty(stripped.to_string());
    }

    // Validate components per RFC 3986
    if let Some(ref p) = path {
        validate_path(p)?;
    }
    if let Some(ref q) = query {
        validate_query(q)?;
    }
    if let Some(ref f) = fragment {
        validate_fragment(f)?;
    }

    Ok(DIDUrlComponents {
        method_specific_id,
        path,
        query,
        fragment,
    })
}

impl fmt::Display for DID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "did:{}:{}", self.method.name(), self.method.identifier())?;
        if let Some(ref path) = self.path {
            write!(f, "/{path}")?;
        }
        if let Some(ref query) = self.query {
            write!(f, "?{query}")?;
        }
        if let Some(ref fragment) = self.fragment {
            write!(f, "#{fragment}")?;
        }
        Ok(())
    }
}

// Construction
impl DID {
    /// Internal constructor that builds the URL from components
    pub(crate) fn build(
        method: DIDMethod,
        path: Option<String>,
        query: Option<String>,
        fragment: Option<String>,
    ) -> Result<Self, DIDError> {
        // Build the DID string
        let mut did_string = format!("did:{}:{}", method.name(), method.identifier());
        if let Some(ref p) = path {
            did_string.push('/');
            did_string.push_str(p);
        }
        if let Some(ref q) = query {
            did_string.push('?');
            did_string.push_str(q);
        }
        if let Some(ref f) = fragment {
            did_string.push('#');
            did_string.push_str(f);
        }

        // Parse as URL to guarantee validity
        let url = url::Url::parse(&did_string).map_err(|e| DIDError::InvalidUrl(e.to_string()))?;

        Ok(DID {
            method,
            path,
            query,
            fragment,
            url,
        })
    }

    /// Create a new DID with a pre-constructed DIDMethod
    pub fn new(method: DIDMethod) -> Result<Self, DIDError> {
        Self::build(method, None, None, None)
    }

    /// Create a new did:key from identifier
    pub fn new_key(id: impl Into<String>) -> Result<Self, DIDError> {
        let method = parse_method("key", &id.into())?;
        Self::build(method, None, None, None)
    }

    /// Create a new did:peer from identifier
    pub fn new_peer(id: impl Into<String>) -> Result<Self, DIDError> {
        let method = parse_method("peer", &id.into())?;
        Self::build(method, None, None, None)
    }

    /// Create a new did:web from identifier
    pub fn new_web(id: impl Into<String>) -> Result<Self, DIDError> {
        let method = parse_method("web", &id.into())?;
        Self::build(method, None, None, None)
    }

    /// Create a new did:jwk from identifier
    pub fn new_jwk(id: impl Into<String>) -> Result<Self, DIDError> {
        let method = parse_method("jwk", &id.into())?;
        Self::build(method, None, None, None)
    }

    /// Parse a DID string (convenience method, equivalent to `str.parse()`)
    pub fn parse(s: &str) -> Result<Self, DIDError> {
        s.parse()
    }

    /// Generate a new did:key with the specified key type
    ///
    /// Returns both the DID and the associated key material (including private key).
    ///
    /// # Example
    /// ```
    /// use affinidi_did_common::{DID, KeyMaterial};
    /// use affinidi_crypto::KeyType;
    ///
    /// let (did, key) = DID::generate_key(KeyType::Ed25519).unwrap();
    /// assert!(did.to_string().starts_with("did:key:z6Mk"));
    /// ```
    pub fn generate_key(key_type: affinidi_crypto::KeyType) -> Result<(Self, crate::KeyMaterial), DIDError> {
        use crate::did_method::key::KeyMaterial;

        let mut key = KeyMaterial::generate(key_type)
            .map_err(|e| DIDError::InvalidMethodSpecificId(e.to_string()))?;

        let multibase = key.public_multibase()
            .map_err(|e| DIDError::InvalidMethodSpecificId(e.to_string()))?;

        let did_string = format!("did:key:{}", multibase);
        let did: DID = did_string.parse()?;

        // Set the key ID to the DID URL with fragment
        key.id = format!("{}#{}", did_string, multibase);

        Ok((did, key))
    }

    // TODO: Implement resolve() once DIDMethod::resolve() is complete
    // pub fn resolve(&self) -> DIDDocument {
    //     self.method.resolve()
    // }
}

// Accessors
impl DID {
    /// Returns the DID method
    pub fn method(&self) -> DIDMethod {
        self.method.clone()
    }

    /// Returns the method-specific identifier
    pub fn method_specific_id(&self) -> String {
        self.method.identifier().to_string()
    }

    /// Returns the path component, if present
    pub fn path(&self) -> Option<String> {
        self.path.clone()
    }

    /// Returns the query component, if present
    pub fn query(&self) -> Option<String> {
        self.query.clone()
    }

    /// Returns the fragment component, if present
    pub fn fragment(&self) -> Option<String> {
        self.fragment.clone()
    }

    /// Returns true if this is a DID URL (has path, query, or fragment)
    pub fn is_url(&self) -> bool {
        self.path.is_some() || self.query.is_some() || self.fragment.is_some()
    }

    /// Returns this DID as a URL
    pub fn url(&self) -> url::Url {
        self.url.clone()
    }
}

// Builder methods (consuming self)
impl DID {
    pub fn with_path(self, path: impl Into<String>) -> Result<Self, DIDError> {
        let path = path.into();
        validate_path(&path)?;
        DID::build(self.method, Some(path), self.query, self.fragment)
    }

    pub fn with_query(self, query: impl Into<String>) -> Result<Self, DIDError> {
        let query = query.into();
        validate_query(&query)?;
        DID::build(self.method, self.path, Some(query), self.fragment)
    }

    pub fn with_fragment(self, fragment: impl Into<String>) -> Result<Self, DIDError> {
        let fragment = fragment.into();
        validate_fragment(&fragment)?;
        DID::build(self.method, self.path, self.query, Some(fragment))
    }
}

// Conversions
impl From<DID> for String {
    fn from(did: DID) -> Self {
        did.to_string()
    }
}

impl TryFrom<String> for DID {
    type Error = DIDError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl TryFrom<&str> for DID {
    type Error = DIDError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_did() {
        let did: DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();
        assert!(matches!(did.method(), DIDMethod::Key { .. }));
        assert_eq!(
            did.method_specific_id(),
            "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
        assert!(!did.is_url());
    }

    #[test]
    fn parse_did_peer() {
        let did: DID = "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            .parse()
            .unwrap();
        assert!(matches!(did.method(), DIDMethod::Peer { .. }));
        assert!(
            did.method_specific_id()
                .starts_with("2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc")
        );
    }

    #[test]
    fn parse_did_web() {
        let did: DID = "did:web:example.com".parse().unwrap();
        assert!(matches!(did.method(), DIDMethod::Web { .. }));
        assert_eq!(did.method_specific_id(), "example.com");
    }

    #[test]
    fn parse_did_with_fragment() {
        let did: DID = "did:example:123#key-1".parse().unwrap();
        assert!(matches!(did.method(), DIDMethod::Other { .. }));
        assert_eq!(did.method_specific_id(), "123");
        assert_eq!(did.fragment(), Some("key-1".to_string()));
        assert!(did.is_url());
    }

    #[test]
    fn parse_did_with_path() {
        let did: DID = "did:example:123/path/to/resource".parse().unwrap();
        assert_eq!(did.path(), Some("path/to/resource".to_string()));
    }

    #[test]
    fn parse_did_with_query() {
        let did: DID = "did:example:123?service=files".parse().unwrap();
        assert_eq!(did.query(), Some("service=files".to_string()));
    }

    #[test]
    fn parse_full_did_url() {
        let did: DID = "did:example:123/path?query=value#fragment".parse().unwrap();
        assert_eq!(did.method_specific_id(), "123");
        assert_eq!(did.path(), Some("path".to_string()));
        assert_eq!(did.query(), Some("query=value".to_string()));
        assert_eq!(did.fragment(), Some("fragment".to_string()));
    }

    #[test]
    fn display_roundtrip() {
        let original = "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc";
        let did: DID = original.parse().unwrap();
        assert_eq!(did.to_string(), original);
    }

    #[test]
    fn display_roundtrip_with_fragment() {
        let original = "did:example:123#key-1";
        let did: DID = original.parse().unwrap();
        assert_eq!(did.to_string(), original);
    }

    #[test]
    fn display_roundtrip_full_url() {
        let original = "did:example:123/path?query=value#fragment";
        let did: DID = original.parse().unwrap();
        assert_eq!(did.to_string(), original);
    }

    #[test]
    fn new_did() {
        let did = DID::new_key("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
        assert_eq!(
            did.to_string(),
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
    }

    #[test]
    fn builder_methods() {
        let did = DID::new_peer("2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc")
            .unwrap()
            .with_fragment("key-1")
            .unwrap();
        assert_eq!(
            did.to_string(),
            "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc#key-1"
        );
    }

    #[test]
    fn error_missing_prefix() {
        let result: Result<DID, _> = "not-a-did".parse();
        assert_eq!(result.unwrap_err(), DIDError::MissingPrefix);
    }

    #[test]
    fn error_invalid_method() {
        let result: Result<DID, _> = "did:UPPER:123".parse();
        assert!(matches!(result.unwrap_err(), DIDError::InvalidMethod(_)));
    }

    #[test]
    fn error_empty_method_specific_id() {
        let result: Result<DID, _> = "did:example:".parse();
        assert!(matches!(
            result.unwrap_err(),
            DIDError::InvalidMethodSpecificId(_)
        ));
    }

    #[test]
    fn method_ethr() {
        let did: DID = "did:ethr:0x1234567890abcdef".parse().unwrap();
        assert!(matches!(did.method(), DIDMethod::Ethr { .. }));
        assert_eq!(did.method_specific_id(), "0x1234567890abcdef");
    }

    #[test]
    fn method_pkh() {
        let did: DID = "did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev"
            .parse()
            .unwrap();
        match did.method() {
            DIDMethod::Pkh {
                chain_namespace,
                chain_reference,
                account_address,
                ..
            } => {
                assert_eq!(chain_namespace, "solana");
                assert_eq!(chain_reference, "4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ");
                assert_eq!(
                    account_address,
                    "CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev"
                );
            }
            _ => panic!("Expected DIDMethod::Pkh"),
        }
    }

    #[test]
    fn method_webvh() {
        let did: DID = "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs"
            .parse()
            .unwrap();
        match did.method() {
            DIDMethod::Webvh {
                scid,
                domain,
                path_segments,
                ..
            } => {
                assert_eq!(scid, "Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai");
                assert_eq!(domain, "identity.foundation");
                assert_eq!(
                    path_segments,
                    vec![
                        "didwebvh-implementations",
                        "implementations",
                        "affinidi-didwebvh-rs"
                    ]
                );
            }
            _ => panic!("Expected DIDMethod::Webvh"),
        }
    }

    #[test]
    fn method_cheqd() {
        let did: DID = "did:cheqd:testnet:cad53e1d-71e0-48d2-9352-39cc3d0fac99"
            .parse()
            .unwrap();
        match did.method() {
            DIDMethod::Cheqd { network, uuid, .. } => {
                assert_eq!(network, "testnet");
                assert_eq!(uuid, "cad53e1d-71e0-48d2-9352-39cc3d0fac99");
            }
            _ => panic!("Expected DIDMethod::Cheqd"),
        }
    }

    #[test]
    fn method_scid() {
        let did: DID = "did:scid:vh:1:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai"
            .parse()
            .unwrap();
        match did.method() {
            DIDMethod::Scid {
                underlying_method,
                version,
                scid,
                ..
            } => {
                assert_eq!(underlying_method, "vh");
                assert_eq!(version, "1");
                assert_eq!(scid, "Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai");
            }
            _ => panic!("Expected DIDMethod::Scid"),
        }
    }

    #[test]
    fn method_other() {
        let did: DID = "did:example:123".parse().unwrap();
        assert!(matches!(did.method(), DIDMethod::Other { method, .. } if method == "example"));
    }

    #[test]
    fn colons_in_method_specific_id() {
        // DIDs can have colons in the method-specific-id
        let did: DID = "did:web:example.com:user:alice".parse().unwrap();
        assert_eq!(did.method_specific_id(), "example.com:user:alice");
    }

    // Validation tests per W3C DID Core 1.0

    #[test]
    fn valid_percent_encoding() {
        let did: DID = "did:web:example.com%3A8080".parse().unwrap();
        assert_eq!(did.method_specific_id(), "example.com%3A8080");
    }

    #[test]
    fn valid_minimal_did() {
        let did: DID = "did:a:b".parse().unwrap();
        assert_eq!(did.method().to_string(), "a");
        assert_eq!(did.method_specific_id(), "b");
    }

    #[test]
    fn valid_idchars() {
        // All valid idchar: ALPHA / DIGIT / "." / "-" / "_"
        let did: DID = "did:example:ABC-123_test.value".parse().unwrap();
        assert_eq!(did.method_specific_id(), "ABC-123_test.value");
    }

    #[test]
    fn error_invalid_character_space() {
        let result: Result<DID, _> = "did:example:has space".parse();
        assert!(matches!(
            result.unwrap_err(),
            DIDError::InvalidMethodSpecificId(_)
        ));
    }

    #[test]
    fn error_invalid_character_at() {
        let result: Result<DID, _> = "did:example:user@domain".parse();
        assert!(matches!(
            result.unwrap_err(),
            DIDError::InvalidMethodSpecificId(_)
        ));
    }

    #[test]
    fn error_trailing_colon() {
        let result: Result<DID, _> = "did:example:123:".parse();
        assert!(matches!(
            result.unwrap_err(),
            DIDError::InvalidMethodSpecificId(_)
        ));
    }

    #[test]
    fn error_invalid_percent_encoding() {
        // Incomplete percent encoding
        let result: Result<DID, _> = "did:example:test%2".parse();
        assert!(matches!(
            result.unwrap_err(),
            DIDError::InvalidMethodSpecificId(_)
        ));
    }

    #[test]
    fn error_invalid_percent_encoding_non_hex() {
        let result: Result<DID, _> = "did:example:test%GH".parse();
        assert!(matches!(
            result.unwrap_err(),
            DIDError::InvalidMethodSpecificId(_)
        ));
    }

    // Normalization tests - empty components become None

    #[test]
    fn normalize_empty_fragment() {
        let did: DID = "did:example:123#".parse().unwrap();
        assert_eq!(did.fragment(), None);
        assert!(!did.is_url());
    }

    #[test]
    fn normalize_empty_query() {
        let did: DID = "did:example:123?".parse().unwrap();
        assert_eq!(did.query(), None);
        assert!(!did.is_url());
    }

    #[test]
    fn normalize_empty_path() {
        let did: DID = "did:example:123/".parse().unwrap();
        assert_eq!(did.path(), None);
        assert!(!did.is_url());
    }

    #[test]
    fn normalize_empty_all() {
        let did: DID = "did:example:123/?#".parse().unwrap();
        assert_eq!(did.path(), None);
        assert_eq!(did.query(), None);
        assert_eq!(did.fragment(), None);
        assert!(!did.is_url());
    }

    #[test]
    fn normalize_mixed_empty_and_present() {
        let did: DID = "did:example:123/?query#".parse().unwrap();
        assert_eq!(did.path(), None);
        assert_eq!(did.query(), Some("query".to_string()));
        assert_eq!(did.fragment(), None);
        assert!(did.is_url()); // query is present
    }

    // Method with digits (W3C allows digits in method name)

    #[test]
    fn valid_method_with_digits() {
        let did: DID = "did:web3:0x123".parse().unwrap();
        assert!(matches!(did.method(), DIDMethod::Other { method, .. } if method == "web3"));
        assert_eq!(did.method_specific_id(), "0x123");
    }

    // DIDMethod serde tests

    #[test]
    fn didmethod_serde_roundtrip() {
        let method = DIDMethod::Web {
            identifier: "example.com".to_string(),
            domain: "example.com".to_string(),
            path_segments: vec![],
        };
        let json = serde_json::to_string(&method).unwrap();
        let parsed: DIDMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(method, parsed);
    }

    #[test]
    fn didmethod_other_serde() {
        let method = DIDMethod::Other {
            method: "ethr".to_string(),
            identifier: "0x123".to_string(),
        };
        let json = serde_json::to_string(&method).unwrap();
        let parsed: DIDMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(method, parsed);
    }

    // RFC 3986 path/query/fragment validation

    #[test]
    fn valid_path_with_pchar() {
        // pchar includes unreserved, sub-delims, ":", "@"
        let did: DID = "did:example:123/path-to_resource.txt".parse().unwrap();
        assert_eq!(did.path(), Some("path-to_resource.txt".to_string()));
    }

    #[test]
    fn valid_query_with_special_chars() {
        // query allows pchar plus "/" and "?"
        let did: DID = "did:example:123?key=value&other=123".parse().unwrap();
        assert_eq!(did.query(), Some("key=value&other=123".to_string()));
    }

    #[test]
    fn valid_fragment_with_slash() {
        // fragment allows pchar plus "/" and "?"
        let did: DID = "did:example:123#section/subsection".parse().unwrap();
        assert_eq!(did.fragment(), Some("section/subsection".to_string()));
    }

    #[test]
    fn error_invalid_path_char() {
        let result: Result<DID, _> = "did:example:123/path<script>".parse();
        assert!(matches!(result.unwrap_err(), DIDError::InvalidPath(_)));
    }

    #[test]
    fn error_invalid_query_char() {
        let result: Result<DID, _> = "did:example:123?query<script>".parse();
        assert!(matches!(result.unwrap_err(), DIDError::InvalidQuery(_)));
    }

    #[test]
    fn error_invalid_fragment_char() {
        let result: Result<DID, _> = "did:example:123#frag<script>".parse();
        assert!(matches!(result.unwrap_err(), DIDError::InvalidFragment(_)));
    }

    #[test]
    fn error_invalid_path_space() {
        let result: Result<DID, _> = "did:example:123/has space".parse();
        assert!(matches!(result.unwrap_err(), DIDError::InvalidPath(_)));
    }

    #[test]
    fn builder_validates_path() {
        let result = DID::new_key("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
            .unwrap()
            .with_path("invalid<path>");
        assert!(matches!(result.unwrap_err(), DIDError::InvalidPath(_)));
    }

    #[test]
    fn builder_validates_fragment() {
        let result = DID::new_key("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
            .unwrap()
            .with_fragment("invalid<frag>");
        assert!(matches!(result.unwrap_err(), DIDError::InvalidFragment(_)));
    }
}
