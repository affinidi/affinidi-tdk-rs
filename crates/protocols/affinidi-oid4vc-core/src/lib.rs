/*!
 * Shared types for the OpenID for Verifiable Credentials (OID4VC) protocol family.
 *
 * This crate provides common types used across SIOPv2, OpenID4VP, and OpenID4VCI:
 *
 * - [`ResponseType`] — protocol response types (id_token, vp_token, code)
 * - [`ResponseMode`] — delivery modes (fragment, direct_post)
 * - [`SubjectSyntaxType`] — subject identifier types (JWK Thumbprint, DID)
 * - [`ClientMetadata`] — Relying Party registration metadata
 * - [`DisplayProperties`] — UI rendering properties
 * - [`compute_jwk_thumbprint`] — RFC 7638 JWK Thumbprint computation
 */

pub mod jwt;

/// ES256 (ECDSA P-256) signer and verifier for production JWT operations.
#[cfg(feature = "es256")]
pub mod es256;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// OAuth 2.0 response types used across OID4VC protocols.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseType {
    /// Self-Issued ID Token (SIOPv2).
    #[serde(rename = "id_token")]
    IdToken,
    /// Verifiable Presentation Token (OpenID4VP).
    #[serde(rename = "vp_token")]
    VpToken,
    /// Combined ID Token + VP Token (SIOPv2 + OpenID4VP).
    #[serde(rename = "vp_token id_token")]
    VpTokenIdToken,
    /// Authorization code (standard OAuth 2.0).
    #[serde(rename = "code")]
    Code,
}

impl std::fmt::Display for ResponseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdToken => write!(f, "id_token"),
            Self::VpToken => write!(f, "vp_token"),
            Self::VpTokenIdToken => write!(f, "vp_token id_token"),
            Self::Code => write!(f, "code"),
        }
    }
}

/// OAuth 2.0 response delivery modes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseMode {
    /// URL fragment (default for id_token response type, same-device).
    #[serde(rename = "fragment")]
    Fragment,
    /// HTTPS POST to redirect_uri (cross-device).
    #[serde(rename = "direct_post")]
    DirectPost,
    /// Encrypted HTTPS POST (HAIP profile).
    #[serde(rename = "direct_post.jwt")]
    DirectPostJwt,
}

impl std::fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fragment => write!(f, "fragment"),
            Self::DirectPost => write!(f, "direct_post"),
            Self::DirectPostJwt => write!(f, "direct_post.jwt"),
        }
    }
}

/// Subject syntax types for identifying credential holders.
///
/// Per SIOPv2 §8.1 and OpenID4VP client metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SubjectSyntaxType {
    /// JWK Thumbprint per RFC 7638.
    /// URI: `urn:ietf:params:oauth:jwk-thumbprint`
    JwkThumbprint,
    /// A specific DID method (e.g., "did:key", "did:web", "did:ebsi").
    Did(String),
}

impl SubjectSyntaxType {
    /// The URN for JWK Thumbprint subject syntax.
    pub const JWK_THUMBPRINT_URN: &'static str = "urn:ietf:params:oauth:jwk-thumbprint";

    /// Parse from a string.
    pub fn parse(s: &str) -> Self {
        if s == Self::JWK_THUMBPRINT_URN {
            Self::JwkThumbprint
        } else {
            Self::Did(s.to_string())
        }
    }

    /// Convert to string representation.
    pub fn as_str(&self) -> &str {
        match self {
            Self::JwkThumbprint => Self::JWK_THUMBPRINT_URN,
            Self::Did(method) => method,
        }
    }

    /// Whether this is a DID-based subject type.
    pub fn is_did(&self) -> bool {
        matches!(self, Self::Did(_))
    }
}

impl std::fmt::Display for SubjectSyntaxType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Compute a JWK Thumbprint per RFC 7638.
///
/// The thumbprint is `base64url(SHA-256(canonical_jwk))` where canonical_jwk
/// is a JSON object with only the REQUIRED members, sorted lexicographically.
///
/// # Supported Key Types
///
/// - **EC** (P-256, secp256k1): members `crv`, `kty`, `x`, `y`
/// - **OKP** (Ed25519): members `crv`, `kty`, `x`
/// - **RSA**: members `e`, `kty`, `n`
pub fn compute_jwk_thumbprint(jwk: &Value) -> Option<String> {
    let kty = jwk.get("kty")?.as_str()?;

    let canonical = match kty {
        "EC" => {
            let crv = jwk.get("crv")?.as_str()?;
            let x = jwk.get("x")?.as_str()?;
            let y = jwk.get("y")?.as_str()?;
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
        }
        "OKP" => {
            let crv = jwk.get("crv")?.as_str()?;
            let x = jwk.get("x")?.as_str()?;
            format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
        }
        "RSA" => {
            let e = jwk.get("e")?.as_str()?;
            let n = jwk.get("n")?.as_str()?;
            format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
        }
        _ => return None,
    };

    let hash = Sha256::digest(canonical.as_bytes());
    Some(URL_SAFE_NO_PAD.encode(hash))
}

/// Display properties for UI rendering (shared across OID4VCI, OpenID4VP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayProperties {
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Locale (e.g., "en-US").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Logo information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<LogoProperties>,
    /// Background color (CSS color string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    /// Text color (CSS color string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
}

/// Logo properties for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoProperties {
    /// URI of the logo image.
    pub uri: String,
    /// Alt text for accessibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
}

/// Client (RP) metadata fields shared across OID4VC protocols.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientMetadata {
    /// Supported subject syntax types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_syntax_types_supported: Option<Vec<String>>,
    /// Preferred ID Token signing algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<String>,
    /// Valid redirect URIs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
    /// Privacy policy URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
    /// Terms of service URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,
    /// Logo URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    /// Client name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// Additional properties.
    #[serde(flatten)]
    pub additional: serde_json::Map<String, Value>,
}

/// Standard OAuth 2.0 error codes used across OID4VC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum OAuthError {
    #[error("invalid_request")]
    #[serde(rename = "invalid_request")]
    InvalidRequest,
    #[error("unauthorized_client")]
    #[serde(rename = "unauthorized_client")]
    UnauthorizedClient,
    #[error("access_denied")]
    #[serde(rename = "access_denied")]
    AccessDenied,
    #[error("unsupported_response_type")]
    #[serde(rename = "unsupported_response_type")]
    UnsupportedResponseType,
    #[error("invalid_scope")]
    #[serde(rename = "invalid_scope")]
    InvalidScope,
    #[error("server_error")]
    #[serde(rename = "server_error")]
    ServerError,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jwk_thumbprint_ec_p256() {
        // RFC 7638 §3.1 example (modified for EC P-256)
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
            "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
        });

        let thumbprint = compute_jwk_thumbprint(&jwk).unwrap();
        assert!(!thumbprint.is_empty());
        // Thumbprint is base64url-no-pad, 43 chars for SHA-256
        assert_eq!(thumbprint.len(), 43);
    }

    #[test]
    fn jwk_thumbprint_okp_ed25519() {
        let jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "Xx4_L89E6RsyvDTzN9wuN3cDwgifPkXMgFJv_HMIxdk"
        });

        let thumbprint = compute_jwk_thumbprint(&jwk).unwrap();
        assert_eq!(thumbprint.len(), 43);
    }

    #[test]
    fn jwk_thumbprint_deterministic() {
        let jwk = json!({"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"});
        let t1 = compute_jwk_thumbprint(&jwk).unwrap();
        let t2 = compute_jwk_thumbprint(&jwk).unwrap();
        assert_eq!(t1, t2);
    }

    #[test]
    fn jwk_thumbprint_different_keys() {
        let jwk1 = json!({"kty": "EC", "crv": "P-256", "x": "a", "y": "b"});
        let jwk2 = json!({"kty": "EC", "crv": "P-256", "x": "c", "y": "d"});
        assert_ne!(compute_jwk_thumbprint(&jwk1), compute_jwk_thumbprint(&jwk2));
    }

    #[test]
    fn jwk_thumbprint_ignores_extra_fields() {
        let jwk1 = json!({"kty": "EC", "crv": "P-256", "x": "a", "y": "b"});
        let jwk2 = json!({"kty": "EC", "crv": "P-256", "x": "a", "y": "b", "kid": "extra"});
        assert_eq!(compute_jwk_thumbprint(&jwk1), compute_jwk_thumbprint(&jwk2));
    }

    #[test]
    fn jwk_thumbprint_unsupported_kty() {
        let jwk = json!({"kty": "oct", "k": "secret"});
        assert!(compute_jwk_thumbprint(&jwk).is_none());
    }

    #[test]
    fn response_type_display() {
        assert_eq!(ResponseType::IdToken.to_string(), "id_token");
        assert_eq!(ResponseType::VpToken.to_string(), "vp_token");
        assert_eq!(
            ResponseType::VpTokenIdToken.to_string(),
            "vp_token id_token"
        );
    }

    #[test]
    fn response_mode_display() {
        assert_eq!(ResponseMode::Fragment.to_string(), "fragment");
        assert_eq!(ResponseMode::DirectPost.to_string(), "direct_post");
        assert_eq!(ResponseMode::DirectPostJwt.to_string(), "direct_post.jwt");
    }

    #[test]
    fn subject_syntax_type_parsing() {
        let jwk = SubjectSyntaxType::parse("urn:ietf:params:oauth:jwk-thumbprint");
        assert_eq!(jwk, SubjectSyntaxType::JwkThumbprint);
        assert!(!jwk.is_did());

        let did = SubjectSyntaxType::parse("did:key");
        assert!(did.is_did());
        assert_eq!(did.as_str(), "did:key");
    }

    #[test]
    fn client_metadata_serialization() {
        let meta = ClientMetadata {
            client_name: Some("Test RP".into()),
            subject_syntax_types_supported: Some(vec![
                "urn:ietf:params:oauth:jwk-thumbprint".into(),
                "did:key".into(),
            ]),
            ..Default::default()
        };

        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("Test RP"));
        assert!(json.contains("did:key"));

        let parsed: ClientMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.client_name.as_deref(), Some("Test RP"));
    }
}
