//! did:peer specific types and validation
//!
//! Implements validation for did:peer method per the spec:
//! https://identity.foundation/peer-did-method-spec/

use std::collections::HashMap;

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::one_or_many::OneOrMany;

/// Peer DID algorithm number (numalgo)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerNumAlgo {
    /// Type 0: Inception key (wraps a did:key)
    InceptionKey = 0,
    /// Type 1: Genesis document (not widely supported)
    GenesisDoc = 1,
    /// Type 2: Multiple inline keys
    MultipleKeys = 2,
}

impl PeerNumAlgo {
    /// Parse numalgo from the first character of method-specific-id
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            '0' => Some(PeerNumAlgo::InceptionKey),
            '1' => Some(PeerNumAlgo::GenesisDoc),
            '2' => Some(PeerNumAlgo::MultipleKeys),
            _ => None,
        }
    }

    /// Convert to character representation
    pub fn to_char(self) -> char {
        match self {
            PeerNumAlgo::InceptionKey => '0',
            PeerNumAlgo::GenesisDoc => '1',
            PeerNumAlgo::MultipleKeys => '2',
        }
    }
}

/// Purpose codes for did:peer type 2 key entries
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerPurpose {
    /// Assertion method
    Assertion,
    /// Capability delegation
    Delegation,
    /// Key agreement (encryption)
    Encryption,
    /// Capability invocation
    Invocation,
    /// Authentication (verification)
    Verification,
    /// Service endpoint
    Service,
}

impl PeerPurpose {
    /// Parse purpose from character
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'A' => Some(PeerPurpose::Assertion),
            'D' => Some(PeerPurpose::Delegation),
            'E' => Some(PeerPurpose::Encryption),
            'I' => Some(PeerPurpose::Invocation),
            'V' => Some(PeerPurpose::Verification),
            'S' => Some(PeerPurpose::Service),
            _ => None,
        }
    }

    /// Convert to character representation
    pub fn to_char(self) -> char {
        match self {
            PeerPurpose::Assertion => 'A',
            PeerPurpose::Delegation => 'D',
            PeerPurpose::Encryption => 'E',
            PeerPurpose::Invocation => 'I',
            PeerPurpose::Verification => 'V',
            PeerPurpose::Service => 'S',
        }
    }

    /// Returns true if this purpose represents a key (not a service)
    pub fn is_key(&self) -> bool {
        !matches!(self, PeerPurpose::Service)
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors specific to did:peer operations
#[derive(Error, Debug)]
pub enum PeerError {
    #[error("Unsupported key type")]
    UnsupportedKeyType,

    #[error("Unsupported curve: {0}")]
    UnsupportedCurve(String),

    #[error("Syntax error in service definition: {0}")]
    ServiceSyntaxError(String),

    #[error("Unsupported numalgo. Only 0 and 2 are supported")]
    UnsupportedNumalgo,

    #[error("Key parsing error: {0}")]
    KeyParsingError(String),

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

// ============================================================================
// Key Types for Generation
// ============================================================================

/// Purpose of a key when creating a did:peer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerKeyPurpose {
    /// Keys for authentication and assertions (V prefix in DID)
    Verification,
    /// Keys for key agreement/encryption (E prefix in DID)
    Encryption,
}

impl PeerKeyPurpose {
    /// Get the DID peer purpose code character
    pub fn to_char(self) -> char {
        match self {
            PeerKeyPurpose::Verification => 'V',
            PeerKeyPurpose::Encryption => 'E',
        }
    }
}

/// Supported key types for did:peer creation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerKeyType {
    Ed25519,
    Secp256k1,
    P256,
}

impl PeerKeyType {
    /// Convert to affinidi_crypto::KeyType
    pub fn to_crypto_key_type(self) -> affinidi_crypto::KeyType {
        match self {
            PeerKeyType::Ed25519 => affinidi_crypto::KeyType::Ed25519,
            PeerKeyType::Secp256k1 => affinidi_crypto::KeyType::Secp256k1,
            PeerKeyType::P256 => affinidi_crypto::KeyType::P256,
        }
    }
}

/// Key specification for creating a did:peer
#[derive(Debug, Clone)]
pub struct PeerCreateKey {
    /// Purpose of this key (Verification or Encryption)
    pub purpose: PeerKeyPurpose,
    /// Key type to generate (required if public_key_multibase is None)
    pub key_type: Option<PeerKeyType>,
    /// Pre-existing public key in multibase format (z6Mk...)
    /// If None, a new key will be generated
    pub public_key_multibase: Option<String>,
}

impl PeerCreateKey {
    /// Create a new key spec for generation
    pub fn new(purpose: PeerKeyPurpose, key_type: PeerKeyType) -> Self {
        Self {
            purpose,
            key_type: Some(key_type),
            public_key_multibase: None,
        }
    }

    /// Create a key spec from an existing multibase key
    pub fn from_multibase(purpose: PeerKeyPurpose, multibase: String) -> Self {
        Self {
            purpose,
            key_type: None,
            public_key_multibase: Some(multibase),
        }
    }
}

/// Result of key generation during did:peer creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCreatedKey {
    /// The multibase-encoded public key (z6Mk...)
    pub key_multibase: String,
    /// The elliptic curve used
    pub curve: String,
    /// Private key value in Base64URL (no padding)
    pub d: String,
    /// Public key X coordinate in Base64URL (no padding)
    pub x: String,
    /// Public key Y coordinate for EC keys (None for Ed25519)
    pub y: Option<String>,
}

// ============================================================================
// Service Types
// ============================================================================

/// Service definition for did:peer
///
/// Uses abbreviated format for encoding in the DID string
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerService {
    /// Service type (e.g., "dm" for DIDCommMessaging)
    #[serde(rename = "t")]
    pub type_: String,

    /// Service endpoint
    #[serde(rename = "s")]
    pub endpoint: PeerServiceEndpoint,

    /// Optional service ID fragment (e.g., "#my-service")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// Service endpoint - can be a simple URI or a structured map
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PeerServiceEndpoint {
    /// Simple URI endpoint
    Uri(String),
    /// Structured endpoint with routing info (long format)
    Long(OneOrMany<PeerServiceEndpointLong>),
    /// Structured endpoint with routing info (short format)
    Short(OneOrMany<PeerServiceEndpointShort>),
}

/// Short format service endpoint map (for DID encoding)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerServiceEndpointShort {
    /// Service URI
    pub uri: String,
    /// Accepted message types (abbreviated)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub a: Vec<String>,
    /// Routing keys (abbreviated)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub r: Vec<String>,
}

/// Long format service endpoint map (standard DID Document format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerServiceEndpointLong {
    /// Service URI
    pub uri: String,
    /// Accepted message types
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accept: Vec<String>,
    /// Routing keys
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routing_keys: Vec<String>,
}

impl PeerServiceEndpointShort {
    /// Convert to long format
    pub fn to_long(&self) -> PeerServiceEndpointLong {
        PeerServiceEndpointLong {
            uri: self.uri.clone(),
            accept: self.a.clone(),
            routing_keys: self.r.clone(),
        }
    }
}

impl PeerServiceEndpointLong {
    /// Convert to short format (for encoding in DID)
    pub fn to_short(&self) -> PeerServiceEndpointShort {
        PeerServiceEndpointShort {
            uri: self.uri.clone(),
            a: self.accept.clone(),
            r: self.routing_keys.clone(),
        }
    }
}

// ============================================================================
// Service Encoding/Decoding
// ============================================================================

impl PeerService {
    /// Encode this service for inclusion in a did:peer string
    pub fn encode(&self) -> Result<String, PeerError> {
        let json = serde_json::to_string(self).map_err(|e| {
            PeerError::ServiceSyntaxError(format!("Failed to serialize service: {e}"))
        })?;
        Ok(format!(
            "S{}",
            BASE64_URL_SAFE_NO_PAD.encode(json.as_bytes())
        ))
    }

    /// Decode a service from a did:peer encoded string (including S prefix)
    pub fn decode(encoded: &str) -> Result<Self, PeerError> {
        let encoded = encoded.strip_prefix('S').unwrap_or(encoded);
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| PeerError::ServiceSyntaxError(format!("Base64 decode failed: {e}")))?;

        serde_json::from_slice(&bytes)
            .map_err(|e| PeerError::ServiceSyntaxError(format!("JSON parse failed: {e}")))
    }

    /// Convert to standard DID Document Service format
    pub fn to_did_service(
        &self,
        did: &str,
        index: u32,
    ) -> Result<crate::service::Service, PeerError> {
        use std::str::FromStr;
        use url::Url;

        // Build service ID
        let id_fragment = if let Some(id) = &self.id {
            id.clone()
        } else if index == 0 {
            "#service".to_string()
        } else {
            format!("#service-{index}")
        };

        let id = Url::from_str(&format!("{did}{id_fragment}"))
            .map_err(|e| PeerError::ServiceSyntaxError(format!("Invalid service ID: {e}")))?;

        // Convert endpoint to standard format
        let service_endpoint = match &self.endpoint {
            PeerServiceEndpoint::Uri(uri) => {
                let url = Url::from_str(uri)
                    .map_err(|e| PeerError::ServiceSyntaxError(format!("Invalid URI: {e}")))?;
                crate::service::Endpoint::Url(url)
            }
            PeerServiceEndpoint::Short(endpoints) => {
                let value = match endpoints {
                    OneOrMany::One(ep) => serde_json::to_value(ep.to_long())
                        .map_err(|e| PeerError::ServiceSyntaxError(e.to_string()))?,
                    OneOrMany::Many(eps) => {
                        let long: Vec<_> = eps.iter().map(|e| e.to_long()).collect();
                        serde_json::to_value(long)
                            .map_err(|e| PeerError::ServiceSyntaxError(e.to_string()))?
                    }
                };
                crate::service::Endpoint::Map(value)
            }
            PeerServiceEndpoint::Long(endpoints) => {
                let value = serde_json::to_value(endpoints)
                    .map_err(|e| PeerError::ServiceSyntaxError(e.to_string()))?;
                crate::service::Endpoint::Map(value)
            }
        };

        Ok(crate::service::Service {
            id: Some(id),
            type_: vec!["DIDCommMessaging".to_string()],
            service_endpoint,
            property_set: HashMap::new(),
        })
    }
}
