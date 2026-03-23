//! JWS envelope structures — wire-compatible with DIDComm v2.1 signed messages.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JWS in General JSON Serialization.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Jws {
    /// BASE64URL(JWS Payload) — the signed DIDComm message
    pub payload: String,
    /// Array of signatures (one per signer)
    pub signatures: Vec<JwsSignature>,
}

/// A single signature entry in a JWS.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct JwsSignature {
    /// BASE64URL(UTF8(JWS Protected Header))
    pub protected: String,
    /// BASE64URL(JWS Signature)
    pub signature: String,
}

/// JWS protected header for DIDComm signed messages.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct JwsProtectedHeader {
    /// Media type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// Signing algorithm: "EdDSA"
    pub alg: String,
    /// Signer KID (DID URL)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Signer's public key as JWK (optional — can be resolved from kid)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Value>,
}
