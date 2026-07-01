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
    /// Per-signature JWS **unprotected** header (RFC 7515 §7.2.1). Not
    /// integrity-protected, so never part of the signing input — but
    /// DIDComm and several implementations (credo-ts, SICPA
    /// didcomm-python) carry the signer `kid` here rather than in the
    /// protected header, so it must be parsed to attribute the signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<JwsUnprotectedHeader>,
    /// BASE64URL(JWS Signature)
    pub signature: String,
}

/// Per-signature JWS unprotected header members DIDComm cares about.
/// Only `kid` is modelled today; unknown members deserialize and are
/// ignored.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct JwsUnprotectedHeader {
    /// Signer KID (DID URL), when carried unprotected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// JWS protected header for DIDComm signed messages.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct JwsProtectedHeader {
    /// Media type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// Signing algorithm: "EdDSA"/"Ed25519" (Ed25519) or "ES256" (P-256)
    pub alg: String,
    /// Signer KID (DID URL)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Signer's public key as JWK (optional — can be resolved from kid)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Value>,
}
