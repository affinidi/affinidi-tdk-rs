//! JWE envelope structures — wire-compatible with the DIDComm v2.1 spec
//! and the existing affinidi-messaging-didcomm crate.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JWE in JSON Serialization (General form).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Jwe {
    /// BASE64URL(UTF8(JWE Protected Header)) — also used as AAD
    pub protected: String,
    /// Array of recipient-specific objects
    pub recipients: Vec<Recipient>,
    /// BASE64URL(JWE Initialization Vector)
    pub iv: String,
    /// BASE64URL(JWE Ciphertext)
    pub ciphertext: String,
    /// BASE64URL(JWE Authentication Tag)
    pub tag: String,
}

/// JWE protected header for DIDComm encrypted messages.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProtectedHeader {
    /// Media type: "application/didcomm-encrypted+json"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// Key management algorithm: "ECDH-1PU+A256KW" or "ECDH-ES+A256KW"
    pub alg: String,
    /// Content encryption algorithm: "A256CBC-HS512"
    pub enc: String,
    /// Sender KID (authcrypt only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skid: Option<String>,
    /// BASE64URL(skid) — PartyUInfo
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apu: Option<String>,
    /// BASE64URL(SHA256(sorted recipient kids joined by ".")) — PartyVInfo
    pub apv: String,
    /// Ephemeral public key as JWK
    pub epk: Value,
}

/// Per-recipient data in JWE.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    /// Per-recipient unprotected header
    pub header: PerRecipientHeader,
    /// BASE64URL(JWE Encrypted Key) — wrapped CEK for this recipient
    pub encrypted_key: String,
}

/// Per-recipient header.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PerRecipientHeader {
    /// Recipient KID as DID URL
    pub kid: String,
}
