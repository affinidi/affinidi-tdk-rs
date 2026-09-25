//! JWE envelope structures — wire-compatible with the DIDComm v2.1 spec
//! and the existing affinidi-messaging-didcomm crate.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::DIDCommError;

/// JOSE `alg` for DIDComm authcrypt.
pub const ALG_AUTHCRYPT: &str = "ECDH-1PU+A256KW";
/// JOSE `alg` for DIDComm anoncrypt.
pub const ALG_ANONCRYPT: &str = "ECDH-ES+A256KW";

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

impl ProtectedHeader {
    /// Decode a JWE's base64url `protected` member.
    pub fn from_base64url(protected: &str) -> Result<Self, DIDCommError> {
        let bytes = Base64UrlUnpadded::decode_vec(protected).map_err(|e| {
            DIDCommError::InvalidMessage(format!("invalid protected header base64: {e}"))
        })?;
        serde_json::from_slice(&bytes).map_err(|e| {
            DIDCommError::InvalidMessage(format!("invalid protected header JSON: {e}"))
        })
    }

    /// The sender key id of an authcrypt (ECDH-1PU) header, `None` for any
    /// other `alg`.
    ///
    /// For ECDH-1PU the header must carry both `skid` and `apu`, `skid` must be
    /// a DID URL with a `#fragment` naming one key, and `apu` must be exactly
    /// `BASE64URL(skid)`. `apu` is the PartyUInfo the key derivation
    /// uses and `skid` is what a recipient resolves the sender key from, so a
    /// header where they differ names two senders and is refused with
    /// [`DIDCommError::SenderKeyBinding`].
    pub fn authcrypt_sender_kid(&self) -> Result<Option<&str>, DIDCommError> {
        if self.alg != ALG_AUTHCRYPT {
            return Ok(None);
        }
        let skid = self.skid.as_deref().ok_or_else(|| {
            DIDCommError::SenderKeyBinding("authcrypt header has no `skid`".into())
        })?;
        if !skid
            .split_once('#')
            .is_some_and(|(did, fragment)| !did.is_empty() && !fragment.is_empty())
        {
            return Err(DIDCommError::SenderKeyBinding(format!(
                "authcrypt `skid` {skid:?} is not a DID URL naming a key (`did#fragment`)"
            )));
        }
        let apu = self.apu.as_deref().ok_or_else(|| {
            DIDCommError::SenderKeyBinding("authcrypt header has no `apu`".into())
        })?;
        let apu_raw = Base64UrlUnpadded::decode_vec(apu)
            .map_err(|e| DIDCommError::SenderKeyBinding(format!("invalid `apu`: {e}")))?;
        if apu_raw != skid.as_bytes() {
            return Err(DIDCommError::SenderKeyBinding(
                "authcrypt `apu` does not encode the `skid`".into(),
            ));
        }
        Ok(Some(skid))
    }
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
