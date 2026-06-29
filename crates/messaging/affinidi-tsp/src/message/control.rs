//! TSP control messages for relationship management.
//!
//! Control messages drive the explicit relationship lifecycle that distinguishes
//! TSP from DIDComm. On the wire they are **not** a serialized body inside a
//! generic payload — each is its own CESR payload-frame variant, byte-compatible
//! with the ToIP `tsp_sdk` reference (v0.9.0-alpha2):
//!
//!   * **Invite** (`DirectRelationProposal`) → `XRFI` + hops + `A` nonce(32) +
//!     empty `B` VID.
//!   * **Accept** (`DirectRelationAffirm`) → `XRFA` + `I` SHA-256 reply(32).
//!   * **Cancel** (`RelationshipCancel`) → `XRFD` + `I` SHA-256 reply(32).
//!
//! The CESR encode/decode of these frames lives in [`crate::message::direct`]
//! (see `encode_payload_frame` / `decode_payload_frame`). This module owns the
//! semantic [`ControlMessage`] type and a compact self-describing
//! `encode`/`decode` used to carry a recovered control across the SDK's
//! `payload` field (the SDK unpacks to bytes, then re-decodes a control).
//!
//! Replay correlation rides on the **thread digest**: `SHA256` of the plaintext
//! payload frame (the `-Z…` bytes before sealing / after decrypt). The accept's
//! `reply` is the invite's thread digest; the cancel's `reply` is the
//! relationship-forming message's thread digest. See
//! [`crate::message::direct::thread_digest`].

use rand_core::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::TspError;

/// Length of a relationship nonce and of a SHA-256 thread digest, in bytes.
pub const DIGEST_LEN: usize = 32;

/// Generate a cryptographically random 32-byte nonce (matching the reference's
/// `Nonce`, which is 32 bytes for 256 bits of security).
pub fn generate_nonce() -> [u8; DIGEST_LEN] {
    let mut nonce = [0u8; DIGEST_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// TSP control message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ControlType {
    /// Relationship Forming Invite (`XRFI` / `DirectRelationProposal`).
    RelationshipFormingInvite = 0x00,
    /// Relationship Forming Accept (`XRFA` / `DirectRelationAffirm`).
    RelationshipFormingAccept = 0x01,
    /// Relationship Cancel (`XRFD` / `RelationshipCancel`).
    RelationshipCancel = 0x02,
}

impl ControlType {
    pub fn from_byte(b: u8) -> Result<Self, TspError> {
        match b {
            0x00 => Ok(ControlType::RelationshipFormingInvite),
            0x01 => Ok(ControlType::RelationshipFormingAccept),
            0x02 => Ok(ControlType::RelationshipCancel),
            _ => Err(TspError::InvalidMessage(format!(
                "unknown control type: 0x{b:02x}"
            ))),
        }
    }
}

/// A TSP control message payload.
///
/// The fields used depend on [`ControlType`]:
///   * **invite** carries a 32-byte `nonce` (and an optional `route` of hop
///     VIDs, normally empty for a direct relationship); `reply` is `None`.
///   * **accept** / **cancel** carry a 32-byte SHA-256 `reply` (the thread
///     digest they respond to); `nonce` is `None` and `route` is empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlMessage {
    /// The control message type.
    pub control_type: ControlType,
    /// The 32-byte nonce (invite only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nonce: Option<[u8; DIGEST_LEN]>,
    /// The 32-byte SHA-256 thread reference (accept / cancel only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reply: Option<[u8; DIGEST_LEN]>,
    /// Hop VIDs carried in an invite (empty for a direct relationship).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub route: Vec<String>,
}

impl ControlMessage {
    /// Create a Relationship Forming Invite (with a fresh random 32-byte nonce
    /// and no route).
    pub fn invite() -> Self {
        Self {
            control_type: ControlType::RelationshipFormingInvite,
            nonce: Some(generate_nonce()),
            reply: None,
            route: Vec::new(),
        }
    }

    /// Create a Relationship Forming Invite carrying a `route` of hop VIDs.
    pub fn invite_routed(route: Vec<String>) -> Self {
        Self {
            control_type: ControlType::RelationshipFormingInvite,
            nonce: Some(generate_nonce()),
            reply: None,
            route,
        }
    }

    /// Create a Relationship Forming Accept referencing the invite's thread
    /// digest (`reply` = `SHA256` of the invite's plaintext payload frame).
    pub fn accept(reply: [u8; DIGEST_LEN]) -> Self {
        Self {
            control_type: ControlType::RelationshipFormingAccept,
            nonce: None,
            reply: Some(reply),
            route: Vec::new(),
        }
    }

    /// Create a Relationship Cancel referencing the relationship-forming
    /// message's thread digest (`reply` = `SHA256` of that plaintext frame).
    pub fn cancel(reply: [u8; DIGEST_LEN]) -> Self {
        Self {
            control_type: ControlType::RelationshipCancel,
            nonce: None,
            reply: Some(reply),
            route: Vec::new(),
        }
    }

    /// The nonce, erroring if absent (invariant: present iff invite).
    pub fn require_nonce(&self) -> Result<&[u8; DIGEST_LEN], TspError> {
        self.nonce
            .as_ref()
            .ok_or_else(|| TspError::InvalidMessage("invite is missing its nonce".into()))
    }

    /// The reply digest, erroring if absent (invariant: present iff accept/cancel).
    pub fn require_reply(&self) -> Result<&[u8; DIGEST_LEN], TspError> {
        self.reply
            .as_ref()
            .ok_or_else(|| TspError::InvalidMessage("control is missing its reply digest".into()))
    }

    /// Encode this control message to a compact self-describing byte form.
    ///
    /// This is **not** the TSP wire form (that is the CESR payload frame built in
    /// [`crate::message::direct`]); it is a local encoding so the SDK — which
    /// unpacks a message down to a `payload: Vec<u8>` — can recover a
    /// [`ControlMessage`] via [`ControlMessage::decode`].
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.control_type as u8);

        match self.control_type {
            ControlType::RelationshipFormingInvite => {
                buf.extend_from_slice(self.nonce.as_ref().unwrap_or(&[0u8; DIGEST_LEN]));
                buf.extend_from_slice(&(self.route.len() as u16).to_be_bytes());
                for hop in &self.route {
                    let bytes = hop.as_bytes();
                    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                    buf.extend_from_slice(bytes);
                }
            }
            ControlType::RelationshipFormingAccept | ControlType::RelationshipCancel => {
                buf.extend_from_slice(self.reply.as_ref().unwrap_or(&[0u8; DIGEST_LEN]));
            }
        }
        buf
    }

    /// Decode a control message from its compact self-describing byte form
    /// (the inverse of [`ControlMessage::encode`]).
    pub fn decode(data: &[u8]) -> Result<Self, TspError> {
        let control_type = data
            .first()
            .ok_or_else(|| TspError::InvalidMessage("control message empty".into()))
            .and_then(|b| ControlType::from_byte(*b))?;
        let mut pos = 1;

        match control_type {
            ControlType::RelationshipFormingInvite => {
                let nonce = read_digest(data, &mut pos, "invite nonce")?;
                let hop_count = read_u16(data, &mut pos, "route length")? as usize;
                let mut route = Vec::with_capacity(hop_count);
                for _ in 0..hop_count {
                    let len = read_u16(data, &mut pos, "hop length")? as usize;
                    let end = pos
                        .checked_add(len)
                        .filter(|e| *e <= data.len())
                        .ok_or_else(|| TspError::InvalidMessage("hop VID truncated".into()))?;
                    let hop = String::from_utf8(data[pos..end].to_vec())
                        .map_err(|_| TspError::InvalidMessage("hop VID not UTF-8".into()))?;
                    pos = end;
                    route.push(hop);
                }
                Ok(Self {
                    control_type,
                    nonce: Some(nonce),
                    reply: None,
                    route,
                })
            }
            ControlType::RelationshipFormingAccept | ControlType::RelationshipCancel => {
                let reply = read_digest(data, &mut pos, "reply digest")?;
                Ok(Self {
                    control_type,
                    nonce: None,
                    reply: Some(reply),
                    route: Vec::new(),
                })
            }
        }
    }
}

fn read_u16(data: &[u8], pos: &mut usize, what: &str) -> Result<u16, TspError> {
    let end = *pos + 2;
    if end > data.len() {
        return Err(TspError::InvalidMessage(format!("{what} truncated")));
    }
    let v = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
    *pos = end;
    Ok(v)
}

fn read_digest(data: &[u8], pos: &mut usize, what: &str) -> Result<[u8; DIGEST_LEN], TspError> {
    let end = *pos + DIGEST_LEN;
    if end > data.len() {
        return Err(TspError::InvalidMessage(format!("{what} truncated")));
    }
    let mut out = [0u8; DIGEST_LEN];
    out.copy_from_slice(&data[*pos..end]);
    *pos = end;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_roundtrip() {
        let msg = ControlMessage::invite();
        let decoded = ControlMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.control_type, ControlType::RelationshipFormingInvite);
        assert_eq!(decoded.nonce.unwrap().len(), 32);
        assert!(decoded.reply.is_none());
        assert!(decoded.route.is_empty());
    }

    #[test]
    fn invite_routed_roundtrip() {
        let route = vec!["did:web:hop1".to_string(), "did:web:hop2".to_string()];
        let msg = ControlMessage::invite_routed(route.clone());
        let decoded = ControlMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.route, route);
    }

    #[test]
    fn accept_roundtrip() {
        let reply = [0xAA; 32];
        let msg = ControlMessage::accept(reply);
        let decoded = ControlMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.control_type, ControlType::RelationshipFormingAccept);
        assert_eq!(decoded.reply.unwrap(), reply);
        assert!(decoded.nonce.is_none());
    }

    #[test]
    fn cancel_roundtrip() {
        let reply = [0x55; 32];
        let msg = ControlMessage::cancel(reply);
        let decoded = ControlMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.control_type, ControlType::RelationshipCancel);
        assert_eq!(decoded.reply.unwrap(), reply);
    }

    #[test]
    fn unknown_control_type() {
        assert!(ControlType::from_byte(0xFF).is_err());
    }

    #[test]
    fn truncated_control_message() {
        assert!(ControlMessage::decode(&[]).is_err());
        assert!(ControlMessage::decode(&[0x00]).is_err()); // invite w/o nonce
        assert!(ControlMessage::decode(&[0x01]).is_err()); // accept w/o reply
    }

    #[test]
    fn generate_nonce_uniqueness() {
        assert_ne!(generate_nonce(), generate_nonce());
    }
}
