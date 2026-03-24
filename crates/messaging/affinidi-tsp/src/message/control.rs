//! TSP control messages for relationship management.
//!
//! Control messages are sent as TSP message payloads with message type `Control`.
//! They manage the explicit relationship lifecycle that distinguishes TSP from DIDComm.

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::TspError;

/// Generate a cryptographically random 16-byte nonce.
pub fn generate_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// TSP control message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ControlType {
    /// Relationship Forming Invite — initiates a relationship.
    RelationshipFormingInvite = 0x00,
    /// Relationship Forming Accept — accepts an invite.
    RelationshipFormingAccept = 0x01,
    /// Relationship Cancel — terminates a relationship.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlMessage {
    /// The control message type.
    pub control_type: ControlType,
    /// Optional thread reference (digest of the message being responded to).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<Vec<u8>>,
    /// Optional 16-byte nonce for replay protection (present in RFI and RFA messages).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<[u8; 16]>,
}

impl ControlMessage {
    /// Create a Relationship Forming Invite (with a random nonce).
    pub fn invite() -> Self {
        Self {
            control_type: ControlType::RelationshipFormingInvite,
            thread_id: None,
            nonce: Some(generate_nonce()),
        }
    }

    /// Create a Relationship Forming Accept referencing the invite (with a random nonce).
    pub fn accept(invite_digest: Vec<u8>) -> Self {
        Self {
            control_type: ControlType::RelationshipFormingAccept,
            thread_id: Some(invite_digest),
            nonce: Some(generate_nonce()),
        }
    }

    /// Create a Relationship Cancel.
    pub fn cancel() -> Self {
        Self {
            control_type: ControlType::RelationshipCancel,
            thread_id: None,
            nonce: None,
        }
    }

    /// Encode the control message to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut cap = 2; // type + thread_id flag
        if let Some(digest) = &self.thread_id {
            cap += 2 + digest.len(); // len + data
        }
        cap += 1; // nonce presence flag
        if self.nonce.is_some() {
            cap += 16;
        }

        let mut buf = Vec::with_capacity(cap);
        buf.push(self.control_type as u8);

        match &self.thread_id {
            Some(digest) => {
                buf.push(1); // has thread_id
                let len = digest.len() as u16;
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(digest);
            }
            None => {
                buf.push(0); // no thread_id
            }
        }

        // Nonce: 1-byte presence flag + 16 bytes if present
        match &self.nonce {
            Some(nonce) => {
                buf.push(1);
                buf.extend_from_slice(nonce);
            }
            None => {
                buf.push(0);
            }
        }

        buf
    }

    /// Decode a control message from bytes.
    pub fn decode(data: &[u8]) -> Result<Self, TspError> {
        if data.len() < 2 {
            return Err(TspError::InvalidMessage("control message too short".into()));
        }

        let control_type = ControlType::from_byte(data[0])?;
        let has_thread = data[1] != 0;

        let mut offset = 2;
        let thread_id = if has_thread {
            if data.len() < offset + 2 {
                return Err(TspError::InvalidMessage(
                    "thread_id length truncated".into(),
                ));
            }
            let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            if data.len() < offset + len {
                return Err(TspError::InvalidMessage("thread_id data truncated".into()));
            }
            let tid = Some(data[offset..offset + len].to_vec());
            offset += len;
            tid
        } else {
            None
        };

        // Nonce: 1-byte presence flag + 16 bytes if present
        let nonce = if offset < data.len() {
            let has_nonce = data[offset] != 0;
            offset += 1;
            if has_nonce {
                if data.len() < offset + 16 {
                    return Err(TspError::InvalidMessage("nonce data truncated".into()));
                }
                let mut n = [0u8; 16];
                n.copy_from_slice(&data[offset..offset + 16]);
                Some(n)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            control_type,
            thread_id,
            nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_roundtrip() {
        let msg = ControlMessage::invite();
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.control_type, ControlType::RelationshipFormingInvite);
        assert!(decoded.thread_id.is_none());
        assert!(decoded.nonce.is_some());
        assert_eq!(decoded.nonce.unwrap().len(), 16);
    }

    #[test]
    fn accept_roundtrip() {
        let digest = vec![0xAA; 32];
        let msg = ControlMessage::accept(digest.clone());
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.control_type, ControlType::RelationshipFormingAccept);
        assert_eq!(decoded.thread_id.unwrap(), digest);
        assert!(decoded.nonce.is_some());
        assert_eq!(decoded.nonce.unwrap().len(), 16);
    }

    #[test]
    fn cancel_roundtrip() {
        let msg = ControlMessage::cancel();
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.control_type, ControlType::RelationshipCancel);
        assert!(decoded.nonce.is_none());
    }

    #[test]
    fn unknown_control_type() {
        assert!(ControlType::from_byte(0xFF).is_err());
    }

    #[test]
    fn truncated_control_message() {
        assert!(ControlMessage::decode(&[]).is_err());
        assert!(ControlMessage::decode(&[0x00]).is_err());
    }

    #[test]
    fn generate_nonce_uniqueness() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2, "two consecutive nonces should differ");
    }

    #[test]
    fn nonce_truncated_in_decode() {
        // Build a message with nonce presence flag = 1, but only 5 bytes of nonce data
        let mut buf = vec![0x00, 0x00]; // invite, no thread_id
        buf.push(1); // has nonce
        buf.extend_from_slice(&[0u8; 5]); // only 5 bytes instead of 16
        assert!(ControlMessage::decode(&buf).is_err());
    }

    #[test]
    fn backward_compat_no_nonce_field() {
        // Simulate a legacy message that lacks the nonce byte entirely
        let buf = vec![0x02, 0x00]; // cancel, no thread_id, no nonce field
        let decoded = ControlMessage::decode(&buf).unwrap();
        assert_eq!(decoded.control_type, ControlType::RelationshipCancel);
        assert!(decoded.nonce.is_none());
    }

    #[test]
    fn explicit_nonce_none_roundtrip() {
        // A message that has the nonce presence flag set to 0
        let msg = ControlMessage {
            control_type: ControlType::RelationshipCancel,
            thread_id: None,
            nonce: None,
        };
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
        assert!(decoded.nonce.is_none());
    }
}
