//! TSP control messages for relationship management.
//!
//! Control messages are sent as TSP message payloads with message type `Control`.
//! They manage the explicit relationship lifecycle that distinguishes TSP from DIDComm.

use serde::{Deserialize, Serialize};

use crate::error::TspError;

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
}

impl ControlMessage {
    /// Create a Relationship Forming Invite.
    pub fn invite() -> Self {
        Self {
            control_type: ControlType::RelationshipFormingInvite,
            thread_id: None,
        }
    }

    /// Create a Relationship Forming Accept referencing the invite.
    pub fn accept(invite_digest: Vec<u8>) -> Self {
        Self {
            control_type: ControlType::RelationshipFormingAccept,
            thread_id: Some(invite_digest),
        }
    }

    /// Create a Relationship Cancel.
    pub fn cancel() -> Self {
        Self {
            control_type: ControlType::RelationshipCancel,
            thread_id: None,
        }
    }

    /// Encode the control message to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let cap = match &self.thread_id {
            Some(digest) => 2 + 2 + digest.len(), // type + flag + len + data
            None => 2,                             // type + flag
        };
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

        buf
    }

    /// Decode a control message from bytes.
    pub fn decode(data: &[u8]) -> Result<Self, TspError> {
        if data.len() < 2 {
            return Err(TspError::InvalidMessage(
                "control message too short".into(),
            ));
        }

        let control_type = ControlType::from_byte(data[0])?;
        let has_thread = data[1] != 0;

        let thread_id = if has_thread {
            if data.len() < 4 {
                return Err(TspError::InvalidMessage(
                    "thread_id length truncated".into(),
                ));
            }
            let len = u16::from_be_bytes([data[2], data[3]]) as usize;
            if data.len() < 4 + len {
                return Err(TspError::InvalidMessage(
                    "thread_id data truncated".into(),
                ));
            }
            Some(data[4..4 + len].to_vec())
        } else {
            None
        };

        Ok(Self {
            control_type,
            thread_id,
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
    }

    #[test]
    fn accept_roundtrip() {
        let digest = vec![0xAA; 32];
        let msg = ControlMessage::accept(digest.clone());
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(
            decoded.control_type,
            ControlType::RelationshipFormingAccept
        );
        assert_eq!(decoded.thread_id.unwrap(), digest);
    }

    #[test]
    fn cancel_roundtrip() {
        let msg = ControlMessage::cancel();
        let encoded = msg.encode();
        let decoded = ControlMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.control_type, ControlType::RelationshipCancel);
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
}
