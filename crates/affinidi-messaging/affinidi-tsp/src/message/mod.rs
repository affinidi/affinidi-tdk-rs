//! TSP message types, encoding, and direct mode operations.

pub mod control;
pub mod direct;
pub mod envelope;

use crate::error::TspError;

/// TSP message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Direct message — sender to receiver, no intermediaries.
    Direct = 0x00,
    /// Nested message — inner TSP message wrapped for metadata privacy.
    Nested = 0x01,
    /// Routed message — message relayed through intermediaries.
    Routed = 0x02,
    /// Control message — relationship management (RFI/RFA/RFD).
    Control = 0x03,
}

impl MessageType {
    pub fn from_byte(b: u8) -> Result<Self, TspError> {
        match b {
            0x00 => Ok(MessageType::Direct),
            0x01 => Ok(MessageType::Nested),
            0x02 => Ok(MessageType::Routed),
            0x03 => Ok(MessageType::Control),
            _ => Err(TspError::InvalidMessage(format!(
                "unknown message type: 0x{b:02x}"
            ))),
        }
    }
}
