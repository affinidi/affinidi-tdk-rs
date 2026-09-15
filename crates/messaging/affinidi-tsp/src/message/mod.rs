//! TSP message types, encoding, and direct mode operations.

pub mod control;
pub mod direct;
pub mod envelope;
pub mod meta;
pub mod routed;
pub mod wire;

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
    /// Generic control message (`XCTL`) — control for the layer above TSP,
    /// carried opaquely.
    ///
    /// Distinct from [`MessageType::Control`], which is TSP's own relationship
    /// lifecycle and has a defined structure. §9.2: "The `CTL` type allows
    /// control messages in unrestricted generic format", and §7.1: "Higher
    /// layers define their own content within the XSCS (data) and XCTL
    /// (control) payloads, which TSP carries opaquely."
    GenericControl = 0x04,
    /// Padding message (`XPAD`) — a message that carries nothing but its own
    /// metadata.
    ///
    /// §9.2: "This type is used to generate messages that carry no meaningful
    /// information other than its metadata." It exists to make traffic harder
    /// to read: §11 notes that timing, size and frequency survive encryption,
    /// nesting and routing alike, and a message with no content still occupies
    /// all three.
    ///
    /// §7.4.3 gives it a second use. An endpoint rotating keys because they may
    /// have been compromised "may also send a padding message to the peers with
    /// which it has relationships. A peer holding stale key state will fail to
    /// verify it and will therefore obtain the new key state, whereas a peer
    /// that receives nothing has no occasion to."
    PaddingOnly = 0x05,
}

impl MessageType {
    pub fn from_byte(b: u8) -> Result<Self, TspError> {
        match b {
            0x00 => Ok(MessageType::Direct),
            0x01 => Ok(MessageType::Nested),
            0x02 => Ok(MessageType::Routed),
            0x03 => Ok(MessageType::Control),
            0x04 => Ok(MessageType::GenericControl),
            0x05 => Ok(MessageType::PaddingOnly),
            _ => Err(TspError::InvalidMessage(format!(
                "unknown message type: 0x{b:02x}"
            ))),
        }
    }
}
