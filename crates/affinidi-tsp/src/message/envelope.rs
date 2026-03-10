//! TSP message envelope — CESR-encoded header with sender/receiver VIDs.
//!
//! The envelope is used as Additional Authenticated Data (AAD) for HPKE,
//! binding the sender and receiver identities to the ciphertext.

use affinidi_cesr::Matter;

use crate::error::TspError;
use crate::message::MessageType;

/// TSP protocol version.
pub const TSP_VERSION: u8 = 1;

/// A TSP message envelope containing the message metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Protocol version.
    pub version: u8,
    /// Message type.
    pub message_type: MessageType,
    /// Sender VID string.
    pub sender: String,
    /// Receiver VID string.
    pub receiver: String,
}

impl Envelope {
    /// Create a new envelope.
    pub fn new(message_type: MessageType, sender: impl Into<String>, receiver: impl Into<String>) -> Self {
        Self {
            version: TSP_VERSION,
            message_type,
            sender: sender.into(),
            receiver: receiver.into(),
        }
    }

    /// Encode the envelope to CESR bytes.
    ///
    /// Format:
    /// - Version + message type as a 2-byte Matter (code "J", 16-byte seed slot,
    ///   but we use a simpler approach: fixed 2-byte prefix)
    /// - Sender VID as variable-length CESR Matter (code "4B")
    /// - Receiver VID as variable-length CESR Matter (code "4B")
    ///
    /// For simplicity, we use a length-prefixed binary format for the envelope
    /// since CESR variable-length encoding requires 4-byte alignment.
    pub fn encode(&self) -> Result<Vec<u8>, TspError> {
        let sender_bytes = self.sender.as_bytes();
        let receiver_bytes = self.receiver.as_bytes();

        // Pre-allocate: 2 (header) + 2 (sender len) + sender + 2 (receiver len) + receiver
        let mut buf = Vec::with_capacity(6 + sender_bytes.len() + receiver_bytes.len());

        // Fixed header: version (1 byte) + message type (1 byte)
        buf.push(self.version);
        buf.push(self.message_type as u8);

        // Sender VID: length-prefixed (2 bytes big-endian + UTF-8)
        let sender_len = sender_bytes.len() as u16;
        buf.extend_from_slice(&sender_len.to_be_bytes());
        buf.extend_from_slice(sender_bytes);

        // Receiver VID: length-prefixed (2 bytes big-endian + UTF-8)
        let receiver_len = receiver_bytes.len() as u16;
        buf.extend_from_slice(&receiver_len.to_be_bytes());
        buf.extend_from_slice(receiver_bytes);

        Ok(buf)
    }

    /// Decode an envelope from bytes. Returns (envelope, bytes_consumed).
    pub fn decode(data: &[u8]) -> Result<(Self, usize), TspError> {
        if data.len() < 6 {
            return Err(TspError::InvalidMessage("envelope too short".into()));
        }

        let version = data[0];
        if version != TSP_VERSION {
            return Err(TspError::InvalidMessage(format!(
                "unsupported TSP version: {version}"
            )));
        }

        let message_type = MessageType::from_byte(data[1])?;
        let mut pos = 2;

        // Sender VID
        let sender_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + sender_len > data.len() {
            return Err(TspError::InvalidMessage("sender VID truncated".into()));
        }
        let sender = std::str::from_utf8(&data[pos..pos + sender_len])
            .map_err(|_| TspError::InvalidMessage("invalid sender VID encoding".into()))?
            .to_string();
        pos += sender_len;

        // Receiver VID
        if pos + 2 > data.len() {
            return Err(TspError::InvalidMessage("receiver length truncated".into()));
        }
        let receiver_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + receiver_len > data.len() {
            return Err(TspError::InvalidMessage("receiver VID truncated".into()));
        }
        let receiver = std::str::from_utf8(&data[pos..pos + receiver_len])
            .map_err(|_| TspError::InvalidMessage("invalid receiver VID encoding".into()))?
            .to_string();
        pos += receiver_len;

        Ok((
            Envelope {
                version,
                message_type,
                sender,
                receiver,
            },
            pos,
        ))
    }

    /// Encode the sender VID as a CESR Matter primitive (qb64).
    pub fn sender_matter(&self) -> Result<Matter, TspError> {
        Ok(Matter::new("4B", self.sender.as_bytes().to_vec())?)
    }

    /// Encode the receiver VID as a CESR Matter primitive (qb64).
    pub fn receiver_matter(&self) -> Result<Matter, TspError> {
        Ok(Matter::new("4B", self.receiver.as_bytes().to_vec())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_encode_decode_roundtrip() {
        let env = Envelope::new(
            MessageType::Direct,
            "did:example:alice",
            "did:example:bob",
        );

        let encoded = env.encode().unwrap();
        let (decoded, consumed) = Envelope::decode(&encoded).unwrap();

        assert_eq!(decoded, env);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn envelope_version() {
        let env = Envelope::new(MessageType::Direct, "alice", "bob");
        assert_eq!(env.version, TSP_VERSION);
    }

    #[test]
    fn envelope_invalid_version() {
        let mut data = Envelope::new(MessageType::Direct, "a", "b")
            .encode()
            .unwrap();
        data[0] = 99; // bad version
        assert!(Envelope::decode(&data).is_err());
    }

    #[test]
    fn envelope_truncated() {
        assert!(Envelope::decode(&[1, 0]).is_err());
    }

    #[test]
    fn envelope_cesr_matter() {
        let env = Envelope::new(MessageType::Direct, "did:example:alice", "did:example:bob");
        let sender_m = env.sender_matter().unwrap();
        assert_eq!(sender_m.code(), "4B");
        assert_eq!(sender_m.raw(), b"did:example:alice");
    }

    #[test]
    fn envelope_control_type() {
        let env = Envelope::new(MessageType::Control, "alice", "bob");
        let encoded = env.encode().unwrap();
        let (decoded, _) = Envelope::decode(&encoded).unwrap();
        assert_eq!(decoded.message_type, MessageType::Control);
    }
}
