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

    /// Encode the envelope to CESR qb2 (binary) bytes.
    ///
    /// Wire format (all CESR qb2-encoded, concatenated):
    /// 1. Header Matter (code `"1AAF"` / Tag1, 3 raw bytes):
    ///    `[version, message_type, 0x00]`
    /// 2. Sender VID Matter (code `"4B"`, variable-length raw bytes)
    /// 3. Receiver VID Matter (code `"4B"`, variable-length raw bytes)
    pub fn encode(&self) -> Result<Vec<u8>, TspError> {
        // Header: version + message_type + padding byte → 3 raw bytes in Tag1
        let header = Matter::new("1AAF", vec![self.version, self.message_type as u8, 0x00])?;
        let sender = Matter::new("4B", self.sender.as_bytes().to_vec())?;
        let receiver = Matter::new("4B", self.receiver.as_bytes().to_vec())?;

        let header_qb2 = header.qb2()?;
        let sender_qb2 = sender.qb2()?;
        let receiver_qb2 = receiver.qb2()?;

        let mut buf = Vec::with_capacity(
            header_qb2.len() + sender_qb2.len() + receiver_qb2.len(),
        );
        buf.extend_from_slice(&header_qb2);
        buf.extend_from_slice(&sender_qb2);
        buf.extend_from_slice(&receiver_qb2);

        Ok(buf)
    }

    /// Decode an envelope from CESR qb2 bytes. Returns (envelope, bytes_consumed).
    pub fn decode(data: &[u8]) -> Result<(Self, usize), TspError> {
        // 1. Parse header Matter (fixed-length Tag1: 6 qb2 bytes)
        let header = Matter::from_qb2(data)
            .map_err(|e| TspError::InvalidMessage(format!("envelope header: {e}")))?;
        if header.code() != "1AAF" {
            return Err(TspError::InvalidMessage(format!(
                "expected header code 1AAF, got {}",
                header.code()
            )));
        }
        let header_raw = header.raw();
        if header_raw.len() < 2 {
            return Err(TspError::InvalidMessage("header raw too short".into()));
        }
        let version = header_raw[0];
        if version != TSP_VERSION {
            return Err(TspError::InvalidMessage(format!(
                "unsupported TSP version: {version}"
            )));
        }
        let message_type = MessageType::from_byte(header_raw[1])?;
        let mut pos = header.full_size_qb2();

        // 2. Parse sender VID Matter (variable-length)
        let sender_matter = Matter::from_qb2(&data[pos..])
            .map_err(|e| TspError::InvalidMessage(format!("sender VID: {e}")))?;
        let sender = std::str::from_utf8(sender_matter.raw())
            .map_err(|_| TspError::InvalidMessage("invalid sender VID encoding".into()))?
            .to_string();
        pos += sender_matter.full_size_qb2();

        // 3. Parse receiver VID Matter (variable-length)
        let receiver_matter = Matter::from_qb2(&data[pos..])
            .map_err(|e| TspError::InvalidMessage(format!("receiver VID: {e}")))?;
        let receiver = std::str::from_utf8(receiver_matter.raw())
            .map_err(|_| TspError::InvalidMessage("invalid receiver VID encoding".into()))?
            .to_string();
        pos += receiver_matter.full_size_qb2();

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
        let env = Envelope::new(MessageType::Direct, "a", "b");
        let mut data = env.encode().unwrap();
        // The version byte is inside the Tag1 Matter's raw payload.
        // Easiest way to test: construct a valid CESR envelope with bad version.
        let bad_header = Matter::new("1AAF", vec![99, 0x00, 0x00]).unwrap();
        let bad_qb2 = bad_header.qb2().unwrap();
        // Replace the header portion (first 6 bytes for Tag1 qb2)
        data[..bad_qb2.len()].copy_from_slice(&bad_qb2);
        assert!(Envelope::decode(&data).is_err());
    }

    #[test]
    fn envelope_truncated() {
        // Too short to contain even the header Matter
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
