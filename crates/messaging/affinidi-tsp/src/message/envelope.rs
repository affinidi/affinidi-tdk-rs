//! TSP message envelope — the binary-CESR `-E` (encrypted-then-signed) header.
//!
//! The envelope is the cleartext outer frame of a TSP message. It carries the
//! TSP version, the sender VID and receiver VID, and is byte-compatible with the
//! ToIP `tsp-sdk` reference. The encoded envelope frame is used verbatim as the
//! HPKE Additional Authenticated Data (AAD), binding sender/receiver identities
//! to the ciphertext.
//!
//! Wire layout of the envelope (the `-E` count-code group):
//! ```text
//! -E<count>                       (TSP_ETS_WRAPPER count code; count = quadlets)
//!   YTSP <version-count>          (encode_version)
//!   <var-data B> sender-VID       (encode_variable_data TSP_VID)
//!   <var-data B> receiver-VID     (encode_variable_data TSP_VID)
//!   X 00 00                       (encode_fixed_data TSP_TMP, 2 zero bytes)
//! ```
//!
//! Note: unlike the previous bespoke format, the message *kind*
//! (Direct/Nested/Routed/Control) is **not** carried in the cleartext envelope.
//! In TSP the kind lives in the encrypted payload frame (see [`crate::message::direct`]).
//! For the Direct-only interop scope, [`Envelope::decode`] reports
//! [`MessageType::Direct`]; carrying the other kinds is a follow-up.

use crate::error::TspError;
use crate::message::MessageType;
use crate::message::wire;

/// TSP protocol version (major) advertised on the wire.
pub const TSP_VERSION: u8 = 1;

/// A TSP message envelope (cleartext header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Protocol version (major).
    pub version: u8,
    /// Message type. Not carried in the cleartext interop envelope; kept for API
    /// stability and populated from the decrypted payload on unpack.
    pub message_type: MessageType,
    /// Sender VID string.
    pub sender: String,
    /// Receiver VID string.
    pub receiver: String,
}

/// A decoded envelope plus the exact byte range of its encoded `-E` frame, which
/// is the HPKE AAD (`raw_header`).
#[derive(Debug, Clone)]
pub struct DecodedEnvelope {
    /// The parsed envelope.
    pub envelope: Envelope,
    /// Number of bytes consumed by the `-E` envelope frame (the AAD length).
    pub header_len: usize,
}

impl Envelope {
    /// Create a new envelope.
    pub fn new(
        message_type: MessageType,
        sender: impl Into<String>,
        receiver: impl Into<String>,
    ) -> Self {
        Self {
            version: TSP_VERSION,
            message_type,
            sender: sender.into(),
            receiver: receiver.into(),
        }
    }

    /// Encode the envelope to its binary-CESR `-E` frame bytes.
    ///
    /// The returned bytes are exactly the HPKE AAD for the message.
    pub fn encode(&self) -> Result<Vec<u8>, TspError> {
        // Build the envelope body first so we can prefix it with the count code.
        let mut body = Vec::new();
        wire::encode_version(&mut body);
        wire::encode_variable_data(wire::TSP_VID, self.sender.as_bytes(), &mut body);
        wire::encode_variable_data(wire::TSP_VID, self.receiver.as_bytes(), &mut body);
        wire::encode_fixed_data(wire::TSP_TMP, &[0u8, 0u8], &mut body);

        if !body.len().is_multiple_of(3) {
            return Err(TspError::InvalidMessage(
                "envelope body not a multiple of 3 bytes".into(),
            ));
        }

        let mut out = Vec::with_capacity(3 + body.len());
        wire::encode_count(wire::TSP_ETS_WRAPPER, (body.len() / 3) as u32, &mut out);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode an envelope from the start of `data`. Returns the envelope and the
    /// number of bytes consumed (the AAD length).
    pub fn decode(data: &[u8]) -> Result<(Self, usize), TspError> {
        let decoded = Self::decode_full(data)?;
        Ok((decoded.envelope, decoded.header_len))
    }

    /// Decode an envelope and report the AAD (`-E` frame) byte length.
    pub fn decode_full(data: &[u8]) -> Result<DecodedEnvelope, TspError> {
        let mut pos = 0usize;

        // Outer ETS wrapper count code (we don't need the count value: we parse
        // the fields directly, matching the reference decoder).
        wire::decode_count(wire::TSP_ETS_WRAPPER, data, &mut pos)
            .ok_or_else(|| TspError::InvalidMessage("missing -E envelope wrapper".into()))?;

        // Version marker.
        wire::decode_version(data, &mut pos)?;

        // Sender VID.
        let sender_bytes = wire::decode_variable_data(wire::TSP_VID, data, &mut pos)
            .ok_or_else(|| TspError::InvalidMessage("missing sender VID".into()))?;
        let sender = String::from_utf8(sender_bytes)
            .map_err(|_| TspError::InvalidMessage("invalid sender VID encoding".into()))?;

        // Receiver VID.
        let receiver_bytes = wire::decode_variable_data(wire::TSP_VID, data, &mut pos)
            .ok_or_else(|| TspError::InvalidMessage("missing receiver VID".into()))?;
        let receiver = String::from_utf8(receiver_bytes)
            .map_err(|_| TspError::InvalidMessage("invalid receiver VID encoding".into()))?;

        // The 2-byte TMP marker (consumed if present; the reference emits it
        // unconditionally for encrypted messages).
        let _ = wire::decode_fixed_data::<2>(wire::TSP_TMP, data, &mut pos);

        Ok(DecodedEnvelope {
            envelope: Envelope {
                version: TSP_VERSION,
                // Not on the wire; populated from the payload frame on unpack.
                message_type: MessageType::Direct,
                sender,
                receiver,
            },
            header_len: pos,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_encode_decode_roundtrip() {
        let env = Envelope::new(MessageType::Direct, "did:web:alice.example", "did:web:bob.example");
        let encoded = env.encode().unwrap();
        let (decoded, consumed) = Envelope::decode(&encoded).unwrap();
        assert_eq!(decoded.sender, env.sender);
        assert_eq!(decoded.receiver, env.receiver);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn envelope_first_byte_is_count_code() {
        let env = Envelope::new(MessageType::Direct, "a", "b");
        let encoded = env.encode().unwrap();
        // -E count code => first byte 0xf8.
        assert_eq!(encoded[0], 0xf8);
    }

    #[test]
    fn envelope_matches_reference_header() {
        // Reference bytes from tsp-sdk seal(Bob->Alice) for these exact VIDs.
        let env = Envelope::new(
            MessageType::Direct,
            "did:web:bob.example",
            "did:web:alice.example",
        );
        let encoded = env.encode().unwrap();
        let expected: &[u8] = &[
            0xf8, 0x40, 0x13, // -E count 19
            0x61, 0x34, 0x8f, // YTSP
            0xf8, 0x00, 0x01, // version count
            0xe8, 0x10, 0x07, 0x00, 0x00, // sender var-data header + 2 lead
        ];
        assert_eq!(&encoded[..expected.len()], expected);
        // The whole header is 19 quadlets * 3 + 3 (count) = 60 bytes.
        assert_eq!(encoded.len(), 60);
    }

    #[test]
    fn envelope_truncated() {
        assert!(Envelope::decode(&[0xf8, 0x40]).is_err());
        assert!(Envelope::decode(&[1, 0]).is_err());
    }
}
