//! TSP message envelope — the binary-CESR `-E` frame (spec Rev 3 §9.1).
//!
//! The envelope is the cleartext outer frame of a TSP message. It carries the
//! TSP version, the sender VID and the receiver VID.
//!
//! Rev 3 changed two things that reach right through the packing code:
//!
//! 1. **One frame for everything.** The `-E` count now covers *all* signable
//!    content — version, VIDs and the ciphertext — where Rev 2's count covered
//!    only the header fields. It therefore cannot be written until the
//!    ciphertext size is known, which is why encoding is split into
//!    [`Envelope::encode_fields`] (the part that exists before sealing) and
//!    [`finalize_frame`] (the part that exists after). Rev 2's separate `-S`
//!    signed-only wrapper is gone: a signed-only message is an `-E` frame whose
//!    payload field is cleartext.
//!
//! 2. **The trailing `XAAA` marker is deleted.** Rev 2 emitted a 2-byte `X 00
//!    00` field after the VIDs. Rev 3 removes it; the receiver-VID field is
//!    always present instead, with the NULL VID `4BAA` meaning "absent".
//!
//! The encoded *fields* — version ‖ VID_sndr ‖ VID_rcvr, without the `-E` count
//! code — are the HPKE-Base associated data (§8). `TSP_Tag` is deliberately not
//! part of the AAD, which is exactly why the split falls where it does.
//!
//! Wire layout:
//! ```text
//! -E<count>                     count = quadlets of everything below
//!   YTSP <version>              `YTSP-ABA` for version 0.1.0
//!   <var-data B> sender-VID
//!   <var-data B> receiver-VID   `4BAA` when absent
//!   <ciphertext or payload>     supplied by the caller
//! ```

use std::ops::Range;

use crate::error::TspError;
use crate::message::MessageType;
use crate::message::wire;

/// TSP protocol version (major) advertised on the wire.
pub const TSP_VERSION: u8 = 0;

/// A TSP message envelope (cleartext header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Protocol version (major).
    pub version: u8,
    /// Message type. Not carried in the cleartext envelope; kept for API
    /// stability and populated from the decrypted payload on unpack.
    pub message_type: MessageType,
    /// Sender VID string.
    pub sender: String,
    /// Receiver VID string. An empty string is the Rev 3 NULL VID `4BAA` —
    /// "no receiver named in the envelope" — which is not a valid VID, so the
    /// empty string is unambiguous as its representation.
    pub receiver: String,
}

/// A decoded envelope plus the byte offsets a caller needs to verify it.
#[derive(Debug, Clone)]
pub struct DecodedEnvelope {
    /// The parsed envelope.
    pub envelope: Envelope,
    /// Byte range of the encoded envelope fields — the HPKE-Base AAD.
    pub aad: Range<usize>,
    /// Offset just past the envelope fields: where the ciphertext (or
    /// cleartext payload) field begins.
    pub header_len: usize,
    /// Offset just past the signable content declared by the `-E` count, i.e.
    /// where the signature attachment begins.
    pub content_end: usize,
    /// MINOR version carried by the message. Never gates processing.
    pub minor: u8,
    /// PATCH version carried by the message. Never gates processing.
    pub patch: u8,
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

    /// Encode the envelope *fields* — version, sender VID, receiver VID —
    /// without the enclosing `-E` count code.
    ///
    /// These bytes are the HPKE-Base associated data (Rev 3 §8:
    /// `aad = CONCAT(TSP_Version, VID_sndr, VID_rcvr)`). Pass the result to
    /// [`finalize_frame`] once the ciphertext exists.
    pub fn encode_fields(&self) -> Result<Vec<u8>, TspError> {
        let mut body = Vec::new();
        wire::encode_version(&mut body);
        wire::encode_variable_data(wire::TSP_VID, self.sender.as_bytes(), &mut body);
        wire::encode_variable_data(wire::TSP_VID, self.receiver.as_bytes(), &mut body);

        if !body.len().is_multiple_of(3) {
            return Err(TspError::InvalidMessage(
                "envelope fields not a multiple of 3 bytes".into(),
            ));
        }
        Ok(body)
    }

    /// Decode an envelope from the start of `data`. Returns the envelope and
    /// the number of bytes consumed by the envelope fields.
    pub fn decode(data: &[u8]) -> Result<(Self, usize), TspError> {
        let decoded = Self::decode_full(data)?;
        Ok((decoded.envelope, decoded.header_len))
    }

    /// Decode an envelope and report the offsets needed to open and verify it.
    pub fn decode_full(data: &[u8]) -> Result<DecodedEnvelope, TspError> {
        let mut pos = 0usize;

        // The `-E` frame. Its count is validated against the message length:
        // Rev 3 §9.1 requires the declared signable length to be checked on
        // receive, so a frame claiming more content than the message holds is
        // rejected here rather than surfacing as a confusing failure later.
        let quadlets = wire::decode_count(wire::TSP_ETS_WRAPPER, data, &mut pos)
            .ok_or_else(|| TspError::NotTsp("missing -E envelope frame".into()))?;
        let content_begin = pos;
        let content_end = (quadlets as usize)
            .checked_mul(3)
            .and_then(|len| content_begin.checked_add(len))
            .filter(|end| *end <= data.len())
            .ok_or_else(|| {
                TspError::InvalidMessage("-E frame declares more content than the message".into())
            })?;

        // Version marker. MAJOR gates processability; MINOR/PATCH are carried.
        let (_, minor, patch) = wire::decode_version(data, &mut pos)?;

        let aad_begin = content_begin;

        // Sender VID.
        let sender_bytes = wire::decode_variable_data(wire::TSP_VID, data, &mut pos)
            .ok_or_else(|| TspError::InvalidMessage("missing sender VID".into()))?;
        let sender = String::from_utf8(sender_bytes)
            .map_err(|_| TspError::InvalidMessage("sender VID is not UTF-8".into()))?;
        if sender.is_empty() {
            return Err(TspError::InvalidMessage(
                "sender VID is the NULL VID; every TSP message names its sender".into(),
            ));
        }

        // Receiver VID. Always present; `4BAA` (empty) means "absent".
        let receiver_bytes = wire::decode_variable_data(wire::TSP_VID, data, &mut pos)
            .ok_or_else(|| TspError::InvalidMessage("missing receiver VID field".into()))?;
        let receiver = String::from_utf8(receiver_bytes)
            .map_err(|_| TspError::InvalidMessage("receiver VID is not UTF-8".into()))?;

        if pos > content_end {
            return Err(TspError::InvalidMessage(
                "envelope fields overrun the -E frame count".into(),
            ));
        }

        Ok(DecodedEnvelope {
            envelope: Envelope {
                version: TSP_VERSION,
                // Not on the wire; populated from the payload frame on unpack.
                message_type: MessageType::Direct,
                sender,
                receiver,
            },
            aad: aad_begin..pos,
            header_len: pos,
            content_end,
            minor,
            patch,
        })
    }
}

/// Prepend the `-E` count code to `fields ‖ body`, producing the complete
/// envelope frame.
///
/// `fields` is the output of [`Envelope::encode_fields`]; `body` is the
/// ciphertext field (or, for a signed-only message, the cleartext payload
/// frame). The count covers both, and excludes the signature attachment that
/// the caller appends afterwards.
pub fn finalize_frame(fields: &[u8], body: &[u8]) -> Result<Vec<u8>, TspError> {
    let content_len = fields.len() + body.len();
    if !content_len.is_multiple_of(3) {
        return Err(TspError::InvalidMessage(
            "envelope content not a multiple of 3 bytes".into(),
        ));
    }
    let mut out = Vec::with_capacity(6 + content_len);
    wire::encode_count(wire::TSP_ETS_WRAPPER, (content_len / 3) as u32, &mut out);
    out.extend_from_slice(fields);
    out.extend_from_slice(body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(sender: &str, receiver: &str, body: &[u8]) -> Vec<u8> {
        let env = Envelope::new(MessageType::Direct, sender, receiver);
        finalize_frame(&env.encode_fields().unwrap(), body).unwrap()
    }

    #[test]
    fn envelope_encode_decode_roundtrip() {
        let body = vec![0u8; 9];
        let encoded = frame("did:web:alice.example", "did:web:bob.example", &body);
        let decoded = Envelope::decode_full(&encoded).unwrap();
        assert_eq!(decoded.envelope.sender, "did:web:alice.example");
        assert_eq!(decoded.envelope.receiver, "did:web:bob.example");
        // The -E count covers the fields *and* the body.
        assert_eq!(decoded.content_end, encoded.len());
        assert_eq!(decoded.header_len, encoded.len() - body.len());
    }

    #[test]
    fn aad_is_the_fields_without_the_count_code() {
        let env = Envelope::new(MessageType::Direct, "did:web:a", "did:web:b");
        let fields = env.encode_fields().unwrap();
        let encoded = finalize_frame(&fields, &[0u8; 3]).unwrap();
        let decoded = Envelope::decode_full(&encoded).unwrap();
        assert_eq!(&encoded[decoded.aad.clone()], &fields[..]);
    }

    #[test]
    fn envelope_carries_no_xaaa_marker() {
        // Rev 2 emitted `X 00 00` after the VIDs; Rev 3 deletes it, so the
        // fields end exactly at the end of the receiver VID.
        let env = Envelope::new(MessageType::Direct, "did:web:a", "did:web:b");
        let fields = env.encode_fields().unwrap();
        let mut pos = 0;
        wire::decode_version(&fields, &mut pos).unwrap();
        wire::decode_variable_data(wire::TSP_VID, &fields, &mut pos).unwrap();
        wire::decode_variable_data(wire::TSP_VID, &fields, &mut pos).unwrap();
        assert_eq!(pos, fields.len());
    }

    #[test]
    fn null_receiver_vid_roundtrips_as_empty() {
        let encoded = frame("did:web:a", "", &[0u8; 3]);
        let decoded = Envelope::decode_full(&encoded).unwrap();
        assert_eq!(decoded.envelope.receiver, "");
        // The NULL VID is `4BAA`: a var-data B field of size 0.
        let mut pos = 0;
        wire::decode_count(wire::TSP_ETS_WRAPPER, &encoded, &mut pos).unwrap();
        wire::decode_version(&encoded, &mut pos).unwrap();
        wire::decode_variable_data(wire::TSP_VID, &encoded, &mut pos).unwrap();
        assert_eq!(&encoded[pos..pos + 3], &[0xe0, 0x10, 0x00]);
    }

    #[test]
    fn null_sender_vid_is_rejected() {
        let encoded = frame("", "did:web:b", &[0u8; 3]);
        assert!(Envelope::decode_full(&encoded).is_err());
    }

    #[test]
    fn frame_count_shorter_than_content_is_rejected() {
        let env = Envelope::new(MessageType::Direct, "did:web:a", "did:web:b");
        let fields = env.encode_fields().unwrap();
        // Claim one quadlet of content; the fields alone are longer.
        let mut bad = Vec::new();
        wire::encode_count(wire::TSP_ETS_WRAPPER, 1, &mut bad);
        bad.extend_from_slice(&fields);
        assert!(Envelope::decode_full(&bad).is_err());
    }

    #[test]
    fn frame_count_longer_than_message_is_rejected() {
        let mut bad = Vec::new();
        wire::encode_count(wire::TSP_ETS_WRAPPER, 4000, &mut bad);
        bad.extend_from_slice(&[0u8; 12]);
        assert!(Envelope::decode_full(&bad).is_err());
    }

    #[test]
    fn envelope_truncated() {
        assert!(Envelope::decode(&[0xf8, 0x40]).is_err());
        assert!(Envelope::decode(&[1, 0]).is_err());
    }
}
