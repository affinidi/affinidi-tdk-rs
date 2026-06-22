//! Ingress sniffing and keys-free envelope metadata.
//!
//! A mediator (or any relay) receiving raw bytes needs to decide *what* a
//! message is and *who* it is for **without** holding any keys — to route it,
//! enforce ACLs, and store it. These helpers provide exactly that:
//!
//! - [`is_tsp`] — a cheap first-byte classifier distinguishing a TSP message
//!   from other wire formats (e.g. JSON-based DIDComm).
//! - [`MetaEnvelope`] — the cleartext envelope (sender VID, receiver VID,
//!   message type) plus the message id, parsed without decrypting the payload.

use sha2::{Digest, Sha256};

use crate::error::TspError;
use crate::message::MessageType;
use crate::message::envelope::Envelope;

/// The leading byte of every TSP message: the CESR Tag1 qb2 magic for code
/// `1AAF` (the full 3-byte magic is `D4 00 05`). DIDComm — being JSON or
/// compact-JWS — starts with `{` (`0x7B`) or `ey…` instead, so this byte is an
/// unambiguous discriminator.
pub const TSP_MAGIC_BYTE: u8 = 0xD4;

/// Cheap classifier: does `bytes` look like a TSP message?
///
/// This is a pre-classifier for ingress routing, not a validator — it inspects
/// only the leading byte. A caller routes `is_tsp(bytes)` input to the TSP
/// handler, which then calls [`MetaEnvelope::parse`] (or a full unpack) to
/// validate and reject anything malformed. Anything not starting with the TSP
/// magic byte is definitely not a TSP message.
pub fn is_tsp(bytes: &[u8]) -> bool {
    bytes.first() == Some(&TSP_MAGIC_BYTE)
}

/// Cleartext metadata of a TSP message, parsed without any keys.
///
/// The TSP envelope carries the sender VID, receiver VID, version, and message
/// type in the clear (they are HPKE additional-authenticated data, bound to the
/// ciphertext but readable). This lets a relay route and account for a message
/// without being able to decrypt its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaEnvelope {
    /// The sender VID.
    pub sender: String,
    /// The receiver VID (the next hop / addressee).
    pub receiver: String,
    /// The message type (Direct / Nested / Routed / Control).
    pub message_type: MessageType,
    /// SHA-256 of the full wire bytes — the message id used for storage and
    /// idempotency (matches the convention of DIDComm-based mediators).
    pub sha256: [u8; 32],
}

impl MetaEnvelope {
    /// Parse the cleartext envelope of a TSP message and compute its id.
    ///
    /// Does **not** decrypt or verify the payload — it only reads the envelope
    /// and hashes the wire bytes. Returns an error if the bytes are not a
    /// well-formed TSP envelope.
    pub fn parse(wire: &[u8]) -> Result<Self, TspError> {
        let (envelope, _consumed) = Envelope::decode(wire)?;
        let sha256: [u8; 32] = Sha256::digest(wire).into();
        Ok(Self {
            sender: envelope.sender,
            receiver: envelope.receiver,
            message_type: envelope.message_type,
            sha256,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::direct;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn packed() -> direct::PackedMessage {
        let sign = SigningKey::generate(&mut OsRng);
        let sender_enc = StaticSecret::random_from_rng(OsRng);
        let recv_enc = StaticSecret::random_from_rng(OsRng);
        direct::pack(
            b"payload",
            MessageType::Direct,
            "did:web:alice",
            "did:web:bob",
            &sign.to_bytes(),
            &sender_enc.to_bytes(),
            &PublicKey::from(&recv_enc).to_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn is_tsp_detects_magic_byte() {
        let msg = packed();
        assert_eq!(msg.bytes[0], TSP_MAGIC_BYTE);
        assert!(is_tsp(&msg.bytes));
    }

    #[test]
    fn is_tsp_rejects_didcomm_and_empty() {
        assert!(!is_tsp(b"{\"protected\":\"...\"}")); // DIDComm JSON
        assert!(!is_tsp(b"eyJhbGciOiJ...")); // compact JWS/JWE
        assert!(!is_tsp(&[])); // empty
    }

    #[test]
    fn meta_envelope_parse_reads_addressing_without_keys() {
        let msg = packed();
        let meta = MetaEnvelope::parse(&msg.bytes).unwrap();
        assert_eq!(meta.sender, "did:web:alice");
        assert_eq!(meta.receiver, "did:web:bob");
        assert_eq!(meta.message_type, MessageType::Direct);
        // id is the sha256 of the full wire bytes, and is deterministic.
        let expected: [u8; 32] = Sha256::digest(&msg.bytes).into();
        assert_eq!(meta.sha256, expected);
    }

    #[test]
    fn meta_envelope_parse_rejects_garbage() {
        assert!(MetaEnvelope::parse(b"not a tsp message").is_err());
        assert!(MetaEnvelope::parse(&[TSP_MAGIC_BYTE, 0x00]).is_err());
    }

    #[test]
    fn meta_envelope_reads_routed_type() {
        let sign = SigningKey::generate(&mut OsRng);
        let sender_enc = StaticSecret::random_from_rng(OsRng);
        let recv_enc = StaticSecret::random_from_rng(OsRng);
        let msg = direct::pack(
            b"routing-layer",
            MessageType::Routed,
            "did:web:alice",
            "did:web:mediator",
            &sign.to_bytes(),
            &sender_enc.to_bytes(),
            &PublicKey::from(&recv_enc).to_bytes(),
        )
        .unwrap();
        let meta = MetaEnvelope::parse(&msg.bytes).unwrap();
        assert_eq!(meta.message_type, MessageType::Routed);
        assert_eq!(meta.receiver, "did:web:mediator");
    }
}
