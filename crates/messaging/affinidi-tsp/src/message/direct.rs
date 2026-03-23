//! TSP direct mode messaging — seal, sign, and encode a message for a recipient.
//!
//! Direct mode is the simplest TSP message mode: one sender, one receiver,
//! no intermediaries. The message is HPKE-sealed (encrypted + sender-authenticated)
//! and then signed with the sender's Ed25519 key.
//!
//! Wire format:
//! ```text
//! [envelope_bytes] [enc:32] [ciphertext_len:u32] [ciphertext] [signature:64]
//! ```

use crate::crypto::{hpke, signing};
use crate::error::TspError;
use crate::message::MessageType;
use crate::message::envelope::Envelope;

/// A packed (sealed + signed) TSP direct message ready for transport.
#[derive(Debug, Clone)]
pub struct PackedMessage {
    /// The raw wire-format bytes.
    pub bytes: Vec<u8>,
}

/// Result of unpacking a TSP message.
#[derive(Debug, Clone)]
pub struct UnpackedMessage {
    /// The decrypted payload.
    pub payload: Vec<u8>,
    /// The sender's VID.
    pub sender: String,
    /// The receiver's VID.
    pub receiver: String,
    /// The message type.
    pub message_type: MessageType,
}

/// Pack a direct TSP message.
///
/// 1. Build envelope (sender VID + receiver VID + message type)
/// 2. HPKE-Auth seal the payload with envelope as AAD
/// 3. Ed25519 sign the envelope + sealed content
pub fn pack(
    payload: &[u8],
    message_type: MessageType,
    sender_vid: &str,
    receiver_vid: &str,
    sender_signing_key: &[u8; 32],
    sender_encryption_key: &[u8; 32],
    receiver_encryption_key: &[u8; 32],
) -> Result<PackedMessage, TspError> {
    // 1. Encode envelope
    let envelope = Envelope::new(message_type, sender_vid, receiver_vid);
    let envelope_bytes = envelope.encode()?;

    // 2. HPKE-Auth seal: encrypt payload with envelope as AAD
    let sealed = hpke::seal(
        payload,
        &envelope_bytes,
        sender_encryption_key,
        receiver_encryption_key,
        b"TSP-v1-direct",
    )?;

    // 3. Build wire format: envelope || enc || ciphertext_len || ciphertext || signature
    let ciphertext_len = sealed.ciphertext.len() as u32;
    let total_len = envelope_bytes.len() + 32 + 4 + sealed.ciphertext.len() + 64;
    let mut wire = Vec::with_capacity(total_len);
    wire.extend_from_slice(&envelope_bytes);
    wire.extend_from_slice(&sealed.enc);
    wire.extend_from_slice(&ciphertext_len.to_be_bytes());
    wire.extend_from_slice(&sealed.ciphertext);

    // 4. Sign the content before signature
    let signature = signing::sign(&wire, sender_signing_key)?;

    // 5. Append signature
    wire.extend_from_slice(&signature);

    Ok(PackedMessage { bytes: wire })
}

/// Unpack a direct TSP message.
///
/// 1. Parse envelope from the wire bytes
/// 2. Extract enc + ciphertext
/// 3. Verify Ed25519 signature
/// 4. HPKE-Auth open (decrypt + verify sender authentication)
pub fn unpack(
    wire: &[u8],
    receiver_decryption_key: &[u8; 32],
    sender_encryption_key: &[u8; 32],
    sender_signing_key: &[u8; 32],
) -> Result<UnpackedMessage, TspError> {
    // Minimum size: envelope(6+) + enc(32) + ct_len(4) + ct(16 min for tag) + sig(64)
    if wire.len() < 122 {
        return Err(TspError::InvalidMessage("message too short".into()));
    }

    // 1. Parse envelope
    let (envelope, env_end) = Envelope::decode(wire)?;

    // 2. Extract enc (32 bytes)
    let enc_start = env_end;
    if enc_start + 32 > wire.len() {
        return Err(TspError::InvalidMessage("enc truncated".into()));
    }
    let enc: [u8; 32] = wire[enc_start..enc_start + 32]
        .try_into()
        .map_err(|_| TspError::InvalidMessage("enc wrong size".into()))?;

    // 3. Extract ciphertext length and ciphertext
    let ct_len_start = enc_start + 32;
    if ct_len_start + 4 > wire.len() {
        return Err(TspError::InvalidMessage("ciphertext length truncated".into()));
    }
    let ct_len =
        u32::from_be_bytes(wire[ct_len_start..ct_len_start + 4].try_into().unwrap()) as usize;
    let ct_start = ct_len_start + 4;
    if ct_start + ct_len > wire.len() {
        return Err(TspError::InvalidMessage("ciphertext truncated".into()));
    }
    let ciphertext = &wire[ct_start..ct_start + ct_len];

    // 4. Extract signature (last 64 bytes)
    let sig_start = ct_start + ct_len;
    if sig_start + 64 > wire.len() {
        return Err(TspError::InvalidMessage("signature truncated".into()));
    }
    let signature: [u8; 64] = wire[sig_start..sig_start + 64]
        .try_into()
        .map_err(|_| TspError::InvalidMessage("signature wrong size".into()))?;

    // 5. Verify signature over everything before the signature
    let signed_content = &wire[..sig_start];
    signing::verify(signed_content, &signature, sender_signing_key)?;

    // 6. HPKE-Auth open: decrypt payload using envelope as AAD
    let envelope_bytes = &wire[..env_end];
    let payload = hpke::open(
        ciphertext,
        envelope_bytes,
        &enc,
        receiver_decryption_key,
        sender_encryption_key,
        b"TSP-v1-direct",
    )?;

    Ok(UnpackedMessage {
        payload,
        sender: envelope.sender,
        receiver: envelope.receiver,
        message_type: envelope.message_type,
    })
}

/// Compute a BLAKE2b-256 digest of a packed message (used as message ID).
pub fn message_digest(packed: &PackedMessage) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(&packed.bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    struct TestKeys {
        sender_sign_sk: [u8; 32],
        sender_sign_pk: [u8; 32],
        sender_enc_sk: [u8; 32],
        sender_enc_pk: [u8; 32],
        receiver_enc_sk: [u8; 32],
        receiver_enc_pk: [u8; 32],
    }

    fn gen_keys() -> TestKeys {
        let sender_sign = SigningKey::generate(&mut OsRng);
        let sender_enc = StaticSecret::random_from_rng(OsRng);
        let receiver_enc = StaticSecret::random_from_rng(OsRng);

        TestKeys {
            sender_sign_sk: sender_sign.to_bytes(),
            sender_sign_pk: sender_sign.verifying_key().to_bytes(),
            sender_enc_sk: sender_enc.to_bytes(),
            sender_enc_pk: PublicKey::from(&sender_enc).to_bytes(),
            receiver_enc_sk: receiver_enc.to_bytes(),
            receiver_enc_pk: PublicKey::from(&receiver_enc).to_bytes(),
        }
    }

    #[test]
    fn pack_unpack_roundtrip() {
        let keys = gen_keys();
        let payload = b"Hello, TSP world!";

        let packed = pack(
            payload,
            MessageType::Direct,
            "did:example:alice",
            "did:example:bob",
            &keys.sender_sign_sk,
            &keys.sender_enc_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        let unpacked = unpack(
            &packed.bytes,
            &keys.receiver_enc_sk,
            &keys.sender_enc_pk,
            &keys.sender_sign_pk,
        )
        .unwrap();

        assert_eq!(unpacked.payload, payload);
        assert_eq!(unpacked.sender, "did:example:alice");
        assert_eq!(unpacked.receiver, "did:example:bob");
        assert_eq!(unpacked.message_type, MessageType::Direct);
    }

    #[test]
    fn tampered_payload_fails() {
        let keys = gen_keys();

        let packed = pack(
            b"original",
            MessageType::Direct,
            "alice",
            "bob",
            &keys.sender_sign_sk,
            &keys.sender_enc_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        let mut tampered = packed.bytes.clone();
        // Tamper with a byte in the ciphertext region
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0xFF;

        assert!(unpack(
            &tampered,
            &keys.receiver_enc_sk,
            &keys.sender_enc_pk,
            &keys.sender_sign_pk,
        )
        .is_err());
    }

    #[test]
    fn wrong_receiver_key_fails() {
        let keys = gen_keys();
        let wrong_sk = StaticSecret::random_from_rng(OsRng);

        let packed = pack(
            b"secret",
            MessageType::Direct,
            "alice",
            "bob",
            &keys.sender_sign_sk,
            &keys.sender_enc_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        assert!(unpack(
            &packed.bytes,
            &wrong_sk.to_bytes(),
            &keys.sender_enc_pk,
            &keys.sender_sign_pk,
        )
        .is_err());
    }

    #[test]
    fn empty_payload() {
        let keys = gen_keys();

        let packed = pack(
            b"",
            MessageType::Direct,
            "alice",
            "bob",
            &keys.sender_sign_sk,
            &keys.sender_enc_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        let unpacked = unpack(
            &packed.bytes,
            &keys.receiver_enc_sk,
            &keys.sender_enc_pk,
            &keys.sender_sign_pk,
        )
        .unwrap();

        assert!(unpacked.payload.is_empty());
    }

    #[test]
    fn message_digest_deterministic() {
        let keys = gen_keys();

        let packed = pack(
            b"test",
            MessageType::Direct,
            "alice",
            "bob",
            &keys.sender_sign_sk,
            &keys.sender_enc_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        let d1 = message_digest(&packed);
        let d2 = message_digest(&packed);
        assert_eq!(d1, d2);
    }

    #[test]
    fn control_message_type() {
        let keys = gen_keys();

        let packed = pack(
            b"\x00\x00", // minimal control payload
            MessageType::Control,
            "alice",
            "bob",
            &keys.sender_sign_sk,
            &keys.sender_enc_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        let unpacked = unpack(
            &packed.bytes,
            &keys.receiver_enc_sk,
            &keys.sender_enc_pk,
            &keys.sender_sign_pk,
        )
        .unwrap();

        assert_eq!(unpacked.message_type, MessageType::Control);
    }
}
