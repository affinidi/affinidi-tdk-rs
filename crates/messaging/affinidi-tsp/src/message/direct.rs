//! TSP direct mode messaging — seal, sign, and CESR-encode a message.
//!
//! Direct mode is the simplest TSP message mode: one sender, one receiver, no
//! intermediaries. The message is HPKE-sealed (encrypted + sender-authenticated)
//! and then signed with the sender's Ed25519 key. The wire encoding is binary
//! CESR, byte-compatible with the ToIP `tsp-sdk` reference (v0.9.0-alpha2).
//!
//! Wire format (an "encrypted-then-signed" / ETS message):
//! ```text
//! -E<count>                         envelope frame (HPKE `info`):
//!   YTSP <version>                    version marker
//!   <var-data B> sender-VID
//!   <var-data B> receiver-VID
//!   X 00 00                           2-byte TMP marker
//! <var-data G> ciphertext           HPKE-Auth ciphertext: ct ‖ tag(16) ‖ enc(32)
//! -C<n> -K<n> <fixed B> sig(64)     Ed25519 signature over everything above
//! ```
//!
//! The encrypted plaintext is itself a CESR payload frame:
//! ```text
//! -Z<count> XSCS <var-data B> plaintext
//! ```
//!
//! HPKE binding (matching the reference exactly): the envelope `-E` frame is the
//! HPKE **`info`**, and the AEAD **AAD is empty**.

use crate::crypto::{hpke, signing};
use crate::error::TspError;
use crate::message::MessageType;
use crate::message::control::{ControlMessage, ControlType, DIGEST_LEN};
use crate::message::envelope::Envelope;
use crate::message::wire;

/// Maximum allowed ciphertext size, kept in lock-step with the variable-data
/// field cap (which mirrors the ToIP reference's `DATA_LIMIT`). The ciphertext is
/// itself a `G` variable-data field, so this matches what the wire layer accepts.
const MAX_MESSAGE_SIZE: usize = crate::message::wire::MAX_FIELD_SIZE;

/// X25519 encapsulated-key length appended to the ciphertext.
const ENC_LEN: usize = 32;
/// ChaCha20Poly1305 authentication tag length.
const TAG_LEN: usize = 16;
/// Ed25519 signature length.
const SIG_LEN: usize = 64;

/// A packed (sealed + signed) TSP direct message ready for transport.
#[derive(Debug, Clone)]
pub struct PackedMessage {
    /// The raw wire-format bytes.
    pub bytes: Vec<u8>,
    /// `SHA256` of the plaintext CESR payload frame (the `-Z…` bytes before
    /// sealing). This is the TSP **thread digest** used to correlate
    /// relationship control messages: an accept's `reply` is the invite's
    /// `thread_digest`, and a cancel's `reply` is the relationship-forming
    /// message's `thread_digest`. The reference (`tsp_sdk`) computes the same
    /// value (`sha256` of the decrypted payload frame) on open.
    pub thread_digest: [u8; DIGEST_LEN],
}

/// Result of unpacking a TSP message.
#[derive(Debug, Clone)]
pub struct UnpackedMessage {
    /// The decrypted payload. For Direct/Control this is the message body; for
    /// Nested it is the opaque inner packed message; for Routed it is the opaque
    /// inner message (the route travels in [`UnpackedMessage::hops`]).
    pub payload: Vec<u8>,
    /// The remaining hop list for a Routed message (empty for Direct, Nested and
    /// Control).
    pub hops: Vec<String>,
    /// The sender's VID.
    pub sender: String,
    /// The receiver's VID.
    pub receiver: String,
    /// The message type, recovered from the encrypted payload frame.
    pub message_type: MessageType,
    /// `SHA256` of the decrypted plaintext CESR payload frame — the TSP
    /// **thread digest** (see [`PackedMessage::thread_digest`]). Always present;
    /// the FSM uses it to correlate a received accept/cancel back to the
    /// relationship-forming message it replies to.
    pub thread_digest: [u8; DIGEST_LEN],
    /// For a [`MessageType::Control`] message, the decoded control payload
    /// (invite / accept / cancel). `None` for all other message types.
    pub control: Option<ControlMessage>,
}

/// Payload-type markers, all using the reference `tsp-sdk` framing verbatim so
/// they are byte-compatible with `tsp-sdk`:
///
///   * Direct → `XSCS`
///   * Nested → `XHOP` + empty hop list
///   * Routed → `XHOP` + non-empty hop list
///   * Control(invite) → `XRFI` + hops + `A` nonce(32) + empty `B` VID
///   * Control(accept) → `XRFA` + `I` SHA-256 reply(32)
///   * Control(cancel) → `XRFD` + `I` SHA-256 reply(32)
mod payload_marker {
    /// Generic message (Direct) — the reference `XSCS` marker, byte-exact.
    pub const DIRECT: [u8; 3] = crate::message::wire::XSCS;
    /// Hop-carrying payload (Nested or Routed) — the reference `XHOP` marker.
    pub const HOP: [u8; 3] = crate::message::wire::XHOP;
    /// Relationship-forming invite (`DirectRelationProposal`).
    pub const INVITE: [u8; 3] = crate::message::wire::XRFI;
    /// Relationship-forming accept (`DirectRelationAffirm`).
    pub const ACCEPT: [u8; 3] = crate::message::wire::XRFA;
    /// Relationship cancel (`RelationshipCancel`).
    pub const CANCEL: [u8; 3] = crate::message::wire::XRFD;
}

/// Encode a SHA-256 digest as the reference's `encode_digest` does: a fixed-data
/// field under the `I` (SHA-256) id.
fn encode_sha256_digest(digest: &[u8; DIGEST_LEN], out: &mut Vec<u8>) {
    wire::encode_fixed_data(wire::TSP_SHA256, digest, out);
}

/// Decode a SHA-256 digest (`I`-coded 32-byte fixed-data field).
fn decode_sha256_digest(frame: &[u8], pos: &mut usize) -> Result<[u8; DIGEST_LEN], TspError> {
    wire::decode_fixed_data::<DIGEST_LEN>(wire::TSP_SHA256, frame, pos)
        .ok_or_else(|| TspError::InvalidMessage("missing or non-SHA256 reply digest".into()))
}

/// Build the CESR payload frame that is encrypted (the HPKE plaintext).
///
/// Layout matches the `tsp_sdk` reference's `encode_payload`:
///   * Direct  → `-Z<count> XSCS <var-data B> body`
///   * Nested  → `-Z<count> XHOP -J0 <var-data B> body`
///   * Routed  → `-Z<count> XHOP -J<n> (B hop)* <var-data B> body`
///   * Control(invite) → `-Z<count> XRFI -J<n> (B hop)* A nonce(32) B(empty)`
///   * Control(accept) → `-Z<count> XRFA I reply(32)`
///   * Control(cancel) → `-Z<count> XRFD I reply(32)`
///
/// For Control, `body` is a [`ControlMessage::encode`] blob; it is decoded back
/// to the structured control so the spec CESR fields can be emitted.
fn encode_payload_frame(
    body: &[u8],
    kind: MessageType,
    hops: &[String],
) -> Result<Vec<u8>, TspError> {
    let mut frame_body = Vec::with_capacity(3 + body.len() + 3);
    match kind {
        MessageType::Direct => {
            frame_body.extend_from_slice(&payload_marker::DIRECT);
            wire::encode_variable_data(wire::TSP_PLAINTEXT, body, &mut frame_body);
        }
        MessageType::Nested => {
            frame_body.extend_from_slice(&payload_marker::HOP);
            let no_hops: [&[u8]; 0] = [];
            wire::encode_hops(&no_hops, &mut frame_body);
            wire::encode_variable_data(wire::TSP_PLAINTEXT, body, &mut frame_body);
        }
        MessageType::Routed => {
            frame_body.extend_from_slice(&payload_marker::HOP);
            wire::encode_hops(hops, &mut frame_body);
            wire::encode_variable_data(wire::TSP_PLAINTEXT, body, &mut frame_body);
        }
        MessageType::Control => {
            let control = ControlMessage::decode(body)?;
            match control.control_type {
                ControlType::RelationshipFormingInvite => {
                    frame_body.extend_from_slice(&payload_marker::INVITE);
                    wire::encode_hops(&control.route, &mut frame_body);
                    wire::encode_fixed_data(
                        wire::TSP_NONCE,
                        control.require_nonce()?,
                        &mut frame_body,
                    );
                    // empty VID (a direct-relationship invite carries no new VID)
                    wire::encode_variable_data(wire::TSP_VID, &[], &mut frame_body);
                }
                ControlType::RelationshipFormingAccept => {
                    frame_body.extend_from_slice(&payload_marker::ACCEPT);
                    encode_sha256_digest(control.require_reply()?, &mut frame_body);
                }
                ControlType::RelationshipCancel => {
                    frame_body.extend_from_slice(&payload_marker::CANCEL);
                    encode_sha256_digest(control.require_reply()?, &mut frame_body);
                }
            }
        }
    }

    debug_assert!(frame_body.len().is_multiple_of(3));
    let mut out = Vec::with_capacity(3 + frame_body.len());
    wire::encode_count(wire::TSP_PAYLOAD, (frame_body.len() / 3) as u32, &mut out);
    out.extend_from_slice(&frame_body);
    Ok(out)
}

/// A decoded payload frame: its message kind, the remaining hop list (Routed
/// only), the plaintext body, and — for Control — the structured control.
struct DecodedFrame {
    kind: MessageType,
    hops: Vec<String>,
    body: Vec<u8>,
    control: Option<ControlMessage>,
}

/// Decode hop VID byte vectors into UTF-8 VID strings.
fn hops_to_strings(hop_bytes: Vec<Vec<u8>>) -> Result<Vec<String>, TspError> {
    hop_bytes
        .into_iter()
        .map(|h| {
            String::from_utf8(h).map_err(|_| TspError::InvalidMessage("hop VID not UTF-8".into()))
        })
        .collect()
}

/// Decode a CESR payload frame into a [`DecodedFrame`].
///
/// `XSCS` → Direct; `XHOP` → Nested (empty hops) or Routed (non-empty);
/// `XRFI`/`XRFA`/`XRFD` → Control (invite / accept / cancel). For Control the
/// `body` is set to the control's [`ControlMessage::encode`] form (so the SDK,
/// which only sees the `payload` bytes, can recover it) and `control` carries
/// the structured message.
fn decode_payload_frame(frame: &[u8]) -> Result<DecodedFrame, TspError> {
    let mut pos = 0usize;
    wire::decode_count(wire::TSP_PAYLOAD, frame, &mut pos)
        .ok_or_else(|| TspError::InvalidMessage("missing -Z payload frame".into()))?;

    // Optional sender-identity VID (ESSR). The reference omits it for HPKE-Auth;
    // skip it if present so we stay tolerant.
    let _ = wire::decode_variable_data(wire::TSP_VID, frame, &mut pos);

    let marker = frame
        .get(pos..pos + 3)
        .ok_or_else(|| TspError::InvalidMessage("missing payload type marker".into()))?;

    if marker == payload_marker::DIRECT {
        pos += 3;
        let body = wire::decode_variable_data(wire::TSP_PLAINTEXT, frame, &mut pos)
            .ok_or_else(|| TspError::InvalidMessage("missing payload plaintext".into()))?;
        Ok(DecodedFrame {
            kind: MessageType::Direct,
            hops: Vec::new(),
            body,
            control: None,
        })
    } else if marker == payload_marker::HOP {
        pos += 3;
        let hops = hops_to_strings(wire::decode_hops(frame, &mut pos)?)?;
        let body = wire::decode_variable_data(wire::TSP_PLAINTEXT, frame, &mut pos)
            .ok_or_else(|| TspError::InvalidMessage("missing payload plaintext".into()))?;
        let kind = if hops.is_empty() {
            MessageType::Nested
        } else {
            MessageType::Routed
        };
        Ok(DecodedFrame {
            kind,
            hops,
            body,
            control: None,
        })
    } else if marker == payload_marker::INVITE {
        pos += 3;
        let route = hops_to_strings(wire::decode_hops(frame, &mut pos)?)?;
        let nonce = wire::decode_fixed_data::<DIGEST_LEN>(wire::TSP_NONCE, frame, &mut pos)
            .ok_or_else(|| TspError::InvalidMessage("missing or malformed invite nonce".into()))?;
        // empty (or new-VID) `B` field; we only support the direct-relationship
        // form, so the VID is expected to be empty.
        let _new_vid = wire::decode_variable_data(wire::TSP_VID, frame, &mut pos)
            .ok_or_else(|| TspError::InvalidMessage("missing invite VID field".into()))?;
        let control = ControlMessage {
            control_type: ControlType::RelationshipFormingInvite,
            nonce: Some(nonce),
            reply: None,
            route,
        };
        Ok(DecodedFrame {
            kind: MessageType::Control,
            hops: Vec::new(),
            body: control.encode(),
            control: Some(control),
        })
    } else if marker == payload_marker::ACCEPT || marker == payload_marker::CANCEL {
        let control_type = if marker == payload_marker::ACCEPT {
            ControlType::RelationshipFormingAccept
        } else {
            ControlType::RelationshipCancel
        };
        pos += 3;
        let reply = decode_sha256_digest(frame, &mut pos)?;
        let control = ControlMessage {
            control_type,
            nonce: None,
            reply: Some(reply),
            route: Vec::new(),
        };
        Ok(DecodedFrame {
            kind: MessageType::Control,
            hops: Vec::new(),
            body: control.encode(),
            control: Some(control),
        })
    } else {
        Err(TspError::InvalidMessage(
            "unsupported TSP payload type marker".into(),
        ))
    }
}

/// Encode the signature frame: `-C<n> -K<n> <fixed B> sig`.
fn encode_signature_frame(signature: &[u8; SIG_LEN], out: &mut Vec<u8>) {
    let quadlets = signature.len().div_ceil(3) as u32;
    wire::encode_count(wire::TSP_ATTACH_GRP, quadlets, out);
    wire::encode_count(wire::TSP_INDEX_SIG_GRP, quadlets, out);
    wire::encode_fixed_data(wire::ED25519_SIGNATURE, signature, out);
}

/// Decode the signature frame at `pos`. Returns the 64-byte Ed25519 signature.
fn decode_signature_frame(data: &[u8], pos: &mut usize) -> Result<[u8; SIG_LEN], TspError> {
    let a = wire::decode_count(wire::TSP_ATTACH_GRP, data, pos)
        .ok_or_else(|| TspError::InvalidMessage("missing -C signature group".into()))?;
    let k = wire::decode_count(wire::TSP_INDEX_SIG_GRP, data, pos)
        .ok_or_else(|| TspError::InvalidMessage("missing -K signature group".into()))?;
    let want = SIG_LEN.div_ceil(3) as u32;
    if a != want || k != want {
        return Err(TspError::InvalidMessage(
            "unexpected signature group size".into(),
        ));
    }
    let sig = wire::decode_fixed_data::<SIG_LEN>(wire::ED25519_SIGNATURE, data, pos)
        .ok_or_else(|| TspError::InvalidMessage("missing Ed25519 signature".into()))?;
    Ok(sig)
}

/// Pack a direct TSP message.
///
/// 1. Build the `-E` envelope frame (this is the HPKE `info`).
/// 2. Build the CESR payload frame (`-Z XSCS <plaintext>`) and HPKE-Auth seal it
///    (empty AAD); append `tag ‖ enc` to the ciphertext.
/// 3. Append the `G` ciphertext frame to the envelope.
/// 4. Ed25519-sign everything so far and append the `-C/-K` signature frame.
pub fn pack(
    payload: &[u8],
    message_type: MessageType,
    sender_vid: &str,
    receiver_vid: &str,
    sender_signing_key: &[u8; 32],
    sender_encryption_key: &[u8; 32],
    receiver_encryption_key: &[u8; 32],
) -> Result<PackedMessage, TspError> {
    pack_with_hops(
        payload,
        message_type,
        &[],
        sender_vid,
        receiver_vid,
        sender_signing_key,
        sender_encryption_key,
        receiver_encryption_key,
    )
}

/// Like [`pack`] but carries a routing `hops` list in the payload frame (used by
/// [`crate::message::routed::pack_routed`] for [`MessageType::Routed`]). For all
/// other kinds `hops` must be empty.
#[allow(clippy::too_many_arguments)]
pub fn pack_with_hops(
    body: &[u8],
    message_type: MessageType,
    hops: &[String],
    sender_vid: &str,
    receiver_vid: &str,
    sender_signing_key: &[u8; 32],
    sender_encryption_key: &[u8; 32],
    receiver_encryption_key: &[u8; 32],
) -> Result<PackedMessage, TspError> {
    // 1. Envelope frame = HPKE info.
    let envelope = Envelope::new(message_type, sender_vid, receiver_vid);
    let envelope_bytes = envelope.encode()?;

    // 2. CESR payload frame, then HPKE-Auth seal it. The thread digest is
    //    SHA256 of this plaintext frame (computed before sealing, matching the
    //    reference's seal-time hash).
    let payload_frame = encode_payload_frame(body, message_type, hops)?;
    let thread_digest = sha256(&payload_frame);
    let sealed = hpke::seal(
        &payload_frame,
        b"", // AAD is empty in the reference
        sender_encryption_key,
        receiver_encryption_key,
        &envelope_bytes, // envelope frame is the HPKE `info`
    )?;

    // Reference ciphertext layout: ct ‖ tag(16) ‖ enc(32). `sealed.ciphertext`
    // already is `ct ‖ tag` (encrypt_in_place appends the tag), so append `enc`.
    let mut g_payload = sealed.ciphertext;
    g_payload.extend_from_slice(&sealed.enc);

    // 3. Build wire: envelope ‖ G(ciphertext).
    let mut wire_bytes = envelope_bytes;
    wire::encode_variable_data(wire::TSP_HPKEAUTH_CIPHERTEXT, &g_payload, &mut wire_bytes);

    // 4. Sign everything so far, append the signature frame.
    let signature = signing::sign(&wire_bytes, sender_signing_key)?;
    encode_signature_frame(&signature, &mut wire_bytes);

    Ok(PackedMessage {
        bytes: wire_bytes,
        thread_digest,
    })
}

/// Unpack a direct TSP message.
///
/// 1. Parse the `-E` envelope frame (the HPKE `info`).
/// 2. Parse the `G` ciphertext frame; verify the Ed25519 signature over the
///    envelope ‖ ciphertext.
/// 3. Split `enc` off the ciphertext and HPKE-Auth open (empty AAD).
/// 4. Decode the CESR payload frame to recover the plaintext.
pub fn unpack(
    wire_bytes: &[u8],
    receiver_decryption_key: &[u8; 32],
    sender_encryption_key: &[u8; 32],
    sender_signing_key: &[u8; 32],
) -> Result<UnpackedMessage, TspError> {
    if wire_bytes.len() < 48 {
        return Err(TspError::InvalidMessage("message too short".into()));
    }

    // 1. Envelope frame (also the HPKE info for tsp-sdk).
    let decoded = Envelope::decode_full(wire_bytes)?;
    let envelope = decoded.envelope;
    let header_len = decoded.header_len;
    let envelope_bytes = &wire_bytes[..header_len];

    // 2. Ciphertext frame (`G` var-data).
    let mut pos = header_len;
    let ct_range =
        wire::decode_variable_data_range(wire::TSP_HPKEAUTH_CIPHERTEXT, wire_bytes, &mut pos)
            .ok_or_else(|| TspError::InvalidMessage("missing G ciphertext frame".into()))?;
    let signed_end = pos; // signature covers everything up to here

    if ct_range.len() > MAX_MESSAGE_SIZE {
        return Err(TspError::InvalidMessage("ciphertext too large".into()));
    }
    if ct_range.len() < ENC_LEN + TAG_LEN {
        return Err(TspError::InvalidMessage("ciphertext truncated".into()));
    }

    // 3. Signature frame over envelope ‖ ciphertext.
    let signature = decode_signature_frame(wire_bytes, &mut pos)?;
    if pos != wire_bytes.len() {
        return Err(TspError::InvalidMessage(
            "trailing bytes after signature".into(),
        ));
    }
    signing::verify(&wire_bytes[..signed_end], &signature, sender_signing_key)?;

    // 4. Split `enc` off the tail and HPKE-Auth open the remainder.
    let g_payload = &wire_bytes[ct_range.clone()];
    let enc_start = g_payload.len() - ENC_LEN;
    let enc: [u8; 32] = g_payload[enc_start..]
        .try_into()
        .map_err(|_| TspError::InvalidMessage("bad enc size".into()))?;
    let ct_and_tag = &g_payload[..enc_start]; // ct ‖ tag

    let payload_frame = hpke::open(
        ct_and_tag,
        b"", // empty AAD
        &enc,
        receiver_decryption_key,
        sender_encryption_key,
        envelope_bytes, // envelope frame is the HPKE `info`
    )?;

    // 5. The thread digest is SHA256 of the decrypted plaintext frame (computed
    //    here, after decrypt — identical to the reference's open-time hash and
    //    to the sender's seal-time `PackedMessage::thread_digest`).
    let thread_digest = sha256(&payload_frame);

    // 6. Decode the CESR payload frame.
    let DecodedFrame {
        kind: message_type,
        hops,
        body: payload,
        control,
    } = decode_payload_frame(&payload_frame)?;

    Ok(UnpackedMessage {
        payload,
        hops,
        sender: envelope.sender,
        receiver: envelope.receiver,
        message_type,
        thread_digest,
        control,
    })
}

/// Compute a SHA-256 digest (the TSP thread-digest hash).
pub fn sha256(data: &[u8]) -> [u8; DIGEST_LEN] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute a BLAKE2s-256 digest of raw wire bytes (used as an opaque message ID,
/// e.g. for the mediator adapter). This is **not** the TSP thread digest — use
/// [`PackedMessage::thread_digest`] / [`UnpackedMessage::thread_digest`] for
/// relationship correlation.
pub fn message_digest_bytes(bytes: &[u8]) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Compute a BLAKE2s-256 digest of a packed message (used as an opaque message
/// ID). For relationship correlation use the TSP thread digest instead
/// ([`PackedMessage::thread_digest`]).
pub fn message_digest(packed: &PackedMessage) -> [u8; 32] {
    message_digest_bytes(&packed.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
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
            "did:web:alice.example",
            "did:web:bob.example",
            &keys.sender_sign_sk,
            &keys.sender_enc_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        // First byte is the -E count code.
        assert_eq!(packed.bytes[0], 0xf8);

        let unpacked = unpack(
            &packed.bytes,
            &keys.receiver_enc_sk,
            &keys.sender_enc_pk,
            &keys.sender_sign_pk,
        )
        .unwrap();

        assert_eq!(unpacked.payload, payload);
        assert_eq!(unpacked.sender, "did:web:alice.example");
        assert_eq!(unpacked.receiver, "did:web:bob.example");
        assert_eq!(unpacked.message_type, MessageType::Direct);
    }

    #[test]
    fn tampered_payload_fails() {
        let keys = gen_keys();
        let packed = pack(
            b"original",
            MessageType::Direct,
            "did:web:a.example",
            "did:web:b.example",
            &keys.sender_sign_sk,
            &keys.sender_enc_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        let mut tampered = packed.bytes.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0xFF;

        assert!(
            unpack(
                &tampered,
                &keys.receiver_enc_sk,
                &keys.sender_enc_pk,
                &keys.sender_sign_pk,
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_receiver_key_fails() {
        let keys = gen_keys();
        let wrong_sk = StaticSecret::random_from_rng(OsRng);
        let packed = pack(
            b"secret",
            MessageType::Direct,
            "did:web:a.example",
            "did:web:b.example",
            &keys.sender_sign_sk,
            &keys.sender_enc_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        assert!(
            unpack(
                &packed.bytes,
                &wrong_sk.to_bytes(),
                &keys.sender_enc_pk,
                &keys.sender_sign_pk,
            )
            .is_err()
        );
    }

    #[test]
    fn empty_payload() {
        let keys = gen_keys();
        let packed = pack(
            b"",
            MessageType::Direct,
            "did:web:a.example",
            "did:web:b.example",
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
            "did:web:a.example",
            "did:web:b.example",
            &keys.sender_sign_sk,
            &keys.sender_enc_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();
        assert_eq!(message_digest(&packed), message_digest(&packed));
    }
}
