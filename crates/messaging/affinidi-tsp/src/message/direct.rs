//! TSP direct mode messaging — seal, sign, and CESR-encode a message.
//!
//! Direct mode is the simplest TSP message mode: one sender, one receiver, no
//! intermediaries. The message is HPKE-Base sealed and then signed with the
//! sender's Ed25519 key, per spec Rev 3.
//!
//! Wire format:
//! ```text
//! -E<count>                       one frame; count covers everything below
//!   YTSP <version>                  `YTSP-AAB`
//!   <var-data B> sender-VID
//!   <var-data B> receiver-VID       `4BAA` when absent
//!   <var-data F> enc ‖ ct         HPKE-Base ciphertext, AEAD tag inside ct
//! -C23 -K22 B0 sig(64)            indexed Ed25519 signature over the above
//! ```
//!
//! The encrypted plaintext is itself a CESR payload frame, and every layout has
//! the same shape: type code, ESSR sender VID, type-specific fields, padding
//! last (§9.2). For a generic message:
//! ```text
//! -Z<count> XSCS <var-data B> sender-VID <var-data B> pad -A<n> <var-data B> body
//! ```
//!
//! # What Rev 3 changed here
//!
//! * **HPKE-Base, not HPKE-Auth.** The sender's KEM key no longer participates,
//!   so packing and unpacking take one fewer secret than they did.
//! * **The crypto binding moved.** Rev 2 passed the envelope as HPKE `info` with
//!   an empty AAD. Rev 3 passes `TSP_Version ‖ VID_sndr ‖ VID_rcvr` as real AAD
//!   and the fixed code `YTSP-` as `info`. The AAD is what carries the ESSR
//!   sender binding now that the KEM does not.
//! * **`TSP_Digest` is on the wire.** Rev 2 correlated relationships on a hash
//!   of the payload frame that was never transmitted, so a receiver could not
//!   check it. Rev 3 embeds a self-addressing digest in the payload and the
//!   receiver recomputes it. See [`derive_said`].
//! * **The `-E` count covers the ciphertext**, so the frame is finalized after
//!   sealing rather than built before it.

use crate::crypto::{hpke, signing};
use crate::error::TspError;
use crate::message::MessageType;
use crate::message::control::{ControlMessage, ControlType, DIGEST_LEN, NONCE_LEN, Referral};
use crate::message::envelope::{self, Envelope};
use crate::message::wire;

/// Maximum allowed ciphertext size, kept in lock-step with the variable-data
/// field cap. The ciphertext is itself an `F` variable-data field, so this
/// matches what the wire layer accepts.
const MAX_MESSAGE_SIZE: usize = crate::message::wire::MAX_FIELD_SIZE;

/// X25519 encapsulated-key length, which prefixes the ciphertext.
const ENC_LEN: usize = 32;
/// ChaCha20Poly1305 authentication tag length.
const TAG_LEN: usize = 16;
/// Ed25519 signature length.
const SIG_LEN: usize = 64;

/// Length of a CESR-encoded SHA-256 digest: the one-character `I` code plus 32
/// bytes. This is the width the SAID dummy occupies during derivation.
const ENCODED_DIGEST_LEN: usize = 33;

/// The dummy byte the SAID derivation writes into the digest's own slot
/// (Rev 3 §7.2.1). `0x23` is `#`.
const SAID_DUMMY: u8 = 0x23;

/// Index of the signing key within the VID's key list, carried in the indexed
/// signature code `B#`. Every VID this crate produces has a single signing key,
/// so the index is always 0; multi-key VIDs are a VID-type concern.
const SIG_INDEX: u8 = 0;

/// Quadlet count of the `-K` indexed-signature group: one 66-byte signature.
const SIG_GROUP_QUADLETS: u32 = 22;
/// Quadlet count of the `-C` attachment group: the `-K` header plus its content.
const ATTACH_GROUP_QUADLETS: u32 = SIG_GROUP_QUADLETS + 1;

/// A packed (sealed + signed) TSP direct message ready for transport.
#[derive(Debug, Clone)]
pub struct PackedMessage {
    /// The raw wire-format bytes.
    pub bytes: Vec<u8>,
    /// The relationship thread id.
    ///
    /// For a control message this is the Rev 3 `TSP_Digest` — for an invite or
    /// an accept, the self-addressing digest embedded in and transmitted with
    /// the message; for a cancel, the digest of the relationship-forming
    /// message it names. For every other message type there is no digest field
    /// on the wire and this is a local `SHA256` of the plaintext payload frame,
    /// useful for correlation but never transmitted or checked.
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
    /// The relationship thread id — see [`PackedMessage::thread_digest`]. For an
    /// invite or an accept this value has been recomputed from the received
    /// bytes and checked against the digest the sender embedded.
    pub thread_digest: [u8; DIGEST_LEN],
    /// For a [`MessageType::Control`] message, the decoded control payload
    /// (invite / accept / cancel). `None` for all other message types.
    pub control: Option<ControlMessage>,
}

/// Payload-type markers (Rev 3 §9.2).
mod payload_marker {
    /// Generic upper-layer message (Direct).
    pub const DIRECT: [u8; 3] = crate::message::wire::XSCS;
    /// Hop-carrying payload (Nested when the hop list is empty, Routed when not).
    pub const HOP: [u8; 3] = crate::message::wire::XHOP;
    /// Relationship-forming invite.
    pub const INVITE: [u8; 3] = crate::message::wire::XRFI;
    /// Relationship-forming accept.
    pub const ACCEPT: [u8; 3] = crate::message::wire::XRFA;
    /// Relationship cancel.
    pub const CANCEL: [u8; 3] = crate::message::wire::XRFD;
}

/// Encode a SHA-256 digest as a CESR fixed-data field under the `I` code.
fn encode_digest(digest: &[u8; DIGEST_LEN], out: &mut Vec<u8>) {
    wire::encode_fixed_data(wire::TSP_SHA256, digest, out);
}

/// Decode a SHA-256 digest (`I`-coded 32-byte fixed-data field).
fn decode_digest(frame: &[u8], pos: &mut usize) -> Result<[u8; DIGEST_LEN], TspError> {
    wire::decode_fixed_data::<DIGEST_LEN>(wire::TSP_SHA256, frame, pos)
        .ok_or_else(|| TspError::InvalidMessage("missing or non-SHA256 digest field".into()))
}

/// Encode the ESSR sender-VID payload field.
///
/// Rev 3 §8 makes this field optional under HPKE-Base — the AAD already binds
/// the sender — but permits carrying it, in which case a receiver MUST check it
/// against the envelope. We carry it. The spec's own security considerations
/// note that the two bindings are then independent, so an implementation "that
/// does not wish to rely on the associated-data handling of a newer HPKE
/// implementation obtains the same property from the payload check alone".
/// Our HPKE is hand-rolled, which is exactly the situation that argues for not
/// resting the sender binding on a single mechanism.
fn encode_sender_field(sender_vid: &str, out: &mut Vec<u8>) {
    wire::encode_variable_data(wire::TSP_VID, sender_vid.as_bytes(), out);
}

/// Encode the padding field. Rev 3 ends every payload layout with one; an
/// absent padding is the empty field `4BAA`.
///
/// Caller-supplied padding — which is what makes the field useful, by obscuring
/// message size — is not yet surfaced through this crate's API.
fn encode_padding(out: &mut Vec<u8>) {
    wire::encode_variable_data(wire::TSP_PLAINTEXT, &[], out);
}

/// Encode the `Referral_Field` (Rev 3 §9.2): a `-J` group holding `VID_new`
/// followed by `Signature_new`, or `-JAA` when the invite introduces nothing.
///
/// The signature uses the same attachment encoding as a message signature.
fn encode_referral(referral: Option<&Referral>, out: &mut Vec<u8>) {
    let Some(referral) = referral else {
        wire::encode_count(wire::TSP_HOP_LIST, 0, out);
        return;
    };

    let mut body = Vec::new();
    wire::encode_variable_data(wire::TSP_VID, referral.new_vid.as_bytes(), &mut body);
    encode_signature_frame(&referral.signature, &mut body);

    debug_assert!(body.len().is_multiple_of(3));
    wire::encode_count(wire::TSP_HOP_LIST, (body.len() / 3) as u32, out);
    out.extend_from_slice(&body);
}

/// Decode a `Referral_Field`. `None` for the empty `-JAA` form.
fn decode_referral(frame: &[u8], pos: &mut usize) -> Result<Option<Referral>, TspError> {
    let quadlets = wire::decode_count(wire::TSP_HOP_LIST, frame, pos)
        .ok_or_else(|| TspError::InvalidMessage("missing referral field".into()))?;
    if quadlets == 0 {
        return Ok(None);
    }
    let group_end = (quadlets as usize)
        .checked_mul(3)
        .and_then(|len| pos.checked_add(len))
        .filter(|end| *end <= frame.len())
        .ok_or_else(|| TspError::InvalidMessage("referral field overruns the payload".into()))?;

    let new_vid = wire::decode_variable_data(wire::TSP_VID, frame, pos)
        .ok_or_else(|| TspError::InvalidMessage("malformed VID in referral field".into()))?;
    let new_vid = String::from_utf8(new_vid)
        .map_err(|_| TspError::InvalidMessage("referral VID is not UTF-8".into()))?;
    if new_vid.is_empty() {
        return Err(TspError::InvalidMessage(
            "referral field names the NULL VID".into(),
        ));
    }
    let signature = decode_signature_frame(frame, pos)?;
    if *pos != group_end {
        return Err(TspError::InvalidMessage(
            "referral field does not fill its own count".into(),
        ));
    }
    Ok(Some(Referral {
        new_vid,
        signature,
    }))
}

/// Build the bytes `Signature_new` is made over (Rev 3 §9.3).
///
/// "`Signature_new` within the `Referral_Field` is made by `VID_new`'s key over
/// {`XRFI`, `VID_sndr | 4BAA`, `Digest`, `Nonce`, `Reply_Path`, `VID_new`}. The
/// referral field's own code and count are not covered; the message signature
/// covers them."
///
/// So `VID_new` contributes as a bare VID field here, without the enclosing
/// `-J` group it sits inside on the wire.
fn referral_signed_data(
    sender_field: &[u8],
    digest: &[u8; DIGEST_LEN],
    nonce: &[u8; NONCE_LEN],
    reply_path: &[String],
    new_vid: &str,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&payload_marker::INVITE);
    data.extend_from_slice(sender_field);
    encode_digest(digest, &mut data);
    wire::encode_fixed_data(wire::TSP_NONCE, nonce, &mut data);
    wire::encode_hops(reply_path, &mut data);
    wire::encode_variable_data(wire::TSP_VID, new_vid.as_bytes(), &mut data);
    data
}

/// Verify the `Signature_new` carried by a referral invite (Rev 3 §7.2.5).
///
/// Not done during [`unpack`], and deliberately so: checking it needs
/// `VID_new`'s public key, and `VID_new` is exactly the identifier the invite
/// exists to introduce — so it has to be resolved first, which this crate's
/// key-in-hand unpacking cannot do. [`unpack`] therefore returns the referral
/// unverified and a caller that can resolve calls this.
///
/// Until it does, the referral is a claim: it says the sender wishes to
/// introduce `VID_new`, and nothing about whether whoever controls `VID_new`
/// agreed. That is the whole point of the signature, so an application that
/// acts on a referral without calling this has skipped the check.
pub fn verify_referral(
    control: &ControlMessage,
    sender_vid: &str,
    new_vid_signing_key: &[u8; 32],
) -> Result<(), TspError> {
    let Some(referral) = control.referral.as_ref() else {
        return Err(TspError::InvalidMessage(
            "control message carries no referral to verify".into(),
        ));
    };
    let digest = control.digest.ok_or_else(|| {
        TspError::InvalidMessage("a referral invite must carry its digest".into())
    })?;
    let nonce = control.require_nonce()?;

    let mut sender_field = Vec::new();
    encode_sender_field(sender_vid, &mut sender_field);
    let signed = referral_signed_data(
        &sender_field,
        &digest,
        nonce,
        &control.route,
        &referral.new_vid,
    );
    signing::verify(&signed, &referral.signature, new_vid_signing_key)
}

/// Derive a self-addressing `TSP_Digest` (Rev 3 §7.2.1).
///
/// The digest covers the message's own envelope fields (version and both VIDs)
/// and its payload fields, with the digest's own slot filled with
/// [`SAID_DUMMY`] over its full encoded width. The `-E` and `-Z` framing tags
/// and the padding field are excluded; the payload type code is included.
///
/// `before` and `after` are the encoded payload fields that precede and follow
/// the digest slot, padding excluded. Verification reverses the derivation:
/// rebuild the same input from the received bytes and compare.
fn derive_said(
    envelope_fields: &[u8],
    type_code: &[u8; 3],
    before: &[u8],
    after: &[u8],
) -> [u8; DIGEST_LEN] {
    let mut input =
        Vec::with_capacity(envelope_fields.len() + 3 + before.len() + ENCODED_DIGEST_LEN + after.len());
    input.extend_from_slice(envelope_fields);
    input.extend_from_slice(type_code);
    input.extend_from_slice(before);
    input.extend_from_slice(&[SAID_DUMMY; ENCODED_DIGEST_LEN]);
    input.extend_from_slice(after);
    sha256(&input)
}

/// Build the CESR payload frame that is encrypted (the HPKE plaintext), and
/// return it with the message's thread digest.
///
/// Layouts (Rev 3 §9.2/§9.3), all beginning with the type code and the ESSR
/// sender VID and ending with the padding field:
/// ```text
/// Direct  -Z<n> XSCS  sndr  pad  -A<n> body
/// Nested  -Z<n> XHOP  sndr  -JAA        pad  <raw inner message>
/// Routed  -Z<n> XHOP  sndr  -J<n> hops  pad  <raw inner message>
/// Invite  -Z<n> XRFI  sndr  Digest  Nonce  Reply_Path  Referral  pad
/// Accept  -Z<n> XRFA  sndr  Digest  Reply_Digest              pad
/// Cancel  -Z<n> XRFD  sndr  Digest                            pad
/// ```
#[allow(clippy::too_many_arguments)]
fn encode_payload_frame(
    body: &[u8],
    kind: MessageType,
    hops: &[String],
    sender_vid: &str,
    envelope_fields: &[u8],
    referral_signing_key: Option<&[u8; 32]>,
) -> Result<(Vec<u8>, [u8; DIGEST_LEN]), TspError> {
    let mut sender_field = Vec::new();
    encode_sender_field(sender_vid, &mut sender_field);

    let mut frame_body = Vec::new();
    let mut said: Option<[u8; DIGEST_LEN]> = None;

    match kind {
        MessageType::Direct => {
            frame_body.extend_from_slice(&payload_marker::DIRECT);
            frame_body.extend_from_slice(&sender_field);
            encode_padding(&mut frame_body);
            // §9.2.3: the upper-layer payload is a generic CESR stream holding
            // a Bytes primitive. TSP carries its content opaquely.
            let mut stream = Vec::new();
            wire::encode_variable_data(wire::TSP_PLAINTEXT, body, &mut stream);
            wire::encode_count(
                wire::TSP_GENERIC_STREAM,
                (stream.len() / 3) as u32,
                &mut frame_body,
            );
            frame_body.extend_from_slice(&stream);
        }
        MessageType::Nested | MessageType::Routed => {
            frame_body.extend_from_slice(&payload_marker::HOP);
            frame_body.extend_from_slice(&sender_field);
            if matches!(kind, MessageType::Nested) {
                let no_hops: [&[u8]; 0] = [];
                wire::encode_hops(&no_hops, &mut frame_body);
            } else {
                wire::encode_hops(hops, &mut frame_body);
            }
            encode_padding(&mut frame_body);
            // The inner message is self-framing and carried raw — Rev 3 drops
            // Rev 2's enclosing `B` var-data field. Every TSP message is
            // quadlet-aligned, so this keeps the frame aligned.
            if !body.len().is_multiple_of(3) {
                return Err(TspError::InvalidMessage(
                    "nested inner message is not quadlet-aligned".into(),
                ));
            }
            frame_body.extend_from_slice(body);
        }
        MessageType::Control => {
            let control = ControlMessage::decode(body)?;
            match control.control_type {
                ControlType::RelationshipFormingInvite => {
                    let nonce = *control.require_nonce()?;

                    // The digest covers the payload fields, and the referral's
                    // contribution to that input is a bare `VID_new` — not the
                    // `-J` group it sits inside on the wire, whose "own code and
                    // count are not covered" (§9.3).
                    let mut digest_after = Vec::new();
                    wire::encode_fixed_data(wire::TSP_NONCE, &nonce, &mut digest_after);
                    wire::encode_hops(&control.route, &mut digest_after);
                    match control.referral.as_ref() {
                        Some(referral) => wire::encode_variable_data(
                            wire::TSP_VID,
                            referral.new_vid.as_bytes(),
                            &mut digest_after,
                        ),
                        None => wire::encode_count(wire::TSP_HOP_LIST, 0, &mut digest_after),
                    }

                    let digest = derive_said(
                        envelope_fields,
                        &payload_marker::INVITE,
                        &sender_field,
                        &digest_after,
                    );

                    // `Signature_new` covers the digest, so it can only be made
                    // once the digest exists — which is why a referral invite
                    // needs the new VID's signing key at pack time rather than
                    // being signable by the caller beforehand.
                    let referral = match (control.referral.as_ref(), referral_signing_key) {
                        (Some(referral), Some(key)) => {
                            let signed = referral_signed_data(
                                &sender_field,
                                &digest,
                                &nonce,
                                &control.route,
                                &referral.new_vid,
                            );
                            Some(Referral {
                                new_vid: referral.new_vid.clone(),
                                signature: signing::sign(&signed, key)?,
                            })
                        }
                        (Some(_), None) => {
                            return Err(TspError::Signing(
                                "a referral invite needs the introduced VID's signing key".into(),
                            ));
                        }
                        (None, _) => None,
                    };

                    frame_body.extend_from_slice(&payload_marker::INVITE);
                    frame_body.extend_from_slice(&sender_field);
                    encode_digest(&digest, &mut frame_body);
                    wire::encode_fixed_data(wire::TSP_NONCE, &nonce, &mut frame_body);
                    wire::encode_hops(&control.route, &mut frame_body);
                    encode_referral(referral.as_ref(), &mut frame_body);
                    encode_padding(&mut frame_body);
                    said = Some(digest);
                }
                ControlType::RelationshipFormingAccept => {
                    // An accept carries two digests, and which is which is easy
                    // to get backwards. `Digest` is the *invite's* digest,
                    // echoed verbatim; `Reply_Digest` is this reply's own
                    // self-addressing digest, and so is the slot the derivation
                    // dummies out. Both fields sit before the padding, so the
                    // echoed digest is part of the derivation input.
                    let mut before = sender_field.clone();
                    encode_digest(control.require_reply()?, &mut before);

                    let digest =
                        derive_said(envelope_fields, &payload_marker::ACCEPT, &before, &[]);
                    frame_body.extend_from_slice(&payload_marker::ACCEPT);
                    frame_body.extend_from_slice(&before);
                    encode_digest(&digest, &mut frame_body);
                    encode_padding(&mut frame_body);
                    said = Some(digest);
                }
                ControlType::RelationshipCancel => {
                    // A cancel's Digest names the relationship-forming message
                    // it ends; it is a reference, not a digest of this message,
                    // so it is echoed rather than derived.
                    let reference = *control.require_reply()?;
                    frame_body.extend_from_slice(&payload_marker::CANCEL);
                    frame_body.extend_from_slice(&sender_field);
                    encode_digest(&reference, &mut frame_body);
                    encode_padding(&mut frame_body);
                    said = Some(reference);
                }
            }
        }
    }

    if !frame_body.len().is_multiple_of(3) {
        return Err(TspError::InvalidMessage(
            "payload frame not a multiple of 3 bytes".into(),
        ));
    }
    let mut out = Vec::with_capacity(6 + frame_body.len());
    wire::encode_count(wire::TSP_PAYLOAD, (frame_body.len() / 3) as u32, &mut out);
    out.extend_from_slice(&frame_body);

    let digest = said.unwrap_or_else(|| sha256(&out));
    Ok((out, digest))
}

/// A decoded payload frame: its message kind, the remaining hop list (Routed
/// only), the plaintext body, the structured control (Control only), and the
/// thread digest.
struct DecodedFrame {
    kind: MessageType,
    hops: Vec<String>,
    body: Vec<u8>,
    control: Option<ControlMessage>,
    thread_digest: [u8; DIGEST_LEN],
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

/// Decode a CESR payload frame.
///
/// `envelope_fields` and `envelope_sender` come from the message's envelope and
/// are needed to recompute a control message's `TSP_Digest` and to check the
/// ESSR sender field against the envelope.
fn decode_payload_frame(
    frame: &[u8],
    envelope_fields: &[u8],
    envelope_sender: &str,
) -> Result<DecodedFrame, TspError> {
    let mut pos = 0usize;
    let quadlets = wire::decode_count(wire::TSP_PAYLOAD, frame, &mut pos)
        .ok_or_else(|| TspError::InvalidMessage("missing -Z payload frame".into()))?;
    let frame_end = (quadlets as usize)
        .checked_mul(3)
        .and_then(|len| pos.checked_add(len))
        .filter(|end| *end <= frame.len())
        .ok_or_else(|| {
            TspError::InvalidMessage("-Z frame declares more content than the payload".into())
        })?;

    let type_code: [u8; 3] = frame
        .get(pos..pos + 3)
        .ok_or_else(|| TspError::InvalidMessage("truncated payload type code".into()))?
        .try_into()
        .expect("3-byte slice");
    pos += 3;

    // Every Rev 3 layout carries the ESSR sender field next. Under HPKE-Base it
    // MAY be the NULL VID; when it is not, it MUST equal the envelope sender.
    let sender_field_begin = pos;
    let sender_bytes = wire::decode_variable_data(wire::TSP_VID, frame, &mut pos)
        .ok_or_else(|| TspError::InvalidMessage("missing ESSR sender VID field".into()))?;
    let sender_field = &frame[sender_field_begin..pos];
    if !sender_bytes.is_empty() {
        let payload_sender = std::str::from_utf8(&sender_bytes)
            .map_err(|_| TspError::InvalidMessage("ESSR sender VID is not UTF-8".into()))?;
        if payload_sender != envelope_sender {
            return Err(TspError::Verification(
                "ESSR sender VID does not match the envelope sender".into(),
            ));
        }
    }

    if type_code == payload_marker::DIRECT {
        let _pad = wire::decode_variable_data(wire::TSP_PLAINTEXT, frame, &mut pos)
            .ok_or_else(|| TspError::InvalidMessage("missing padding field".into()))?;
        let stream_quadlets = wire::decode_count(wire::TSP_GENERIC_STREAM, frame, &mut pos)
            .ok_or_else(|| TspError::InvalidMessage("missing -A payload stream".into()))?;
        let stream_end = (stream_quadlets as usize)
            .checked_mul(3)
            .and_then(|len| pos.checked_add(len))
            .filter(|end| *end <= frame_end)
            .ok_or_else(|| {
                TspError::InvalidMessage("-A stream overruns the payload frame".into())
            })?;
        let body = wire::decode_variable_data(wire::TSP_PLAINTEXT, frame, &mut pos)
            .ok_or_else(|| TspError::InvalidMessage("missing payload body".into()))?;
        if pos > stream_end {
            return Err(TspError::InvalidMessage(
                "payload body overruns the -A stream".into(),
            ));
        }
        Ok(DecodedFrame {
            kind: MessageType::Direct,
            hops: Vec::new(),
            body,
            control: None,
            thread_digest: sha256(&frame[..frame_end]),
        })
    } else if type_code == payload_marker::HOP {
        let hops = hops_to_strings(wire::decode_hops(frame, &mut pos)?)?;
        let _pad = wire::decode_variable_data(wire::TSP_PLAINTEXT, frame, &mut pos)
            .ok_or_else(|| TspError::InvalidMessage("missing padding field".into()))?;
        // The inner message runs to the end of the frame.
        let body = frame[pos..frame_end].to_vec();
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
            thread_digest: sha256(&frame[..frame_end]),
        })
    } else if type_code == payload_marker::INVITE
        || type_code == payload_marker::ACCEPT
        || type_code == payload_marker::CANCEL
    {
        // The first digest field means different things per type: an invite's
        // is its own self-addressing digest, an accept's and a cancel's is a
        // reference to an earlier message.
        let first_digest = decode_digest(frame, &mut pos)?;

        let mut referral = None;
        let (control_type, nonce, reply, route) = if type_code == payload_marker::INVITE {
            let nonce = wire::decode_fixed_data::<NONCE_LEN>(wire::TSP_NONCE, frame, &mut pos)
                .ok_or_else(|| TspError::InvalidMessage("missing or malformed nonce".into()))?;
            let reply_path = hops_to_strings(wire::decode_hops(frame, &mut pos)?)?;
            referral = decode_referral(frame, &mut pos)?;
            (
                ControlType::RelationshipFormingInvite,
                Some(nonce),
                None,
                reply_path,
            )
        } else if type_code == payload_marker::ACCEPT {
            // An accept's second digest is its own; the first, already read, is
            // the invite it answers.
            let own = decode_digest(frame, &mut pos)?;
            (
                ControlType::RelationshipFormingAccept,
                None,
                Some(own),
                Vec::new(),
            )
        } else {
            (ControlType::RelationshipCancel, None, None, Vec::new())
        };

        // Which slot the derivation dummies out, and therefore what counts as
        // "before" and "after" it, differs by type.
        let thread_digest = match control_type {
            // The digest slot is first: everything after it is derivation input.
            ControlType::RelationshipFormingInvite => {
                // Rebuild the derivation input rather than slicing the frame:
                // §9.3 puts a bare `VID_new` in it, not the `-J` group the
                // referral occupies on the wire, so the bytes here and the bytes
                // there are deliberately different.
                let mut after = Vec::new();
                if let Some(n) = nonce {
                    wire::encode_fixed_data(wire::TSP_NONCE, &n, &mut after);
                }
                wire::encode_hops(&route, &mut after);
                match referral.as_ref() {
                    Some(r) => wire::encode_variable_data(
                        wire::TSP_VID,
                        r.new_vid.as_bytes(),
                        &mut after,
                    ),
                    None => wire::encode_count(wire::TSP_HOP_LIST, 0, &mut after),
                }

                let recomputed = derive_said(envelope_fields, &type_code, sender_field, &after);
                if recomputed != first_digest {
                    return Err(TspError::Verification(
                        "TSP_Digest does not match the message it identifies".into(),
                    ));
                }
                first_digest
            }
            // The digest slot is last, and the echoed invite digest before it is
            // part of the input.
            ControlType::RelationshipFormingAccept => {
                let own = reply.expect("accept always decodes its own digest");
                let mut before = sender_field.to_vec();
                encode_digest(&first_digest, &mut before);
                let recomputed = derive_said(envelope_fields, &type_code, &before, &[]);
                if recomputed != own {
                    return Err(TspError::Verification(
                        "TSP_Digest does not match the message it identifies".into(),
                    ));
                }
                own
            }
            // A cancel's only digest references another message, so there is
            // nothing self-addressing to recompute.
            ControlType::RelationshipCancel => first_digest,
        };

        let _pad = wire::decode_variable_data(wire::TSP_PLAINTEXT, frame, &mut pos)
            .ok_or_else(|| TspError::InvalidMessage("missing padding field".into()))?;

        let control = ControlMessage {
            control_type,
            digest: Some(thread_digest),
            nonce,
            // `reply` is always the digest of the earlier message this one
            // refers to: for an accept and a cancel, the first digest field.
            reply: match control_type {
                ControlType::RelationshipFormingInvite => None,
                ControlType::RelationshipFormingAccept | ControlType::RelationshipCancel => {
                    Some(first_digest)
                }
            },
            route,
            referral,
        };
        Ok(DecodedFrame {
            kind: MessageType::Control,
            hops: Vec::new(),
            body: control.encode(),
            control: Some(control),
            thread_digest,
        })
    } else {
        Err(TspError::InvalidMessage(
            "unsupported TSP payload type marker".into(),
        ))
    }
}

/// Encode the signature attachment: `-C23 -K22 B0 sig(64)`.
///
/// Rev 3 §9.5: the counts are length-based — the `-C` group holds the `-K`
/// header plus its content — and the signature uses the *indexed* code `B#`,
/// not Rev 2's non-indexed `0B`.
fn encode_signature_frame(signature: &[u8; SIG_LEN], out: &mut Vec<u8>) {
    wire::encode_count(wire::TSP_ATTACH_GRP, ATTACH_GROUP_QUADLETS, out);
    wire::encode_count(wire::TSP_INDEX_SIG_GRP, SIG_GROUP_QUADLETS, out);
    wire::encode_indexed_ed25519_signature(SIG_INDEX, signature, out);
}

/// Decode the signature attachment at `pos`, returning the Ed25519 signature.
///
/// A signature attachment is mandatory. An attachment that will not parse is a
/// rejection, never "this message is unsigned" — treating it as the latter is a
/// verification bypass, since corrupting the attachment code would then skip the
/// check entirely.
fn decode_signature_frame(data: &[u8], pos: &mut usize) -> Result<[u8; SIG_LEN], TspError> {
    let attach = wire::decode_count(wire::TSP_ATTACH_GRP, data, pos)
        .ok_or_else(|| TspError::InvalidMessage("missing -C signature attachment".into()))?;
    let group_begin = *pos;
    let group_end = (attach as usize)
        .checked_mul(3)
        .and_then(|len| group_begin.checked_add(len))
        .filter(|end| *end <= data.len())
        .ok_or_else(|| {
            TspError::InvalidMessage("-C attachment declares more content than the message".into())
        })?;

    let indexed = wire::decode_count(wire::TSP_INDEX_SIG_GRP, data, pos)
        .ok_or_else(|| TspError::InvalidMessage("missing -K indexed signature group".into()))?;
    let sig_group_end = (indexed as usize)
        .checked_mul(3)
        .and_then(|len| pos.checked_add(len))
        .filter(|end| *end <= group_end)
        .ok_or_else(|| {
            TspError::InvalidMessage("-K group overruns the -C attachment".into())
        })?;

    let (index, signature) = wire::decode_indexed_ed25519_signature(data, pos)
        .ok_or_else(|| TspError::InvalidMessage("missing indexed Ed25519 signature".into()))?;
    if *pos > sig_group_end {
        return Err(TspError::InvalidMessage(
            "signature overruns the -K group".into(),
        ));
    }

    // §9.5 allows any index — it selects among a VID's signing keys, and §3
    // leaves their order to the VID type — but we resolve exactly one key per
    // VID, so index 0 is the only one we can check a signature against. This is
    // therefore a limitation of our VID model rather than a rule of the spec,
    // and it will need revisiting if we ever model multi-key VIDs.
    //
    // Rejecting rather than ignoring also matters on its own: the index lives
    // in the signature attachment, which the message signature does not cover,
    // so ignoring it would let anyone flip those bits and produce a second byte
    // sequence that verifies identically. The mediator keys message storage and
    // idempotency on a digest of the whole wire bytes, so that would be a dedup
    // bypass.
    if index != SIG_INDEX {
        return Err(TspError::Verification(format!(
            "signature names key index {index}, but only index {SIG_INDEX} can be verified"
        )));
    }

    // Rev 3 tolerates further signatures in the group; we verify the first and
    // skip the rest, since choosing among a VID's keys by index is a VID-type
    // concern this crate does not model.
    *pos = group_end;
    Ok(signature)
}

/// Pack a direct TSP message.
pub fn pack(
    payload: &[u8],
    message_type: MessageType,
    sender_vid: &str,
    receiver_vid: &str,
    sender_signing_key: &[u8; 32],
    receiver_encryption_key: &[u8; 32],
) -> Result<PackedMessage, TspError> {
    pack_with_hops(
        payload,
        message_type,
        &[],
        sender_vid,
        receiver_vid,
        sender_signing_key,
        receiver_encryption_key,
    )
}

/// Like [`pack`] but carries a routing `hops` list in the payload frame (used by
/// [`crate::message::routed::pack_routed`] for [`MessageType::Routed`]). For all
/// other kinds `hops` must be empty.
///
/// Note that HPKE-Base does not use the sender's encryption key at all, so —
/// unlike Rev 2 — packing needs only the sender's *signing* secret.
pub fn pack_with_hops(
    body: &[u8],
    message_type: MessageType,
    hops: &[String],
    sender_vid: &str,
    receiver_vid: &str,
    sender_signing_key: &[u8; 32],
    receiver_encryption_key: &[u8; 32],
) -> Result<PackedMessage, TspError> {
    pack_inner(
        body,
        message_type,
        hops,
        sender_vid,
        receiver_vid,
        sender_signing_key,
        receiver_encryption_key,
        None,
    )
}

/// Pack an invite that introduces `new_vid` over this relationship (Rev 3
/// §7.2.5, parallel relationship forming).
///
/// `new_vid_signing_key` signs `Signature_new`, which covers the message's
/// digest and so cannot be produced before packing — which is why the key is
/// needed here rather than the caller signing beforehand.
#[allow(clippy::too_many_arguments)]
pub fn pack_referral_invite(
    control: &ControlMessage,
    sender_vid: &str,
    receiver_vid: &str,
    sender_signing_key: &[u8; 32],
    new_vid_signing_key: &[u8; 32],
    receiver_encryption_key: &[u8; 32],
) -> Result<PackedMessage, TspError> {
    if control.referral.is_none() {
        return Err(TspError::InvalidMessage(
            "pack_referral_invite needs a control message carrying a referral".into(),
        ));
    }
    pack_inner(
        &control.encode(),
        MessageType::Control,
        &[],
        sender_vid,
        receiver_vid,
        sender_signing_key,
        receiver_encryption_key,
        Some(new_vid_signing_key),
    )
}

#[allow(clippy::too_many_arguments)]
fn pack_inner(
    body: &[u8],
    message_type: MessageType,
    hops: &[String],
    sender_vid: &str,
    receiver_vid: &str,
    sender_signing_key: &[u8; 32],
    receiver_encryption_key: &[u8; 32],
    referral_signing_key: Option<&[u8; 32]>,
) -> Result<PackedMessage, TspError> {
    // 1. Envelope fields. These are the HPKE-Base AAD.
    let envelope = Envelope::new(message_type, sender_vid, receiver_vid);
    let envelope_fields = envelope.encode_fields()?;

    // 2. Plaintext payload frame, and the thread digest it carries.
    let (payload_frame, thread_digest) = encode_payload_frame(
        body,
        message_type,
        hops,
        sender_vid,
        &envelope_fields,
        referral_signing_key,
    )?;

    // 3. Seal. `aad` binds the ciphertext to the version and both VIDs;
    //    `info` is the fixed protocol code.
    let sealed = hpke::seal(
        &payload_frame,
        &envelope_fields,
        receiver_encryption_key,
        wire::TSP_INFO,
    )?;

    // 4. Ciphertext field: `enc ‖ ct`, with the AEAD tag inside `ct`. Rev 2 put
    //    `enc` at the end.
    let mut ciphertext = Vec::with_capacity(ENC_LEN + sealed.ciphertext.len());
    ciphertext.extend_from_slice(&sealed.enc);
    ciphertext.extend_from_slice(&sealed.ciphertext);

    let mut ciphertext_field = Vec::new();
    wire::encode_variable_data(
        wire::TSP_HPKE_BASE_CIPHERTEXT,
        &ciphertext,
        &mut ciphertext_field,
    );

    // 5. Close the `-E` frame over the fields and the ciphertext, then sign it.
    let mut wire_bytes = envelope::finalize_frame(&envelope_fields, &ciphertext_field)?;
    let signature = signing::sign(&wire_bytes, sender_signing_key)?;
    encode_signature_frame(&signature, &mut wire_bytes);

    Ok(PackedMessage {
        bytes: wire_bytes,
        thread_digest,
    })
}

/// Unpack a direct TSP message.
///
/// The signature is verified before anything is decrypted, and the AAD is
/// rebuilt from the received envelope bytes so that a ciphertext sealed under a
/// different sender or receiver will not open.
pub fn unpack(
    wire_bytes: &[u8],
    receiver_decryption_key: &[u8; 32],
    sender_signing_key: &[u8; 32],
) -> Result<UnpackedMessage, TspError> {
    if wire_bytes.len() < 48 {
        return Err(TspError::InvalidMessage("message too short".into()));
    }

    // 1. Envelope.
    let decoded = Envelope::decode_full(wire_bytes)?;
    let envelope = decoded.envelope;
    let envelope_fields = wire_bytes[decoded.aad.clone()].to_vec();

    // 2. Ciphertext field.
    let mut pos = decoded.header_len;
    let ct_range = wire::decode_variable_data_range(
        wire::TSP_HPKE_BASE_CIPHERTEXT,
        wire_bytes,
        &mut pos,
    )
    .ok_or_else(|| TspError::InvalidMessage("missing F ciphertext field".into()))?;

    // The `-E` count is authoritative for where the signable content ends; the
    // ciphertext field must fill it exactly.
    if pos != decoded.content_end {
        return Err(TspError::InvalidMessage(
            "ciphertext field does not fill the -E frame".into(),
        ));
    }

    if ct_range.len() > MAX_MESSAGE_SIZE {
        return Err(TspError::InvalidMessage("ciphertext too large".into()));
    }
    if ct_range.len() < ENC_LEN + TAG_LEN {
        return Err(TspError::InvalidMessage("ciphertext truncated".into()));
    }

    // 3. Signature over the whole `-E` frame.
    let signature = decode_signature_frame(wire_bytes, &mut pos)?;
    if pos != wire_bytes.len() {
        return Err(TspError::InvalidMessage(
            "trailing bytes after signature".into(),
        ));
    }
    signing::verify(
        &wire_bytes[..decoded.content_end],
        &signature,
        sender_signing_key,
    )?;

    // 4. Split `enc` off the front and open the remainder.
    let ciphertext = &wire_bytes[ct_range.clone()];
    let enc: [u8; 32] = ciphertext[..ENC_LEN]
        .try_into()
        .map_err(|_| TspError::InvalidMessage("bad enc size".into()))?;

    let payload_frame = hpke::open(
        &ciphertext[ENC_LEN..],
        &envelope_fields,
        &enc,
        receiver_decryption_key,
        wire::TSP_INFO,
    )?;

    // 5. Decode the payload frame, verifying the embedded digest and the ESSR
    //    sender field against the envelope.
    let DecodedFrame {
        kind: message_type,
        hops,
        body: payload,
        control,
        thread_digest,
    } = decode_payload_frame(&payload_frame, &envelope_fields, &envelope.sender)?;

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
    use crate::PrivateVid;
    use ed25519_dalek::SigningKey;
    use x25519_dalek::{PublicKey, StaticSecret};

    struct TestKeys {
        sender_sign_sk: [u8; 32],
        sender_sign_pk: [u8; 32],
        receiver_enc_sk: [u8; 32],
        receiver_enc_pk: [u8; 32],
    }

    fn gen_keys() -> TestKeys {
        let sender_sign = SigningKey::generate(&mut rand_10::rng());
        let receiver_enc = StaticSecret::random_from_rng(&mut rand_10::rng());

        TestKeys {
            sender_sign_sk: sender_sign.to_bytes(),
            sender_sign_pk: sender_sign.verifying_key().to_bytes(),
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
            &keys.receiver_enc_pk,
        )
        .unwrap();

        // First byte is the -E count code.
        assert_eq!(packed.bytes[0], 0xf8);

        let unpacked = unpack(
            &packed.bytes,
            &keys.receiver_enc_sk,
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
                    &keys.sender_sign_pk,
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_receiver_key_fails() {
        let keys = gen_keys();
        let wrong_sk = StaticSecret::random_from_rng(&mut rand_10::rng());
        let packed = pack(
            b"secret",
            MessageType::Direct,
            "did:web:a.example",
            "did:web:b.example",
            &keys.sender_sign_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        assert!(
            unpack(
                &packed.bytes,
                &wrong_sk.to_bytes(),
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
            &keys.receiver_enc_pk,
        )
        .unwrap();

        let unpacked = unpack(
            &packed.bytes,
            &keys.receiver_enc_sk,
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
            &keys.receiver_enc_pk,
        )
        .unwrap();
        assert_eq!(message_digest(&packed), message_digest(&packed));
    }

    // ---- Rev 3 conformance ----

    /// The ciphertext is `enc ‖ ct` under the HPKE-Base `F` code. Rev 2 put
    /// `enc` at the *end* under the HPKE-Auth `G` code, so a message packed by
    /// a Rev 2 build does not even locate its own ciphertext field here.
    #[test]
    fn ciphertext_is_enc_first_under_the_f_code() {
        let keys = gen_keys();
        let packed = pack(
            b"x",
            MessageType::Direct,
            "did:web:alice",
            "did:web:bob",
            &keys.sender_sign_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        let decoded = Envelope::decode_full(&packed.bytes).unwrap();
        let mut pos = decoded.header_len;
        let ct = wire::decode_variable_data_range(
            wire::TSP_HPKE_BASE_CIPHERTEXT,
            &packed.bytes,
            &mut pos,
        )
        .expect("ciphertext must be an F field");
        assert!(ct.len() > ENC_LEN + TAG_LEN);

        // The Rev 2 `G` code must not parse.
        let mut pos = decoded.header_len;
        assert!(
            wire::decode_variable_data_range(
                wire::cesr_int("G") as u32,
                &packed.bytes,
                &mut pos
            )
            .is_none()
        );
    }

    /// The `-E` count covers the ciphertext, so the signature attachment begins
    /// exactly where the frame's declared content ends.
    #[test]
    fn envelope_frame_encloses_the_ciphertext() {
        let keys = gen_keys();
        let packed = pack(
            b"payload",
            MessageType::Direct,
            "did:web:alice",
            "did:web:bob",
            &keys.sender_sign_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        let decoded = Envelope::decode_full(&packed.bytes).unwrap();
        assert!(decoded.content_end > decoded.header_len);
        // What follows the frame is the -C attachment: 3 + 3 + 66 bytes.
        assert_eq!(packed.bytes.len() - decoded.content_end, 72);
    }

    /// An invite's `TSP_Digest` is on the wire and is recomputed by the
    /// receiver. Rev 2's thread digest was never transmitted, so this check
    /// could not exist.
    #[test]
    fn invite_digest_is_carried_and_verified() {
        let keys = gen_keys();
        let invite = ControlMessage::invite();

        let packed = pack(
            &invite.encode(),
            MessageType::Control,
            "did:web:alice",
            "did:web:bob",
            &keys.sender_sign_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        let unpacked = unpack(&packed.bytes, &keys.receiver_enc_sk, &keys.sender_sign_pk).unwrap();
        assert_eq!(unpacked.thread_digest, packed.thread_digest);

        let control = unpacked.control.expect("invite decodes to a control");
        assert_eq!(control.digest, Some(packed.thread_digest));
        assert_eq!(control.nonce, invite.nonce);
    }

    /// The digest is self-addressing, so it binds the envelope too: the same
    /// invite sent between different VIDs has a different thread id.
    #[test]
    fn digest_binds_the_envelope() {
        let keys = gen_keys();
        let invite = ControlMessage::invite();

        let to_bob = pack(
            &invite.encode(),
            MessageType::Control,
            "did:web:alice",
            "did:web:bob",
            &keys.sender_sign_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();
        let to_carol = pack(
            &invite.encode(),
            MessageType::Control,
            "did:web:alice",
            "did:web:carol",
            &keys.sender_sign_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        assert_ne!(to_bob.thread_digest, to_carol.thread_digest);
    }

    /// A tampered digest is caught on receive. The signature covers the
    /// ciphertext, so this is checked by corrupting the plaintext frame and
    /// re-sealing it — i.e. by a sender that signs correctly but lies about the
    /// digest, which is precisely the case the SAID exists to catch.
    #[test]
    fn a_lied_about_digest_is_rejected() {
        let keys = gen_keys();
        let envelope = Envelope::new(MessageType::Control, "did:web:alice", "did:web:bob");
        let fields = envelope.encode_fields().unwrap();

        let invite = ControlMessage::invite();
        let (mut frame, digest) = encode_payload_frame(
            &invite.encode(),
            MessageType::Control,
            &[],
            "did:web:alice",
            &fields,

            None,
        )
        .unwrap();

        // Flip a byte of the embedded digest, then seal and sign honestly.
        let slot = frame
            .windows(DIGEST_LEN)
            .position(|w| w == digest)
            .expect("digest is embedded in the frame");
        frame[slot] ^= 0xFF;

        let sealed = hpke::seal(&frame, &fields, &keys.receiver_enc_pk, wire::TSP_INFO).unwrap();
        let mut ciphertext = sealed.enc.to_vec();
        ciphertext.extend_from_slice(&sealed.ciphertext);
        let mut field = Vec::new();
        wire::encode_variable_data(wire::TSP_HPKE_BASE_CIPHERTEXT, &ciphertext, &mut field);
        let mut bytes = envelope::finalize_frame(&fields, &field).unwrap();
        let sig = signing::sign(&bytes, &keys.sender_sign_sk).unwrap();
        encode_signature_frame(&sig, &mut bytes);

        let err = unpack(&bytes, &keys.receiver_enc_sk, &keys.sender_sign_pk).unwrap_err();
        assert!(matches!(err, TspError::Verification(_)), "got {err:?}");
    }

    /// The ESSR sender field must agree with the envelope. This is the second,
    /// independent sender binding the spec permits under HPKE-Base — the AAD
    /// being the first.
    #[test]
    fn essr_sender_mismatch_is_rejected() {
        let keys = gen_keys();
        let envelope = Envelope::new(MessageType::Direct, "did:web:alice", "did:web:bob");
        let fields = envelope.encode_fields().unwrap();

        // Build a frame whose ESSR sender field names someone else.
        let (frame, _) = encode_payload_frame(
            b"body",
            MessageType::Direct,
            &[],
            "did:web:mallory",
            &fields,
            None,
        )
        .unwrap();

        let sealed = hpke::seal(&frame, &fields, &keys.receiver_enc_pk, wire::TSP_INFO).unwrap();
        let mut ciphertext = sealed.enc.to_vec();
        ciphertext.extend_from_slice(&sealed.ciphertext);
        let mut field = Vec::new();
        wire::encode_variable_data(wire::TSP_HPKE_BASE_CIPHERTEXT, &ciphertext, &mut field);
        let mut bytes = envelope::finalize_frame(&fields, &field).unwrap();
        let sig = signing::sign(&bytes, &keys.sender_sign_sk).unwrap();
        encode_signature_frame(&sig, &mut bytes);

        let err = unpack(&bytes, &keys.receiver_enc_sk, &keys.sender_sign_pk).unwrap_err();
        assert!(matches!(err, TspError::Verification(_)), "got {err:?}");
    }

    /// The AAD names both VIDs, so a ciphertext sealed for one envelope will not
    /// open under another even when the signature is rebuilt to match.
    #[test]
    fn ciphertext_does_not_open_under_a_substituted_envelope() {
        let keys = gen_keys();
        let packed = pack(
            b"secret",
            MessageType::Direct,
            "did:web:alice",
            "did:web:bob",
            &keys.sender_sign_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        // Lift the ciphertext into an envelope naming a different receiver.
        let decoded = Envelope::decode_full(&packed.bytes).unwrap();
        let ct_field = &packed.bytes[decoded.header_len..decoded.content_end];

        let substituted = Envelope::new(MessageType::Direct, "did:web:alice", "did:web:carol");
        let fields = substituted.encode_fields().unwrap();
        let mut bytes = envelope::finalize_frame(&fields, ct_field).unwrap();
        let sig = signing::sign(&bytes, &keys.sender_sign_sk).unwrap();
        encode_signature_frame(&sig, &mut bytes);

        let err = unpack(&bytes, &keys.receiver_enc_sk, &keys.sender_sign_pk).unwrap_err();
        assert!(matches!(err, TspError::Hpke(_)), "got {err:?}");
    }

    /// A corrupted signature attachment must be a rejection, never "unsigned".
    /// The reference found a real bypass here: an unparseable attachment
    /// decoded as "no signature" and skipped verification altogether.
    #[test]
    fn a_corrupt_signature_attachment_is_rejected_not_ignored() {
        let keys = gen_keys();
        let packed = pack(
            b"payload",
            MessageType::Direct,
            "did:web:alice",
            "did:web:bob",
            &keys.sender_sign_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        let decoded = Envelope::decode_full(&packed.bytes).unwrap();
        for offset in 0..3 {
            let mut bytes = packed.bytes.clone();
            bytes[decoded.content_end + offset] ^= 0xFF;
            assert!(
                unpack(&bytes, &keys.receiver_enc_sk, &keys.sender_sign_pk).is_err(),
                "corrupting attachment byte {offset} must not bypass verification"
            );
        }
    }

    /// Flipping any single byte of a packed message must be caught. This is the
    /// sweep that found the two gaps the reference reported; it is cheap and it
    /// covers frames we do not otherwise think to test.
    #[test]
    fn every_single_byte_flip_is_rejected() {
        let keys = gen_keys();
        let packed = pack(
            b"payload",
            MessageType::Direct,
            "did:web:alice",
            "did:web:bob",
            &keys.sender_sign_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        for i in 0..packed.bytes.len() {
            let mut bytes = packed.bytes.clone();
            bytes[i] ^= 0x01;
            assert!(
                unpack(&bytes, &keys.receiver_enc_sk, &keys.sender_sign_pk).is_err(),
                "flipping byte {i} produced a message that verified"
            );
        }
    }

    // ---- The Rev 2 / Rev 3 boundary ----
    //
    // These pin what a Rev 2 message does when it meets this build. They exist
    // because Rev 3 is wire-breaking but did *not* change the version the
    // envelope advertises — both revisions say `YTSP-AAB` — so the two can only
    // be told apart structurally. If dual-revision support is ever built, this
    // is the discriminator it has to rest on.

    /// Build the Rev 2 wire shape by hand. The envelope prefix is byte-identical
    /// to Rev 3's; Rev 2 then diverges with the `XAAA` marker and a `G`
    /// ciphertext where Rev 3 has an `F` one.
    fn rev2_shaped_message(sender: &str, receiver: &str) -> Vec<u8> {
        let mut header = Vec::new();
        wire::encode_version(&mut header);
        wire::encode_variable_data(wire::TSP_VID, sender.as_bytes(), &mut header);
        wire::encode_variable_data(wire::TSP_VID, receiver.as_bytes(), &mut header);
        wire::encode_fixed_data(wire::cesr_int("X") as u32, &[0, 0], &mut header);

        // Rev 2's -E count covered the header only, not the ciphertext.
        let mut out = Vec::new();
        wire::encode_count(wire::TSP_ETS_WRAPPER, (header.len() / 3) as u32, &mut out);
        out.extend_from_slice(&header);

        wire::encode_variable_data(wire::cesr_int("G") as u32, &[0xAAu8; 96], &mut out);

        wire::encode_count(wire::TSP_ATTACH_GRP, 22, &mut out);
        wire::encode_count(wire::TSP_INDEX_SIG_GRP, 22, &mut out);
        wire::encode_fixed_data(wire::ED25519_SIGNATURE, &[0x11u8; 64], &mut out);
        out
    }

    /// The version field does not separate the revisions — both encode
    /// `YTSP-AAB` — so the first difference is the byte after the two VIDs:
    /// Rev 2's `XAAA` marker, or Rev 3's `F` ciphertext field.
    #[test]
    fn rev2_and_rev3_differ_only_after_the_vids() {
        let keys = gen_keys();
        let rev2 = rev2_shaped_message("did:web:alice", "did:web:bob");
        let rev3 = pack(
            b"x",
            MessageType::Direct,
            "did:web:alice",
            "did:web:bob",
            &keys.sender_sign_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap()
        .bytes;

        let d2 = Envelope::decode_full(&rev2).unwrap();
        let d3 = Envelope::decode_full(&rev3).unwrap();

        // The version marker and both VIDs are byte-identical: everything from
        // just past the `-E` count code to the end of the receiver VID.
        assert_eq!(d2.header_len, d3.header_len);
        assert_eq!(rev2[3..d2.header_len], rev3[3..d3.header_len]);

        // Two things do differ. The `-E` count, because Rev 3 covers the
        // ciphertext with it and Rev 2 covered only the header...
        assert_ne!(rev2[..3], rev3[..3]);
        assert!(d3.content_end > d2.content_end);

        // ...and, unambiguously, the byte after the VIDs.
        assert_eq!(rev2[d2.header_len], 0x5c, "Rev 2 continues with XAAA");
        assert_ne!(rev3[d3.header_len], 0x5c, "Rev 3 continues with the F field");
    }

    /// A Rev 2 message is refused with a clear error rather than misread. It
    /// gets as far as the ciphertext field, where `G` is no longer a code this
    /// build knows.
    #[test]
    fn a_rev2_message_is_rejected_not_misread() {
        let keys = gen_keys();
        let rev2 = rev2_shaped_message("did:web:alice", "did:web:bob");
        let err = unpack(&rev2, &keys.receiver_enc_sk, &keys.sender_sign_pk).unwrap_err();
        assert!(
            matches!(err, TspError::InvalidMessage(_)),
            "expected a clean rejection, got {err:?}"
        );
    }

    /// Keys-free addressing reads both revisions. The envelope prefix a relay
    /// needs — the `-E` frame, the version and both VIDs — did not change, so a
    /// mediator can route, apply ACLs and store a message of either revision
    /// without knowing which it is holding.
    #[test]
    fn keys_free_addressing_reads_both_revisions() {
        let rev2 = rev2_shaped_message("did:web:alice", "did:web:bob");
        assert!(crate::message::meta::is_tsp(&rev2));

        let meta = crate::message::meta::MetaEnvelope::parse(&rev2).unwrap();
        assert_eq!(meta.sender, "did:web:alice");
        assert_eq!(meta.receiver, "did:web:bob");
    }

    /// Rev 3 widened the `-E` count to cover the ciphertext, which makes the
    /// long count code `--E#####` reachable for the first time — Rev 2's count
    /// covered only the header and so was always short. Messages either side of
    /// the 4095-quadlet boundary must round-trip and must classify as TSP.
    ///
    /// Two real bugs hid behind that boundary until Rev 3 crossed it: a long
    /// count decoded with the identifier bits still in it, and an ingress
    /// classifier that knew only the short framing's leading byte.
    #[test]
    fn messages_either_side_of_the_long_count_boundary_round_trip() {
        let keys = gen_keys();
        // ~12 KB of content is where the `-E` count stops fitting in 12 bits.
        for size in [100usize, 12_000, 20_000, 60_000] {
            let payload = vec![0x41u8; size];
            let packed = pack(
                &payload,
                MessageType::Direct,
                "did:web:alice",
                "did:web:bob",
                &keys.sender_sign_sk,
                &keys.receiver_enc_pk,
            )
            .unwrap();

            assert!(
                crate::message::meta::is_tsp(&packed.bytes),
                "a {size}-byte message must classify as TSP at ingress"
            );
            assert!(
                crate::message::meta::MetaEnvelope::parse(&packed.bytes).is_ok(),
                "a {size}-byte message must expose keys-free addressing"
            );

            let unpacked =
                unpack(&packed.bytes, &keys.receiver_enc_sk, &keys.sender_sign_pk).unwrap();
            assert_eq!(unpacked.payload, payload, "{size}-byte round trip");
        }
    }

    /// A long-form message is framed `--E#####` and so leads with `0xFB`, not
    /// the `0xF8` of the short form. Pinned because an ingress classifier that
    /// knows only one of them silently misroutes the other.
    #[test]
    fn long_framing_uses_its_own_leading_byte() {
        let keys = gen_keys();
        let small = pack(
            b"x",
            MessageType::Direct,
            "did:web:alice",
            "did:web:bob",
            &keys.sender_sign_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();
        let large = pack(
            &vec![0x41u8; 20_000],
            MessageType::Direct,
            "did:web:alice",
            "did:web:bob",
            &keys.sender_sign_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        assert_eq!(small.bytes[0], crate::message::meta::TSP_MAGIC_BYTE);
        assert_eq!(large.bytes[0], crate::message::meta::TSP_MAGIC_BYTE_LONG);
    }

    /// An accept carries two digests and their order is interop-visible:
    /// `XRFA, VID_sndr, Digest, Reply_Digest` where `Digest` is the *invite's*
    /// digest echoed verbatim and `Reply_Digest` is the accept's own
    /// self-addressing digest.
    ///
    /// A round-trip test cannot see this. Encoder and decoder agree with each
    /// other under either order, so the only way to catch a swap is to assert
    /// the position of a value that came from somewhere else — here, the
    /// invite's digest, which must appear in the *first* slot.
    #[test]
    fn an_accept_echoes_the_invite_digest_in_the_first_slot() {
        let keys = gen_keys();

        let invite_packed = pack(
            &ControlMessage::invite().encode(),
            MessageType::Control,
            "did:web:alice",
            "did:web:bob",
            &keys.sender_sign_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();
        let invite_digest = invite_packed.thread_digest;

        let accept_packed = pack(
            &ControlMessage::accept(invite_digest).encode(),
            MessageType::Control,
            "did:web:bob",
            "did:web:alice",
            &keys.sender_sign_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        // The accept's own digest is distinct from the invite's...
        assert_ne!(accept_packed.thread_digest, invite_digest);

        let unpacked = unpack(
            &accept_packed.bytes,
            &keys.receiver_enc_sk,
            &keys.sender_sign_pk,
        )
        .unwrap();
        let control = unpacked.control.expect("accept decodes to a control");

        // ...`reply` is the invite it answers, read from the first slot...
        assert_eq!(control.reply, Some(invite_digest));
        // ...and `digest` is the accept's own, read from the second.
        assert_eq!(control.digest, Some(accept_packed.thread_digest));
        assert_eq!(unpacked.thread_digest, accept_packed.thread_digest);
    }

    /// Pin the accept's field order in the plaintext frame directly: the
    /// invite's digest must sit in the first digest position, before the
    /// accept's own.
    #[test]
    fn accept_field_order_is_digest_then_reply_digest() {
        let envelope = Envelope::new(MessageType::Control, "did:web:bob", "did:web:alice");
        let fields = envelope.encode_fields().unwrap();
        let invite_digest = [0x7Au8; DIGEST_LEN];

        let (frame, own) = encode_payload_frame(
            &ControlMessage::accept(invite_digest).encode(),
            MessageType::Control,
            &[],
            "did:web:bob",
            &fields,

            None,
        )
        .unwrap();

        let first = frame
            .windows(DIGEST_LEN)
            .position(|w| w == invite_digest)
            .expect("the invite digest is carried");
        let second = frame
            .windows(DIGEST_LEN)
            .position(|w| w == own)
            .expect("the accept's own digest is carried");
        assert!(
            first < second,
            "the echoed invite digest must precede the accept's own"
        );
    }

    // ---- Rev 3 §7.2.5: parallel relationship forming ----

    /// A referral invite round-trips, and its `Signature_new` verifies against
    /// the introduced VID's key.
    #[test]
    fn a_referral_invite_round_trips_and_its_signature_verifies() {
        let keys = gen_keys();
        let new_vid = PrivateVid::generate("did:example:alice-parallel");

        let packed = pack_referral_invite(
            &ControlMessage::invite_referral("did:example:alice-parallel"),
            "did:example:alice",
            "did:example:bob",
            &keys.sender_sign_sk,
            &new_vid.signing_key,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        let unpacked = unpack(&packed.bytes, &keys.receiver_enc_sk, &keys.sender_sign_pk).unwrap();
        let control = unpacked.control.expect("a referral invite decodes to a control");
        let referral = control.referral.as_ref().expect("the referral survives");
        assert_eq!(referral.new_vid, "did:example:alice-parallel");

        verify_referral(&control, "did:example:alice", &new_vid.verifying_key)
            .expect("Signature_new verifies against the introduced VID");
    }

    /// The signature is made by the *introduced* VID, not the sender. Checking
    /// it against the sender's key must fail, or the field would prove nothing
    /// beyond what the message signature already proves.
    #[test]
    fn a_referral_signature_does_not_verify_against_the_senders_key() {
        let keys = gen_keys();
        let new_vid = PrivateVid::generate("did:example:alice-parallel");

        let packed = pack_referral_invite(
            &ControlMessage::invite_referral("did:example:alice-parallel"),
            "did:example:alice",
            "did:example:bob",
            &keys.sender_sign_sk,
            &new_vid.signing_key,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        let unpacked = unpack(&packed.bytes, &keys.receiver_enc_sk, &keys.sender_sign_pk).unwrap();
        let control = unpacked.control.unwrap();

        assert!(
            verify_referral(&control, "did:example:alice", &keys.sender_sign_pk).is_err(),
            "the sender's key must not satisfy Signature_new"
        );
    }

    /// The signature covers the digest, which covers the envelope — so a
    /// referral lifted into a message between different VIDs does not verify.
    /// That is what stops one being replayed into another relationship.
    #[test]
    fn a_referral_does_not_survive_being_moved_to_another_relationship() {
        let keys = gen_keys();
        let new_vid = PrivateVid::generate("did:example:alice-parallel");
        let control = ControlMessage::invite_referral("did:example:alice-parallel");

        let to_bob = pack_referral_invite(
            &control,
            "did:example:alice",
            "did:example:bob",
            &keys.sender_sign_sk,
            &new_vid.signing_key,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        let unpacked = unpack(&to_bob.bytes, &keys.receiver_enc_sk, &keys.sender_sign_pk).unwrap();
        let decoded = unpacked.control.unwrap();

        // Same referral, checked as though it had arrived from a different
        // sender: the digest in the signed data no longer matches.
        assert!(
            verify_referral(&decoded, "did:example:mallory", &new_vid.verifying_key).is_err(),
            "a referral must not verify under a different sender VID"
        );
    }

    /// An invite that introduces nothing carries the empty `-JAA` field, and
    /// there is nothing to verify.
    #[test]
    fn a_plain_invite_carries_no_referral() {
        let keys = gen_keys();
        let packed = pack(
            &ControlMessage::invite().encode(),
            MessageType::Control,
            "did:example:alice",
            "did:example:bob",
            &keys.sender_sign_sk,
            &keys.receiver_enc_pk,
        )
        .unwrap();

        let unpacked = unpack(&packed.bytes, &keys.receiver_enc_sk, &keys.sender_sign_pk).unwrap();
        let control = unpacked.control.unwrap();
        assert!(control.referral.is_none());
        assert!(verify_referral(&control, "did:example:alice", &keys.sender_sign_pk).is_err());
    }

    /// Packing a referral without the introduced VID's key is refused rather
    /// than silently producing an invite with an unusable signature.
    #[test]
    fn a_referral_invite_needs_the_introduced_vids_key() {
        let keys = gen_keys();
        let envelope = Envelope::new(MessageType::Control, "did:example:alice", "did:example:bob");
        let fields = envelope.encode_fields().unwrap();

        let err = encode_payload_frame(
            &ControlMessage::invite_referral("did:example:alice-parallel").encode(),
            MessageType::Control,
            &[],
            "did:example:alice",
            &fields,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, TspError::Signing(_)), "got {err:?}");
        let _ = keys;
    }
}
