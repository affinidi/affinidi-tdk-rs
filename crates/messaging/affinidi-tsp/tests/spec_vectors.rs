//! Conformance against the specification's own test vectors (Rev 3 Appendix A).
//!
//! These are the strongest evidence this crate has that it reads Rev 3
//! correctly, and they check something the interop harness cannot. The harness
//! packs with one implementation and unpacks with the other, so a shared
//! misreading of the spec passes it: both sides agree, and nothing external says
//! whether the agreement is right. These vectors were generated once, published
//! in the specification, and are fixed — a message that unpacks here is one the
//! specification says is a valid Rev 3 message, whatever any implementation
//! thinks.
//!
//! What that buys, concretely, is the `TSP_Digest` derivation. `unpack`
//! recomputes an invite's or accept's SAID from the received bytes and refuses
//! the message on a mismatch, and the derivation covers the version, both
//! envelope VIDs and the payload fields with the digest's own slot dummied out
//! (§7.2.1). So every control vector below verifies that whole construction
//! against a value this crate had no part in producing.
//!
//! The vectors are qb64 — CESR's text domain — which transcodes directly to the
//! qb2 binary domain this crate works in, so decoding is plain base64url and no
//! CESR-aware conversion is involved.
//!
//! Fixture: `tests/vectors/rev3.json`, lifted verbatim from spec commit
//! `c80b0e4`. The private keys in it are published in the specification and must
//! never be used for anything else.

use affinidi_tsp::MessageType;
use affinidi_tsp::message::control::ControlType;
use affinidi_tsp::message::direct::unpack;
use serde_json::Value;

/// Decode CESR's text domain. It is base64url without padding, and every TSP
/// frame is a whole number of 24-bit groups, so this is a straight transcode
/// rather than a CESR-aware conversion.
fn qb64(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for ch in s.bytes() {
        let v = ALPHABET
            .iter()
            .position(|c| *c == ch)
            .unwrap_or_else(|| panic!("not base64url: {:?}", ch as char));
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn key(s: &str) -> [u8; 32] {
    qb64(s).try_into().expect("32-byte key")
}

struct Vectors {
    json: Value,
}

impl Vectors {
    fn load() -> Self {
        let raw = include_str!("vectors/rev3.json");
        Self {
            json: serde_json::from_str(raw).expect("fixture parses"),
        }
    }

    fn id(&self, name: &str, field: &str) -> String {
        self.json["identifiers"][name][field]
            .as_str()
            .unwrap_or_else(|| panic!("no identifiers.{name}.{field}"))
            .to_string()
    }

    fn vector(&self, name: &str) -> &Value {
        let v = &self.json["vectors"][name];
        assert!(!v.is_null(), "no vector {name}");
        v
    }

    fn field(&self, vector: &str, field: &str) -> String {
        self.vector(vector)[field]
            .as_str()
            .unwrap_or_else(|| panic!("vector {vector} has no {field}"))
            .to_string()
    }

    /// Unpack a vector's `message` with the keys its `sender`/`receiver` name.
    fn unpack(&self, name: &str) -> affinidi_tsp::message::direct::UnpackedMessage {
        let sender = self.field(name, "sender");
        let receiver = self.field(name, "receiver");
        let message = qb64(&self.field(name, "message"));
        unpack(
            &message,
            &key(&self.id(&receiver, "skE")),
            &key(&self.id(&sender, "pkS")),
        )
        .unwrap_or_else(|e| panic!("vector {name} must unpack: {e}"))
    }

    fn assert_parties(
        &self,
        name: &str,
        unpacked: &affinidi_tsp::message::direct::UnpackedMessage,
    ) {
        assert_eq!(
            unpacked.sender,
            self.id(&self.field(name, "sender"), "id"),
            "{name}: sender VID"
        );
        assert_eq!(
            unpacked.receiver,
            self.id(&self.field(name, "receiver"), "id"),
            "{name}: receiver VID"
        );
    }
}

/// The confidential application message: HPKE-Base, ChaCha20Poly1305, with the
/// AAD being the envelope that precedes the ciphertext.
///
/// This one vector exercises the whole Rev 3 crypto change at once. Under Rev 2
/// it would not open at all: the mode was HPKE-Auth, the ciphertext code was `G`
/// rather than `F`, `info` was the `-E` frame rather than the five bytes
/// `YTSP-`, and the AAD was empty.
#[test]
fn direct_hpke_base() {
    let v = Vectors::load();
    let unpacked = v.unpack("direct-hpke-base");
    v.assert_parties("direct-hpke-base", &unpacked);
    assert_eq!(unpacked.message_type, MessageType::Direct);
    assert_eq!(unpacked.payload, b"hello world");
    assert!(unpacked.confidential, "the vector is a sealed message");
}

/// The non-confidential message (§3.5): the payload frame sits in the clear
/// where a ciphertext would be, under the same `-Z` framing.
///
/// Asserted at the byte level as well, which is possible only here — nothing is
/// encrypted, so the vector's `payload` must appear verbatim inside its
/// `message`. That pins the frame layout itself, not just what we recover from
/// it.
#[test]
fn direct_signed_only() {
    let v = Vectors::load();
    let unpacked = v.unpack("direct-signed-only");
    v.assert_parties("direct-signed-only", &unpacked);
    assert_eq!(unpacked.message_type, MessageType::Direct);
    assert_eq!(unpacked.payload, b"public announcement!");
    assert!(
        !unpacked.confidential,
        "a signed-only message is not confidential, and the distinction is the point of \
         reporting it"
    );

    let message = qb64(&v.field("direct-signed-only", "message"));
    let payload = qb64(&v.field("direct-signed-only", "payload"));
    assert!(
        message.windows(payload.len()).any(|w| w == payload),
        "the payload frame appears verbatim in the message"
    );
}

/// The relationship-forming invite, and with it the `TSP_Digest` derivation.
///
/// `unpack` recomputes the SAID over the received bytes and refuses the message
/// if it does not match what the sender embedded, so the assertion that this
/// vector unpacks at all is the assertion that our §7.2.1 derivation agrees with
/// the reference's, over a value we had no hand in producing.
#[test]
fn control_rfi() {
    let v = Vectors::load();
    let unpacked = v.unpack("control-rfi-direct");
    v.assert_parties("control-rfi-direct", &unpacked);
    assert_eq!(unpacked.message_type, MessageType::Control);

    let control = unpacked.control.as_ref().expect("an invite is a control");
    assert_eq!(control.control_type, ControlType::RelationshipFormingInvite);
    assert_eq!(
        control.digest,
        Some(unpacked.thread_digest),
        "the invite's Digest is its own SAID"
    );
    assert_eq!(
        control.nonce.expect("an invite carries a nonce").len(),
        16,
        "Rev 3 halved the nonce to 128 bits"
    );
    assert!(
        control.route.is_empty(),
        "a direct invite's Reply_Path is empty (-JAA)"
    );
    assert!(
        control.referral.is_none(),
        "a direct invite introduces nothing (-JAA)"
    );
}

/// The accept, and the two-digest ordering that Rev 3 swapped.
///
/// The cross-vector check is the valuable part: the accept's echoed digest must
/// equal the *invite vector's* SAID. That is what makes these two vectors one
/// exchange rather than two unrelated messages, and it is exactly the field
/// ordering we had backwards — §7 puts the echoed invite digest in `Digest` and
/// the accept's own SAID in `Reply_Digest`.
#[test]
fn control_rfa_echoes_the_invite() {
    let v = Vectors::load();
    let invite = v.unpack("control-rfi-direct");
    let accept = v.unpack("control-rfa-direct");
    v.assert_parties("control-rfa-direct", &accept);

    assert_eq!(
        accept.sender,
        v.id("bob", "id"),
        "the accept comes back the other way"
    );

    let control = accept.control.as_ref().expect("an accept is a control");
    assert_eq!(control.control_type, ControlType::RelationshipFormingAccept);
    assert_eq!(
        control.reply,
        Some(invite.thread_digest),
        "the accept echoes the invite's digest"
    );
    assert_eq!(
        control.digest,
        Some(accept.thread_digest),
        "and carries its own SAID as Reply_Digest"
    );
    assert_ne!(
        accept.thread_digest, invite.thread_digest,
        "the two directions of the relationship have different ids"
    );
}

/// The `control-rfd` vector as published is truncated, and cannot be decoded by
/// anyone.
///
/// Its `message` is 393 characters — a length base64 cannot produce, since 4
/// characters carry 3 bytes and a remainder of 1 is impossible. In the spec
/// source the fourth line of the block is 65 characters where every other line
/// in every other vector is 68, so three characters were lost in generation or
/// editing.
///
/// The arithmetic says exactly how many. Every TSP message is
/// `3 + count*3 + 72` bytes: the `-E` count code, the content it declares, and
/// the signature group (`-C` plus its 23 quadlets). This vector's `-E` declares
/// 74 quadlets, so it should be 297 bytes / 396 characters. Every other vector
/// in the appendix satisfies that identity exactly; this one is 3 characters
/// short of it.
///
/// So this test asserts the defect rather than working around it. When the
/// specification republishes the vector it will start failing, which is the
/// signal to replace it with the real check — the assertions are written out
/// below ready for that, since they are the point of the vector: a cancel
/// carries one digest naming the relationship it ends, and no nonce, Rev 3
/// having removed the one it used to have.
///
/// Reported upstream against PR #63.
#[test]
fn control_rfd_vector_is_truncated_upstream() {
    let v = Vectors::load();
    let message = v.field("control-rfd", "message");

    assert_eq!(
        message.len() % 4,
        1,
        "if this vector now decodes, the spec has republished it — restore the real check: \
         unpack it, assert ControlType::RelationshipCancel, assert its `reply` equals the \
         control-rfi-direct vector's thread digest, and assert `nonce` is None"
    );

    // The length it should have, from the count its own envelope declares.
    let declared = qb64(&message[..4]);
    let count = (u32::from_be_bytes([0, declared[0], declared[1], declared[2]]) & 0xFFF) as usize;
    let expected_bytes = 3 + count * 3 + 72;
    assert_eq!(expected_bytes, 297);
    assert_eq!(
        expected_bytes * 4 / 3,
        396,
        "the vector should be 396 characters; it is {}",
        message.len()
    );
}

/// The identity the truncation was caught by, applied to every vector that is
/// intact: a TSP message is its `-E` count code, the content that count
/// declares, and a fixed-size signature group.
///
/// Worth asserting across the whole appendix rather than only where it failed.
/// It is a cheap check that catches a whole class of transcription damage, and
/// it found a real defect in a published vector on first contact.
#[test]
fn every_intact_vector_has_a_self_consistent_length() {
    let v = Vectors::load();
    let names = [
        "direct-sealed-box",
        "direct-hpke-base",
        "direct-signed-only",
        "control-rfi-direct",
        "control-rfa-direct",
        "control-rfi-sealed-box",
        "nested-direct",
        "routed",
    ];
    for name in names {
        let bytes = qb64(&v.field(name, "message"));
        let count = (u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) & 0xFFF) as usize;
        assert_eq!(
            bytes.len(),
            3 + count * 3 + 72,
            "{name}: -E count code + declared content + signature group"
        );
    }
}

/// The nested message: an `XHOP` payload with an empty hop list carrying a
/// complete inner message, which is then unpacked with the inner pair's keys.
///
/// Rev 3 carries the inner message raw, without Rev 2's enclosing `B` var-data
/// field, so a Rev 2 reader does not find an inner message here at all.
#[test]
fn nested_direct() {
    let v = Vectors::load();
    let outer = v.unpack("nested-direct");
    v.assert_parties("nested-direct", &outer);
    assert_eq!(outer.message_type, MessageType::Nested);
    assert!(
        outer.hops.is_empty(),
        "a nested message's hop list is empty; that is what makes it nested rather than routed"
    );

    let inner = unpack(
        &outer.payload,
        &key(&v.id("nested_bob", "skE")),
        &key(&v.id("nested_alice", "pkS")),
    )
    .expect("the inner message unpacks with the inner pair's keys");
    assert_eq!(inner.sender, v.id("nested_alice", "id"));
    assert_eq!(inner.receiver, v.id("nested_bob", "id"));
    assert_eq!(inner.payload, b"hello world");
}

/// The routed message, and the hop-list rule that is easiest to get wrong.
///
/// §5.3.3: the last entry is the *destination's own VID at its intermediary*,
/// not the intermediary's VID. And §9.2 changed the `-J` count to the byte
/// length of the group rather than the number of VIDs in it — a Rev 2 reader
/// takes this two-VID list as a 40-entry one.
#[test]
fn routed() {
    let v = Vectors::load();
    let outer = v.unpack("routed");
    v.assert_parties("routed", &outer);
    assert_eq!(outer.message_type, MessageType::Routed);

    assert_eq!(
        outer.hops,
        vec![v.id("q", "id"), v.id("nested_bob", "id")],
        "the route ends at the destination's VID, not its intermediary's"
    );

    let inner = unpack(
        &outer.payload,
        &key(&v.id("nested_bob", "skE")),
        &key(&v.id("nested_alice", "pkS")),
    )
    .expect("the end-to-end message unpacks");
    assert_eq!(inner.payload, b"hello world");
}

/// The two Sealed Box vectors are not exercised: this crate implements
/// HPKE-Base only.
///
/// Kept as a note rather than deleted from the fixture. §8 keeps the libsodium
/// sealed box for existing implementations while telling new ones to use
/// HPKE-Base, so not implementing it is a decision rather than an omission — and
/// if that is ever revisited, the vectors are already here. They differ in two
/// payload rules beyond the cipher: the digest is Blake2b-256 under CESR code
/// `F` rather than `I`, and `VID_sndr` must carry the sender because the sealed
/// box is anonymous.
#[test]
fn sealed_box_vectors_are_present_but_unimplemented() {
    let v = Vectors::load();
    for name in ["direct-sealed-box", "control-rfi-sealed-box"] {
        assert!(
            !v.field(name, "message").is_empty(),
            "{name} is in the fixture for whenever Sealed Box is implemented"
        );
    }
}
