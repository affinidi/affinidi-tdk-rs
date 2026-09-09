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

/// The relationship cancel, and the two fields Rev 3 changed about it.
///
/// A cancel names the relationship it ends by the digest of the message that
/// formed it, and carries no nonce — Rev 2 had one, for the case where the
/// digest was absent, and Rev 3 removed both the case and the nonce.
///
/// The cross-vector check is what makes this a cancel of *this* relationship
/// rather than a well-formed message in isolation: its echoed digest must be
/// the `control-rfi-direct` vector's SAID, the same value the accept echoes.
///
/// This vector was truncated when the appendix was first published — 393
/// characters, a length base64 cannot produce — and this crate carried a test
/// asserting the defect until it was fixed. Reported against PR #63, where it
/// turned out not to be alone: five values were three characters short, this
/// one, `pq_alice`'s ML-DSA signing key, the post-quantum vector, and two long
/// forms whose `did:peer:4` hash no longer matched the document they carried.
/// All five are repaired as of spec commit `66a1580`, and the fixture check in
/// `every_vector_has_a_self_consistent_length` below now covers the whole
/// appendix rather than the part of it that decoded.
#[test]
fn control_rfd() {
    let v = Vectors::load();
    let invite = v.unpack("control-rfi-direct");
    let cancel = v.unpack("control-rfd");
    v.assert_parties("control-rfd", &cancel);
    assert_eq!(cancel.message_type, MessageType::Control);

    let control = cancel.control.as_ref().expect("a cancel is a control");
    assert_eq!(control.control_type, ControlType::RelationshipCancel);
    assert_eq!(
        control.reply,
        Some(invite.thread_digest),
        "the cancel names the relationship-forming message it ends"
    );
    assert!(
        control.nonce.is_none(),
        "Rev 3 removed the cancel's nonce, which existed only for the case where the digest \
         was absent"
    );
    assert!(control.route.is_empty(), "a cancel has no reply path");
    assert!(control.referral.is_none(), "a cancel introduces nothing");
}

/// The identity the truncation was caught by, now applied to every vector in
/// the appendix: a TSP message is its `-E` count code, the content that count
/// declares, and a signature group that declares its own length the same way.
///
/// Cheap, and it catches a whole class of transcription damage — it found a
/// real defect in a published vector on first contact, and the scan that
/// followed found four more. Written against both count codes rather than a
/// fixed 72-byte tail, so it covers the post-quantum vector too: an ML-DSA-65
/// signature group is 3318 bytes where an indexed Ed25519 one is 72, and a test
/// that assumed the smaller would simply skip the vector most likely to be
/// mis-transcribed.
#[test]
fn every_vector_has_a_self_consistent_length() {
    let v = Vectors::load();
    let names = [
        "direct-sealed-box",
        "direct-hpke-base",
        "direct-signed-only",
        "control-rfi-direct",
        "control-rfa-direct",
        "control-rfd",
        "control-rfi-sealed-box",
        "nested-direct",
        "routed",
        "direct-hpke-base-pq",
    ];
    // A CESR count code is four characters: two of identifier, two of count in
    // base64. Both `-E` and `-C` are counted in quadlets, each three bytes.
    fn count_at(bytes: &[u8], at: usize) -> usize {
        (u32::from_be_bytes([0, bytes[at], bytes[at + 1], bytes[at + 2]]) & 0xFFF) as usize
    }

    for name in names {
        let raw = v.field(name, "message");
        assert_eq!(
            raw.len() % 4,
            0,
            "{name}: {} characters, which base64 cannot produce",
            raw.len()
        );
        let bytes = qb64(&raw);
        let signable = 3 + count_at(&bytes, 0) * 3;
        let signature = 3 + count_at(&bytes, signable) * 3;
        assert_eq!(
            bytes.len(),
            signable + signature,
            "{name}: -E count code + declared content + declared signature group"
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

/// The libsodium sealed box (§8.3), against the specification's own vectors.
///
/// This is the scheme §8 tells new implementations not to use — "implementors
/// SHOULD consider migrating to the HPKE option specified in this document. We
/// MAY remove this option in the future" — so it exists here to read messages
/// from peers that have not migrated. Which makes vector conformance the whole
/// point: an implementation nobody sends to has no other way to know it is
/// right, and a sealed box is non-deterministic, so it cannot be checked by
/// re-packing and comparing bytes.
///
/// Three details in the construction are invisible to a round-trip test,
/// because an implementation that gets them wrong agrees with itself perfectly:
/// the HSalsa20 key-derivation step, libsodium's MAC-before-ciphertext layout,
/// and the nonce being derived from both public keys rather than random. These
/// vectors are what catches all three.
#[test]
fn direct_sealed_box() {
    let v = Vectors::load();
    let unpacked = v.unpack("direct-sealed-box");
    v.assert_parties("direct-sealed-box", &unpacked);
    assert_eq!(unpacked.message_type, MessageType::Direct);
    assert_eq!(unpacked.payload, b"hello world");
    assert!(unpacked.confidential);
}

/// A sealed-box invite, which exercises the two payload rules the scheme
/// changes.
///
/// The digest is Blake2b-256 under CESR code `F`, not SHA-256 under `I`. Both
/// are 32 bytes, so nothing but the code distinguishes them — and since `unpack`
/// recomputes the SAID and refuses a mismatch, this vector verifying at all is
/// the assertion that we hash with the right algorithm *and* read the right
/// code.
///
/// The sender VID also travels inside the encrypted payload rather than as the
/// NULL VID. It has to: a sealed box is anonymous and has no AAD, so the payload
/// is the only place the sender's identity can be bound (§8, and §3.7 step 7
/// makes the receiver check it against the envelope).
#[test]
fn control_rfi_sealed_box() {
    let v = Vectors::load();
    let unpacked = v.unpack("control-rfi-sealed-box");
    v.assert_parties("control-rfi-sealed-box", &unpacked);
    assert_eq!(unpacked.message_type, MessageType::Control);

    let control = unpacked.control.as_ref().expect("an invite is a control");
    assert_eq!(control.control_type, ControlType::RelationshipFormingInvite);
    assert_eq!(
        control.digest,
        Some(unpacked.thread_digest),
        "the invite's Blake2b-256 Digest is its own SAID"
    );
    assert_eq!(control.nonce.expect("a nonce").len(), 16);

    // The same exchange under HPKE-Base produces a *different* digest for
    // otherwise identical content, because the algorithm differs. Worth
    // asserting: it is what proves the Blake2b path is actually being taken
    // rather than SHA-256 quietly agreeing.
    let hpke_invite = v.unpack("control-rfi-direct");
    assert_ne!(
        unpacked.thread_digest, hpke_invite.thread_digest,
        "Blake2b-256 and SHA-256 must not produce the same digest"
    );
}

/// A sealed box packed here is read back here, and is not mistaken for
/// HPKE-Base.
///
/// The round trip is the weak half of this test; the useful half is that the
/// ciphertext code differs, since that code is the only thing on the wire that
/// says which scheme sealed a message.
#[test]
fn a_sealed_box_round_trips_and_is_distinguishable() {
    use affinidi_tsp::message::direct::{pack, pack_sealed_box};

    let v = Vectors::load();
    let alice = v.id("alice", "id");
    let bob = v.id("bob", "id");
    let alice_sign = key(&v.id("alice", "skS"));
    let bob_enc_pk = key(&v.id("bob", "pkE"));
    let bob_enc_sk = key(&v.id("bob", "skE"));
    let alice_verify = key(&v.id("alice", "pkS"));

    let sealed = pack_sealed_box(
        b"over the old scheme",
        MessageType::Direct,
        &alice,
        &bob,
        &alice_sign,
        &bob_enc_pk,
    )
    .expect("pack under the sealed box");

    let unpacked = unpack(&sealed.bytes, &bob_enc_sk, &alice_verify).expect("unpack it");
    assert_eq!(unpacked.payload, b"over the old scheme");
    assert_eq!(unpacked.sender, alice);

    // Same message, other scheme: the bytes must differ where the ciphertext
    // code sits, which is what lets a receiver tell them apart at all.
    let hpke = pack(
        b"over the old scheme",
        MessageType::Direct,
        &alice,
        &bob,
        &alice_sign,
        &bob_enc_pk,
    )
    .expect("pack under HPKE-Base");
    let unpacked_hpke = unpack(&hpke.bytes, &bob_enc_sk, &alice_verify).expect("unpack it");
    assert_eq!(unpacked_hpke.payload, b"over the old scheme");
    assert_ne!(
        sealed.bytes, hpke.bytes,
        "the two schemes produce different frames"
    );
}
