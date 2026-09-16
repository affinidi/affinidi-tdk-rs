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
//! Fixture: `tests/vectors/rev3.json`, lifted verbatim from the merged
//! specification, commit `f5b8668`, where the version is `YTSP-AAC`. The private
//! keys in it are published in the specification and must never be used for
//! anything else.

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

/// Every vector is at the merged specification's version, `YTSP-AAC` — the
/// marker this crate emits.
///
/// The fixture was `YTSP-ABA` before the merge, and those vectors verified
/// here too, because MINOR does not gate processing. That tolerance is exactly
/// why this is worth asserting: a stale fixture would otherwise pass unnoticed.
#[test]
fn every_vector_is_at_the_merged_version() {
    let v = Vectors::load();
    let mut ours = Vec::new();
    affinidi_tsp::message::wire::encode_version(&mut ours);
    for (name, vector) in v.json["vectors"].as_object().expect("vectors") {
        let message = vector["message"].as_str().expect("message");
        assert!(
            message[4..].starts_with("YTSP-AAC"),
            "{name}: expected YTSP-AAC after the frame code"
        );
        assert_eq!(qb64(message)[3..9], ours[..], "{name}: version bytes");
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
/// right. A sealed box is non-deterministic, so re-packing it byte for byte
/// needs the vector's own ephemeral secret; `repack::direct_sealed_box` does
/// that under the `test-vectors` feature.
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
/// Byte-exact re-pack: every vector that publishes its ephemeral material is
/// regenerated from its identifiers, its printed payload and that material, and
/// must come out identical to the published `message`.
///
/// Opening a vector proves we read what the reference wrote. This proves the
/// converse, which nothing else can: that what we write is, bit for bit, what
/// the specification says. A round trip cannot show it — our encoder and
/// decoder agree with each other whatever they agree on — and the interop
/// suites only show that some other implementation reads it.
///
/// The payload fields — ESSR sender NULL or present, digest echoed, nonce,
/// route, padding, inner message — are read off the vector's printed `payload`,
/// not restated here, so a test cannot quietly agree with a wrong constant.
/// Digests are never taken from it: an invite's and an accept's SAID are
/// recomputed by the packer and have to land on the published bytes.
///
/// Needs the `test-vectors` feature, which this crate's dev-dependency on
/// itself turns on for its own tests.
#[cfg(feature = "test-vectors")]
mod repack {
    use super::*;
    use affinidi_tsp::message::control::{ControlMessage, DIGEST_LEN, NONCE_LEN};
    use affinidi_tsp::message::direct::Padding;
    use affinidi_tsp::message::direct::insecure_deterministic::{
        Options, PayloadSender, Protection, pack_insecure_deterministic,
    };
    use affinidi_tsp::message::wire;

    /// A vector's printed payload frame, read field by field.
    struct Printed {
        kind: [u8; 3],
        sender: PayloadSender,
        digest: Option<[u8; DIGEST_LEN]>,
        nonce: Option<[u8; NONCE_LEN]>,
        hops: Vec<String>,
        padding: Vec<u8>,
        /// The application bytes of an `XSCS`, or the raw inner message of an
        /// `XHOP`.
        body: Vec<u8>,
    }

    fn parse(qb64_payload: &str, sealed_box: bool) -> Printed {
        let frame = qb64(qb64_payload);
        let mut pos = 0;
        let quadlets = wire::decode_count(wire::TSP_PAYLOAD, &frame, &mut pos).expect("-Z");
        assert_eq!(
            3 + quadlets as usize * 3,
            frame.len(),
            "the payload is one frame"
        );
        let kind: [u8; 3] = frame[pos..pos + 3].try_into().unwrap();
        pos += 3;
        let sender = match wire::decode_variable_data(wire::TSP_VID, &frame, &mut pos)
            .expect("ESSR sender field")
            .len()
        {
            0 => PayloadSender::Null,
            _ => PayloadSender::Present,
        };
        let digest_code = if sealed_box {
            wire::TSP_BLAKE2B256
        } else {
            wire::TSP_SHA256
        };
        let digest = |pos: &mut usize| {
            wire::decode_fixed_data::<DIGEST_LEN>(digest_code, &frame, pos).expect("digest")
        };
        let padding = |pos: &mut usize| {
            wire::decode_variable_data(wire::TSP_PLAINTEXT, &frame, pos).expect("padding field")
        };
        let hop_list = |pos: &mut usize| -> Vec<String> {
            wire::decode_hops(&frame, pos)
                .expect("-J list")
                .into_iter()
                .map(|h| String::from_utf8(h).unwrap())
                .collect()
        };

        let mut p = Printed {
            kind,
            sender,
            digest: None,
            nonce: None,
            hops: Vec::new(),
            padding: Vec::new(),
            body: Vec::new(),
        };
        match &kind {
            k if *k == wire::XSCS => {
                p.padding = padding(&mut pos);
                wire::decode_count(wire::TSP_GENERIC_STREAM, &frame, &mut pos).expect("-A");
                p.body = wire::decode_variable_data(wire::TSP_PLAINTEXT, &frame, &mut pos)
                    .expect("Bytes");
            }
            k if *k == wire::XRFI => {
                digest(&mut pos); // our own SAID: recomputed, not supplied
                p.nonce = Some(
                    wire::decode_fixed_data::<NONCE_LEN>(wire::TSP_NONCE, &frame, &mut pos)
                        .expect("nonce"),
                );
                p.hops = hop_list(&mut pos); // Reply_Path
                assert!(
                    hop_list(&mut pos).is_empty(),
                    "no vector carries a referral"
                );
                p.padding = padding(&mut pos);
            }
            k if *k == wire::XRFA => {
                p.digest = Some(digest(&mut pos)); // the invite's, echoed
                digest(&mut pos); // Reply_Digest: our own SAID, recomputed
                p.padding = padding(&mut pos);
            }
            k if *k == wire::XRFD => {
                p.digest = Some(digest(&mut pos));
                p.padding = padding(&mut pos);
            }
            k if *k == wire::XHOP => {
                p.hops = hop_list(&mut pos);
                p.padding = padding(&mut pos);
                p.body = frame[pos..].to_vec();
                pos = frame.len();
            }
            other => panic!("no vector has payload type {other:?}"),
        }
        assert_eq!(pos, frame.len(), "every printed field is accounted for");
        p
    }

    fn repack(name: &str) {
        let v = Vectors::load();
        let vector = v.vector(name);
        let sender = v.field(name, "sender");
        let receiver = v.field(name, "receiver");
        let ephemeral = |field: &str| -> Option<[u8; 32]> {
            vector.get(field).and_then(Value::as_str).map(key)
        };
        let (protection, sealed_box) = match (ephemeral("ikmE"), ephemeral("skEm")) {
            (Some(ikm_e), None) => (Protection::HpkeBase { ikm_e }, false),
            (None, Some(ephemeral_secret)) => (Protection::SealedBox { ephemeral_secret }, true),
            (None, None) => (Protection::SignedOnly, false),
            _ => panic!("{name} publishes both ikmE and skEm"),
        };
        let printed = parse(&v.field(name, "payload"), sealed_box);

        // The published ephemeral public key must be the one the material
        // derives — checked through the packed bytes below, since `enc` (or the
        // sealed box's leading public key) is the first thing in the
        // ciphertext.
        let (body, message_type) = match &printed.kind {
            k if *k == wire::XSCS => (printed.body.clone(), MessageType::Direct),
            k if *k == wire::XHOP => (
                printed.body.clone(),
                if printed.hops.is_empty() {
                    MessageType::Nested
                } else {
                    MessageType::Routed
                },
            ),
            k => {
                let mut control = if *k == wire::XRFI {
                    let mut c = ControlMessage::invite_routed(printed.hops.clone());
                    c.nonce = printed.nonce;
                    c
                } else if *k == wire::XRFA {
                    ControlMessage::accept(printed.digest.unwrap())
                } else {
                    ControlMessage::cancel(printed.digest.unwrap())
                };
                control.digest = None;
                (control.encode(), MessageType::Control)
            }
        };
        let hops = if message_type == MessageType::Routed {
            printed.hops.clone()
        } else {
            Vec::new()
        };

        let packed = pack_insecure_deterministic(
            &body,
            message_type,
            &v.id(&sender, "id"),
            &v.id(&receiver, "id"),
            &key(&v.id(&sender, "skS")),
            &key(&v.id(&receiver, "pkE")),
            protection,
            &Options {
                payload_sender: printed.sender,
                padding: Padding::Exact(printed.padding.clone()),
                hops: &hops,
                ..Options::default()
            },
        )
        .unwrap_or_else(|e| panic!("{name}: pack: {e}"));

        let expected = qb64(&v.field(name, "message"));
        if packed.bytes != expected {
            let at = packed
                .bytes
                .iter()
                .zip(&expected)
                .position(|(a, b)| a != b)
                .unwrap_or(packed.bytes.len().min(expected.len()));
            panic!(
                "{name}: re-packed bytes differ from the vector at byte {at} \
                 (lengths {} vs {})",
                packed.bytes.len(),
                expected.len()
            );
        }

        if let Some(pk_em) = vector.get("pkEm").and_then(Value::as_str) {
            // Where the ciphertext field's data begins: the envelope, then a
            // variable-data header, whose lead bytes are zero.
            let decoded = affinidi_tsp::message::envelope::Envelope::decode_full(&expected)
                .expect("envelope");
            let code = if sealed_box {
                wire::TSP_SEALED_BOX_CIPHERTEXT
            } else {
                wire::TSP_HPKE_BASE_CIPHERTEXT
            };
            let mut pos = decoded.header_len;
            let ct = wire::decode_variable_data_range(code, &expected, &mut pos).expect("ct");
            assert_eq!(
                expected[ct.start..ct.start + 32],
                key(pk_em),
                "{name}: the ciphertext opens with the published pkEm"
            );
        }
    }

    #[test]
    fn direct_sealed_box() {
        repack("direct-sealed-box");
    }

    #[test]
    fn direct_hpke_base() {
        repack("direct-hpke-base");
    }

    #[test]
    fn direct_signed_only() {
        repack("direct-signed-only");
    }

    #[test]
    fn control_rfi_direct() {
        repack("control-rfi-direct");
    }

    #[test]
    fn control_rfa_direct() {
        repack("control-rfa-direct");
    }

    #[test]
    fn control_rfd() {
        repack("control-rfd");
    }

    #[test]
    fn control_rfi_sealed_box() {
        repack("control-rfi-sealed-box");
    }

    #[test]
    fn nested_direct() {
        repack("nested-direct");
    }

    #[test]
    fn routed() {
        repack("routed");
    }

    /// Only the post-quantum vector is left out, and on purpose: it publishes
    /// no ephemeral material, because the hybrid KEM draws encapsulation
    /// randomness the vector does not record. This pins that list, so a vector
    /// added to the fixture has to be placed on one side of it.
    #[test]
    fn every_vector_with_ephemeral_material_is_repacked() {
        let v = Vectors::load();
        let repacked = [
            "direct-sealed-box",
            "direct-hpke-base",
            "direct-signed-only",
            "control-rfi-direct",
            "control-rfa-direct",
            "control-rfd",
            "control-rfi-sealed-box",
            "nested-direct",
            "routed",
        ];
        for (name, vector) in v.json["vectors"].as_object().unwrap() {
            let has_material = vector.get("ikmE").is_some() || vector.get("skEm").is_some();
            let signed_only = name == "direct-signed-only";
            assert_eq!(
                repacked.contains(&name.as_str()),
                has_material || signed_only,
                "{name}: re-packed iff it publishes ephemeral material or needs none"
            );
        }
    }

    /// A pinned ephemeral key makes a pack reproducible, which is exactly the
    /// property that makes it unsafe: the same inputs give the same bytes.
    /// Pinned so that the hazard the module documents is also a tested fact.
    #[test]
    fn the_same_ephemeral_gives_the_same_ciphertext() {
        let v = Vectors::load();
        let pack = || {
            pack_insecure_deterministic(
                b"hello world",
                MessageType::Direct,
                &v.id("alice", "id"),
                &v.id("bob", "id"),
                &key(&v.id("alice", "skS")),
                &key(&v.id("bob", "pkE")),
                Protection::HpkeBase { ikm_e: [7; 32] },
                &Options::default(),
            )
            .unwrap()
            .bytes
        };
        assert_eq!(pack(), pack());
    }

    /// The sealed box has no AAD, so §8 requires its payload to name the
    /// sender; a NULL sender field is refused rather than packed.
    #[test]
    fn a_sealed_box_refuses_a_null_payload_sender() {
        let v = Vectors::load();
        let err = pack_insecure_deterministic(
            b"x",
            MessageType::Direct,
            &v.id("alice", "id"),
            &v.id("bob", "id"),
            &key(&v.id("alice", "skS")),
            &key(&v.id("bob", "pkE")),
            Protection::SealedBox {
                ephemeral_secret: [7; 32],
            },
            &Options {
                payload_sender: PayloadSender::Null,
                ..Options::default()
            },
        )
        .expect_err("NULL sender under the sealed box");
        assert!(format!("{err}").contains("sender"), "{err}");
    }
}

/// The post-quantum vector, and everything it is the only check on.
///
/// This is the vector the branch could not use when Rev 3's appendix was first
/// published: its message, `pq_alice`'s ML-DSA signing key and both
/// post-quantum long forms were truncated, and the spec did not say whether the
/// 32-byte encryption key was a whole key or a prefix of one. All four were
/// reported against PR #63 and all four are fixed, which is what makes this
/// test possible at all.
///
/// It is worth the effort because a round-trip proves nothing here. Three
/// choices in the post-quantum path are invisible to `pack` talking to
/// `unpack`, and each is a plausible way to be wrong on the wire:
///
/// * **Which hybrid.** IANA assigns `0x647a` to X-Wing; `draft-ietf-hpke-pq`
///   asks to replace that entry with `MLKEM768-X25519`. Same `Nsecret`, `Nenc`,
///   `Npk`, `Nsk` — so building the wrong one fails decapsulation with no
///   length mismatch to point at it.
/// * **Which ML-DSA.** Pure with an empty context, prehash, and `sign_internal`
///   all produce a 3309-byte signature over the same message, and each verifies
///   perfectly against itself.
/// * **Which key expansion.** The published encryption key is a 32-byte seed;
///   an implementation that took it for a raw ML-KEM key would agree with
///   itself and with nobody.
#[cfg(feature = "pq")]
mod post_quantum {
    use super::*;
    use affinidi_tsp::crypto::{hpke_pq, ml_dsa};
    use affinidi_tsp::message::direct::{DecryptionKey, VerifyingKey, pack_pq, unpack_with};

    fn sized<const N: usize>(v: &Vectors, id: &str, field: &str) -> Box<[u8; N]> {
        qb64(&v.id(id, field))
            .into_boxed_slice()
            .try_into()
            .unwrap_or_else(|b: Box<[u8]>| {
                panic!("{id}.{field} is {} bytes, expected {N}", b.len())
            })
    }

    /// The published post-quantum keys are the sizes the algorithms define.
    ///
    /// Cheap, and it is the check that would have caught the truncation without
    /// any base64 reasoning: a 5373-character ML-DSA signing key is 4029 bytes
    /// where FIPS 204 says 4032.
    #[test]
    fn the_published_key_sizes_are_the_algorithms_own() {
        let v = Vectors::load();
        for id in ["pq_alice", "pq_bob"] {
            assert_eq!(qb64(&v.id(id, "pkS")).len(), ml_dsa::PK_LEN, "{id}.pkS");
            assert_eq!(qb64(&v.id(id, "skS")).len(), ml_dsa::SK_LEN, "{id}.skS");
            assert_eq!(qb64(&v.id(id, "pkE")).len(), hpke_pq::PK_LEN, "{id}.pkE");
            assert_eq!(qb64(&v.id(id, "skE")).len(), hpke_pq::SK_LEN, "{id}.skE");
            assert_eq!(v.id(id, "sigKeyType"), "MlDsa65");
            assert_eq!(v.id(id, "encKeyType"), "MLKEM768-X25519");
        }
    }

    /// The 32-byte encryption key is a seed, and `DeriveKeyPair` expands it to
    /// the published 1216-byte public key.
    ///
    /// This is the sentence Rev 3 gained on 8 September, checked rather than
    /// taken on trust — and it is what settles the key expansion independently
    /// of whether the message opens.
    #[test]
    fn the_seed_expands_to_the_published_public_key() {
        let v = Vectors::load();
        for id in ["pq_alice", "pq_bob"] {
            let seed = sized::<{ hpke_pq::SK_LEN }>(&v, id, "skE");
            let published = sized::<{ hpke_pq::PK_LEN }>(&v, id, "pkE");
            let derived = hpke_pq::public_key_from_private(&seed).expect("expand the seed");
            assert_eq!(
                derived.as_slice(),
                published.as_slice(),
                "{id}: DeriveKeyPair(seed) must be the published encryption key"
            );
        }
    }

    /// The whole post-quantum path, end to end, against bytes we had no hand in
    /// producing: the hybrid KEM, the ML-DSA-65 signature under `1AAQ`, and the
    /// `4F` ciphertext split at 1120 rather than 32.
    #[test]
    fn direct_hpke_base_pq() {
        let v = Vectors::load();
        let message = qb64(&v.field("direct-hpke-base-pq", "message"));
        let sk = sized::<{ hpke_pq::SK_LEN }>(&v, "pq_bob", "skE");
        let pk = sized::<{ ml_dsa::PK_LEN }>(&v, "pq_alice", "pkS");

        let unpacked = unpack_with(
            &message,
            DecryptionKey::MlKem768X25519(&sk),
            VerifyingKey::MlDsa65(&pk),
        )
        .expect("the post-quantum vector must unpack");

        assert_eq!(unpacked.sender, v.id("pq_alice", "id"));
        assert_eq!(unpacked.receiver, v.id("pq_bob", "id"));
        assert_eq!(unpacked.message_type, MessageType::Direct);
        assert_eq!(unpacked.payload, b"hello world");
        assert!(unpacked.confidential);

        // Same plaintext as `direct-hpke-base`, which is the point of the
        // vector: post-quantum is not a different message, only different keys.
        let classical = v.unpack("direct-hpke-base");
        assert_eq!(unpacked.payload, classical.payload);
    }

    /// A post-quantum message this crate packs is one the same crate reads
    /// back, and its frame has the shape the vector has.
    ///
    /// The round trip is the weak half. The useful half is the framing, which
    /// is otherwise checked by nothing: HPKE seals with fresh randomness, so
    /// the vector's bytes cannot be reproduced and only their structure can be
    /// compared.
    ///
    /// The one structural difference is deliberate and is asserted rather than
    /// tolerated. §8 makes the ESSR sender field optional under HPKE-Base,
    /// because the AAD already binds the sender; the reference omits it and we
    /// carry it, for the reason given at `encode_sender_field`. So our frame is
    /// longer than the vector's by exactly that field and by nothing else —
    /// which is a sharper check than equality would have been, since it pins
    /// where the difference is allowed to be.
    #[test]
    fn a_packed_post_quantum_message_matches_the_vector_shape() {
        let v = Vectors::load();
        let alice = v.id("pq_alice", "id");
        let bob = v.id("pq_bob", "id");
        let sign = sized::<{ ml_dsa::SK_LEN }>(&v, "pq_alice", "skS");
        let verify = sized::<{ ml_dsa::PK_LEN }>(&v, "pq_alice", "pkS");
        let enc_pk = sized::<{ hpke_pq::PK_LEN }>(&v, "pq_bob", "pkE");
        let enc_sk = sized::<{ hpke_pq::SK_LEN }>(&v, "pq_bob", "skE");

        let packed = pack_pq(
            b"hello world",
            MessageType::Direct,
            &alice,
            &bob,
            &sign,
            &enc_pk,
        )
        .expect("pack a post-quantum message");

        let vector = qb64(&v.field("direct-hpke-base-pq", "message"));

        // `4B##` code plus the VID, against the vector's `4BAA` NULL VID.
        let sender_field = 3 + alice.len().next_multiple_of(3);
        assert_eq!(
            packed.bytes.len(),
            vector.len() + sender_field - 3,
            "our frame is the vector's plus the optional ESSR sender field"
        );

        // The framing itself. A CESR code word is 24 bits — six of selector,
        // six of identifier, twelve of count — so comparing whole code bytes
        // would compare the counts, which differ by the sender field. Compare
        // the selector and identifier, which are what say *what* a field is.
        let code_at = |bytes: &[u8], at: usize| -> (u32, u32) {
            let w = u32::from_be_bytes([0, bytes[at], bytes[at + 1], bytes[at + 2]]);
            (w >> 18, (w >> 12) & 0x3f)
        };
        assert_eq!(
            code_at(&packed.bytes, 0),
            code_at(&vector, 0),
            "the -E frame code is unchanged by the key type"
        );

        // The envelope is identical in both — same version, same two VIDs — so
        // the ciphertext field starts at the same offset in each.
        let ciphertext_at = 3 + 6 + 60 + 60;
        assert_eq!(
            code_at(&packed.bytes, ciphertext_at),
            code_at(&vector, ciphertext_at),
            "a post-quantum ciphertext uses the same 4F/5F/6F code as any other"
        );

        // And the signature: `1AAQ` rather than the indexed `B#`, in both.
        let sig_at = |bytes: &[u8]| -> usize {
            let count = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) & 0xfff;
            3 + count as usize * 3
        };
        assert_eq!(
            &packed.bytes[sig_at(&packed.bytes) + 6..sig_at(&packed.bytes) + 9],
            &vector[sig_at(&vector) + 6..sig_at(&vector) + 9],
            "an ML-DSA-65 signature sits under 1AAQ inside the same -C/-K groups"
        );

        let unpacked = unpack_with(
            &packed.bytes,
            DecryptionKey::MlKem768X25519(&enc_sk),
            VerifyingKey::MlDsa65(&verify),
        )
        .expect("read it back");
        assert_eq!(unpacked.payload, b"hello world");
    }

    /// A post-quantum message must not verify against a classical key, and the
    /// failure has to come from the scheme rather than from the bytes.
    #[test]
    fn the_signature_scheme_must_match_the_senders_key_type() {
        let v = Vectors::load();
        let message = qb64(&v.field("direct-hpke-base-pq", "message"));
        let sk = sized::<{ hpke_pq::SK_LEN }>(&v, "pq_bob", "skE");
        let ed25519 = key(&v.id("alice", "pkS"));

        let err = unpack_with(
            &message,
            DecryptionKey::MlKem768X25519(&sk),
            VerifyingKey::Ed25519(&ed25519),
        )
        .expect_err("an ML-DSA signature must not be checked against an Ed25519 key");
        assert!(
            format!("{err}").contains("does not match"),
            "expected a scheme mismatch, got: {err}"
        );
    }
}
