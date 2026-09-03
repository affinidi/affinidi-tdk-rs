//! Binary CESR wire primitives for TSP, byte-compatible with the ToIP
//! `tsp-sdk` reference (v0.9.0-alpha2).
//!
//! TSP frames messages in a compact *binary* CESR domain (qb2-like), which is a
//! different encoding from the text/qb64-derived primitives in the workspace's
//! `affinidi-cesr` crate. `affinidi-cesr` models CESR primitives as
//! `code-string + soft-count + lead-padded data` (e.g. var-data code `"4B"`),
//! whereas `tsp-sdk` packs a `selector | identifier | size` triple directly into
//! the leading bits of each frame and encodes lead bytes *in the selector*. The
//! two are not wire-interoperable, so to interoperate with `tsp-sdk` byte-for-byte
//! we port its small set of binary primitives here rather than bending
//! `affinidi-cesr` (which is used elsewhere).
//!
//! Ported from `tsp_sdk::cesr` (`encode.rs`/`decode.rs`/`packet.rs`), which is
//! dual-licensed Apache-2.0 OR MIT.
//!
//! # Frame kinds
//! - **fixed data**: `encode_fixed_data(id, payload)` — a `selector|id` header
//!   sized to pad `payload.len()` up to a multiple of 3.
//! - **variable data**: `encode_variable_data(id, payload)` — a
//!   `selector(D4+lead)|id|size` header followed by `lead` zero bytes + payload.
//! - **count code**: `encode_count(id, count)` — a `-` (DASH) framed group
//!   header carrying a quadlet count (number of following 3-byte groups).

use crate::error::TspError;

// CESR base-64 selector values (index of the base64url alphabet character).
const D0: u32 = 52; // 'A'-relative: base64 index of '0'
const D1: u32 = D0 + 1;
const D4: u32 = D0 + 4;
const D5: u32 = D0 + 5;
const D6: u32 = D0 + 6;
const D7: u32 = D0 + 7;
const D8: u32 = D0 + 8;
const D9: u32 = D0 + 9;
const DASH: u32 = 62;

/// Maximum size we accept for a single variable-data field, mirroring the ToIP
/// reference (`tsp_sdk`'s `DATA_LIMIT = 3 * (1 << 24)`, ~48 MiB) so we accept any
/// field the reference can validly produce. Guards against hostile size headers.
pub const MAX_FIELD_SIZE: usize = 3 * (1 << 24);

/// Interpret a base64url string as a big-endian integer of its 6-bit symbols.
/// Used to derive the numeric identifier of single/short CESR codes (e.g. the
/// `"B"`, `"G"`, `"X"` selectors used by TSP).
pub const fn cesr_int(s: &str) -> u64 {
    let b = s.as_bytes();
    let mut acc = 0u64;
    let mut i = 0;
    while i < b.len() {
        let ch = b[i];
        let v = if ch.is_ascii_uppercase() {
            ch - b'A'
        } else if ch.is_ascii_lowercase() {
            ch - b'a' + 26
        } else if ch.is_ascii_digit() {
            ch - b'0' + 52
        } else if ch == b'-' {
            62
        } else if ch == b'_' {
            63
        } else {
            // Only ASCII base64url is ever passed here from constants below.
            0
        };
        acc = (acc << 6) | v as u64;
        i += 1;
    }
    acc
}

/// Produce the fixed-size big-endian byte form of a short CESR code (used for
/// the 3-byte payload type markers like `XSCS` / `YTSP`).
pub const fn cesr_data<const N: usize>(s: &str) -> [u8; N] {
    let val = cesr_int(s);
    let src = u64::to_be_bytes(val);
    let start = src.len() - N;
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = src[start + i];
        i += 1;
    }
    out
}

fn bits(value: u32, n: u8) -> u32 {
    let mask = (1u32 << n) - 1;
    value & mask
}

fn mask(n: u8) -> u32 {
    (1u32 << n) - 1
}

fn extract_triplet(q: &[u8; 3]) -> u32 {
    u32::from_be_bytes([0, q[0], q[1], q[2]])
}

// ---- TSP identifiers / framing codes (from tsp_sdk::cesr::packet) ----

/// `B`: var-data plaintext payload, and (as fixed-data id) the Ed25519 signature.
pub const TSP_PLAINTEXT: u32 = cesr_int("B") as u32;
/// `B`: var-data VID identifier. An empty VID encodes to `4BAA` — the Rev 3
/// NULL VID, which is how "absent" is spelled for every VID-shaped field.
pub const TSP_VID: u32 = cesr_int("B") as u32;
/// `F`: var-data HPKE-Base ciphertext (Rev 3 §9.4, codes `4F`/`5F`/`6F` and the
/// long forms). Rev 2's HPKE-Auth `G` codes are struck from the code table.
pub const TSP_HPKE_BASE_CIPHERTEXT: u32 = cesr_int("F") as u32;
/// `B`: Ed25519 signature identifier, used as the leading character of the
/// *indexed* signature code `B#` (Rev 3 §9.5).
pub const ED25519_SIGNATURE: u32 = cesr_int("B") as u32;
/// `A`: fixed-data id for a relationship nonce. Rev 3 §9.2 makes the nonce 128
/// bits, which puts it under the two-character code `0A`; the code follows from
/// the payload length in [`encode_fixed_data`].
pub const TSP_NONCE: u32 = cesr_int("A") as u32;
/// `I`: fixed-data id for a SHA-256 digest (32 bytes) — the `TSP_Digest` /
/// `Reply_Digest` carried by the relationship-forming payloads.
pub const TSP_SHA256: u32 = cesr_int("I") as u32;

/// `-E`: the single envelope frame. In Rev 3 its count covers *all* signable
/// content — version, VIDs and the ciphertext — not just the header, so it can
/// only be written once the ciphertext size is known. Rev 2's separate `-S`
/// signed-only wrapper is gone; a signed-only message is an `-E` frame whose
/// payload is cleartext.
pub const TSP_ETS_WRAPPER: u16 = cesr_int("E") as u16;
/// `-Z`: count-code wrapper for the CESR payload frame.
pub const TSP_PAYLOAD: u16 = cesr_int("Z") as u16;
/// `-J`: count-code group for a hop (routing) list, a reply path, or a referral.
/// Rev 3 §9.2: the count is the **byte length** of the group, not the number of
/// VIDs in it.
pub const TSP_HOP_LIST: u16 = cesr_int("J") as u16;
/// `-A`: generic CESR stream, the container Rev 3 §9.2.3 requires around every
/// `XSCS` / `XCTL` upper-layer payload.
pub const TSP_GENERIC_STREAM: u16 = cesr_int("A") as u16;
/// `-C`: count-code attach group for the signature.
pub const TSP_ATTACH_GRP: u16 = cesr_int("C") as u16;
/// `-K`: count-code indexed-signature group for the signature.
pub const TSP_INDEX_SIG_GRP: u16 = cesr_int("K") as u16;

/// 3-byte payload-type marker for a generic (GenericMessage / Content) payload.
pub const XSCS: [u8; 3] = cesr_data("XSCS");
/// 3-byte payload-type marker for a hop-carrying payload (Nested when the hop
/// list is empty, Routed otherwise).
pub const XHOP: [u8; 3] = cesr_data("XHOP");
/// 3-byte payload-type marker for a relationship-forming invite
/// (`DirectRelationProposal`).
pub const XRFI: [u8; 3] = cesr_data("XRFI");
/// 3-byte payload-type marker for a relationship-forming accept
/// (`DirectRelationAffirm`).
pub const XRFA: [u8; 3] = cesr_data("XRFA");
/// 3-byte payload-type marker for a relationship cancel
/// (`RelationshipCancel`).
pub const XRFD: [u8; 3] = cesr_data("XRFD");
/// 3-byte payload-type marker for a generic control payload (Rev 3 §9.2).
pub const XCTL: [u8; 3] = cesr_data("XCTL");
/// 3-byte payload-type marker for a padding-only message (Rev 3 §9.2).
pub const XPAD: [u8; 3] = cesr_data("XPAD");
/// 3-byte TSP version genus marker.
pub const YTSP: [u8; 3] = cesr_data("YTSP");
/// The TSP protocol code `YTSP-`, used verbatim as the HPKE-Base `info` input
/// (Rev 3 §8). Five ASCII characters, not the 3-byte binary [`YTSP`] marker.
pub const TSP_INFO: &[u8] = b"YTSP-";

/// TSP version `(major, minor)` advertised on the wire, encoded as the
/// `YTSP-###` marker of §9.1 — `YTSP-AAC` for `0.2`.
///
/// # Two components, not three
///
/// The marker is one character of MAJOR and two of MINOR. The published §9.1
/// text reads the three characters as MAJOR, MINOR, PATCH instead, and gives
/// the current version as `YTSP-ABA`; we do not follow it, deliberately.
///
/// PATCH has no role in a wire version. Semver defines it as a
/// backward-compatible bug fix — a change that by definition cannot alter what
/// goes over the wire — so a receiver can never act on it, and six bits of
/// every envelope would carry something no peer can use. Semver versions code;
/// a library implementing TSP has two versions, its own and the protocol's, and
/// they are not the same number.
///
/// The two readings also disagree about the value, which is how the split shows
/// itself. The trailing 12 bits are identical on the wire; only their
/// interpretation differs:
///
/// ```text
/// marker                MAJOR   trailing 12 bits   MAJOR.MINOR   MAJOR.MINOR.PATCH
/// AAB  (Rev 2)              0                  1           0.1               0.0.1
/// ABA  (published Rev 3)    0                 64          0.64               0.1.0
/// AAC  (here)               0                  2           0.2               0.0.2
/// ```
///
/// Rev 2 was 1 and `ABA` reads as 64 — a jump that is an artifact of splitting
/// the field, not a version anyone chose. Raised on the spec PR by Sam Smith,
/// whose reading this follows; ours anticipates the resolution rather than
/// waiting for it, on the grounds that `AAC` is where it lands if the argument
/// holds.
///
/// Nothing about interoperating depends on the choice. Only MAJOR gates
/// processability, MAJOR is the same first character under both readings, and
/// neither the reference implementation nor this one refuses a message on
/// MINOR — the reference discards MINOR entirely. The published Appendix A
/// vectors carry `ABA` and still verify here, because a message's digest and
/// signature cover the version bytes *it* carries, not ours.
pub const TSP_VERSION: (u16, u16) = (0, 2);

/// MINOR occupies the whole 12-bit count of the version code.
const fn encoded_version() -> u16 {
    TSP_VERSION.1
}

// ---- Encoding ----

/// Encode fixed-size data with a known identifier.
pub fn encode_fixed_data(identifier: u32, payload: &[u8], out: &mut Vec<u8>) {
    let total_size = (payload.len() + 1).next_multiple_of(3);
    let hdr_bytes = total_size - payload.len();
    let word = match hdr_bytes {
        1 => bits(identifier, 6) << 18,
        2 => (D0 << 18) | (bits(identifier, 6) << 12),
        3 => (D1 << 18) | bits(identifier, 18),
        _ => unreachable!("fixed-data header bytes in 1..=3"),
    };
    out.extend_from_slice(&u32::to_be_bytes(word)[1..=hdr_bytes]);
    out.extend_from_slice(payload);
}

/// Encode variable-size data with a known identifier.
pub fn encode_variable_data(identifier: u32, payload: &[u8], out: &mut Vec<u8>) {
    let padded_size = payload.len().next_multiple_of(3);
    let lead_bytes = padded_size - payload.len();
    let selector = D4 + lead_bytes as u32;
    let size = (padded_size / 3) as u32;

    if size < 64 * 64 && identifier < 64 {
        let word = (bits(selector, 6) << 18) | (bits(identifier, 6) << 12) | bits(size, 12);
        out.extend_from_slice(&u32::to_be_bytes(word)[1..]);
    } else {
        let word = (bits(selector + 3, 6) << 18) | bits(identifier, 18);
        out.extend_from_slice(&u32::to_be_bytes(word)[1..]);
        out.extend_from_slice(&u32::to_be_bytes(bits(size, 24))[1..]);
    }
    let zeros = [0u8; 2];
    out.extend_from_slice(&zeros[..lead_bytes]);
    out.extend_from_slice(payload);
}

/// Encode a count-code group header for `identifier` carrying `count` quadlets.
///
/// The long form is `--X#####` (Rev 3 §9). Rev 2 emitted `-0X#####`, which
/// belonged to a superseded draft of the CESR v2 tables; the master table for
/// genus `-_AAACAA` that Rev 3 pins carries only the double-dash form. This is
/// a one-character change that a round-trip test cannot catch — encoder and
/// decoder agree either way — so `long_count_uses_double_dash` pins the bytes.
pub fn encode_count(identifier: u16, count: u32, out: &mut Vec<u8>) {
    if count < 4096 {
        let word = (DASH << 18) | (bits(identifier as u32, 6) << 12) | bits(count, 12);
        out.extend_from_slice(&u32::to_be_bytes(word)[1..]);
    } else {
        let word1 =
            (DASH << 18) | (DASH << 12) | (bits(identifier as u32, 6) << 6) | bits(count >> 24, 6);
        let word2 = bits(count, 24);
        out.extend_from_slice(&u32::to_be_bytes(word1)[1..]);
        out.extend_from_slice(&u32::to_be_bytes(word2)[1..]);
    }
}

/// Encode the TSP version marker (`YTSP` genus + version count code).
pub fn encode_version(out: &mut Vec<u8>) {
    out.extend_from_slice(&YTSP);
    encode_count(TSP_VERSION.0, encoded_version() as u32, out);
}

/// Encode a `-J` VID list: the group header followed by one `B` var-data field
/// per VID. Used for the routing hop list, and in Rev 3 also for the
/// `Reply_Path` and `Referral_Field` payload fields.
///
/// Rev 3 §9.2 changed what the count means: it is the **byte length** of the
/// group (in quadlets), not the number of VIDs. An empty list is `-JAA`, which
/// is how an absent reply path / referral and a direct (non-routed) nesting are
/// all spelled.
pub fn encode_hops(hops: &[impl AsRef<[u8]>], out: &mut Vec<u8>) {
    let mut body = Vec::new();
    for hop in hops {
        encode_variable_data(TSP_VID, hop.as_ref(), &mut body);
    }
    debug_assert!(body.len().is_multiple_of(3));
    encode_count(TSP_HOP_LIST, (body.len() / 3) as u32, out);
    out.extend_from_slice(&body);
}

/// Decode a `-J` VID list at `*pos`. On success advances `*pos` past the group
/// header and every VID field, and returns the VID byte vectors.
///
/// The group's declared byte length is authoritative: VIDs are read until it is
/// exactly consumed, and a list whose fields overrun or underrun it is
/// rejected rather than truncated.
pub fn decode_hops(stream: &[u8], pos: &mut usize) -> Result<Vec<Vec<u8>>, TspError> {
    let quadlets = decode_count(TSP_HOP_LIST, stream, pos)
        .ok_or_else(|| TspError::InvalidMessage("missing -J VID list".into()))?;
    let group_len = (quadlets as usize)
        .checked_mul(3)
        .filter(|n| *n <= MAX_FIELD_SIZE)
        .ok_or_else(|| TspError::InvalidMessage("-J VID list too long".into()))?;
    let group_end = pos
        .checked_add(group_len)
        .filter(|end| *end <= stream.len())
        .ok_or_else(|| TspError::InvalidMessage("-J VID list overruns message".into()))?;

    let mut hops = Vec::new();
    while *pos < group_end {
        let hop = decode_variable_data(TSP_VID, stream, pos)
            .ok_or_else(|| TspError::InvalidMessage("malformed VID in -J list".into()))?;
        if *pos > group_end {
            return Err(TspError::InvalidMessage(
                "VID overruns the -J list byte count".into(),
            ));
        }
        hops.push(hop);
        // The route limit bounds the list independently of its byte count, so a
        // long-but-well-formed list can't drive unbounded allocation.
        if hops.len() > crate::message::routed::MAX_HOPS {
            return Err(TspError::InvalidMessage("hop list too long".into()));
        }
    }
    Ok(hops)
}

// ---- Decoding ----

/// Decode a count-code group header for `identifier`. On success advances
/// `*pos` past the header and returns the quadlet count.
pub fn decode_count(identifier: u16, stream: &[u8], pos: &mut usize) -> Option<u32> {
    let s = stream.get(*pos..*pos + 3)?;
    let word = extract_triplet(s.try_into().unwrap());
    let index = word & mask(12);
    let expected = (DASH << 18) | (bits(identifier as u32, 6) << 12) | bits(index, 12);
    // Long form `--X#####` (Rev 3). No ambiguity with the short form: that
    // would need an identifier equal to DASH (62), and every TSP group code is
    // a small letter index.
    let expected_long =
        (DASH << 18) | (DASH << 12) | (bits(identifier as u32, 6) << 6) | bits(index & 0x3F, 6);
    if word == expected {
        *pos += 3;
        Some(index)
    } else if word == expected_long {
        let s2 = stream.get(*pos + 3..*pos + 6)?;
        let next = extract_triplet(s2.try_into().unwrap());
        *pos += 6;
        // The long count is 30 bits: the high 6 live in the low 6 bits of this
        // word (alongside the identifier), the low 24 in the next. `index` here
        // still carries the identifier in its upper bits, so it must be masked
        // before being shifted in — without the mask the count comes back
        // enormous.
        Some(((index & mask(6)) << 24) | next)
    } else {
        None
    }
}

/// Decode fixed-size data of `N` bytes with a known identifier. On success
/// advances `*pos` and returns the `N` data bytes.
pub fn decode_fixed_data<const N: usize>(
    identifier: u32,
    stream: &[u8],
    pos: &mut usize,
) -> Option<[u8; N]> {
    let total_size = (N + 1).next_multiple_of(3);
    let hdr_bytes = total_size - N;
    let word = match hdr_bytes {
        1 => bits(identifier, 6) << 18,
        2 => (D0 << 18) | (bits(identifier, 6) << 12),
        3 => (D1 << 18) | bits(identifier, 18),
        _ => return None,
    };
    let hdr = stream.get(*pos..*pos + hdr_bytes)?;
    let want = &u32::to_be_bytes(word)[1..=hdr_bytes];
    if hdr != want {
        return None;
    }
    let data = stream.get(*pos + hdr_bytes..*pos + total_size)?;
    let out: [u8; N] = data.try_into().ok()?;
    *pos += total_size;
    Some(out)
}

/// Decode variable-size data with a known identifier. On success advances
/// `*pos` past the field and returns the data byte range within `stream`.
pub fn decode_variable_data_range(
    identifier: u32,
    stream: &[u8],
    pos: &mut usize,
) -> Option<std::ops::Range<usize>> {
    let s = stream.get(*pos..)?;
    let head = s.get(0..3)?;
    let input = extract_triplet(head.try_into().unwrap());
    let selector = input >> 18;

    let size;
    let found_id;
    if selector == D4 || selector == D5 || selector == D6 {
        found_id = (input >> 12) & mask(6);
        size = input & mask(12);
    } else if selector == D7 || selector == D8 || selector == D9 {
        found_id = input & mask(18);
        let s2 = s.get(3..6)?;
        size = extract_triplet(s2.try_into().unwrap());
    } else {
        return None;
    }

    if found_id != identifier {
        return None;
    }
    if (size as usize).saturating_mul(3) > MAX_FIELD_SIZE {
        return None;
    }

    let offset = (selector - D4) as usize;
    let data_begin = offset + 3;
    let data_end = (offset + 1).next_multiple_of(3) + 3 * size as usize;
    // Bounds check against the sub-slice.
    s.get(data_begin..data_end)?;

    // Rev 3 §3.7: CESR primitives are canonically encoded — lead bytes are
    // zero — and a receiver MUST reject a non-canonical one rather than
    // normalize it. Digests and signatures are taken over exact bytes, so
    // accepting a non-canonical primitive would admit two distinct byte
    // sequences for the same value, with two different signature inputs.
    let lead = offset % 3;
    if s.get(data_begin - lead..data_begin)?
        .iter()
        .any(|&b| b != 0)
    {
        return None;
    }
    let range = (data_begin + *pos)..(data_end + *pos);
    *pos = range.end;
    Some(range)
}

/// Decode variable-size data with a known identifier, returning a copy.
pub fn decode_variable_data(identifier: u32, stream: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let range = decode_variable_data_range(identifier, stream, pos)?;
    Some(stream[range].to_vec())
}

/// Decode and validate the TSP version marker, returning `(major, minor,
/// patch)`. Advances `*pos`.
///
/// Rev 3 §9.1 separates two failures that Rev 2 conflated. Bytes that are not a
/// `YTSP` genus marker at all are [`TspError::NotTsp`]; a well-formed marker
/// whose MAJOR we do not speak is [`TspError::VersionMismatch`]. MINOR and
/// PATCH are carried to the caller, never rejected — only MAJOR gates whether
/// the message is processable.
/// Read the version marker at the start of a whole frame, without gating on it.
///
/// [`decode_version`] refuses a MAJOR this build does not speak, which is right
/// on the parsing path and wrong when the question is "what revision is this?".
/// Used to attribute a failed parse to a revision mismatch, where the frame has
/// by definition not parsed and the answer is wanted anyway.
pub fn decode_frame_version(stream: &[u8], pos: &mut usize) -> Result<(u16, u16), TspError> {
    decode_count(TSP_ETS_WRAPPER, stream, pos)
        .ok_or_else(|| TspError::NotTsp("missing -E envelope frame".into()))?;
    read_version(stream, pos)
}

pub fn decode_version(stream: &[u8], pos: &mut usize) -> Result<(u16, u16), TspError> {
    let (major, minor) = read_version(stream, pos)?;
    if major != TSP_VERSION.0 {
        return Err(TspError::VersionMismatch {
            found: major,
            supported: TSP_VERSION.0,
        });
    }
    Ok((major, minor))
}

fn read_version(stream: &[u8], pos: &mut usize) -> Result<(u16, u16), TspError> {
    let hdr = stream
        .get(*pos..*pos + YTSP.len())
        .ok_or_else(|| TspError::NotTsp("truncated version marker".into()))?;
    if hdr != YTSP {
        return Err(TspError::NotTsp("not a YTSP genus marker".into()));
    }
    *pos += YTSP.len();

    let s = stream
        .get(*pos..*pos + 3)
        .ok_or_else(|| TspError::NotTsp("truncated version count code".into()))?;
    let word = extract_triplet(s.try_into().unwrap());
    if word >> 18 != DASH {
        return Err(TspError::NotTsp("malformed version count code".into()));
    }
    let major = ((word >> 12) & mask(6)) as u16;
    let minor = (word & mask(12)) as u16;
    *pos += 3;
    Ok((major, minor))
}

/// Encode an indexed Ed25519 signature primitive (Rev 3 §9.5).
///
/// The code is `B#`: `B` identifies an Ed25519 indexed signature and the second
/// Base64 character is the index of the signing key in the VID's key list. The
/// 2-byte code is followed by the 64-byte signature, 66 bytes in all (88
/// characters in the text domain). Rev 2 used the *non-indexed* `0B` code,
/// which is a different two bytes on the wire.
pub fn encode_indexed_ed25519_signature(index: u8, signature: &[u8; 64], out: &mut Vec<u8>) {
    let word = (bits(ED25519_SIGNATURE, 6) << 18) | (bits(index as u32, 6) << 12);
    out.extend_from_slice(&u32::to_be_bytes(word)[1..=2]);
    out.extend_from_slice(signature);
}

/// Decode an indexed Ed25519 signature primitive, returning `(index,
/// signature)`. Advances `*pos` past the 66-byte primitive.
pub fn decode_indexed_ed25519_signature(stream: &[u8], pos: &mut usize) -> Option<(u8, [u8; 64])> {
    let hdr = stream.get(*pos..*pos + 2)?;
    let word = ((hdr[0] as u32) << 16) | ((hdr[1] as u32) << 8);
    if word >> 18 != bits(ED25519_SIGNATURE, 6) {
        return None;
    }
    // The low 12 bits of the code word are structural zeroes; a non-zero value
    // there is a non-canonical primitive, which §3.7 requires us to reject.
    if word & mask(12) != 0 {
        return None;
    }
    let index = ((word >> 12) & mask(6)) as u8;
    let sig: [u8; 64] = stream.get(*pos + 2..*pos + 66)?.try_into().ok()?;
    *pos += 66;
    Some((index, sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_spec() {
        // Rev 3 §9: ciphertext moves from the HPKE-Auth `G` codes to the
        // HPKE-Base `F` codes, and `X` (the deleted XAAA marker) is gone.
        assert_eq!(TSP_VID, 1);
        assert_eq!(TSP_HPKE_BASE_CIPHERTEXT, 5);
        assert_eq!(TSP_ETS_WRAPPER, 4);
        assert_eq!(TSP_PAYLOAD, 25);
        assert_eq!(TSP_GENERIC_STREAM, 0);
        assert_eq!(TSP_HOP_LIST, 9);
        assert_eq!(TSP_ATTACH_GRP, 2);
        assert_eq!(TSP_INDEX_SIG_GRP, 10);
        assert_eq!(TSP_NONCE, 0);
        assert_eq!(TSP_SHA256, 8);
    }

    #[test]
    fn long_count_uses_double_dash() {
        // Rev 3 §9: the long form is `--E#####`, not Rev 2's `-0E#####`. The
        // second character is DASH (62), not '0' (52). A round-trip test cannot
        // see this — encoder and decoder agree either way — so pin the bytes.
        let mut buf = Vec::new();
        encode_count(TSP_ETS_WRAPPER, 5000, &mut buf);
        assert_eq!(buf.len(), 6);
        // word1 = DASH<<18 | DASH<<12 | id<<6 | count>>24
        //       = 62<<18 | 62<<12 | 4<<6 | 0  -> f8 fe 20 ... wait: check bytes.
        let word1 = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | buf[2] as u32;
        assert_eq!(word1 >> 18, 62, "first character must be '-'");
        assert_eq!(
            (word1 >> 12) & 0x3f,
            62,
            "second character must be '-', not '0'"
        );
        assert_eq!((word1 >> 6) & 0x3f, TSP_ETS_WRAPPER as u32);

        let mut pos = 0;
        assert_eq!(decode_count(TSP_ETS_WRAPPER, &buf, &mut pos), Some(5000));
        assert_eq!(pos, 6);
    }

    #[test]
    fn indexed_ed25519_signature_roundtrip() {
        // Rev 3 §9.5: code `B#`, 66 bytes in all. Index 0 is `B0` -> 04 00.
        let sig = [0x5Au8; 64];
        let mut buf = Vec::new();
        encode_indexed_ed25519_signature(0, &sig, &mut buf);
        assert_eq!(buf.len(), 66);
        assert_eq!(&buf[..2], &[0x04, 0x00]);

        let mut pos = 0;
        let (index, got) = decode_indexed_ed25519_signature(&buf, &mut pos).unwrap();
        assert_eq!(index, 0);
        assert_eq!(got, sig);
        assert_eq!(pos, 66);
    }

    #[test]
    fn indexed_signature_carries_its_index() {
        let sig = [0u8; 64];
        let mut buf = Vec::new();
        encode_indexed_ed25519_signature(3, &sig, &mut buf);
        let mut pos = 0;
        let (index, _) = decode_indexed_ed25519_signature(&buf, &mut pos).unwrap();
        assert_eq!(index, 3);
    }

    #[test]
    fn rev2_non_indexed_signature_code_is_rejected() {
        // Rev 2 emitted the non-indexed `0B` code via encode_fixed_data.
        let sig = [0u8; 64];
        let mut buf = Vec::new();
        encode_fixed_data(ED25519_SIGNATURE, &sig, &mut buf);
        assert_eq!(&buf[..2], &[0xd0, 0x10]);
        let mut pos = 0;
        assert!(decode_indexed_ed25519_signature(&buf, &mut pos).is_none());
    }

    #[test]
    fn non_canonical_lead_bytes_are_rejected() {
        // Rev 3 §3.7: lead bytes are zero, and a receiver rejects a primitive
        // whose padding is not canonical rather than normalizing it.
        let vid = b"did:web:bob.example"; // 19 bytes -> 2 lead bytes
        let mut buf = Vec::new();
        encode_variable_data(TSP_VID, vid, &mut buf);
        assert_eq!(&buf[3..5], &[0x00, 0x00]);

        let mut pos = 0;
        assert!(decode_variable_data(TSP_VID, &buf, &mut pos).is_some());

        buf[3] = 0x01;
        let mut pos = 0;
        assert!(decode_variable_data(TSP_VID, &buf, &mut pos).is_none());
    }

    #[test]
    fn version_reports_major_mismatch_separately_from_not_tsp() {
        let mut buf = Vec::new();
        encode_version(&mut buf);
        let mut pos = 0;
        assert_eq!(decode_version(&buf, &mut pos).unwrap(), (0, 2));

        // A YTSP marker with a different MAJOR is TSP, but unprocessable.
        let mut other = Vec::new();
        other.extend_from_slice(&YTSP);
        encode_count(1, 0, &mut other);
        let mut pos = 0;
        assert!(matches!(
            decode_version(&other, &mut pos),
            Err(TspError::VersionMismatch { found: 1, .. })
        ));

        // Bytes that are not a YTSP marker at all are not TSP.
        let mut pos = 0;
        assert!(matches!(
            decode_version(b"not-tsp-at-all", &mut pos),
            Err(TspError::NotTsp(_))
        ));
    }

    #[test]
    fn hop_list_count_is_byte_length_not_vid_count() {
        // Rev 3 §9.2 (D6): the -J count is the byte length of the group.
        let hops = [b"did:web:hop1".as_slice(), b"did:web:exit".as_slice()];
        let mut buf = Vec::new();
        encode_hops(&hops, &mut buf);

        let mut pos = 0;
        let quadlets = decode_count(TSP_HOP_LIST, &buf, &mut pos).unwrap();
        assert_eq!(quadlets as usize * 3, buf.len() - pos);
        assert_ne!(quadlets, 2, "count must not be the number of VIDs");
    }

    #[test]
    fn relationship_markers_match_reference() {
        // cesr_data("XRFI"/"XRFA"/"XRFD") — relationship payload-type markers.
        assert_eq!(XRFI, cesr_data::<3>("XRFI"));
        assert_eq!(XRFA, cesr_data::<3>("XRFA"));
        assert_eq!(XRFD, cesr_data::<3>("XRFD"));
    }

    #[test]
    fn ytsp_marker_bytes() {
        assert_eq!(YTSP, [0x61, 0x34, 0x8f]);
    }

    #[test]
    fn xscs_marker_bytes() {
        // cesr_data("XSCS"): X=23,S=18,C=2,S=18 -> 010111 010010 000010 010010
        // = 0x5d 0x20 0x92
        assert_eq!(XSCS, [0x5d, 0x20, 0x92]);
    }

    #[test]
    fn count_roundtrip() {
        let mut buf = Vec::new();
        encode_count(TSP_ETS_WRAPPER, 19, &mut buf);
        assert_eq!(buf, [0xf8, 0x40, 0x13]);
        let mut pos = 0;
        assert_eq!(decode_count(TSP_ETS_WRAPPER, &buf, &mut pos), Some(19));
        assert_eq!(pos, 3);
    }

    #[test]
    fn version_roundtrip() {
        let mut buf = Vec::new();
        encode_version(&mut buf);
        // `YTSP-AAC`: the `-` selector, MAJOR 0 as `A`, then MINOR 2 filling
        // the 12-bit count as `AC`.
        assert_eq!(buf, [0x61, 0x34, 0x8f, 0xf8, 0x00, 0x02]);
        let mut pos = 0;
        decode_version(&buf, &mut pos).unwrap();
        assert_eq!(pos, 6);
    }

    #[test]
    fn variable_data_roundtrip_no_lead() {
        // 19-byte VID -> 2 lead bytes (D6 selector).
        let vid = b"did:web:bob.example";
        let mut buf = Vec::new();
        encode_variable_data(TSP_VID, vid, &mut buf);
        // header e8 10 07 then 2 lead bytes then data
        assert_eq!(&buf[..3], &[0xe8, 0x10, 0x07]);
        assert_eq!(&buf[3..5], &[0x00, 0x00]);
        assert_eq!(&buf[5..], vid);
        let mut pos = 0;
        let got = decode_variable_data(TSP_VID, &buf, &mut pos).unwrap();
        assert_eq!(got, vid);
        assert_eq!(pos, buf.len());
    }

    #[test]
    fn variable_data_roundtrip_aligned() {
        // 21-byte VID -> 0 lead bytes (D4 selector).
        let vid = b"did:web:alice.example";
        let mut buf = Vec::new();
        encode_variable_data(TSP_VID, vid, &mut buf);
        assert_eq!(&buf[..3], &[0xe0, 0x10, 0x07]);
        assert_eq!(&buf[3..], vid);
        let mut pos = 0;
        let got = decode_variable_data(TSP_VID, &buf, &mut pos).unwrap();
        assert_eq!(got, vid);
    }

    #[test]
    fn hops_empty_roundtrip() {
        let mut buf = Vec::new();
        let no_hops: [&[u8]; 0] = [];
        encode_hops(&no_hops, &mut buf);
        // Just the -J0 count header.
        let mut pos = 0;
        let got = decode_hops(&buf, &mut pos).unwrap();
        assert!(got.is_empty());
        assert_eq!(pos, buf.len());
    }

    #[test]
    fn hops_roundtrip() {
        let hops = [b"did:web:hop1".as_slice(), b"did:web:exit".as_slice()];
        let mut buf = Vec::new();
        encode_hops(&hops, &mut buf);
        let mut pos = 0;
        let got = decode_hops(&buf, &mut pos).unwrap();
        assert_eq!(
            got,
            vec![b"did:web:hop1".to_vec(), b"did:web:exit".to_vec()]
        );
        assert_eq!(pos, buf.len());
    }

    #[test]
    fn nonce_is_128_bit_under_the_0a_code() {
        // Rev 3 §9.2 (D9): the nonce is 128 bits. The two-character code `0A`
        // follows from the length: 16 bytes -> total 18, header 2 bytes.
        let nonce = [0x11u8; 16];
        let mut buf = Vec::new();
        encode_fixed_data(TSP_NONCE, &nonce, &mut buf);
        assert_eq!(buf.len(), 18);
        assert_eq!(&buf[..2], &[0xd0, 0x00]);
        let mut pos = 0;
        assert_eq!(
            decode_fixed_data::<16>(TSP_NONCE, &buf, &mut pos).unwrap(),
            nonce
        );
    }
}
