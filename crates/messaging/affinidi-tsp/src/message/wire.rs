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

/// Maximum size we will allocate / accept for a single variable-data field
/// (1 MiB), guarding against hostile size headers.
pub const MAX_FIELD_SIZE: usize = 1_048_576;

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
/// `B`: var-data VID identifier.
pub const TSP_VID: u32 = cesr_int("B") as u32;
/// `G`: var-data HPKE-Auth ciphertext.
pub const TSP_HPKEAUTH_CIPHERTEXT: u32 = cesr_int("G") as u32;
/// `B`: fixed-data Ed25519 signature identifier.
pub const ED25519_SIGNATURE: u32 = cesr_int("B") as u32;
/// `X`: a 2-byte fixed-data marker emitted after the envelope VIDs.
pub const TSP_TMP: u32 = cesr_int("X") as u32;

/// `-E`: outer count-code wrapper for an encrypted-then-signed (ETS) envelope.
pub const TSP_ETS_WRAPPER: u16 = cesr_int("E") as u16;
/// `-Z`: count-code wrapper for the (to-be-encrypted) CESR payload frame.
pub const TSP_PAYLOAD: u16 = cesr_int("Z") as u16;
/// `-J`: count-code group for a hop (routing) list.
pub const TSP_HOP_LIST: u16 = cesr_int("J") as u16;
/// `-C`: count-code attach group for the signature.
pub const TSP_ATTACH_GRP: u16 = cesr_int("C") as u16;
/// `-K`: count-code indexed-signature group for the signature.
pub const TSP_INDEX_SIG_GRP: u16 = cesr_int("K") as u16;

/// 3-byte payload-type marker for a generic (GenericMessage / Content) payload.
pub const XSCS: [u8; 3] = cesr_data("XSCS");
/// 3-byte payload-type marker for a hop-carrying payload (Nested when the hop
/// list is empty, Routed otherwise).
pub const XHOP: [u8; 3] = cesr_data("XHOP");
/// 3-byte TSP version genus marker.
pub const YTSP: [u8; 3] = cesr_data("YTSP");

/// TSP version `(major, minor, patch)` advertised on the wire.
pub const TSP_VERSION: (u16, u8, u8) = (0, 0, 1);

const fn encoded_version() -> u16 {
    (TSP_VERSION.1 as u16) << 6 | (TSP_VERSION.2 as u16)
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
pub fn encode_count(identifier: u16, count: u32, out: &mut Vec<u8>) {
    if count < 4096 {
        let word = (DASH << 18) | (bits(identifier as u32, 6) << 12) | bits(count, 12);
        out.extend_from_slice(&u32::to_be_bytes(word)[1..]);
    } else {
        let word1 =
            (DASH << 18) | (D0 << 12) | (bits(identifier as u32, 6) << 6) | bits(count >> 24, 6);
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

/// Encode a hop (routing) list: a `-J<count>` group header followed by one
/// `B` var-data field per hop VID. Byte-compatible with `tsp_sdk`'s
/// `encode_hops`. An empty list encodes to just the `-J0` header (this is how
/// a Nested payload is distinguished from a Routed one).
pub fn encode_hops(hops: &[impl AsRef<[u8]>], out: &mut Vec<u8>) {
    encode_count(TSP_HOP_LIST, hops.len() as u32, out);
    for hop in hops {
        encode_variable_data(TSP_VID, hop.as_ref(), out);
    }
}

/// Decode a hop (routing) list at `*pos`. On success advances `*pos` past the
/// `-J` group + every hop field and returns the hop VID byte vectors.
pub fn decode_hops(stream: &[u8], pos: &mut usize) -> Result<Vec<Vec<u8>>, TspError> {
    let count = decode_count(TSP_HOP_LIST, stream, pos)
        .ok_or_else(|| TspError::InvalidMessage("missing -J hop list".into()))?;
    if count as usize > MAX_FIELD_SIZE {
        return Err(TspError::InvalidMessage("hop list too long".into()));
    }
    let mut hops = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let hop = decode_variable_data(TSP_VID, stream, pos)
            .ok_or_else(|| TspError::InvalidMessage("malformed hop VID".into()))?;
        hops.push(hop);
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
    let expected_long =
        (DASH << 18) | (D0 << 12) | (bits(identifier as u32, 6) << 6) | bits(index & 0x3F, 6);
    if word == expected {
        *pos += 3;
        Some(index)
    } else if word == expected_long {
        let s2 = stream.get(*pos + 3..*pos + 6)?;
        let next = extract_triplet(s2.try_into().unwrap());
        *pos += 6;
        Some(index << 24 | next)
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
    let range = (data_begin + *pos)..(data_end + *pos);
    *pos = range.end;
    Some(range)
}

/// Decode variable-size data with a known identifier, returning a copy.
pub fn decode_variable_data(
    identifier: u32,
    stream: &[u8],
    pos: &mut usize,
) -> Option<Vec<u8>> {
    let range = decode_variable_data_range(identifier, stream, pos)?;
    Some(stream[range].to_vec())
}

/// Decode and validate the TSP version marker. Advances `*pos`.
pub fn decode_version(stream: &[u8], pos: &mut usize) -> Result<(), TspError> {
    let hdr = stream
        .get(*pos..*pos + YTSP.len())
        .ok_or_else(|| TspError::InvalidMessage("truncated version marker".into()))?;
    if hdr != YTSP {
        return Err(TspError::InvalidMessage("not a YTSP version marker".into()));
    }
    *pos += YTSP.len();
    decode_count(TSP_VERSION.0, stream, pos)
        .ok_or_else(|| TspError::InvalidMessage("bad TSP version count code".into()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_reference() {
        // From tsp_sdk: cesr!("B")=1, cesr!("G")=6, cesr!("X")=23, cesr!("E")=4,
        // cesr!("Z")=25, cesr!("C")=2, cesr!("K")=10.
        assert_eq!(TSP_VID, 1);
        assert_eq!(TSP_HPKEAUTH_CIPHERTEXT, 6);
        assert_eq!(TSP_TMP, 23);
        assert_eq!(TSP_ETS_WRAPPER, 4);
        assert_eq!(TSP_PAYLOAD, 25);
        assert_eq!(TSP_ATTACH_GRP, 2);
        assert_eq!(TSP_INDEX_SIG_GRP, 10);
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
        assert_eq!(buf, [0x61, 0x34, 0x8f, 0xf8, 0x00, 0x01]);
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
    fn fixed_data_tmp_marker() {
        let mut buf = Vec::new();
        encode_fixed_data(TSP_TMP, &[0, 0], &mut buf);
        assert_eq!(buf, [0x5c, 0x00, 0x00]);
        let mut pos = 0;
        let got = decode_fixed_data::<2>(TSP_TMP, &buf, &mut pos).unwrap();
        assert_eq!(got, [0, 0]);
        assert_eq!(pos, 3);
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
        assert_eq!(got, vec![b"did:web:hop1".to_vec(), b"did:web:exit".to_vec()]);
        assert_eq!(pos, buf.len());
    }

    #[test]
    fn fixed_data_ed25519_sig() {
        let sig = [0xABu8; 64];
        let mut buf = Vec::new();
        encode_fixed_data(ED25519_SIGNATURE, &sig, &mut buf);
        // 64 -> total 66, hdr 2 -> word (D0<<18)|(1<<12) -> d0 10
        assert_eq!(&buf[..2], &[0xd0, 0x10]);
        let mut pos = 0;
        let got = decode_fixed_data::<64>(ED25519_SIGNATURE, &buf, &mut pos).unwrap();
        assert_eq!(got, sig);
    }
}
