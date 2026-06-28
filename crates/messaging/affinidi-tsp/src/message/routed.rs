//! TSP routed mode (§5.3) and nested mode (§5.5).
//!
//! **Routed mode** carries a message through one or more intermediaries. The
//! ordered list of remaining hops travels inside the HPKE-sealed payload of each
//! routing layer, so only the addressed intermediary can read it. An
//! intermediary opens its layer, takes the next hop, and re-seals the remaining
//! route + the (still opaque) inner message to that hop — re-authenticating as
//! itself. The **inner** message is opaque to every intermediary: it is sealed
//! end-to-end to the exit/recipient and merely carried.
//!
//! Routing-layer wire layout (the plaintext sealed to each hop):
//! ```text
//! [hop_count:u16] ( [vid_len:u16][vid utf8] )*  [inner_len:u32][inner bytes]
//! ```
//!
//! **Nested mode** is the degenerate metadata-privacy wrapper: an inner packed
//! TSP message carried as the opaque payload of an outer message addressed to a
//! single intermediary. It is `pack`/`unpack` with [`MessageType::Nested`]; the
//! intermediary forwards the inner bytes without being able to read them.
//!
//! Note: in routed mode each intermediary sees the *remaining route* (the hop
//! VIDs), but never the inner content. Onion-style routing that hides the route
//! itself from intermediaries is a future extension; the inner stays opaque
//! today, which is what the metadata-privacy bridge relies on.

use crate::error::TspError;
use crate::message::MessageType;
use crate::message::direct::{self, PackedMessage};

/// Maximum number of hops in a route, bounding both memory and forwarding loops.
pub const MAX_HOPS: usize = 16;

/// Maximum inner-message size carried in a routing layer (mirrors direct mode).
const MAX_INNER_SIZE: usize = 1_048_576;

/// Encode a routing payload: the remaining hop list followed by the opaque inner
/// message. This is the plaintext that gets HPKE-sealed to the addressed hop.
pub(crate) fn encode_route(remaining: &[String], inner: &[u8]) -> Result<Vec<u8>, TspError> {
    if remaining.len() > MAX_HOPS {
        return Err(TspError::InvalidMessage(format!(
            "route has {} hops, exceeds maximum of {MAX_HOPS}",
            remaining.len()
        )));
    }
    if inner.len() > MAX_INNER_SIZE {
        return Err(TspError::InvalidMessage(format!(
            "inner message {} bytes exceeds maximum of {MAX_INNER_SIZE}",
            inner.len()
        )));
    }

    let mut buf = Vec::new();
    buf.extend_from_slice(&(remaining.len() as u16).to_be_bytes());
    for vid in remaining {
        let bytes = vid.as_bytes();
        let len = u16::try_from(bytes.len())
            .map_err(|_| TspError::InvalidMessage("hop VID too long".into()))?;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(bytes);
    }
    buf.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    buf.extend_from_slice(inner);
    Ok(buf)
}

/// Decode a routing payload into `(remaining_route, inner)`.
pub(crate) fn decode_route(bytes: &[u8]) -> Result<(Vec<String>, Vec<u8>), TspError> {
    let mut pos = 0usize;
    let hop_count = read_u16(bytes, &mut pos)? as usize;
    if hop_count > MAX_HOPS {
        return Err(TspError::InvalidMessage(format!(
            "routing header claims {hop_count} hops, exceeds maximum of {MAX_HOPS}"
        )));
    }

    let mut route = Vec::with_capacity(hop_count);
    for _ in 0..hop_count {
        let len = read_u16(bytes, &mut pos)? as usize;
        let end = pos
            .checked_add(len)
            .filter(|e| *e <= bytes.len())
            .ok_or_else(|| TspError::InvalidMessage("routing hop VID truncated".into()))?;
        let vid = std::str::from_utf8(&bytes[pos..end])
            .map_err(|_| TspError::InvalidMessage("routing hop VID not UTF-8".into()))?
            .to_string();
        route.push(vid);
        pos = end;
    }

    let inner_len = read_u32(bytes, &mut pos)? as usize;
    if inner_len > MAX_INNER_SIZE {
        return Err(TspError::InvalidMessage(format!(
            "inner message length {inner_len} exceeds maximum of {MAX_INNER_SIZE}"
        )));
    }
    let end = pos
        .checked_add(inner_len)
        .filter(|e| *e <= bytes.len())
        .ok_or_else(|| TspError::InvalidMessage("inner message truncated".into()))?;
    let inner = bytes[pos..end].to_vec();
    Ok((route, inner))
}

fn read_u16(bytes: &[u8], pos: &mut usize) -> Result<u16, TspError> {
    let end = pos
        .checked_add(2)
        .filter(|e| *e <= bytes.len())
        .ok_or_else(|| TspError::InvalidMessage("routing payload truncated (u16)".into()))?;
    let v = u16::from_be_bytes(bytes[*pos..end].try_into().unwrap());
    *pos = end;
    Ok(v)
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, TspError> {
    let end = pos
        .checked_add(4)
        .filter(|e| *e <= bytes.len())
        .ok_or_else(|| TspError::InvalidMessage("routing payload truncated (u32)".into()))?;
    let v = u32::from_be_bytes(bytes[*pos..end].try_into().unwrap());
    *pos = end;
    Ok(v)
}

/// Pack a routed message addressed to `first_hop`, carrying `remaining_route`
/// (the hops to visit after `first_hop`, in order) and the opaque `inner`
/// message (already sealed end-to-end to the exit/recipient).
///
/// The full path is `[first_hop] ++ remaining_route`; when an intermediary's
/// remaining route is empty it is the exit and consumes `inner`.
#[allow(clippy::too_many_arguments)]
pub fn pack_routed(
    inner: &[u8],
    remaining_route: &[String],
    sender_vid: &str,
    first_hop_vid: &str,
    sender_signing_key: &[u8; 32],
    sender_encryption_key: &[u8; 32],
    first_hop_encryption_key: &[u8; 32],
) -> Result<PackedMessage, TspError> {
    let routing = encode_route(remaining_route, inner)?;
    direct::pack(
        &routing,
        MessageType::Routed,
        sender_vid,
        first_hop_vid,
        sender_signing_key,
        sender_encryption_key,
        first_hop_encryption_key,
    )
}

/// Pack a nested message: an inner packed TSP message carried as the opaque
/// payload of an outer message to `intermediary_vid` (metadata-privacy wrapper).
#[allow(clippy::too_many_arguments)]
pub fn pack_nested(
    inner: &PackedMessage,
    sender_vid: &str,
    intermediary_vid: &str,
    sender_signing_key: &[u8; 32],
    sender_encryption_key: &[u8; 32],
    intermediary_encryption_key: &[u8; 32],
) -> Result<PackedMessage, TspError> {
    direct::pack(
        &inner.bytes,
        MessageType::Nested,
        sender_vid,
        intermediary_vid,
        sender_signing_key,
        sender_encryption_key,
        intermediary_encryption_key,
    )
}

/// What an intermediary should do after opening a routed layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteStep {
    /// Re-seal `inner` + `remaining` and forward to `next`.
    Forward {
        /// The next hop's VID (the new envelope receiver).
        next: String,
        /// The route to carry onward (the hops after `next`).
        remaining: Vec<String>,
        /// The opaque inner message, unchanged.
        inner: Vec<u8>,
    },
    /// This hop is the exit: consume / deliver `inner` (sealed to the recipient).
    Deliver {
        /// The opaque inner message for this hop to deliver or process.
        inner: Vec<u8>,
    },
}

/// Determine the next routing step from a decrypted routed payload (the
/// `payload` returned by unpacking a [`MessageType::Routed`] message).
pub fn next_hop(routing_payload: &[u8]) -> Result<RouteStep, TspError> {
    let (route, inner) = decode_route(routing_payload)?;
    match route.split_first() {
        None => Ok(RouteStep::Deliver { inner }),
        Some((next, rest)) => Ok(RouteStep::Forward {
            next: next.clone(),
            remaining: rest.to_vec(),
            inner,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::direct::unpack;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    struct Party {
        vid: String,
        sign_sk: [u8; 32],
        sign_pk: [u8; 32],
        enc_sk: [u8; 32],
        enc_pk: [u8; 32],
    }

    fn party(vid: &str) -> Party {
        let sign = SigningKey::generate(&mut OsRng);
        let enc = StaticSecret::random_from_rng(OsRng);
        Party {
            vid: vid.to_string(),
            sign_sk: sign.to_bytes(),
            sign_pk: sign.verifying_key().to_bytes(),
            enc_sk: enc.to_bytes(),
            enc_pk: PublicKey::from(&enc).to_bytes(),
        }
    }

    #[test]
    fn encode_decode_route_roundtrip() {
        let route = vec!["did:web:hop2".to_string(), "did:web:exit".to_string()];
        let inner = b"opaque inner message".to_vec();
        let encoded = encode_route(&route, &inner).unwrap();
        let (decoded_route, decoded_inner) = decode_route(&encoded).unwrap();
        assert_eq!(decoded_route, route);
        assert_eq!(decoded_inner, inner);
    }

    #[test]
    fn decode_route_rejects_truncation() {
        assert!(decode_route(&[0x00]).is_err()); // not even a full hop_count
        // hop_count = 1 but no hop follows
        assert!(decode_route(&[0x00, 0x01]).is_err());
    }

    #[test]
    fn encode_route_rejects_too_many_hops() {
        let route: Vec<String> = (0..MAX_HOPS + 1).map(|i| format!("did:web:h{i}")).collect();
        assert!(encode_route(&route, b"x").is_err());
    }

    #[test]
    fn next_hop_forward_then_deliver() {
        // route [hop2, exit]: first step forwards to hop2 leaving [exit];
        // then [exit] forwards to exit leaving []; then [] delivers.
        let inner = b"payload".to_vec();
        let p1 = encode_route(&["hop2".into(), "exit".into()], &inner).unwrap();
        match next_hop(&p1).unwrap() {
            RouteStep::Forward {
                next,
                remaining,
                inner: i,
            } => {
                assert_eq!(next, "hop2");
                assert_eq!(remaining, vec!["exit".to_string()]);
                assert_eq!(i, inner);
            }
            other => panic!("expected Forward, got {other:?}"),
        }

        let p_exit = encode_route(&[], &inner).unwrap();
        assert_eq!(next_hop(&p_exit).unwrap(), RouteStep::Deliver { inner });
    }

    /// Full multi-hop crypto round-trip: alice → hop1 → hop2 (exit) carrying an
    /// inner message sealed end-to-end alice → final. Proves (a) each hop can
    /// open only its own routing layer, (b) the inner stays opaque until final,
    /// (c) re-sealing at each hop re-authenticates the relaying party.
    #[test]
    fn routed_multihop_roundtrip() {
        let alice = party("did:web:alice");
        let hop1 = party("did:web:hop1");
        let hop2 = party("did:web:hop2");
        let final_p = party("did:web:final");

        // 1. alice seals the inner message end-to-end to final (Direct).
        let inner = direct::pack(
            b"the secret",
            MessageType::Direct,
            &alice.vid,
            &final_p.vid,
            &alice.sign_sk,
            &alice.enc_sk,
            &final_p.enc_pk,
        )
        .unwrap();

        // 2. alice packs a routed layer to hop1, route = [hop2, final].
        //    (hop2 is the exit intermediary; final is the last hop it delivers to.)
        let layer1 = pack_routed(
            &inner.bytes,
            &["did:web:hop2".into(), "did:web:final".into()],
            &alice.vid,
            &hop1.vid,
            &alice.sign_sk,
            &alice.enc_sk,
            &hop1.enc_pk,
        )
        .unwrap();

        // 3. hop1 opens its layer (it is the receiver), reads the route.
        let at_hop1 = unpack(&layer1.bytes, &hop1.enc_sk, &alice.enc_pk, &alice.sign_pk).unwrap();
        assert_eq!(at_hop1.message_type, MessageType::Routed);
        let step1 = next_hop(&at_hop1.payload).unwrap();
        let (next1, rest1, carried1) = match step1 {
            RouteStep::Forward {
                next,
                remaining,
                inner,
            } => (next, remaining, inner),
            other => panic!("hop1 expected Forward, got {other:?}"),
        };
        assert_eq!(next1, "did:web:hop2");
        assert_eq!(rest1, vec!["did:web:final".to_string()]);
        // The inner is still opaque (it equals alice's sealed bytes).
        assert_eq!(carried1, inner.bytes);

        // 4. hop1 re-seals to hop2 (authenticating as hop1).
        let layer2 = pack_routed(
            &carried1,
            &rest1,
            &hop1.vid,
            &hop2.vid,
            &hop1.sign_sk,
            &hop1.enc_sk,
            &hop2.enc_pk,
        )
        .unwrap();

        // 5. hop2 opens its layer, sees route [final] → forward/deliver to final.
        let at_hop2 = unpack(&layer2.bytes, &hop2.enc_sk, &hop1.enc_pk, &hop1.sign_pk).unwrap();
        let step2 = next_hop(&at_hop2.payload).unwrap();
        let (next2, rest2, carried2) = match step2 {
            RouteStep::Forward {
                next,
                remaining,
                inner,
            } => (next, remaining, inner),
            other => panic!("hop2 expected Forward, got {other:?}"),
        };
        assert_eq!(next2, "did:web:final");
        assert!(rest2.is_empty());

        // 6. hop2 forwards the opaque inner to final (no re-seal needed: the
        //    inner is already a complete message sealed alice → final). final
        //    unpacks it directly and recovers the plaintext.
        let delivered = unpack(&carried2, &final_p.enc_sk, &alice.enc_pk, &alice.sign_pk).unwrap();
        assert_eq!(delivered.payload, b"the secret");
        assert_eq!(delivered.sender, "did:web:alice");
        assert_eq!(delivered.receiver, "did:web:final");
    }

    /// A hop cannot open a routing layer addressed to a different hop.
    #[test]
    fn intermediary_cannot_open_wrong_layer() {
        let alice = party("did:web:alice");
        let hop1 = party("did:web:hop1");
        let hop2 = party("did:web:hop2");

        let layer = pack_routed(
            b"inner",
            &["did:web:hop2".into()],
            &alice.vid,
            &hop1.vid,
            &alice.sign_sk,
            &alice.enc_sk,
            &hop1.enc_pk,
        )
        .unwrap();

        // hop2 tries to open hop1's layer with its own key — must fail.
        assert!(unpack(&layer.bytes, &hop2.enc_sk, &alice.enc_pk, &alice.sign_pk).is_err());
    }

    /// Nested wrapper: an inner packed message carried opaquely to an intermediary.
    #[test]
    fn nested_wrapper_roundtrip() {
        let alice = party("did:web:alice");
        let mediator = party("did:web:mediator");
        let bob = party("did:web:bob");

        let inner = direct::pack(
            b"for bob only",
            MessageType::Direct,
            &alice.vid,
            &bob.vid,
            &alice.sign_sk,
            &alice.enc_sk,
            &bob.enc_pk,
        )
        .unwrap();

        // alice nests the inner inside an outer to the mediator.
        let nested = pack_nested(
            &inner,
            &alice.vid,
            &mediator.vid,
            &alice.sign_sk,
            &alice.enc_sk,
            &mediator.enc_pk,
        )
        .unwrap();

        // mediator opens the outer, gets the opaque inner, cannot read bob's plaintext.
        let at_mediator = unpack(
            &nested.bytes,
            &mediator.enc_sk,
            &alice.enc_pk,
            &alice.sign_pk,
        )
        .unwrap();
        assert_eq!(at_mediator.message_type, MessageType::Nested);
        assert_eq!(at_mediator.payload, inner.bytes);
        assert!(
            unpack(
                &at_mediator.payload,
                &mediator.enc_sk,
                &alice.enc_pk,
                &alice.sign_pk
            )
            .is_err(),
            "mediator must not be able to open the inner sealed to bob"
        );

        // bob opens the inner.
        let at_bob = unpack(&inner.bytes, &bob.enc_sk, &alice.enc_pk, &alice.sign_pk).unwrap();
        assert_eq!(at_bob.payload, b"for bob only");
    }
}
