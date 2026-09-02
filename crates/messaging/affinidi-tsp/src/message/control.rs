//! TSP control messages for relationship management.
//!
//! Control messages drive the explicit relationship lifecycle that
//! distinguishes TSP from DIDComm. On the wire they are **not** a serialized
//! body inside a generic payload — each is its own CESR payload-frame variant
//! (spec Rev 3 §9.3), and every one of them begins with the ESSR sender-VID
//! field and ends with the padding field:
//!
//!   * **Invite** → `XRFI, VID_sndr, Digest, Nonce, Reply_Path, Referral, Pad`
//!   * **Accept** → `XRFA, VID_sndr, Digest, Reply_Digest, Pad`
//!   * **Cancel** → `XRFD, VID_sndr, Digest, Pad`
//!
//! The CESR encode/decode of these frames lives in [`crate::message::direct`]
//! (see `encode_payload_frame` / `decode_payload_frame`). This module owns the
//! semantic [`ControlMessage`] type and a local `encode`/`decode` used to carry
//! a recovered control across the SDK's `payload` field.
//!
//! Correlation rides on the **`TSP_Digest`** (§7.2.1), which Rev 3 changed from
//! a convention into a wire field. It is a self-addressing digest computed over
//! the message's own envelope and payload with the digest's own slot dummied
//! out, carried in the message, and recomputed by the receiver. Rev 2 correlated
//! on a hash of the encrypted payload that was never transmitted and so could
//! never be checked. An accept's `Reply_Digest` and a cancel's `Digest` echo an
//! earlier message's digest verbatim; they are not recomputed.

use rand_core::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::TspError;

/// Length of a SHA-256 digest, in bytes.
pub const DIGEST_LEN: usize = 32;

/// Length of a relationship nonce, in bytes.
///
/// Rev 3 §9.2 (D9) fixes the nonce at 128 bits; Rev 2 used 256. The CESR code
/// follows from the length — 16 bytes lands under the two-character `0A` code —
/// so this constant is the only place the change needs to be made.
pub const NONCE_LEN: usize = 16;

/// Generate a cryptographically random 128-bit nonce.
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// TSP control message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ControlType {
    /// Relationship Forming Invite (`XRFI` / `DirectRelationProposal`).
    RelationshipFormingInvite = 0x00,
    /// Relationship Forming Accept (`XRFA` / `DirectRelationAffirm`).
    RelationshipFormingAccept = 0x01,
    /// Relationship Cancel (`XRFD` / `RelationshipCancel`).
    RelationshipCancel = 0x02,
}

impl ControlType {
    pub fn from_byte(b: u8) -> Result<Self, TspError> {
        match b {
            0x00 => Ok(ControlType::RelationshipFormingInvite),
            0x01 => Ok(ControlType::RelationshipFormingAccept),
            0x02 => Ok(ControlType::RelationshipCancel),
            _ => Err(TspError::InvalidMessage(format!(
                "unknown control type: 0x{b:02x}"
            ))),
        }
    }
}

/// A new VID introduced over an existing relationship (spec Rev 3 §7.2.5).
///
/// An endpoint that already has a relationship with a peer can use it to
/// introduce a second, parallel one: the invite names the new VID and carries
/// that VID's own signature, so the peer learns the new identifier over a
/// channel it already trusts and can check that whoever controls the new VID
/// agreed to the introduction.
///
/// The signature is made by `VID_new`'s key over the payload fields that
/// precede it — the type code, the ESSR sender VID, the digest, the nonce, the
/// reply path and `VID_new` itself. The referral field's own code and count are
/// not covered; the message signature covers those.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Referral {
    /// The VID being introduced.
    pub new_vid: String,
    /// `Signature_new`, made by `new_vid`'s key. See [`Referral`].
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
}

/// serde for a 64-byte signature.
///
/// serde derives array impls only up to 32 elements, and this is the local
/// encoding used to carry a recovered control through the SDK's `payload`
/// field, not the wire form — so it serializes as a byte sequence and checks
/// the length coming back rather than widening the type to a `Vec`.
mod signature_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub(super) fn serialize<S: Serializer>(
        signature: &[u8; 64],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(signature.iter())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 64], D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes.try_into().map_err(|v: Vec<u8>| {
            D::Error::custom(format!("expected a 64-byte signature, got {}", v.len()))
        })
    }
}

/// A TSP control message payload.
///
/// The fields used depend on [`ControlType`]:
///   * **invite** carries a 128-bit `nonce` and, once packed, its own `digest`;
///     `route` is the `Reply_Path`, empty for a direct reply.
///   * **accept** carries its own `digest` and a `reply` — the invite's digest,
///     echoed as `Reply_Digest`.
///   * **cancel** carries only `reply`, the digest of the relationship-forming
///     message it ends; `digest` mirrors it, since a cancel has no digest of
///     its own to derive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlMessage {
    /// The control message type.
    pub control_type: ControlType,
    /// This message's own self-addressing digest — the Rev 3 `TSP_Digest`
    /// (§7.2.1), carried on the wire by an invite and an accept and verified by
    /// the receiver. It is the thread id of the exchange this message opens.
    ///
    /// Set by the packing code, which is the only place that can compute it:
    /// the derivation covers the envelope, which a caller constructing a
    /// `ControlMessage` does not yet have.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub digest: Option<[u8; DIGEST_LEN]>,
    /// The 128-bit nonce (invite only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nonce: Option<[u8; NONCE_LEN]>,
    /// A digest referring to an earlier message, copied verbatim rather than
    /// recomputed: an accept's `Digest` (the invite it answers) or a cancel's
    /// `Digest` (the relationship-forming message it ends).
    ///
    /// Note which spec field this is, because the accept's two digests are easy
    /// to swap: §7 puts the *echoed* one in `Digest` and the accept's own SAID
    /// in `Reply_Digest`, so the self-addressing one is [`Self::digest`] and
    /// this is not it, despite the name.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reply: Option<[u8; DIGEST_LEN]>,
    /// The invite's `Reply_Path` (Rev 3 §9.2): the route over which the peer is
    /// to send its accept. Empty — encoded `-JAA` — for a direct reply.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub route: Vec<String>,
    /// The invite's `Referral_Field` (§7.2.5): a new VID introduced over this
    /// relationship, with that VID's own signature. `None` — encoded `-JAA` —
    /// for an invite that introduces nothing.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub referral: Option<Referral>,
}

impl ControlMessage {
    /// Create a Relationship Forming Invite with a fresh 128-bit nonce and a
    /// direct reply path.
    pub fn invite() -> Self {
        Self {
            control_type: ControlType::RelationshipFormingInvite,
            digest: None,
            nonce: Some(generate_nonce()),
            reply: None,
            route: Vec::new(),
            referral: None,
        }
    }

    /// Create a Relationship Forming Invite carrying a `Reply_Path` — the route
    /// the peer is to send its accept over.
    pub fn invite_routed(route: Vec<String>) -> Self {
        Self {
            control_type: ControlType::RelationshipFormingInvite,
            digest: None,
            nonce: Some(generate_nonce()),
            reply: None,
            route,
            referral: None,
        }
    }

    /// Create a Relationship Forming Invite that introduces `new_vid` over an
    /// existing relationship (§7.2.5, parallel relationship forming).
    ///
    /// The signature is left empty here and filled in when the message is
    /// packed: it covers the digest, which does not exist until then.
    pub fn invite_referral(new_vid: impl Into<String>) -> Self {
        Self {
            control_type: ControlType::RelationshipFormingInvite,
            digest: None,
            nonce: Some(generate_nonce()),
            reply: None,
            route: Vec::new(),
            referral: Some(Referral {
                new_vid: new_vid.into(),
                signature: [0u8; 64],
            }),
        }
    }

    /// Create a Relationship Forming Accept answering the invite whose
    /// `TSP_Digest` is `reply`. The accept's own digest is derived at pack time.
    pub fn accept(reply: [u8; DIGEST_LEN]) -> Self {
        Self {
            control_type: ControlType::RelationshipFormingAccept,
            digest: None,
            nonce: None,
            reply: Some(reply),
            route: Vec::new(),
            referral: None,
        }
    }

    /// Create a Relationship Cancel naming the relationship-forming message it
    /// ends by that message's `TSP_Digest`.
    ///
    /// Rev 3 §9.3 requires the digest to be present: a relationship cannot be
    /// formed without an invite, so both parties hold at least that digest.
    /// This is why the cancel no longer carries a nonce — the nonce existed
    /// only to cover the case where the digest was absent.
    pub fn cancel(reply: [u8; DIGEST_LEN]) -> Self {
        Self {
            control_type: ControlType::RelationshipCancel,
            digest: None,
            nonce: None,
            reply: Some(reply),
            route: Vec::new(),
            referral: None,
        }
    }

    /// The nonce, erroring if absent (invariant: present iff invite).
    pub fn require_nonce(&self) -> Result<&[u8; NONCE_LEN], TspError> {
        self.nonce
            .as_ref()
            .ok_or_else(|| TspError::InvalidMessage("invite is missing its nonce".into()))
    }

    /// The reply digest, erroring if absent (invariant: present iff accept/cancel).
    pub fn require_reply(&self) -> Result<&[u8; DIGEST_LEN], TspError> {
        self.reply
            .as_ref()
            .ok_or_else(|| TspError::InvalidMessage("control is missing its reply digest".into()))
    }

    /// Encode this control message to a local, self-describing byte form.
    ///
    /// This is **not** the TSP wire form — that is the CESR payload frame built
    /// in [`crate::message::direct`]. It exists so the SDK, which unpacks a
    /// message down to a `payload: Vec<u8>`, can recover a [`ControlMessage`]
    /// via [`ControlMessage::decode`]. Because it never leaves the process,
    /// its shape is ours to choose, and it uses serde rather than a hand-rolled
    /// framing so that adding a field cannot silently desynchronize the two
    /// halves — which is a live risk now that the payload carries a digest, a
    /// nonce of a different width, and a reply path.
    pub fn encode(&self) -> Vec<u8> {
        // A ControlMessage is a small struct of plain data; serialization
        // cannot fail, and an empty body would be rejected by `decode`.
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Decode a control message from its local byte form (the inverse of
    /// [`ControlMessage::encode`]).
    pub fn decode(data: &[u8]) -> Result<Self, TspError> {
        serde_json::from_slice(data)
            .map_err(|e| TspError::InvalidMessage(format!("malformed control message: {e}")))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_roundtrip() {
        let msg = ControlMessage::invite();
        let decoded = ControlMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.control_type, ControlType::RelationshipFormingInvite);
        assert_eq!(decoded.nonce.unwrap().len(), NONCE_LEN);
        assert!(decoded.reply.is_none());
        assert!(decoded.route.is_empty());
    }

    #[test]
    fn invite_routed_roundtrip() {
        let route = vec!["did:web:hop1".to_string(), "did:web:hop2".to_string()];
        let msg = ControlMessage::invite_routed(route.clone());
        let decoded = ControlMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.route, route);
    }

    #[test]
    fn accept_roundtrip() {
        let reply = [0xAA; 32];
        let msg = ControlMessage::accept(reply);
        let decoded = ControlMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.control_type, ControlType::RelationshipFormingAccept);
        assert_eq!(decoded.reply.unwrap(), reply);
        assert!(decoded.nonce.is_none());
    }

    #[test]
    fn cancel_roundtrip() {
        let reply = [0x55; 32];
        let msg = ControlMessage::cancel(reply);
        let decoded = ControlMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.control_type, ControlType::RelationshipCancel);
        assert_eq!(decoded.reply.unwrap(), reply);
    }

    #[test]
    fn unknown_control_type() {
        assert!(ControlType::from_byte(0xFF).is_err());
    }

    #[test]
    fn truncated_control_message() {
        assert!(ControlMessage::decode(&[]).is_err());
        assert!(ControlMessage::decode(&[0x00]).is_err()); // invite w/o nonce
        assert!(ControlMessage::decode(&[0x01]).is_err()); // accept w/o reply
    }

    #[test]
    fn generate_nonce_uniqueness() {
        assert_ne!(generate_nonce(), generate_nonce());
    }
}
