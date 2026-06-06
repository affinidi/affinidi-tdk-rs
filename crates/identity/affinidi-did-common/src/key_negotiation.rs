//! Sender/recipient key-agreement negotiation for DIDComm encryption.
//!
//! Packing an authcrypt (ECDH-1PU) message requires the sender and the
//! recipient to share an elliptic curve. A DID document may advertise
//! several `keyAgreement` keys on different curves, so picking a working
//! pair is a small negotiation rather than a blind `first()`.
//!
//! This module is the single home for that logic — both the
//! DID-authentication layer and the messaging SDK delegate here, mapping
//! the neutral [`KeyNegotiationError`] into their own error type at the
//! call site. It lives in `affinidi-did-common` because that crate already
//! owns [`Document`] decoding and already depends on `affinidi-crypto`; no
//! new dependency edge is introduced, and the crypto crate stays free of
//! DID types.
//!
//! Sender *secret* resolution is deliberately **not** done here — it needs
//! the async secrets resolver, which would drag another dependency into
//! this crate. Call sites resolve their sender secrets, hand us the set of
//! curves they can actually use, and we choose the best recipient pairing.

use affinidi_crypto::jose::key_agreement::{Curve, PublicKeyAgreement};

use crate::{Document, DocumentExt, verification_method::VerificationRelationship};

/// Default curve preference, most-preferred first.
///
/// `X25519 > P-256 > P-384 > P-521 > secp256k1`: modern/safe curves first,
/// then the NIST P-curves in ascending size, with secp256k1 last (least
/// preferred for general DIDComm use). When several pairings are possible,
/// the earliest curve in the *active* preference list that both sides offer
/// wins. This is the policy used when a caller does not override it; pass a
/// custom `&[Curve]` to [`negotiate_authcrypt`] / [`select_anoncrypt_key`] to
/// force a different order at runtime (e.g. a FIPS deployment that wants
/// P-256 first). Both the authcrypt and anoncrypt paths consult the same
/// ordering, so signed and anonymous encryption never diverge in which curve
/// they choose.
pub const DEFAULT_CURVE_PREFERENCE: [Curve; 5] = [
    Curve::X25519,
    Curve::P256,
    Curve::P384,
    Curve::P521,
    Curve::K256,
];

/// Errors from key-agreement resolution and negotiation.
///
/// Neutral by design: each call site maps these into its own error type so
/// the message context (`DIDAuthError` / `ATMError`) stays at the boundary.
#[derive(Debug, thiserror::Error)]
pub enum KeyNegotiationError {
    /// No verification method matched the given key id.
    #[error("verification method not found: {0}")]
    NotFound(String),

    /// The verification material decoded, but its multicodec is not a
    /// supported key-agreement curve (e.g. an Ed25519 signing key listed
    /// under `keyAgreement`).
    #[error("unsupported multicodec for key agreement: 0x{0:x}")]
    UnsupportedCodec(u64),

    /// The verification material could not be decoded at all.
    #[error("invalid verification material: {0}")]
    InvalidMaterial(String),

    /// The decoded bytes were not a valid public key for the curve.
    #[error("invalid key bytes: {0}")]
    InvalidKeyBytes(String),

    /// Sender and recipient share no common key-agreement curve. Names the
    /// curve set each side actually offered, to aid mediator interop
    /// debugging.
    #[error(
        "no common key-agreement curve: sender offers {sender:?}, recipient offers {recipient:?}"
    )]
    NoCommonCurve {
        /// Curves the sender can use (has a usable secret for).
        sender: Vec<Curve>,
        /// Curves the recipient advertises a usable key-agreement key on.
        recipient: Vec<Curve>,
    },

    /// The recipient advertised key-agreement keys, but none resolved to a
    /// supported curve (anoncrypt). Lists the key ids that were tried.
    #[error("recipient has no usable key-agreement key (tried: {0:?})")]
    NoUsableRecipientKey(Vec<String>),
}

/// A chosen authcrypt pairing on a shared curve.
#[derive(Debug)]
pub struct AuthcryptMatch<'a> {
    /// The negotiated curve (the caller selects its sender key on this curve).
    pub curve: Curve,
    /// The recipient key-agreement key id to encrypt to.
    pub recipient_kid: &'a str,
    /// The recipient public key.
    pub recipient_pub: PublicKeyAgreement,
}

/// Resolve a single `keyAgreement` verification method into a
/// [`PublicKeyAgreement`].
///
/// Checks embedded verification methods first, then the document's
/// top-level `verificationMethod` set, and decodes the material through the
/// shared [`VerificationMethod::decode_public_key`] parser so JWK and
/// multibase do not drift between call sites.
///
/// [`VerificationMethod::decode_public_key`]: crate::verification_method::VerificationMethod::decode_public_key
pub fn resolve_public_key_agreement(
    doc: &Document,
    kid: &str,
) -> Result<PublicKeyAgreement, KeyNegotiationError> {
    let vm = doc
        .key_agreement
        .iter()
        .filter_map(|ka| match ka {
            VerificationRelationship::VerificationMethod(vm) if vm.id.as_str() == kid => {
                Some(vm.as_ref())
            }
            _ => None,
        })
        .next()
        .or_else(|| doc.get_verification_method(kid))
        .ok_or_else(|| KeyNegotiationError::NotFound(kid.to_string()))?;

    let (codec, key_bytes) = vm
        .decode_public_key()
        .map_err(|e| KeyNegotiationError::InvalidMaterial(e.to_string()))?;

    let curve = match codec {
        affinidi_encoding::X25519_PUB => Curve::X25519,
        affinidi_encoding::P256_PUB => Curve::P256,
        affinidi_encoding::SECP256K1_PUB => Curve::K256,
        affinidi_encoding::P384_PUB => Curve::P384,
        affinidi_encoding::P521_PUB => Curve::P521,
        other => return Err(KeyNegotiationError::UnsupportedCodec(other)),
    };

    PublicKeyAgreement::from_raw_bytes(curve, &key_bytes)
        .map_err(|e| KeyNegotiationError::InvalidKeyBytes(e.to_string()))
}

/// Resolve the recipient's advertised key-agreement keys, preserving
/// document order and skipping entries that do not resolve to a supported
/// curve (undecodable codecs, unsupported curves, bad key bytes).
fn resolve_recipient_keys<'a>(
    doc: &Document,
    recipient_ka_kids: &[&'a str],
) -> Vec<(&'a str, PublicKeyAgreement)> {
    recipient_ka_kids
        .iter()
        .copied()
        .filter_map(|kid| {
            resolve_public_key_agreement(doc, kid)
                .ok()
                .map(|pk| (kid, pk))
        })
        .collect()
}

/// Negotiate the best authcrypt pairing from the cross-product of the
/// sender's usable curves and the recipient's usable key-agreement keys.
///
/// `sender_curves` is the set of curves the sender has a usable secret for
/// (order is irrelevant — selection follows `preference`). `preference` is
/// the active curve-preference policy, most-preferred first; pass
/// [`DEFAULT_CURVE_PREFERENCE`] for the standard policy or a custom slice to
/// force a different order. The earliest curve in `preference` that both
/// sides offer is chosen, and the first recipient key on that curve (in
/// document order) is returned.
///
/// Returns [`KeyNegotiationError::NoCommonCurve`] (naming both offered sets)
/// when no shared curve exists.
pub fn negotiate_authcrypt<'a>(
    sender_curves: &[Curve],
    doc: &Document,
    recipient_ka_kids: &[&'a str],
    preference: &[Curve],
) -> Result<AuthcryptMatch<'a>, KeyNegotiationError> {
    let recipient = resolve_recipient_keys(doc, recipient_ka_kids);

    for &curve in preference {
        if sender_curves.contains(&curve)
            && let Some((kid, pk)) = recipient.iter().find(|(_, pk)| pk.curve() == curve)
        {
            return Ok(AuthcryptMatch {
                curve,
                recipient_kid: kid,
                recipient_pub: pk.clone(),
            });
        }
    }

    Err(KeyNegotiationError::NoCommonCurve {
        sender: dedup_preserve_order(sender_curves.iter().copied()),
        recipient: dedup_preserve_order(recipient.iter().map(|(_, pk)| pk.curve())),
    })
}

/// Select an anoncrypt recipient key using the **same** curve-preference
/// selection as [`negotiate_authcrypt`] — there is simply no sender side to
/// intersect with. The recipient's most-preferred usable curve (per
/// `preference`) wins, and the first key on it (document order) is returned.
/// Keeping the two paths identical avoids a surprising divergence between
/// signed and anonymous encryption over which curve gets used.
pub fn select_anoncrypt_key<'a>(
    doc: &Document,
    recipient_ka_kids: &[&'a str],
    preference: &[Curve],
) -> Result<(&'a str, PublicKeyAgreement), KeyNegotiationError> {
    let recipient = resolve_recipient_keys(doc, recipient_ka_kids);

    for &curve in preference {
        if let Some((kid, pk)) = recipient.iter().find(|(_, pk)| pk.curve() == curve) {
            return Ok((kid, pk.clone()));
        }
    }
    Err(KeyNegotiationError::NoUsableRecipientKey(
        recipient_ka_kids.iter().map(|k| k.to_string()).collect(),
    ))
}

/// Deduplicate curves preserving first-seen order, for stable, readable
/// error messages. Unlike the preference filter, this names *every* offered
/// curve (even ones outside the active preference) so a mismatch error shows
/// the real picture.
fn dedup_preserve_order(curves: impl IntoIterator<Item = Curve>) -> Vec<Curve> {
    let mut out: Vec<Curve> = Vec::new();
    for c in curves {
        if !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_crypto::jose::key_agreement::PrivateKeyAgreement;
    use serde_json::{Value, json};

    // A valid KA verification method, built from a freshly generated key of
    // the given curve and serialised as a `publicKeyJwk` (the shared decoder
    // accepts JWK, so this avoids re-implementing SEC1 encoding in the test).
    fn ka_vm(kid: &str, curve: Curve) -> Value {
        let pub_key = PrivateKeyAgreement::generate(curve).public_key();
        json!({
            "id": kid,
            "type": "JsonWebKey2020",
            "controller": "did:web:example",
            "publicKeyJwk": pub_key.to_jwk(),
        })
    }

    // An Ed25519 *signing* key erroneously listed under keyAgreement: it
    // decodes fine but its multicodec is not a supported KA curve, so
    // resolution rejects it at the codec step (no key parsing needed — 32
    // arbitrary bytes suffice).
    fn ed25519_vm(kid: &str) -> Value {
        json!({
            "id": kid,
            "type": "Multikey",
            "controller": "did:web:example",
            "publicKeyMultibase":
                affinidi_encoding::encode_multikey(affinidi_encoding::ED25519_PUB, &[9u8; 32]),
        })
    }

    // Build a Document whose keyAgreement lists every supplied VM by id.
    fn doc_with(vms: &[Value]) -> Document {
        let kids: Vec<&str> = vms.iter().map(|vm| vm["id"].as_str().unwrap()).collect();
        serde_json::from_value(json!({
            "id": "did:web:example",
            "verificationMethod": vms,
            "keyAgreement": kids,
        }))
        .unwrap()
    }

    // The standard policy, used by most tests.
    const PREF: &[Curve] = &DEFAULT_CURVE_PREFERENCE;

    // Real bug from the PR description: a *valid* key on the wrong curve must
    // be skipped, not just an undecodable codec. Recipient offers [P-256,
    // X25519]; an X25519 sender must select the X25519 key.
    #[test]
    fn authcrypt_skips_valid_wrong_curve_key() {
        let doc = doc_with(&[
            ka_vm("did:web:example#p256", Curve::P256),
            ka_vm("did:web:example#x", Curve::X25519),
        ]);
        let kids = ["did:web:example#p256", "did:web:example#x"];
        let m = negotiate_authcrypt(&[Curve::X25519], &doc, &kids, PREF).unwrap();
        assert_eq!(m.curve, Curve::X25519);
        assert_eq!(m.recipient_kid, "did:web:example#x");
        assert_eq!(m.recipient_pub.curve(), Curve::X25519);
    }

    // The original #355 test scenario: first keyAgreement entry is an
    // Ed25519 signing key (undecodable as KA); the X25519 key after it wins.
    #[test]
    fn authcrypt_skips_undecodable_codec() {
        let doc = doc_with(&[
            ed25519_vm("did:web:example#ed"),
            ka_vm("did:web:example#x", Curve::X25519),
        ]);
        let kids = ["did:web:example#ed", "did:web:example#x"];
        let m = negotiate_authcrypt(&[Curve::X25519], &doc, &kids, PREF).unwrap();
        assert_eq!(m.recipient_kid, "did:web:example#x");
    }

    // Bidirectional negotiation: sender's *first* curve (P-256) has no
    // recipient match, but its second (X25519) does. Must still succeed.
    #[test]
    fn authcrypt_uses_sender_second_curve() {
        let doc = doc_with(&[ka_vm("did:web:example#x", Curve::X25519)]);
        let kids = ["did:web:example#x"];
        // Sender curve list ordered P-256 first to prove order-independence.
        let m = negotiate_authcrypt(&[Curve::P256, Curve::X25519], &doc, &kids, PREF).unwrap();
        assert_eq!(m.curve, Curve::X25519);
        assert_eq!(m.recipient_kid, "did:web:example#x");
    }

    // Multiple valid pairings: both sides offer P-256 and X25519. The default
    // preference (X25519 > P-256) must win regardless of the order keys
    // appear in the document or the sender list.
    #[test]
    fn authcrypt_follows_curve_preference() {
        let doc = doc_with(&[
            ka_vm("did:web:example#p256", Curve::P256),
            ka_vm("did:web:example#x", Curve::X25519),
        ]);
        let kids = ["did:web:example#p256", "did:web:example#x"];
        // P-256 listed first on the sender side; X25519 must still win.
        let m = negotiate_authcrypt(&[Curve::P256, Curve::X25519], &doc, &kids, PREF).unwrap();
        assert_eq!(m.curve, Curve::X25519);
    }

    // Runtime policy override (#2): same doc as above, but a caller forces
    // P-256 first — the override must beat the default X25519-first policy.
    #[test]
    fn authcrypt_honours_custom_preference_override() {
        let doc = doc_with(&[
            ka_vm("did:web:example#p256", Curve::P256),
            ka_vm("did:web:example#x", Curve::X25519),
        ]);
        let kids = ["did:web:example#p256", "did:web:example#x"];
        let fips_first = [Curve::P256, Curve::X25519, Curve::K256];
        let m =
            negotiate_authcrypt(&[Curve::P256, Curve::X25519], &doc, &kids, &fips_first).unwrap();
        assert_eq!(m.curve, Curve::P256);
        assert_eq!(m.recipient_kid, "did:web:example#p256");
    }

    // No shared curve: sender P-256 only, recipient X25519 only. The error
    // must name both offered curve sets.
    #[test]
    fn authcrypt_no_common_curve_names_both_sets() {
        let doc = doc_with(&[ka_vm("did:web:example#x", Curve::X25519)]);
        let kids = ["did:web:example#x"];
        let err = negotiate_authcrypt(&[Curve::P256], &doc, &kids, PREF).unwrap_err();
        match &err {
            KeyNegotiationError::NoCommonCurve { sender, recipient } => {
                assert_eq!(sender, &vec![Curve::P256]);
                assert_eq!(recipient, &vec![Curve::X25519]);
            }
            other => panic!("expected NoCommonCurve, got {other:?}"),
        }
        let msg = err.to_string();
        assert!(msg.contains("P256"), "msg names sender curve: {msg}");
        assert!(msg.contains("X25519"), "msg names recipient curve: {msg}");
    }

    // Anoncrypt: first entry is an undecodable Ed25519 codec; selection must
    // fall through to the usable X25519 key rather than failing on first().
    #[test]
    fn anoncrypt_skips_undecodable_first_key() {
        let doc = doc_with(&[
            ed25519_vm("did:web:example#ed"),
            ka_vm("did:web:example#x", Curve::X25519),
        ]);
        let kids = ["did:web:example#ed", "did:web:example#x"];
        let (kid, pk) = select_anoncrypt_key(&doc, &kids, PREF).unwrap();
        assert_eq!(kid, "did:web:example#x");
        assert_eq!(pk.curve(), Curve::X25519);
    }

    // Anoncrypt now follows the SAME curve preference as authcrypt (#4):
    // recipient lists secp256k1 *first*, X25519 second — anoncrypt must still
    // pick X25519 (most-preferred), not the document-first secp256k1.
    #[test]
    fn anoncrypt_follows_curve_preference() {
        let doc = doc_with(&[
            ka_vm("did:web:example#k", Curve::K256),
            ka_vm("did:web:example#x", Curve::X25519),
        ]);
        let kids = ["did:web:example#k", "did:web:example#x"];
        let (kid, pk) = select_anoncrypt_key(&doc, &kids, PREF).unwrap();
        assert_eq!(kid, "did:web:example#x");
        assert_eq!(pk.curve(), Curve::X25519);
    }

    #[test]
    fn anoncrypt_no_usable_key_lists_tried() {
        let doc = doc_with(&[ed25519_vm("did:web:example#ed")]);
        let kids = ["did:web:example#ed"];
        let err = select_anoncrypt_key(&doc, &kids, PREF).unwrap_err();
        assert!(matches!(err, KeyNegotiationError::NoUsableRecipientKey(_)));
        assert!(err.to_string().contains("did:web:example#ed"));
    }

    // secp256k1 is the least-preferred but still usable curve.
    #[test]
    fn authcrypt_matches_secp256k1() {
        let doc = doc_with(&[ka_vm("did:web:example#k", Curve::K256)]);
        let kids = ["did:web:example#k"];
        let m = negotiate_authcrypt(&[Curve::K256], &doc, &kids, PREF).unwrap();
        assert_eq!(m.curve, Curve::K256);
    }

    // The larger NIST curves negotiate end-to-end through the shared helper
    // (full JWE/wire support lives in affinidi-crypto + the DIDComm layer).
    #[test]
    fn authcrypt_matches_p384_and_p521() {
        for curve in [Curve::P384, Curve::P521] {
            let doc = doc_with(&[ka_vm("did:web:example#ec", curve)]);
            let kids = ["did:web:example#ec"];
            let m = negotiate_authcrypt(&[curve], &doc, &kids, PREF).unwrap();
            assert_eq!(m.curve, curve);
            assert_eq!(m.recipient_pub.curve(), curve);
        }
    }

    // With the default preference, P-256 outranks the larger NIST curves and
    // secp256k1: a recipient offering all of them, to a sender that has all,
    // selects P-256 (after X25519, which isn't offered here).
    #[test]
    fn authcrypt_default_preference_orders_nist_curves() {
        let doc = doc_with(&[
            ka_vm("did:web:example#k", Curve::K256),
            ka_vm("did:web:example#p521", Curve::P521),
            ka_vm("did:web:example#p384", Curve::P384),
            ka_vm("did:web:example#p256", Curve::P256),
        ]);
        let kids = [
            "did:web:example#k",
            "did:web:example#p521",
            "did:web:example#p384",
            "did:web:example#p256",
        ];
        let m = negotiate_authcrypt(
            &[Curve::K256, Curve::P521, Curve::P384, Curve::P256],
            &doc,
            &kids,
            PREF,
        )
        .unwrap();
        assert_eq!(m.curve, Curve::P256);
    }
}
