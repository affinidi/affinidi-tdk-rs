//! Identity types for DIDComm v1.
//!
//! Mirrors [`affinidi_messaging_didcomm::identity`] — [`PrivateIdentity`],
//! [`ResolvedIdentity`], [`Mediator`], `generate` / `to_resolved` — so code
//! written against one reads the same as code written against the other. The
//! divergences below are protocol, not preference.
//!
//! # A v1 envelope contains no DID
//!
//! This is the single most consequential difference between the two versions,
//! and it shapes everything else in this crate.
//!
//! A v2.1 authcrypt envelope names its sender with a `skid` that is a **DID
//! URL** (`did:example:alice#key-2`). Decrypting it therefore yields the
//! sender's DID directly, and `affinidi-messaging-sdk` can go straight from
//! envelope to DID document.
//!
//! A v1 authcrypt envelope names its sender with a **bare base58 Ed25519
//! verkey** (`GJ1SzoWzavQYfNL9XkaJdrQejfztN4Xqdsi…`). There is no DID anywhere
//! in the envelope, in any header, at any layer. The verkey -> DID binding is
//! *connection state* — in Aries it is the `theirDid` on the connection record,
//! established during the connection/DID-exchange handshake and stored by the
//! agent.
//!
//! So this crate cannot derive an authenticated sender DID on its own. It must
//! be told the binding ([`ResolvedIdentity`], registered in
//! [`crate::store::DIDCommV1Store`]), and when it has not been told,
//! [`crate::UnpackResult`] says so in its own variant rather than inventing a
//! DID or handing back a plausible-looking `None`.
//!
//! # Consequences for the Trust Tasks binding
//!
//! [`Did`] normalises to bare-DID form (no fragment), because the Trust Tasks
//! framework compares the transport identity against a document's `issuer` /
//! `recipient` by **exact string equality**. Two v1-specific hazards remain,
//! and neither can be fixed inside this crate:
//!
//! 1. **Unqualified DIDs.** Aries v1 predates DID-qualified identifiers, and
//!    live connections routinely carry a bare 22-character base58 NYM
//!    (`WgWxqztrNooG92RXvxSTWv`) where a v2 stack would carry
//!    `did:sov:WgWxqztrNooG92RXvxSTWv`. Those are the same identity and
//!    different strings. [`Did`] accepts both and reports which it has via
//!    [`Did::is_qualified`]; it deliberately does **not** guess a method
//!    prefix, because guessing wrong silently mis-attributes a message.
//! 2. **`did:peer` numalgo drift.** A v1 connection may record `theirDid` in a
//!    different `did:peer` numalgo than the Trust Task document uses.
//!
//! Both mean the binding specification has to state the canonical form it
//! compares against, and where the conversion happens. See the crate-level
//! docs.

use std::fmt;

use affinidi_crypto::did_key::ed25519_pub_to_x25519_bytes;
use affinidi_crypto::ed25519::ed25519_private_to_x25519;
use zeroize::Zeroizing;

use crate::error::DIDCommV1Error;

/// A bare DID, normalised for exact string comparison.
///
/// Construction strips any DID-URL suffix — fragment, path, or query — so that
/// `did:example:alice#key-1` and `did:example:alice` compare equal. The
/// method-specific identifier is **not** case-folded: DID syntax makes it
/// case-sensitive, and lowercasing a `did:key` or a base58 NYM would change
/// which identity it names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Did(String);

impl Did {
    /// Normalise a DID or DID URL to its bare DID form.
    ///
    /// Accepts an unqualified Aries identifier (no `did:` prefix) as well as a
    /// qualified DID — see the [module docs](self) for why refusing the former
    /// would break real v1 interop.
    pub fn parse(did_url: &str) -> Result<Self, DIDCommV1Error> {
        let trimmed = did_url.trim();
        // Cut at the first DID-URL delimiter. `;` is deliberately not a
        // delimiter here: matrix parameters are legacy DID-URL syntax that no
        // v1 agent emits, and `;` appears legitimately inside the *message
        // type* URIs v1 uses (`did:sov:BzCbs…;spec/basicmessage/1.0/message`),
        // so treating it as one invites truncating a value that was never a DID.
        let bare = trimmed
            .split(['#', '?', '/'])
            .next()
            .unwrap_or(trimmed)
            .trim();

        if bare.is_empty() {
            return Err(DIDCommV1Error::InvalidIdentifier(
                "a DID cannot be empty".into(),
            ));
        }
        Ok(Self(bare.to_string()))
    }

    /// The normalised DID string, as compared by the Trust Tasks framework.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this identifier carries a `did:` method prefix.
    ///
    /// `false` means an unqualified Aries identifier, which will not compare
    /// equal to a qualified `issuer` in a Trust Task document even when it
    /// names the same party. See the [module docs](self).
    pub fn is_qualified(&self) -> bool {
        self.0.starts_with("did:")
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<Did> for String {
    fn from(did: Did) -> Self {
        did.0
    }
}

/// An Ed25519 public key, the v1 key identifier.
///
/// Displays and serializes as base58btc, which is the form that appears in an
/// envelope's `kid` header and in Aries connection records. The v2 counterpart
/// is a DID-URL `kid` string; see the [module docs](self).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Verkey([u8; 32]);

impl Verkey {
    /// Wrap raw Ed25519 public key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Decode a base58btc verkey, as it appears in an envelope `kid`.
    pub fn from_base58(encoded: &str) -> Result<Self, DIDCommV1Error> {
        let decoded = bs58::decode(encoded.trim())
            .into_vec()
            .map_err(|e| DIDCommV1Error::InvalidKey(format!("verkey is not valid base58: {e}")))?;
        let bytes: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
            DIDCommV1Error::InvalidKey(format!("verkey is {} bytes, expected 32", decoded.len()))
        })?;
        Ok(Self(bytes))
    }

    /// Decode a verkey written **either** as bare base58btc **or** as a
    /// `did:key:z6Mk…`.
    ///
    /// Both spellings appear on the wire for the same key, and which one a peer
    /// sends is its configuration. Aries RFC 0211 specifies `did:key` for
    /// `recipient_key` and `routing_keys`, but base58 predates it and is still
    /// widely sent; Credo normalises with `didKeyToVerkey` on receipt and picks
    /// its own outbound form from `useDidKeyInProtocols`.
    ///
    /// Comparing the two spellings with `==` silently drops half the ecosystem,
    /// in the same way [`crate::message::message_type`] describes for message
    /// type URIs. Parse with this, then compare [`Verkey`]s.
    pub fn parse(encoded: &str) -> Result<Self, DIDCommV1Error> {
        let encoded = encoded.trim();
        if encoded.starts_with("did:key:") {
            return Self::from_did_key(encoded);
        }
        Self::from_base58(encoded)
    }

    /// Decode a `did:key:z6Mk…` Ed25519 identifier.
    pub fn from_did_key(did_key: &str) -> Result<Self, DIDCommV1Error> {
        Ok(Self(affinidi_crypto::did_key::did_key_to_ed25519_pub(
            did_key.trim(),
        )?))
    }

    /// This verkey as a `did:key:z6Mk…` identifier — the RFC 0211 spelling.
    pub fn to_did_key(&self) -> String {
        affinidi_crypto::did_key::ed25519_pub_to_did_key(&self.0)
    }

    /// The raw Ed25519 public key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The base58btc encoding used on the wire.
    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }

    /// The X25519 public key this verkey converts to for key agreement.
    ///
    /// v1 does key agreement on the Montgomery form of the Ed25519 key rather
    /// than publishing a separate key-agreement key, so there is no v1
    /// equivalent of the v2 `key_agreement_kid` / `key_agreement_public` split.
    pub fn to_x25519(&self) -> Result<[u8; 32], DIDCommV1Error> {
        Ok(ed25519_pub_to_x25519_bytes(&self.0)?)
    }
}

impl fmt::Display for Verkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base58())
    }
}

/// A local identity with the private key material for v1 operations.
///
/// The v2 counterpart holds a key-agreement key *and* a separate signing key.
/// v1 holds one Ed25519 key and derives the key-agreement key from it, so
/// there is a single `signing_private` here and no curve parameter.
pub struct PrivateIdentity {
    /// The DID this key belongs to — the local end of the connection.
    pub did: Did,
    /// The Ed25519 public key. Appears as `kid` in envelopes addressed to us.
    pub verkey: Verkey,
    /// The Ed25519 private key seed.
    signing_private: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for PrivateIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateIdentity")
            .field("did", &self.did)
            .field("verkey", &self.verkey)
            .field("signing_private", &"[REDACTED]")
            .finish()
    }
}

impl PrivateIdentity {
    /// Create an identity with a freshly generated Ed25519 key.
    ///
    /// The v2 crate also offers `generate_with_curve`; v1 has no curve agility
    /// (see [`crate::crypto`]), so there is deliberately no counterpart.
    pub fn generate(did: &str) -> Result<Self, DIDCommV1Error> {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_10::rng());
        Self::from_signing_key(did, &signing_key.to_bytes())
    }

    /// Build an identity from an existing Ed25519 private key seed — the usual
    /// path when key material comes from a wallet rather than being generated.
    pub fn from_signing_key(did: &str, signing_private: &[u8; 32]) -> Result<Self, DIDCommV1Error> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(signing_private);
        Ok(Self {
            did: Did::parse(did)?,
            verkey: Verkey::from_bytes(signing_key.verifying_key().to_bytes()),
            signing_private: Zeroizing::new(*signing_private),
        })
    }

    /// The X25519 private key for key agreement, derived from the Ed25519 seed.
    pub fn x25519_private(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(ed25519_private_to_x25519(&self.signing_private))
    }

    /// The X25519 public key matching [`Self::x25519_private`].
    pub fn x25519_public(&self) -> Result<[u8; 32], DIDCommV1Error> {
        self.verkey.to_x25519()
    }

    /// The public half of this identity, as a peer would hold it.
    pub fn to_resolved(&self) -> ResolvedIdentity {
        ResolvedIdentity {
            did: self.did.clone(),
            verkey: self.verkey,
        }
    }
}

/// A remote party's public identity: the DID *and* the verkey it is bound to.
///
/// Both halves are required. The verkey alone is what a v1 envelope
/// authenticates; the DID alone is what the Trust Tasks framework compares
/// against. Registering a [`ResolvedIdentity`] in
/// [`crate::store::DIDCommV1Store`] is what lets this crate turn the former
/// into the latter — see the [module docs](self).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIdentity {
    /// The peer's DID — an Aries connection's `theirDid`.
    pub did: Did,
    /// The Ed25519 verkey that authenticates this peer's authcrypt envelopes.
    pub verkey: Verkey,
}

impl ResolvedIdentity {
    /// Bind a DID to a verkey.
    pub fn new(did: &str, verkey: Verkey) -> Result<Self, DIDCommV1Error> {
        Ok(Self {
            did: Did::parse(did)?,
            verkey,
        })
    }

    /// The X25519 public key used to encrypt to this peer.
    pub fn x25519_public(&self) -> Result<[u8; 32], DIDCommV1Error> {
        self.verkey.to_x25519()
    }
}

/// A mediator / routing key that messages are forwarded through.
///
/// v1 forwarding wraps the inner envelope in an anoncrypt envelope addressed to
/// the routing key, exactly as the v2 crate's [`Mediator`] does — but a v1
/// routing key is a verkey, not a DID URL.
///
/// [`Mediator`]: affinidi_messaging_didcomm::identity::Mediator
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mediator {
    /// The mediator's routing verkey.
    pub verkey: Verkey,
}

impl Mediator {
    /// Create a mediator route for a routing verkey.
    pub fn new(verkey: Verkey) -> Self {
        Self { verkey }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_strips_the_key_fragment() {
        let did = Did::parse("did:example:alice#key-1").unwrap();
        assert_eq!(did.as_str(), "did:example:alice");
        assert_eq!(did, Did::parse("did:example:alice").unwrap());
    }

    #[test]
    fn did_strips_path_and_query_but_not_semicolons() {
        assert_eq!(
            Did::parse("did:example:alice/path?x=1#frag")
                .unwrap()
                .as_str(),
            "did:example:alice"
        );
        // A `;` is not a DID-URL delimiter for our purposes — v1 message type
        // URIs contain one, and truncating there would corrupt a value that was
        // never a DID in the first place.
        assert_eq!(
            Did::parse("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec")
                .unwrap()
                .as_str(),
            "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec"
        );
    }

    #[test]
    fn did_is_case_sensitive() {
        assert_ne!(
            Did::parse("did:key:z6MkABC").unwrap(),
            Did::parse("did:key:z6mkabc").unwrap(),
            "lowercasing a DID changes which identity it names"
        );
    }

    #[test]
    fn did_accepts_unqualified_aries_identifiers() {
        let did = Did::parse("WgWxqztrNooG92RXvxSTWv").unwrap();
        assert_eq!(did.as_str(), "WgWxqztrNooG92RXvxSTWv");
        assert!(
            !did.is_qualified(),
            "callers need to be able to detect the unqualified form"
        );
        assert!(
            Did::parse("did:sov:WgWxqztrNooG92RXvxSTWv")
                .unwrap()
                .is_qualified()
        );
    }

    #[test]
    fn did_rejects_empty() {
        assert!(Did::parse("").is_err());
        assert!(Did::parse("   ").is_err());
        assert!(Did::parse("#frag").is_err());
    }

    #[test]
    fn verkey_base58_roundtrip() {
        let verkey = Verkey::from_bytes([7u8; 32]);
        let encoded = verkey.to_base58();
        assert_eq!(Verkey::from_base58(&encoded).unwrap(), verkey);
    }

    /// The property that keeps `recipient_key` / `routing_keys` interoperable:
    /// both spellings of one key must parse to the same [`Verkey`].
    #[test]
    fn verkey_parses_both_did_key_and_base58() {
        let verkey = Verkey::from_bytes([9u8; 32]);
        let base58 = verkey.to_base58();
        let did_key = verkey.to_did_key();

        assert!(did_key.starts_with("did:key:z6Mk"));
        assert_ne!(
            base58, did_key,
            "the two spellings are different strings..."
        );
        assert_eq!(Verkey::parse(&base58).unwrap(), verkey);
        assert_eq!(
            Verkey::parse(&did_key).unwrap(),
            verkey,
            "...but must name the same key"
        );
        assert_eq!(Verkey::from_did_key(&did_key).unwrap(), verkey);
    }

    #[test]
    fn verkey_parse_tolerates_surrounding_whitespace() {
        let verkey = Verkey::from_bytes([3u8; 32]);
        assert_eq!(
            Verkey::parse(&format!("  {}\n", verkey.to_base58())).unwrap(),
            verkey
        );
        assert_eq!(
            Verkey::parse(&format!(" {} ", verkey.to_did_key())).unwrap(),
            verkey
        );
    }

    #[test]
    fn verkey_parse_rejects_a_non_ed25519_did_key() {
        // A `did:key` for some other curve must not be silently accepted as an
        // Ed25519 verkey.
        assert!(
            Verkey::from_did_key("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme")
                .is_err()
        );
        assert!(Verkey::parse("did:key:not-a-key").is_err());
    }

    #[test]
    fn verkey_rejects_wrong_length_and_bad_base58() {
        assert!(Verkey::from_base58(&bs58::encode([1u8; 31]).into_string()).is_err());
        assert!(Verkey::from_base58("not base58 0OIl").is_err());
    }

    /// The X25519 key derived from the private seed must match the one derived
    /// from the published verkey — if these disagreed, we could encrypt to a
    /// peer but never decrypt what they sent back.
    #[test]
    fn derived_x25519_keys_agree() {
        use x25519_dalek::{PublicKey, StaticSecret};

        let identity = PrivateIdentity::generate("did:example:alice").unwrap();
        let from_private =
            PublicKey::from(&StaticSecret::from(*identity.x25519_private())).to_bytes();
        let from_verkey = identity.x25519_public().unwrap();
        assert_eq!(from_private, from_verkey);
    }

    #[test]
    fn to_resolved_carries_did_and_verkey() {
        let identity = PrivateIdentity::generate("did:example:alice#key-1").unwrap();
        let resolved = identity.to_resolved();
        assert_eq!(resolved.did.as_str(), "did:example:alice");
        assert_eq!(resolved.verkey, identity.verkey);
    }

    #[test]
    fn private_identity_debug_redacts_the_key() {
        let identity = PrivateIdentity::generate("did:example:alice").unwrap();
        let rendered = format!("{identity:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains(&format!("{:?}", identity.signing_private.as_ref())));
    }
}
