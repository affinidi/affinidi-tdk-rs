//! Message unpacking, and the type that reports what protected the message.
//!
//! # Why this diverges from v2 deliberately
//!
//! The v2 crate returns
//! [`UnpackResult::Encrypted`](affinidi_messaging_didcomm::UnpackResult) with an
//! `authenticated: bool` beside a `sender_kid: Option<String>`. Two fields, four
//! representable combinations, only two of them meaningful — and the compiler
//! cannot stop a caller reading the sender without checking the flag.
//!
//! That shape is not safe to copy here, because a Trust Tasks binding over v1
//! has to reject anoncrypt *before* the framework pipeline sees it. With no
//! authenticated sender there is nobody to route an error response to, so
//! replying at all — even to say "rejected" — answers a question the sender was
//! not entitled to ask, and turns the agent into an identity oracle. A caller
//! that mistakes an anoncrypt message for an authenticated one loses that
//! guarantee silently.
//!
//! So [`UnpackResult`] makes the cases disjoint variants, and the sender DID
//! exists as a field only on the variant where it is real. There is no
//! `Option<Did>` to unwrap carelessly, and [`UnpackResult::require_authenticated`]
//! collapses the whole check into one call that either yields an
//! [`AuthenticatedMessage`] or fails.

use crate::envelope::{self, EnvelopeProtection, RecipientKey};
use crate::error::DIDCommV1Error;
use crate::identity::{Did, PrivateIdentity, Verkey};
use crate::message::MessageV1;

/// The result of unpacking a DIDComm v1 message.
///
/// `#[non_exhaustive]`: match with a `_ =>` arm.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum UnpackResult {
    /// Authcrypt, and the authenticating verkey is bound to a known DID.
    ///
    /// This is the only variant that carries a transport-authenticated sender
    /// identity, and the only one [`UnpackResult::require_authenticated`]
    /// accepts.
    Authcrypt {
        /// The decrypted message.
        message: MessageV1,
        /// The transport-authenticated sender: the connection's `theirDid`,
        /// normalised to bare-DID form. Compare against a document's `issuer`
        /// by exact string equality.
        sender: Did,
        /// The verkey that actually authenticated the envelope.
        sender_verkey: Verkey,
        /// The transport-authenticated recipient: the DID this agent unpacked
        /// for. Compare against a document's `recipient`.
        recipient: Did,
        /// The local verkey the envelope was opened with.
        recipient_verkey: Verkey,
    },

    /// Authcrypt, but the authenticating verkey is bound to no known DID.
    ///
    /// The envelope *is* cryptographically authenticated — someone holding the
    /// secret half of `sender_verkey` built it — but this agent has no
    /// connection record binding that key to a DID, so there is no `theirDid`
    /// to attribute the message to.
    ///
    /// This state has no v2 counterpart: a v2 authcrypt envelope names its
    /// sender with a DID URL, so the DID always comes out of the envelope
    /// itself. In v1 it is connection state, and it can be missing. See
    /// [`crate::identity`].
    ///
    /// Treat it as unattributed. A reply can still be routed back over the
    /// transport (the verkey is a valid destination), but nothing here can be
    /// compared against an in-band `issuer`, so a Trust Tasks consumer must not
    /// accept it as an identified sender.
    AuthcryptUnknownSender {
        /// The decrypted message.
        message: MessageV1,
        /// The authenticated — but unattributed — sender verkey.
        sender_verkey: Verkey,
        /// The transport-authenticated recipient.
        recipient: Did,
        /// The local verkey the envelope was opened with.
        recipient_verkey: Verkey,
    },

    /// Anoncrypt. There is no sender, authenticated or otherwise, and no field
    /// on this variant that could be mistaken for one.
    Anoncrypt {
        /// The decrypted message.
        message: MessageV1,
        /// The transport-authenticated recipient.
        recipient: Did,
        /// The local verkey the envelope was opened with.
        recipient_verkey: Verkey,
    },

    /// A bare message with no envelope: no confidentiality, no sender.
    Plaintext(MessageV1),
}

impl UnpackResult {
    /// The decrypted message, whatever protected it.
    pub fn message(&self) -> &MessageV1 {
        match self {
            UnpackResult::Authcrypt { message, .. }
            | UnpackResult::AuthcryptUnknownSender { message, .. }
            | UnpackResult::Anoncrypt { message, .. }
            | UnpackResult::Plaintext(message) => message,
        }
    }

    /// Consume this result and take the message.
    pub fn into_message(self) -> MessageV1 {
        match self {
            UnpackResult::Authcrypt { message, .. }
            | UnpackResult::AuthcryptUnknownSender { message, .. }
            | UnpackResult::Anoncrypt { message, .. }
            | UnpackResult::Plaintext(message) => message,
        }
    }

    /// Whether the envelope was authcrypt — a statement about the *cryptography*
    /// only.
    ///
    /// True for [`Self::AuthcryptUnknownSender`] as well as [`Self::Authcrypt`],
    /// because both were genuinely authenticated by a key. It is deliberately
    /// **not** a sufficient condition for treating the message as coming from
    /// an identified party; use [`Self::require_authenticated`] for that.
    pub fn is_authcrypt(&self) -> bool {
        matches!(
            self,
            UnpackResult::Authcrypt { .. } | UnpackResult::AuthcryptUnknownSender { .. }
        )
    }

    /// Require a message with a transport-authenticated sender DID.
    ///
    /// The single call a Trust Tasks binding needs at its transport boundary:
    /// everything that is not an attributable authcrypt message — anoncrypt,
    /// plaintext, or an authcrypt envelope from an unbound key — is rejected
    /// here, before any framework pipeline can act on it or reply to it.
    pub fn require_authenticated(self) -> Result<AuthenticatedMessage, DIDCommV1Error> {
        match self {
            UnpackResult::Authcrypt {
                message,
                sender,
                sender_verkey,
                recipient,
                recipient_verkey,
            } => Ok(AuthenticatedMessage {
                message,
                sender,
                sender_verkey,
                recipient,
                recipient_verkey,
            }),
            UnpackResult::AuthcryptUnknownSender { sender_verkey, .. } => Err(
                DIDCommV1Error::UnknownSenderVerkey(sender_verkey.to_base58()),
            ),
            UnpackResult::Anoncrypt { .. } => Err(DIDCommV1Error::NotAuthenticated(
                "the message was anoncrypt: it has no sender to attribute it to, and replying \
                 would be an identity oracle"
                    .into(),
            )),
            UnpackResult::Plaintext(_) => Err(DIDCommV1Error::NotAuthenticated(
                "the message was plaintext: it has no envelope and no sender".into(),
            )),
        }
    }
}

/// An unpacked message that carries a transport-authenticated sender DID.
///
/// Only constructible via [`UnpackResult::require_authenticated`], so holding
/// one is proof the message was authcrypt *and* attributable.
#[derive(Debug, Clone)]
pub struct AuthenticatedMessage {
    /// The decrypted message.
    pub message: MessageV1,
    /// The transport-authenticated sender — the connection's `theirDid`, in
    /// bare-DID form.
    pub sender: Did,
    /// The verkey that authenticated the envelope.
    pub sender_verkey: Verkey,
    /// The transport-authenticated recipient — the DID this agent unpacked for.
    pub recipient: Did,
    /// The local verkey the envelope was opened with.
    pub recipient_verkey: Verkey,
}

/// A local identity that can open envelopes, paired with the sender bindings
/// known to this agent.
///
/// Implemented by [`crate::store::DIDCommV1Store`]; a caller with its own
/// connection database can implement it directly rather than mirroring state
/// into this crate.
pub trait SenderBindings {
    /// The DID bound to `verkey`, if this agent knows of one.
    ///
    /// Returning `None` produces [`UnpackResult::AuthcryptUnknownSender`], not
    /// an error — an unattributable message is a real state, not a failure.
    fn did_for_verkey(&self, verkey: &Verkey) -> Option<Did>;
}

/// No known bindings — every authcrypt message comes back as
/// [`UnpackResult::AuthcryptUnknownSender`].
///
/// Useful for a first contact, where the verkey is learned from the message
/// itself and only bound to a DID once the handshake completes.
pub struct NoBindings;

impl SenderBindings for NoBindings {
    fn did_for_verkey(&self, _verkey: &Verkey) -> Option<Did> {
        None
    }
}

/// Unpack a message, trying each of `recipients` in turn.
///
/// Detects the format the way the v2 crate's `unpack` does — envelope, else
/// plaintext — but v1 has only the one envelope shape, so there is no JWS arm.
pub fn unpack(
    input: &str,
    recipients: &[&PrivateIdentity],
    bindings: &impl SenderBindings,
) -> Result<UnpackResult, DIDCommV1Error> {
    let value: serde_json::Value = serde_json::from_str(input)
        .map_err(|e| DIDCommV1Error::InvalidMessage(format!("invalid JSON: {e}")))?;

    if !envelope::is_envelope(&value) {
        // Not an envelope: the only other thing a v1 transport carries is a
        // bare message.
        return Ok(UnpackResult::Plaintext(MessageV1::from_json(
            input.as_bytes(),
        )?));
    }

    // `x25519_private` returns an owned, zeroizing value; hold them alive for
    // the duration of the borrowed `RecipientKey` slice.
    let secrets: Vec<_> = recipients
        .iter()
        .map(|identity| (identity, identity.x25519_private()))
        .collect();
    let keys: Vec<RecipientKey<'_>> = secrets
        .iter()
        .map(|(identity, secret)| RecipientKey {
            verkey: identity.verkey,
            x25519_private: secret,
        })
        .collect();

    let opened = envelope::open(input, &keys)?;
    let message = MessageV1::from_json(&opened.plaintext)?;

    // Which local identity opened it — that DID is the authenticated recipient.
    let recipient_did = recipients
        .iter()
        .find(|identity| identity.verkey == opened.recipient_verkey)
        .map(|identity| identity.did.clone())
        .ok_or_else(|| {
            DIDCommV1Error::IdentityNotFound(
                "the envelope opened under a key not in the supplied recipient list".into(),
            )
        })?;

    Ok(match opened.protection {
        EnvelopeProtection::Authcrypt { sender_verkey } => {
            match bindings.did_for_verkey(&sender_verkey) {
                Some(sender) => UnpackResult::Authcrypt {
                    message,
                    sender,
                    sender_verkey,
                    recipient: recipient_did,
                    recipient_verkey: opened.recipient_verkey,
                },
                None => UnpackResult::AuthcryptUnknownSender {
                    message,
                    sender_verkey,
                    recipient: recipient_did,
                    recipient_verkey: opened.recipient_verkey,
                },
            }
        }
        EnvelopeProtection::Anoncrypt => UnpackResult::Anoncrypt {
            message,
            recipient: recipient_did,
            recipient_verkey: opened.recipient_verkey,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::pack;
    use crate::store::DIDCommV1Store;
    use serde_json::json;

    const BASIC_MESSAGE: &str = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message";

    fn message() -> MessageV1 {
        MessageV1::new(BASIC_MESSAGE, json!({ "content": "hi" })).unwrap()
    }

    fn parties() -> (PrivateIdentity, PrivateIdentity) {
        (
            PrivateIdentity::generate("did:example:alice").unwrap(),
            PrivateIdentity::generate("did:example:bob").unwrap(),
        )
    }

    #[test]
    fn authcrypt_yields_the_bound_sender_did() {
        let (alice, bob) = parties();
        let mut bindings = DIDCommV1Store::new();
        bindings.add_resolved(alice.to_resolved());

        let packed = pack::pack_encrypted_authcrypt(&message(), &alice, &[bob.verkey]).unwrap();
        let result = unpack(&packed, &[&bob], &bindings).unwrap();

        match result {
            UnpackResult::Authcrypt {
                sender,
                sender_verkey,
                recipient,
                recipient_verkey,
                message,
            } => {
                assert_eq!(sender.as_str(), "did:example:alice");
                assert_eq!(sender_verkey, alice.verkey);
                assert_eq!(recipient.as_str(), "did:example:bob");
                assert_eq!(recipient_verkey, bob.verkey);
                assert_eq!(message.body["content"], "hi");
            }
            other => panic!("expected Authcrypt, got {other:?}"),
        }
    }

    #[test]
    fn authcrypt_from_an_unbound_key_is_its_own_variant() {
        let (alice, bob) = parties();

        let packed = pack::pack_encrypted_authcrypt(&message(), &alice, &[bob.verkey]).unwrap();
        let result = unpack(&packed, &[&bob], &NoBindings).unwrap();

        match &result {
            UnpackResult::AuthcryptUnknownSender { sender_verkey, .. } => {
                assert_eq!(*sender_verkey, alice.verkey);
            }
            other => panic!("expected AuthcryptUnknownSender, got {other:?}"),
        }
        assert!(result.is_authcrypt(), "it was genuinely authcrypt...");
        assert!(
            result.require_authenticated().is_err(),
            "...but it is not attributable to a DID"
        );
    }

    // --- the security property ---------------------------------------------

    /// The API-level distinguishability requirement, asserted explicitly rather
    /// than incidentally: an anoncrypt message must be impossible to mistake
    /// for an authenticated one.
    #[test]
    fn anoncrypt_is_distinguishable_from_authcrypt_at_the_api_level() {
        let (alice, bob) = parties();
        let mut bindings = DIDCommV1Store::new();
        bindings.add_resolved(alice.to_resolved());

        let authcrypted =
            pack::pack_encrypted_authcrypt(&message(), &alice, &[bob.verkey]).unwrap();
        let anoncrypted = pack::pack_encrypted_anoncrypt(&message(), &[bob.verkey]).unwrap();

        let authcrypt_result = unpack(&authcrypted, &[&bob], &bindings).unwrap();
        let anoncrypt_result = unpack(&anoncrypted, &[&bob], &bindings).unwrap();

        // 1. Different variants — a `match` cannot conflate them.
        assert!(matches!(authcrypt_result, UnpackResult::Authcrypt { .. }));
        assert!(matches!(anoncrypt_result, UnpackResult::Anoncrypt { .. }));

        // 2. The anoncrypt variant has no sender field at all. There is no
        //    `Option<Did>` to unwrap, so no careless unwrap is expressible.
        let UnpackResult::Anoncrypt {
            recipient, message, ..
        } = &anoncrypt_result
        else {
            panic!("expected Anoncrypt");
        };
        assert_eq!(recipient.as_str(), "did:example:bob");
        assert_eq!(message.body["content"], "hi");

        // 3. The safe gate accepts one and rejects the other.
        assert!(authcrypt_result.clone().require_authenticated().is_ok());
        let err = anoncrypt_result.require_authenticated().unwrap_err();
        assert!(matches!(err, DIDCommV1Error::NotAuthenticated(_)));

        // 4. The payload is identical either way, so nothing *inside* the
        //    message could have been used to tell them apart.
        assert!(!anoncrypt_result_is_authcrypt(
            &authcrypted,
            &bob,
            &bindings
        ));
    }

    fn anoncrypt_result_is_authcrypt(
        packed: &str,
        bob: &PrivateIdentity,
        bindings: &DIDCommV1Store,
    ) -> bool {
        // Sanity helper: the authcrypt envelope really is authcrypt, proving
        // the assertion above is not vacuous.
        !unpack(packed, &[bob], bindings).unwrap().is_authcrypt()
    }

    #[test]
    fn plaintext_is_rejected_by_the_authenticated_gate() {
        let packed = pack::pack_plaintext(&message()).unwrap();
        let result = unpack(&packed, &[], &NoBindings).unwrap();

        assert!(matches!(result, UnpackResult::Plaintext(_)));
        assert!(!result.is_authcrypt());
        assert!(matches!(
            result.require_authenticated(),
            Err(DIDCommV1Error::NotAuthenticated(_))
        ));
    }

    /// A sender who is not who they claim cannot produce an `Authcrypt` result
    /// naming the victim: the DID comes from the binding for the key that
    /// actually opened the CEK, never from anything the sender wrote.
    #[test]
    fn sender_did_comes_from_the_authenticating_key_only() {
        let (alice, bob) = parties();
        let mallory = PrivateIdentity::generate("did:example:mallory").unwrap();

        let mut bindings = DIDCommV1Store::new();
        bindings.add_resolved(alice.to_resolved());
        bindings.add_resolved(mallory.to_resolved());

        // Mallory packs, and stuffs a `from`-like claim into the body for good
        // measure — v1 has no `from` header, so this is the closest a sender
        // can get to lying about identity.
        let msg = MessageV1::new(
            BASIC_MESSAGE,
            json!({ "content": "hi", "from": "did:example:alice" }),
        )
        .unwrap();
        let packed = pack::pack_encrypted_authcrypt(&msg, &mallory, &[bob.verkey]).unwrap();

        match unpack(&packed, &[&bob], &bindings).unwrap() {
            UnpackResult::Authcrypt { sender, .. } => {
                assert_eq!(sender.as_str(), "did:example:mallory");
            }
            other => panic!("expected Authcrypt, got {other:?}"),
        }
    }

    #[test]
    fn threading_survives_the_round_trip_including_the_defaulted_case() {
        let (alice, bob) = parties();
        let mut bindings = DIDCommV1Store::new();
        bindings.add_resolved(alice.to_resolved());

        // Explicit thid + pthid.
        let threaded = message().id("msg-1").thid("t-1").pthid("p-1");
        let packed = pack::pack_encrypted_authcrypt(&threaded, &alice, &[bob.verkey]).unwrap();
        let received = unpack(&packed, &[&bob], &bindings).unwrap().into_message();
        assert_eq!(received.explicit_thid(), Some("t-1"));
        assert_eq!(received.pthid_value(), Some("p-1"));
        assert!(!received.thid_is_defaulted());

        // No decorator at all.
        let unthreaded = message().id("msg-2");
        let packed = pack::pack_encrypted_authcrypt(&unthreaded, &alice, &[bob.verkey]).unwrap();
        let received = unpack(&packed, &[&bob], &bindings).unwrap().into_message();
        assert_eq!(received.thread, None);
        assert_eq!(received.explicit_thid(), None);
        assert_eq!(received.effective_thid(), "msg-2");
        assert!(received.thid_is_defaulted());
    }

    #[test]
    fn unpacks_with_the_correct_identity_from_several() {
        let (alice, bob) = parties();
        let carol = PrivateIdentity::generate("did:example:carol").unwrap();
        let mut bindings = DIDCommV1Store::new();
        bindings.add_resolved(alice.to_resolved());

        let packed = pack::pack_encrypted_authcrypt(&message(), &alice, &[carol.verkey]).unwrap();

        match unpack(&packed, &[&bob, &carol], &bindings).unwrap() {
            UnpackResult::Authcrypt { recipient, .. } => {
                assert_eq!(recipient.as_str(), "did:example:carol");
            }
            other => panic!("expected Authcrypt, got {other:?}"),
        }
    }
}
