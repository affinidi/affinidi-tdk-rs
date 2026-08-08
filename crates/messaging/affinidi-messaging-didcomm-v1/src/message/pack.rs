//! Message packing.
//!
//! Mirrors [`affinidi_messaging_didcomm::message::pack`]. The v2 crate also
//! offers `pack_signed` / `pack_signed_multi`; **v1 has no signed-envelope
//! equivalent**. RFC 0019 defines exactly two protections, authcrypt and
//! anoncrypt, so there is no v1 counterpart to v2.1's sign-then-encrypt
//! non-repudiation path — a v1 message is authenticated or it is not, and it is
//! never non-repudiable at the transport layer.

use crate::envelope;
use crate::error::DIDCommV1Error;
use crate::identity::{PrivateIdentity, Verkey};
use crate::message::MessageV1;

/// Pack a message as authcrypt — the sender's key authenticates the envelope.
///
/// Mirrors `pack_encrypted_authcrypt` on the v2 crate. The v2 signature takes
/// `(sender_kid, sender_private, &[(recipient_kid, recipient_pub)])`; here both
/// key identifier and key material are the same Ed25519 verkey, so the
/// parameters collapse accordingly.
pub fn pack_encrypted_authcrypt(
    msg: &MessageV1,
    sender: &PrivateIdentity,
    recipients: &[Verkey],
) -> Result<String, DIDCommV1Error> {
    if recipients.is_empty() {
        return Err(DIDCommV1Error::InvalidMessage(
            "an envelope needs at least one recipient".into(),
        ));
    }
    let plaintext = msg.to_json()?;
    envelope::pack_authcrypt(
        &plaintext,
        &sender.verkey,
        &sender.x25519_private(),
        recipients,
    )
}

/// Pack a message as anoncrypt — no sender information at all.
///
/// Mirrors `pack_encrypted_anoncrypt` on the v2 crate.
///
/// # When not to use this
///
/// The recipient cannot attribute the result, so it cannot reply to it or
/// report an error against it. Use anoncrypt for messages that genuinely need
/// no response — a forward wrapper, an out-of-band invitation — and authcrypt
/// for everything that expects one.
pub fn pack_encrypted_anoncrypt(
    msg: &MessageV1,
    recipients: &[Verkey],
) -> Result<String, DIDCommV1Error> {
    if recipients.is_empty() {
        return Err(DIDCommV1Error::InvalidMessage(
            "an envelope needs at least one recipient".into(),
        ));
    }
    let plaintext = msg.to_json()?;
    envelope::pack_anoncrypt(&plaintext, recipients)
}

/// Serialize a message without any envelope.
///
/// Mirrors `pack_plaintext` on the v2 crate. The output has no confidentiality
/// and no authenticated sender; [`crate::UnpackResult::Plaintext`] is what a
/// receiver gets back for it.
pub fn pack_plaintext(msg: &MessageV1) -> Result<String, DIDCommV1Error> {
    serde_json::to_string(msg).map_err(|e| DIDCommV1Error::Serialization(format!("plaintext: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const BASIC_MESSAGE: &str = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message";

    fn message() -> MessageV1 {
        MessageV1::new(BASIC_MESSAGE, json!({ "content": "hi" })).unwrap()
    }

    #[test]
    fn rejects_an_empty_recipient_list() {
        let alice = PrivateIdentity::generate("did:example:alice").unwrap();
        assert!(pack_encrypted_authcrypt(&message(), &alice, &[]).is_err());
        assert!(pack_encrypted_anoncrypt(&message(), &[]).is_err());
    }

    #[test]
    fn plaintext_is_the_bare_message_json() {
        let msg = message().id("msg-1");
        let packed = pack_plaintext(&msg).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&packed).unwrap();
        assert_eq!(parsed["@id"], "msg-1");
        assert_eq!(parsed["content"], "hi");
    }
}
