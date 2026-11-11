use std::sync::Arc;

use affinidi_messaging_didcomm::UnpackMetadata;
use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};

/// Per-message context passed to handlers and middleware.
///
/// Cloning is cheap — all fields are either small strings or `Arc`-wrapped.
/// `sender_did` is the DID that authenticated the message (see
/// [`authenticated_sender_did`]), never the plaintext `from`; `None` when
/// nothing authenticated it.
#[derive(Clone)]
pub struct HandlerContext {
    pub listener_id: String,
    pub atm: ATM,
    pub profile: Arc<ATMProfile>,
    pub sender_did: Option<String>,
    pub message_id: String,
    pub thread_id: String,
    pub parent_thread_id: Option<String>,
}

#[cfg(test)]
pub(crate) async fn test_context() -> HandlerContext {
    use affinidi_messaging_sdk::config::ATMConfig;
    use affinidi_tdk_common::TDKSharedState;
    use affinidi_tdk_common::config::TDKConfig;

    let tdk = TDKSharedState::new(TDKConfig::headless().expect("headless TDK config"))
        .await
        .expect("TDK shared state");
    let atm = ATM::new(
        ATMConfig::builder().build().expect("ATM config"),
        std::sync::Arc::new(tdk),
    )
    .await
    .expect("ATM");
    let profile = ATMProfile::new(&atm, None, "did:example:service".into(), None)
        .await
        .expect("profile");
    HandlerContext {
        listener_id: "test".into(),
        atm,
        profile: Arc::new(profile),
        sender_did: Some("did:example:peer".into()),
        message_id: "msg-1".into(),
        thread_id: "msg-1".into(),
        parent_thread_id: None,
    }
}

/// The DID that authenticated a message: its verified JWS signer, else its
/// authcrypt sender. `None` when the message is not authenticated, or when the
/// signer and the authcrypt sender are different DIDs.
pub fn authenticated_sender_did(meta: &UnpackMetadata) -> Option<String> {
    fn key_did(kid: &str) -> Option<&str> {
        kid.split_once('#')
            .filter(|(did, fragment)| !did.is_empty() && !fragment.is_empty())
            .map(|(did, _)| did)
    }

    let signer = match meta.sign_from.as_deref() {
        Some(kid) => Some(key_did(kid)?),
        None => None,
    };
    let encrypter = match meta.encrypted_from_kid.as_deref() {
        Some(kid) if meta.authenticated => Some(key_did(kid)?),
        _ => None,
    };
    match (signer, encrypter) {
        (Some(signer), Some(encrypter)) if signer != encrypter => None,
        (signer, encrypter) => signer.or(encrypter).map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(
        authenticated: bool,
        encrypted_from: Option<&str>,
        sign_from: Option<&str>,
    ) -> UnpackMetadata {
        UnpackMetadata {
            authenticated,
            encrypted_from_kid: encrypted_from.map(str::to_string),
            sign_from: sign_from.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn signer_is_the_sender() {
        let meta = meta(false, None, Some("did:example:alice#key-1"));
        assert_eq!(
            authenticated_sender_did(&meta).as_deref(),
            Some("did:example:alice")
        );
    }

    #[test]
    fn authcrypt_sender_is_the_sender() {
        let meta = meta(true, Some("did:example:alice#key-2"), None);
        assert_eq!(
            authenticated_sender_did(&meta).as_deref(),
            Some("did:example:alice")
        );
    }

    #[test]
    fn unauthenticated_encrypter_is_not_a_sender() {
        let meta = meta(false, Some("did:example:alice#key-2"), None);
        assert_eq!(authenticated_sender_did(&meta), None);
    }

    #[test]
    fn signer_and_encrypter_disagreeing_is_no_sender() {
        let meta = meta(
            true,
            Some("did:example:mallory#key-2"),
            Some("did:example:alice#key-1"),
        );
        assert_eq!(authenticated_sender_did(&meta), None);
    }

    #[test]
    fn key_id_without_fragment_is_no_sender() {
        assert_eq!(
            authenticated_sender_did(&meta(true, Some("did:example:alice"), None)),
            None
        );
        assert_eq!(
            authenticated_sender_did(&meta(false, None, Some("did:example:alice"))),
            None
        );
    }
}
