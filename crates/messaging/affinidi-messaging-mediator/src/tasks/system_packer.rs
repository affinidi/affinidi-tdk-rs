//! The mediator's implementation of the forwarding processor's packing seam.
//!
//! [`ForwardingProcessor`] lives in `mediator-common`, which has no DIDComm,
//! resolver, or secrets dependency of its own, so it asks its host to encrypt
//! anything the mediator authors. This is that host side: the same
//! [`didcomm_compat::pack_encrypted`] that every protocol reply goes through
//! (see `messages::store`, `messages::protocols::routing::rewrap_for_relay`),
//! reached through the [`SystemMessagePacker`] trait instead of a direct call
//! — `mediator-common` is a dependency of this crate, so the call has to go the
//! other way.
//!
//! [`ForwardingProcessor`]:
//!     affinidi_messaging_mediator_common::tasks::forwarding::ForwardingProcessor
//! [`didcomm_compat::pack_encrypted`]: crate::didcomm_compat::pack_encrypted

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::tasks::forwarding::SystemMessagePacker;
use affinidi_secrets_resolver::ThreadedSecretsResolver;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

/// Authcrypts mediator-authored messages under the mediator's own DID.
pub struct MediatorSystemPacker {
    mediator_did: String,
    did_resolver: DIDCacheClient,
    secrets: Arc<ThreadedSecretsResolver>,
}

impl MediatorSystemPacker {
    /// Build a packer from the mediator's identity and its operating secrets.
    ///
    /// `did_resolver` should be the resolver that has already preloaded the
    /// mediator's own DID document: authcrypt resolves *both* ends, and a
    /// `did:web`/`did:webvh` mediator may not be able to reach its own document
    /// over the network from inside its deployment.
    pub fn new(
        mediator_did: String,
        did_resolver: DIDCacheClient,
        secrets: Arc<ThreadedSecretsResolver>,
    ) -> Self {
        Self {
            mediator_did,
            did_resolver,
            secrets,
        }
    }
}

#[async_trait]
impl SystemMessagePacker for MediatorSystemPacker {
    fn mediator_did(&self) -> &str {
        &self.mediator_did
    }

    async fn pack(&self, plaintext: &Value, to_did: &str) -> Result<String, String> {
        // A DIDComm plaintext *is* a `Message`, so this is a shape check rather
        // than a conversion: it fails only if the caller built something that
        // isn't one, which would have produced an undecodable envelope anyway.
        let message: Message = serde_json::from_value(plaintext.clone())
            .map_err(|e| format!("not a DIDComm plaintext message: {e}"))?;

        crate::didcomm_compat::pack_encrypted(
            &message,
            to_did,
            Some(&self.mediator_did),
            &self.did_resolver,
            &*self.secrets,
        )
        .await
        .map(|(packed, _)| packed)
    }
}
