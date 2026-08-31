//! The packing seam for messages the **mediator itself** authors.
//!
//! Everything a client sends through the mediator arrives already packed and
//! leaves the same way, so the forwarding processor never needed to encrypt
//! anything — until it has to tell a sender that their forward was abandoned.
//! That report has no client-supplied envelope to reuse: the mediator is the
//! author, and it must pack it under its own DID or the recipient's default
//! receive policy (authcrypt-only since the SDK's `enforce authcrypt messages
//! by default` change) throws it away unread.
//!
//! Packing lives behind a trait rather than in this crate because
//! `mediator-common` deliberately carries no DIDComm, DID-resolver, or
//! secrets-resolver dependency — it is the lean layer that the SDK-flavoured
//! consumers take with `default-features = false`, and the mediator crate that
//! *does* own `pack_encrypted` depends on this one (so calling into it directly
//! would be a dependency cycle). The mediator injects an implementation with
//! [`ForwardingProcessor::with_system_packer`]; a consumer that has no mediator
//! identity to pack with — the standalone `forwarding_processor` binary, whose
//! config is a database plus a forwarding block and nothing else — leaves it
//! unset and gets a loud log instead of an unreadable message.
//!
//! [`ForwardingProcessor::with_system_packer`]:
//!     crate::tasks::forwarding::ForwardingProcessor::with_system_packer

use async_trait::async_trait;
use serde_json::Value;

/// Packs a mediator-authored DIDComm plaintext for one recipient.
///
/// Implementations authcrypt **from the mediator's own DID**: anoncrypt is not
/// an acceptable substitute, because bare `AnoncryptPlaintext` is not in the
/// SDK's default accepted set either — the recipient needs an authenticated
/// sender to bind the message's `from` to.
#[async_trait]
pub trait SystemMessagePacker: Send + Sync {
    /// The mediator's own DID. Callers stamp it as the plaintext's `from`
    /// before packing: the SDK's addressing-consistency check rejects a
    /// message whose authcrypt `skid` does not resolve to the same DID as
    /// `from`, so the two must agree or the report is refused after decryption
    /// rather than before it.
    fn mediator_did(&self) -> &str;

    /// Authcrypt `plaintext` from [`mediator_did`](Self::mediator_did) to
    /// `to_did`, returning the serialized envelope to store.
    ///
    /// `plaintext` is a complete DIDComm plaintext message (`id`, `type`,
    /// `from`, `to`, `body`, …). The error is a human-readable string destined
    /// for an operator log, so it should say *why* packing failed — an
    /// unresolvable recipient and a recipient with no key-agreement key are
    /// different operational problems.
    async fn pack(&self, plaintext: &Value, to_did: &str) -> Result<String, String>;
}
