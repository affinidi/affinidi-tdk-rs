//! Concrete [`MediatorStore`] implementations.
//!
//! Each impl is feature-gated so deployments only compile the backend
//! they actually use:
//! - [`redis_store`] (`redis-backend`): multi-mediator clusters with
//!   cross-process pub/sub. Wraps the existing `Database` + Lua flow.
//! - `fjall_store` (`fjall-backend`): single-node persistence, embedded
//!   LSM. Lands in a later commit.
//! - `memory_store` (`memory-backend`): tests-only, in-process. Lands
//!   in a later commit.
//!
//! [`MediatorStore`]: affinidi_messaging_mediator_common::store::MediatorStore

#[cfg(feature = "redis-backend")]
pub mod redis_store;

#[cfg(feature = "redis-backend")]
pub use redis_store::RedisStore;

#[cfg(feature = "fjall-backend")]
pub mod fjall_store;

#[cfg(feature = "fjall-backend")]
pub use fjall_store::FjallStore;

#[cfg(feature = "memory-backend")]
pub mod memory_store;

#[cfg(feature = "memory-backend")]
pub use memory_store::MemoryStore;

// ─── Cross-backend helpers ──────────────────────────────────────────────────
//
// These helpers are independent of any backend — they live here (not
// in `redis_store.rs`) so non-Redis builds can still call them from
// the OOB discovery handler.

use crate::common::time::unix_timestamp_secs;
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator_common::errors::MediatorError;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

/// Build the absolute `expires_at` for an OOB invitation given the
/// invitation's optional `expires_time` and the configured
/// `oob_invite_ttl`. Mirrors the legacy computation so handlers can
/// produce the same value before calling the trait method.
pub fn oob_expires_at(invite: &Message, oob_invite_ttl: u64) -> u64 {
    let now = unix_timestamp_secs();
    match invite.expires_time {
        Some(expiry) if expiry > now + oob_invite_ttl => now + oob_invite_ttl,
        Some(expiry) => expiry,
        None => now + oob_invite_ttl,
    }
}

/// Encode a DIDComm `Message` to the base64-url form the trait
/// expects. Mirrors the legacy serialisation so callers don't have to
/// know the encoding.
pub fn encode_oob_invite(invite: &Message) -> Result<String, MediatorError> {
    let json = serde_json::to_string(invite).map_err(|err| {
        MediatorError::InternalError(
            19,
            "oob".into(),
            format!("serialize OOB invite failed: {err}"),
        )
    })?;
    Ok(BASE64_URL_SAFE_NO_PAD.encode(json))
}
