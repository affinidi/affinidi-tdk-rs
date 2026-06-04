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
pub use affinidi_messaging_mediator_common::store::redis::RedisStore;

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

/// Backend-agnostic auth-flow test harness.
///
/// The Redis path has integration tests covering the full session
/// lifecycle the auth handlers run; Fjall and memory previously only
/// tested session ops in isolation. This generic helper exercises the
/// whole sequence against any [`MediatorStore`] so every backend gets
/// parity — each backend's test module constructs its store and calls
/// [`run_auth_session_flow`](auth_flow_harness::run_auth_session_flow).
// Only the fjall and memory backends call this harness (the Redis path has
// its own integration tests). Gating it to those features keeps it from being
// dead code — and tripping `-D warnings` — under a redis-backend-only build
// such as the coverage job (#351).
#[cfg(all(test, any(feature = "fjall-backend", feature = "memory-backend")))]
pub(crate) mod auth_flow_harness {
    use affinidi_messaging_mediator_common::store::{MediatorStore, Session, SessionState};
    use sha256::digest;

    /// Drive `create_session` → `update_session_authenticated` →
    /// `get_session(new, did)` → refresh-hash rotation → `delete_session`,
    /// mirroring `handlers::authenticate`. Asserts the session's identity
    /// and state survive each transition and that stale session IDs stop
    /// resolving.
    pub(crate) async fn run_auth_session_flow<S: MediatorStore>(store: &S) {
        let did = "did:peer:2.authflow";
        let did_hash = digest(did);
        let old_sid = "challenge-sid-0";
        let new_sid = "auth-sid-0";

        // 1. Challenge issued — a `ChallengeSent` session is created.
        let challenge = Session {
            session_id: old_sid.to_string(),
            challenge: "challenge-nonce".to_string(),
            state: SessionState::ChallengeSent,
            did: did.to_string(),
            did_hash: did_hash.clone(),
            ..Default::default()
        };
        store
            .create_session(&challenge)
            .await
            .expect("create_session");

        let got = store
            .get_session(old_sid, did)
            .await
            .expect("get challenge");
        assert_eq!(got.state, SessionState::ChallengeSent);
        assert_eq!(got.did, did, "did round-trips on the challenge read");

        // 2. Authentication succeeds — promote and rename under a new ID.
        store
            .update_session_authenticated(old_sid, new_sid, did, "refresh-hash-1")
            .await
            .expect("update_session_authenticated");

        let auth = store
            .get_session(new_sid, did)
            .await
            .expect("get authenticated");
        assert_eq!(auth.state, SessionState::Authenticated);
        assert!(auth.authenticated, "authenticated flag set");
        assert_eq!(auth.did, did, "did survives promotion");
        assert_eq!(auth.did_hash, did_hash, "did_hash survives promotion");
        assert_eq!(auth.refresh_token_hash.as_deref(), Some("refresh-hash-1"));

        // The old challenge ID must no longer resolve after the rename.
        assert!(
            store.get_session(old_sid, did).await.is_err(),
            "old challenge session ID gone after rename"
        );

        // 3. Refresh — rotate the refresh-token hash in place.
        store
            .update_refresh_token_hash(new_sid, "refresh-hash-2")
            .await
            .expect("update_refresh_token_hash");
        let rotated = store
            .get_session(new_sid, did)
            .await
            .expect("get after refresh");
        assert_eq!(
            rotated.state,
            SessionState::Authenticated,
            "state survives refresh-hash rotation"
        );
        assert_eq!(rotated.did, did, "did survives refresh-hash rotation");
        assert_eq!(
            rotated.refresh_token_hash.as_deref(),
            Some("refresh-hash-2")
        );

        // 4. Logout — delete the session; it must stop resolving.
        store.delete_session(new_sid).await.expect("delete_session");
        assert!(
            store.get_session(new_sid, did).await.is_err(),
            "session gone after logout"
        );
    }
}
