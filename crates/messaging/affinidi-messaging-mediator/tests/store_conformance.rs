//! Backend-conformance suite for `MediatorStore` (mediator T15).
//!
//! Fjall and Redis must stay *semantically* aligned, but they can't share
//! code — the Redis logic lives in Lua. This suite expresses one set of
//! backend-agnostic semantic checks against an `Arc<dyn MediatorStore>` and
//! instantiates them against every in-process backend compiled in, so a
//! divergence between two independent implementations surfaces as a named
//! failing test (e.g. `fjall::message_store_and_counters`).
//!
//! Run it with the in-process backends enabled:
//! ```text
//! cargo test -p affinidi-messaging-mediator \
//!   --no-default-features --features didcomm,memory-backend,fjall-backend \
//!   --test store_conformance
//! ```
//!
//! Coverage so far (against **Memory** and **Fjall**):
//! account lifecycle; ACL set/get; message store + inbox counters;
//! forward-queue consumer-group claim/ack, delete, and autoclaim (crashed-
//! consumer recovery); session put/get/delete lifecycle; access-list
//! add/count/remove/clear. Memory and Fjall agree on all of these — no
//! divergence found between the two independent implementations.
//!
//! Planned next increments (tracked under mediator T15): session-expiry /
//! TTL-sweep semantics and access-list *mode* (allow-list vs deny-list)
//! evaluation, plus a **`REDIS_URL`-gated** backend in a Redis CI job. Redis
//! needs per-test isolation (the in-process backends get a fresh store per
//! test; a shared Redis needs a unique key prefix or `FLUSHDB`), so it lands
//! with that plumbing rather than as an unverifiable stub here.

#![cfg(any(feature = "memory-backend", feature = "fjall-backend"))]

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_mediator_common::store::MediatorStore;
use affinidi_messaging_mediator_common::store::types::{ForwardQueueEntry, Session};
use affinidi_messaging_sdk::protocols::mediator::{
    accounts::{Account, AccountType},
    acls::MediatorACLSet,
};

/// Far-future expiry so stored messages don't lapse mid-test.
const NEVER: u64 = 9_999_999_999;

fn allow_all() -> MediatorACLSet {
    MediatorACLSet::from_string_ruleset("ALLOW_ALL").expect("ALLOW_ALL ruleset")
}

/// An admin session, used as the authority for account/message removal.
fn admin_session(admin_did_hash: &str) -> Session {
    Session {
        did_hash: admin_did_hash.to_string(),
        account_type: AccountType::RootAdmin,
        ..Default::default()
    }
}

// ─── Conformance checks (backend-agnostic) ──────────────────────────────────

/// Account create → exists → fetch → remove → gone.
async fn check_account_lifecycle(store: Arc<dyn MediatorStore>) {
    let did = "did_hash_account_lifecycle";

    assert!(
        !store.account_exists(did).await.expect("account_exists"),
        "account must not exist before it is added"
    );

    let added: Account = store
        .account_add(did, &allow_all(), None)
        .await
        .expect("account_add");
    assert_eq!(
        added.did_hash, did,
        "account_add returns the created account"
    );

    assert!(
        store.account_exists(did).await.expect("account_exists"),
        "account must exist after add"
    );
    let fetched = store
        .account_get(did)
        .await
        .expect("account_get")
        .expect("account present after add");
    assert_eq!(fetched.did_hash, did);

    let removed = store
        .account_remove(&admin_session("admin_hash"), did)
        .await
        .expect("account_remove");
    assert!(
        removed,
        "account_remove reports success for an existing account"
    );
    assert!(
        !store.account_exists(did).await.expect("account_exists"),
        "account must be gone after remove"
    );
}

/// Setting a DID's ACL is read back verbatim.
async fn check_acl_set_get_roundtrip(store: Arc<dyn MediatorStore>) {
    let did = "did_hash_acl_roundtrip";
    store
        .account_add(did, &MediatorACLSet::default(), None)
        .await
        .expect("account_add");

    let acls = allow_all();
    let written = store.set_did_acl(did, &acls).await.expect("set_did_acl");
    assert_eq!(
        written.to_u64(),
        acls.to_u64(),
        "set_did_acl returns the value it stored"
    );

    let read = store
        .get_did_acl(did)
        .await
        .expect("get_did_acl")
        .expect("ACL present after set");
    assert_eq!(
        read.to_u64(),
        acls.to_u64(),
        "get_did_acl reads back exactly what set_did_acl wrote"
    );
}

/// Storing a message updates the recipient's inbox counters; the message is
/// then individually retrievable.
async fn check_message_store_and_counters(store: Arc<dyn MediatorStore>) {
    let to = "did_hash_recipient_msg";
    let from = "did_hash_sender_msg";
    store
        .account_add(to, &allow_all(), None)
        .await
        .expect("account_add recipient");

    let before = store.inbox_status(to).await.expect("inbox_status before");
    assert_eq!(before.message_count, 0, "inbox starts empty");

    let body = "{\"protected\":\"conformance-test-message\"}";
    let id = store
        .store_message("session-id", body, to, Some(from), NEVER, 1000)
        .await
        .expect("store_message");
    assert!(!id.is_empty(), "store_message returns a non-empty id");

    let after = store.inbox_status(to).await.expect("inbox_status after");
    assert_eq!(
        after.message_count, 1,
        "storing one message increments message_count"
    );
    assert!(
        after.total_bytes >= body.len() as u64,
        "total_bytes reflects the stored payload ({} >= {})",
        after.total_bytes,
        body.len()
    );

    let fetched = store
        .get_message(to, &id)
        .await
        .expect("get_message")
        .expect("stored message is retrievable by id");
    assert_eq!(
        fetched.msg_id, id,
        "fetched message id matches the stored id"
    );
    assert!(fetched.size > 0, "fetched message reports a non-zero size");
}

/// Forward-queue consumer-group semantics: enqueue → len → read (claim) →
/// ack. The claimed entry round-trips its addressing fields.
async fn check_forward_queue_claim_ack(store: Arc<dyn MediatorStore>) {
    assert_eq!(
        store.forward_queue_len().await.expect("forward_queue_len"),
        0,
        "forward queue starts empty"
    );

    let entry = ForwardQueueEntry {
        stream_id: String::new(),
        message: "relay-envelope".to_string(),
        to_did_hash: "next_hash".to_string(),
        from_did_hash: "from_hash".to_string(),
        from_did: "did:peer:from".to_string(),
        to_did: "did:peer:next".to_string(),
        endpoint_url: "https://peer.example.com/inbound".to_string(),
        received_at_ms: 1,
        delay_milli: 0,
        expires_at: NEVER,
        retry_count: 0,
        hop_count: 1,
    };
    let stream_id = store
        .forward_queue_enqueue(&entry, 1000)
        .await
        .expect("forward_queue_enqueue");
    assert!(!stream_id.is_empty(), "enqueue assigns a stream id");

    assert_eq!(
        store.forward_queue_len().await.expect("forward_queue_len"),
        1,
        "len reflects the enqueued entry"
    );

    let claimed = store
        .forward_queue_read(
            "conformance-group",
            "consumer-1",
            10,
            Duration::from_millis(50),
        )
        .await
        .expect("forward_queue_read");
    assert_eq!(claimed.len(), 1, "read claims the one queued entry");
    let got = &claimed[0];
    assert_eq!(got.to_did, "did:peer:next");
    assert_eq!(got.endpoint_url, "https://peer.example.com/inbound");
    assert!(!got.stream_id.is_empty(), "read populates the stream id");

    let ids: Vec<&str> = claimed.iter().map(|e| e.stream_id.as_str()).collect();
    store
        .forward_queue_ack("conformance-group", &ids)
        .await
        .expect("forward_queue_ack");
}

/// Session put → get (found) → delete → get (gone). `get_session` joins the
/// session record with the DID account, so the account is created first.
async fn check_session_lifecycle(store: Arc<dyn MediatorStore>) {
    let did = "did:example:conformance_session_user";
    let did_hash = sha256::digest(did);
    store
        .account_add(&did_hash, &allow_all(), None)
        .await
        .expect("account_add for session DID");

    let session = Session {
        session_id: "conformance-session-1".to_string(),
        did: did.to_string(),
        did_hash: did_hash.clone(),
        ..Default::default()
    };
    store
        .put_session(&session, Duration::from_secs(300))
        .await
        .expect("put_session");

    let fetched = store
        .get_session(&session.session_id, did)
        .await
        .expect("get_session returns the stored session");
    assert_eq!(fetched.did, did, "round-tripped session keeps its DID");

    store
        .delete_session(&session.session_id)
        .await
        .expect("delete_session");
    assert!(
        store.get_session(&session.session_id, did).await.is_err(),
        "get_session must error once the session is deleted"
    );
}

/// Access-list add → count → list → remove → clear.
async fn check_access_list_lifecycle(store: Arc<dyn MediatorStore>) {
    let owner = "did_hash_access_list_owner";
    store
        .account_add(owner, &allow_all(), None)
        .await
        .expect("account_add owner");

    assert_eq!(
        store.access_list_count(owner).await.expect("count empty"),
        0,
        "access list starts empty"
    );

    let sender = "did_hash_listed_sender".to_string();
    store
        .access_list_add(1000, owner, std::slice::from_ref(&sender))
        .await
        .expect("access_list_add");
    assert_eq!(
        store
            .access_list_count(owner)
            .await
            .expect("count after add"),
        1,
        "count reflects the added entry"
    );

    store
        .access_list_remove(owner, std::slice::from_ref(&sender))
        .await
        .expect("access_list_remove");
    assert_eq!(
        store
            .access_list_count(owner)
            .await
            .expect("count after remove"),
        0,
        "count returns to zero after remove"
    );

    // Clear is idempotent on an already-empty list.
    store
        .access_list_clear(owner)
        .await
        .expect("access_list_clear");
    assert_eq!(
        store
            .access_list_count(owner)
            .await
            .expect("count after clear"),
        0,
    );
}

/// Forward-queue: an unread enqueued entry can be deleted directly, dropping
/// the queue length back to zero.
async fn check_forward_queue_delete(store: Arc<dyn MediatorStore>) {
    let entry = ForwardQueueEntry {
        stream_id: String::new(),
        message: "to-delete".to_string(),
        to_did_hash: "next_hash".to_string(),
        from_did_hash: "from_hash".to_string(),
        from_did: "did:peer:from".to_string(),
        to_did: "did:peer:next".to_string(),
        endpoint_url: "https://peer.example.com/inbound".to_string(),
        received_at_ms: 1,
        delay_milli: 0,
        expires_at: NEVER,
        retry_count: 0,
        hop_count: 1,
    };
    let stream_id = store
        .forward_queue_enqueue(&entry, 1000)
        .await
        .expect("forward_queue_enqueue");
    assert_eq!(store.forward_queue_len().await.expect("len"), 1);

    store
        .forward_queue_delete(&[stream_id.as_str()])
        .await
        .expect("forward_queue_delete");
    assert_eq!(
        store.forward_queue_len().await.expect("len after delete"),
        0,
        "deleting the entry empties the queue"
    );
}

/// Forward-queue autoclaim: an entry claimed by one consumer and left idle is
/// reclaimable by another (the recovery path for a crashed consumer).
async fn check_forward_queue_autoclaim(store: Arc<dyn MediatorStore>) {
    let entry = ForwardQueueEntry {
        stream_id: String::new(),
        message: "to-reclaim".to_string(),
        to_did_hash: "next_hash".to_string(),
        from_did_hash: "from_hash".to_string(),
        from_did: "did:peer:from".to_string(),
        to_did: "did:peer:next".to_string(),
        endpoint_url: "https://peer.example.com/inbound".to_string(),
        received_at_ms: 1,
        delay_milli: 0,
        expires_at: NEVER,
        retry_count: 0,
        hop_count: 1,
    };
    store
        .forward_queue_enqueue(&entry, 1000)
        .await
        .expect("forward_queue_enqueue");

    // Consumer 1 claims it, then leaves it pending (no ack).
    let claimed = store
        .forward_queue_read("g", "consumer-1", 10, Duration::from_millis(50))
        .await
        .expect("forward_queue_read");
    assert_eq!(claimed.len(), 1, "consumer-1 claims the entry");

    // Consumer 2 reclaims anything idle beyond zero — i.e. the pending entry.
    let reclaimed = store
        .forward_queue_autoclaim("g", "consumer-2", Duration::ZERO, 10)
        .await
        .expect("forward_queue_autoclaim");
    assert_eq!(
        reclaimed.len(),
        1,
        "consumer-2 reclaims the idle pending entry"
    );

    let ids: Vec<&str> = reclaimed.iter().map(|e| e.stream_id.as_str()).collect();
    store.forward_queue_ack("g", &ids).await.expect("ack");
}

// ─── Backend instantiation + test generation ────────────────────────────────

/// A constructed backend plus anything that must outlive it (Fjall's temp dir).
struct Backend {
    store: Arc<dyn MediatorStore>,
    #[allow(dead_code)]
    keepalive: Option<Box<dyn std::any::Any>>,
}

/// Build a backend, run its `initialize()` (a no-op for the in-process
/// backends, Lua-script load for Redis), and hand back the ready store.
async fn ready(backend: Backend) -> Arc<dyn MediatorStore> {
    backend.store.initialize().await.expect("store initialize");
    backend.store
}

#[cfg(feature = "memory-backend")]
fn memory_backend() -> Backend {
    use affinidi_messaging_mediator::store::MemoryStore;
    Backend {
        store: Arc::new(MemoryStore::new()),
        keepalive: None,
    }
}

#[cfg(feature = "fjall-backend")]
fn fjall_backend() -> Backend {
    use affinidi_messaging_mediator::store::FjallStore;
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = Arc::new(FjallStore::open(dir.path()).expect("FjallStore::open"));
    Backend {
        store,
        keepalive: Some(Box::new(dir)),
    }
}

/// Generate one `#[tokio::test]` per check for a backend `$ctor`.
macro_rules! conformance_for {
    ($modname:ident, $ctor:expr) => {
        mod $modname {
            use super::*;

            #[tokio::test]
            async fn account_lifecycle() {
                check_account_lifecycle(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn acl_set_get_roundtrip() {
                check_acl_set_get_roundtrip(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn message_store_and_counters() {
                check_message_store_and_counters(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn forward_queue_claim_ack() {
                check_forward_queue_claim_ack(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn session_lifecycle() {
                check_session_lifecycle(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn access_list_lifecycle() {
                check_access_list_lifecycle(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn forward_queue_delete() {
                check_forward_queue_delete(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn forward_queue_autoclaim() {
                check_forward_queue_autoclaim(ready($ctor).await).await;
            }
        }
    };
}

#[cfg(feature = "memory-backend")]
conformance_for!(memory, memory_backend());

#[cfg(feature = "fjall-backend")]
conformance_for!(fjall, fjall_backend());
