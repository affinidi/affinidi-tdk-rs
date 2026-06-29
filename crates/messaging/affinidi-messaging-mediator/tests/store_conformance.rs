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
//! Coverage (against **Memory** and **Fjall**) — eleven semantic areas:
//! account lifecycle; ACL set/get; message store + inbox counters;
//! forward-queue consumer-group claim/ack, delete, and autoclaim (crashed-
//! consumer recovery); session put/get/delete lifecycle; session-expiry sweep;
//! access-list add/count/remove/clear; access-list *mode* (allow-list vs
//! deny-list) evaluation; audit-log record + newest-first cursor pagination.
//!
//! Memory and Fjall agree on all of these, with **one documented divergence**
//! the suite surfaced: `sweep_expired_sessions`'s `now_secs` argument is
//! honored by Fjall (wall-clock) but ignored by Memory (monotonic `Instant`) —
//! benign in production, see `check_session_expiry_sweep` and the trait doc.
//!
//! The same checks also run against **Redis** under `redis-backend`, gated on a
//! `REDIS_URL` environment variable (CI sets it via a `redis:7` service; a plain
//! local `cargo test` without it skips them). Redis keys are global (no per-test
//! namespace), so each Redis check is pinned to its own logical DB index and
//! `FLUSHDB`-ed at setup — that gives the same fresh-store-per-test isolation the
//! in-process backends get for free. See `redis_backend` and `conformance_for_redis!`.

#![cfg(any(
    feature = "memory-backend",
    feature = "fjall-backend",
    feature = "redis-backend"
))]

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_mediator_common::store::MediatorStore;
use affinidi_messaging_mediator_common::store::types::{ForwardQueueEntry, Session, SessionState};
use affinidi_messaging_mediator_common::types::audit::{AuditAction, AuditLogEntry};
use affinidi_messaging_sdk::protocols::mediator::{
    accounts::{Account, AccountType},
    acls::{AccessListModeType, MediatorACLSet},
};

/// Far-future expiry so stored messages don't lapse mid-test.
const NEVER: u64 = 9_999_999_999;

fn allow_all() -> MediatorACLSet {
    MediatorACLSet::from_string_ruleset("ALLOW_ALL").expect("ALLOW_ALL ruleset")
}

/// A default ACL set with an explicit access-list `mode` applied.
fn acls_with_mode(mode: AccessListModeType) -> MediatorACLSet {
    let mut acls = MediatorACLSet::default();
    // admin = true so the bit can be set on a fresh set.
    acls.set_access_list_mode(mode, false, true)
        .expect("set_access_list_mode");
    acls
}

/// An admin session, used as the authority for account/message removal.
fn admin_session(admin_did_hash: &str) -> Session {
    Session {
        did_hash: admin_did_hash.to_string(),
        account_type: AccountType::RootAdmin,
        ..Default::default()
    }
}

/// Count a DID's access-list entries by paging `access_list_list`. The store
/// has no standalone count primitive (callers derive it from the listing or
/// from `account_get().access_list_count`); this mirrors that.
///
/// **Backend divergence in the terminal-cursor convention** (surfaced by this
/// suite): the in-process backends signal "no more pages" with `cursor: None`,
/// while Redis pages via `SSCAN`, whose terminal cursor is `0` — so it returns
/// `cursor: Some(0)`. Production never loops on this itself (the handler returns
/// the cursor straight to the client), so both conventions ship; a correct
/// cursor consumer must therefore treat **either `None` or `Some(0)`** as
/// terminal. A consumer that stops only on `None` loops forever against Redis.
/// See the `access_list_list` trait doc.
async fn access_list_len(store: &Arc<dyn MediatorStore>, did_hash: &str) -> usize {
    let mut total = 0;
    let mut cursor = 0u64;
    loop {
        let page = store
            .access_list_list(did_hash, cursor)
            .await
            .expect("access_list_list");
        total += page.did_hashes.len();
        match page.cursor {
            // `None` (in-process backends) or `0` (Redis/SSCAN) both mean done.
            None | Some(0) => break,
            Some(next) => cursor = next,
        }
    }
    total
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
        // A realistic state: production only ever persists sessions in a valid
        // state. Redis's `get_session` rejects `SessionState::Unknown` (the
        // `..Default::default()` value) as a corrupt pre-0.14 record, so a
        // backend-agnostic test must store a real state to round-trip on Redis.
        state: SessionState::Authenticated,
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
        access_list_len(&store, owner).await,
        0,
        "access list starts empty"
    );

    let sender = "did_hash_listed_sender".to_string();
    store
        .access_list_add(1000, owner, std::slice::from_ref(&sender))
        .await
        .expect("access_list_add");
    assert_eq!(
        access_list_len(&store, owner).await,
        1,
        "count reflects the added entry"
    );

    store
        .access_list_remove(owner, std::slice::from_ref(&sender))
        .await
        .expect("access_list_remove");
    assert_eq!(
        access_list_len(&store, owner).await,
        0,
        "count returns to zero after remove"
    );

    // Clear is idempotent on an already-empty list.
    store
        .access_list_clear(owner)
        .await
        .expect("access_list_clear");
    assert_eq!(access_list_len(&store, owner).await, 0);
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

/// Session-expiry: a session whose TTL has lapsed is reclaimed by
/// `sweep_expired_sessions`, so `get_session` then errors. Both in-process
/// backends must agree on this (the trait default is a no-op, so each
/// overrides it).
///
/// DOCUMENTED DIVERGENCE (surfaced by this suite): the `now_secs` argument is
/// **not** honored uniformly. `FjallStore` (and Redis) treat it as the
/// wall-clock cutoff and sweep records whose stored `expires_at_unix <=
/// now_secs`. `MemoryStore` ignores `now_secs` entirely and sweeps against its
/// own monotonic `Instant::now()` (matching its lazy-expiry path). In
/// production this is benign — the `session_expiry_sweep` task always passes
/// the real clock, so both reclaim the same lapsed sessions — but a caller
/// that passed a *synthetic* `now_secs` (as a naive test would) would see
/// Fjall act on it and Memory not. This test therefore lets the TTL lapse in
/// real time so both backends agree regardless of how they read `now_secs`.
async fn check_session_expiry_sweep(store: Arc<dyn MediatorStore>) {
    let did = "did:example:conformance_expiry_user";
    let did_hash = sha256::digest(did);
    store
        .account_add(&did_hash, &allow_all(), None)
        .await
        .expect("account_add");

    let session = Session {
        session_id: "conformance-expiring-session".to_string(),
        did: did.to_string(),
        did_hash,
        // Valid state so Redis's `get_session` accepts the record (see
        // `check_session_lifecycle`); the in-process backends ignore it.
        state: SessionState::Authenticated,
        ..Default::default()
    };
    store
        .put_session(&session, Duration::from_secs(1))
        .await
        .expect("put_session");
    assert!(
        store.get_session(&session.session_id, did).await.is_ok(),
        "session is present before its 1s TTL lapses"
    );

    // Let the 1-second TTL lapse in real (monotonic *and* wall-clock) time, so
    // both the Instant-based (Memory) and now_secs-based (Fjall) sweeps agree.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    store
        .sweep_expired_sessions(NEVER)
        .await
        .expect("sweep_expired_sessions");
    assert!(
        store.get_session(&session.session_id, did).await.is_err(),
        "session is gone after the sweep reclaims the lapsed record"
    );
}

/// Access-list *mode* evaluation: `ExplicitAllow` is an allow-list (only listed
/// senders may send), `ExplicitDeny` is a deny-list (only listed senders are
/// blocked). The two backends must agree on this gate — it is the per-recipient
/// authorization the mediator enforces on every delivery.
async fn check_access_list_mode_semantics(store: Arc<dyn MediatorStore>) {
    let listed = "did_hash_listed_sender".to_string();
    let unlisted = "did_hash_unlisted_sender";

    // ExplicitAllow (allow-list): listed → allowed, unlisted → denied.
    let allow_owner = "did_hash_allowlist_owner";
    store
        .account_add(
            allow_owner,
            &acls_with_mode(AccessListModeType::ExplicitAllow),
            None,
        )
        .await
        .expect("add allow-list owner");
    store
        .access_list_add(1000, allow_owner, std::slice::from_ref(&listed))
        .await
        .expect("add to allow-list");
    assert!(
        store.access_list_allowed(allow_owner, Some(&listed)).await,
        "allow-list admits a listed sender"
    );
    assert!(
        !store.access_list_allowed(allow_owner, Some(unlisted)).await,
        "allow-list rejects an unlisted sender"
    );

    // ExplicitDeny (deny-list): listed → denied, unlisted → allowed.
    let deny_owner = "did_hash_denylist_owner";
    store
        .account_add(
            deny_owner,
            &acls_with_mode(AccessListModeType::ExplicitDeny),
            None,
        )
        .await
        .expect("add deny-list owner");
    store
        .access_list_add(1000, deny_owner, std::slice::from_ref(&listed))
        .await
        .expect("add to deny-list");
    assert!(
        !store.access_list_allowed(deny_owner, Some(&listed)).await,
        "deny-list rejects a listed sender"
    );
    assert!(
        store.access_list_allowed(deny_owner, Some(unlisted)).await,
        "deny-list admits an unlisted sender"
    );
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

/// Build a Redis-backed store on a dedicated logical DB (`db_index`), or `None`
/// when `REDIS_URL` is unset so a plain `cargo test` skips the Redis checks
/// instead of failing on a missing server. CI sets `REDIS_URL` to a `redis:7`
/// service and runs every index.
///
/// Isolation: Redis keys are global (counters, the forward-queue stream,
/// `SCHEMA_MIGRATIONS`), so two checks sharing a DB would interfere. Each check
/// gets its own index and a `FLUSHDB` here wipes anything a prior run left —
/// reproducing the fresh-store-per-test guarantee the in-process backends have.
#[cfg(feature = "redis-backend")]
async fn redis_backend(db_index: u8) -> Option<Backend> {
    use affinidi_messaging_mediator::store::RedisStore;
    use affinidi_messaging_mediator_common::database::{DatabaseHandler, config::DatabaseConfig};

    let base = match std::env::var("REDIS_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            eprintln!("SKIP redis conformance (db {db_index}): REDIS_URL not set");
            return None;
        }
    };
    // Append the DB index as the URL path component Redis reads as `SELECT`.
    let database_url = format!("{}/{db_index}", base.trim_end_matches('/'));

    // The mediator's own Lua functions — the Redis backend can't operate
    // without them. `initialize()` (called by `ready`) loads this file.
    let functions_file = concat!(env!("CARGO_MANIFEST_DIR"), "/conf/atm-functions.lua").to_string();

    let config = DatabaseConfig {
        functions_file: Some(functions_file.clone()),
        database_url,
        database_timeout: 2,
        circuit_breaker_threshold: 5,
        circuit_breaker_recovery_secs: 10,
    };

    let handler = DatabaseHandler::new(&config)
        .await
        .expect("connect to REDIS_URL — is the server reachable?");
    let store = RedisStore::new(
        handler,
        config.circuit_breaker_threshold,
        config.circuit_breaker_recovery_secs,
        config.functions_file.clone(),
    );

    // Wipe this logical DB so the check starts from a clean keyspace. Loaded
    // Lua FUNCTIONs are server-global, not per-DB, so FLUSHDB doesn't disturb
    // them (and `initialize()` reloads them anyway).
    let mut conn = store.get_connection().await.expect("redis connection");
    // `::redis` — the extern crate, not the sibling `mod redis` this suite's
    // test-generation macro creates (which would shadow a bare `redis::`).
    ::redis::cmd("FLUSHDB")
        .query_async::<()>(&mut conn)
        .await
        .expect("FLUSHDB");

    Some(Backend {
        store: Arc::new(store),
        keepalive: None,
    })
}

/// Audit log: recording, newest-first ordering, cursor pagination, and
/// round-trip fidelity of a record. (The bounded-ring trim at
/// `AUDIT_LOG_MAX_ENTRIES` is not exercised here — filling it would cost tens of
/// thousands of writes; the trim is small and reviewed at each backend.)
async fn check_audit_log_lifecycle(store: Arc<dyn MediatorStore>) {
    // Fresh store: empty, terminal cursor.
    let page = store.audit_log_list(0, 100).await.expect("list empty");
    assert!(page.entries.is_empty(), "fresh store has no audit entries");
    assert_eq!(page.cursor, 0);

    // Record five entries in order 0..5.
    for i in 0..5u64 {
        let entry = AuditLogEntry {
            timestamp: 1000 + i,
            actor_did_hash: format!("admin{i}"),
            target_did_hash: format!("target{i}"),
            action: AuditAction::SetAcl,
            detail: format!("entry {i}"),
        };
        store.audit_log_record(&entry).await.expect("record");
    }

    // Single page: newest-first (entry 4 first, entry 0 last), cursor exhausted.
    let page = store.audit_log_list(0, 100).await.expect("list all");
    assert_eq!(page.entries.len(), 5);
    assert_eq!(page.entries[0].detail, "entry 4");
    assert_eq!(page.entries[4].detail, "entry 0");
    assert_eq!(page.cursor, 0, "single page exhausts the log");

    // Round-trip fidelity of the newest record.
    assert_eq!(page.entries[0].actor_did_hash, "admin4");
    assert_eq!(page.entries[0].target_did_hash, "target4");
    assert_eq!(page.entries[0].action, AuditAction::SetAcl);
    assert_eq!(page.entries[0].timestamp, 1004);

    // Pagination, 2 per page, newest-first across page boundaries.
    let p0 = store.audit_log_list(0, 2).await.expect("page 0");
    assert_eq!(
        p0.entries
            .iter()
            .map(|e| e.detail.as_str())
            .collect::<Vec<_>>(),
        ["entry 4", "entry 3"]
    );
    assert_ne!(p0.cursor, 0, "more pages remain");

    let p1 = store.audit_log_list(p0.cursor, 2).await.expect("page 1");
    assert_eq!(
        p1.entries
            .iter()
            .map(|e| e.detail.as_str())
            .collect::<Vec<_>>(),
        ["entry 2", "entry 1"]
    );
    assert_ne!(p1.cursor, 0);

    let p2 = store.audit_log_list(p1.cursor, 2).await.expect("page 2");
    assert_eq!(
        p2.entries
            .iter()
            .map(|e| e.detail.as_str())
            .collect::<Vec<_>>(),
        ["entry 0"]
    );
    assert_eq!(p2.cursor, 0, "last page is terminal");
}

/// OOB discovery invitation: store → get (round-trips invite + DID) → delete →
/// get-is-gone, plus delete-of-missing reports `false`.
///
/// Regression guard for the Redis backend: its `oob_discovery_get` and
/// `oob_discovery_delete` trait methods previously recursed into themselves
/// (no inherent method of the same name existed), so the first call to either
/// stack-overflowed. Driving the round-trip against every backend — Redis
/// included — would have surfaced that immediately.
async fn check_oob_discovery_roundtrip(store: Arc<dyn MediatorStore>) {
    let did_hash = "did_hash_oob_roundtrip";
    let invite_b64 = "eyJvb2IiOiJpbnZpdGUtcGF5bG9hZCJ9";
    // Far-future absolute expiry (year 2100) so the invite is live on every
    // backend: Redis stamps it with `EXPIREAT`, the in-process backends keep it
    // while `expires_at > now`.
    let expires_at = 4_102_444_800u64;

    let oob_id = store
        .oob_discovery_store(did_hash, invite_b64, expires_at)
        .await
        .expect("oob_discovery_store");

    let got = store
        .oob_discovery_get(&oob_id)
        .await
        .expect("oob_discovery_get")
        .expect("invite present after store");
    assert_eq!(
        got,
        (invite_b64.to_string(), did_hash.to_string()),
        "oob_discovery_get round-trips (invite, did_hash)"
    );

    assert!(
        store
            .oob_discovery_delete(&oob_id)
            .await
            .expect("oob_discovery_delete"),
        "delete reports success for a stored invite"
    );

    assert!(
        store
            .oob_discovery_get(&oob_id)
            .await
            .expect("oob_discovery_get after delete")
            .is_none(),
        "invite is gone after delete"
    );

    assert!(
        !store
            .oob_discovery_delete(&oob_id)
            .await
            .expect("oob_discovery_delete missing"),
        "deleting a missing invite reports false"
    );
}

/// Generate one `#[tokio::test]` per check for a backend `$ctor`.
/// Gated to the in-process backends that use it — a Redis-only build drives the
/// async `conformance_for_redis!` instead, so an ungated def would warn (unused)
/// under `-D warnings`.
#[cfg(any(feature = "memory-backend", feature = "fjall-backend"))]
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
            #[tokio::test]
            async fn session_expiry_sweep() {
                check_session_expiry_sweep(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn access_list_mode_semantics() {
                check_access_list_mode_semantics(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn audit_log_lifecycle() {
                check_audit_log_lifecycle(ready($ctor).await).await;
            }
            #[tokio::test]
            async fn oob_discovery_roundtrip() {
                check_oob_discovery_roundtrip(ready($ctor).await).await;
            }
        }
    };
}

#[cfg(feature = "memory-backend")]
conformance_for!(memory, memory_backend());

#[cfg(feature = "fjall-backend")]
conformance_for!(fjall, fjall_backend());

/// Like [`conformance_for!`] but for the async, `REDIS_URL`-gated Redis ctor.
/// Each test is pinned to a distinct logical DB index for isolation and skips
/// (returns early) when `redis_backend` yields `None` (no `REDIS_URL`).
#[cfg(feature = "redis-backend")]
macro_rules! conformance_for_redis {
    ($modname:ident, $($test:ident => $check:ident @ $db:literal),+ $(,)?) => {
        mod $modname {
            use super::*;
            $(
                #[tokio::test]
                async fn $test() {
                    let Some(backend) = redis_backend($db).await else { return };
                    $check(ready(backend).await).await;
                }
            )+
        }
    };
}

// One distinct DB index per check (1..=10) so the global keys (counters, the
// forward-queue stream) never collide across the suite running in parallel.
#[cfg(feature = "redis-backend")]
conformance_for_redis!(redis,
    account_lifecycle        => check_account_lifecycle        @ 1,
    acl_set_get_roundtrip    => check_acl_set_get_roundtrip    @ 2,
    message_store_and_counters => check_message_store_and_counters @ 3,
    forward_queue_claim_ack  => check_forward_queue_claim_ack  @ 4,
    session_lifecycle        => check_session_lifecycle        @ 5,
    access_list_lifecycle    => check_access_list_lifecycle    @ 6,
    forward_queue_delete     => check_forward_queue_delete     @ 7,
    forward_queue_autoclaim  => check_forward_queue_autoclaim  @ 8,
    session_expiry_sweep     => check_session_expiry_sweep     @ 9,
    access_list_mode_semantics => check_access_list_mode_semantics @ 10,
    audit_log_lifecycle      => check_audit_log_lifecycle      @ 11,
    oob_discovery_roundtrip  => check_oob_discovery_roundtrip  @ 12,
);
