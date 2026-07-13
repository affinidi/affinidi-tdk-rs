//! Regression tests for the Fjall backend's in-memory entry counters.
//!
//! `audit_log` and `forward_queue` are both bounded keyspaces, so both need
//! their length on every insert to enforce the bound. Fjall has no O(1) exact
//! length, so [`FjallStore`] maintains the counts in memory: seeded by one scan
//! at open, then adjusted under `write_lock`.
//!
//! That trades an O(n) scan per insert for a value that can *drift* — a count
//! that disagrees with the keyspace silently corrupts the bound (a ring that
//! trims too eagerly, or never trims at all). These tests pin the three ways it
//! could drift: the trim path, a reopen, and a delete of a key that isn't there.

#![cfg(all(feature = "fjall-backend", feature = "didcomm"))]

use affinidi_messaging_mediator::store::FjallStore;
use affinidi_messaging_mediator_common::{
    store::{MediatorStore, types::ForwardQueueEntry},
    types::audit::{AUDIT_LOG_MAX_ENTRIES, AuditAction, AuditLogEntry},
};
use std::sync::Arc;

fn audit_entry(i: usize) -> AuditLogEntry {
    AuditLogEntry {
        timestamp: 1000 + i as u64,
        actor_did_hash: format!("actor{i}"),
        target_did_hash: format!("target{i}"),
        action: AuditAction::SetAcl,
        detail: format!("entry {i}"),
    }
}

fn forward_entry(i: usize) -> ForwardQueueEntry {
    ForwardQueueEntry {
        stream_id: String::new(),
        message: format!("message {i}"),
        to_did_hash: "to_hash".into(),
        from_did_hash: "from_hash".into(),
        from_did: "did:example:from".into(),
        to_did: "did:example:to".into(),
        endpoint_url: "https://example.com/".into(),
        received_at_ms: 0,
        delay_milli: 0,
        expires_at: 0,
        retry_count: 0,
        hop_count: 0,
    }
}

/// The ring must cap at `AUDIT_LOG_MAX_ENTRIES` and keep the *newest* entries.
///
/// This is the path where a drifting counter does real damage: the trim
/// computes `over` from the count, so an over-count trims live entries and an
/// under-count lets the ring grow past its bound.
///
/// Doubles as a guard on the fix that motivated the counter — the old code ran
/// a full O(n) scan per insert, so this test was quadratic (~10^8 decodes).
#[tokio::test]
async fn audit_log_ring_caps_and_keeps_newest() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = Arc::new(FjallStore::open(dir.path()).expect("open"));
    store.initialize().await.expect("initialize");

    let overshoot = 25usize;
    for i in 0..AUDIT_LOG_MAX_ENTRIES + overshoot {
        store
            .audit_log_record(&audit_entry(i))
            .await
            .expect("record");
    }

    // Newest-first. The first page must start at the very last entry written,
    // proving the trim dropped from the old end, not the new one.
    let page = store.audit_log_list(0, 100).await.expect("list");
    let newest = AUDIT_LOG_MAX_ENTRIES + overshoot - 1;
    assert_eq!(page.entries[0].detail, format!("entry {newest}"));

    // Walk the whole ring and count it. This is the assertion that actually
    // catches drift: it counts what's *in the keyspace*, not what the counter
    // claims. They must agree, and both must equal the cap.
    let mut total = 0usize;
    let mut cursor = 0u32;
    let mut oldest_seen = String::new();
    loop {
        let page = store.audit_log_list(cursor, 100).await.expect("page");
        if page.entries.is_empty() {
            break;
        }
        total += page.entries.len();
        if let Some(last) = page.entries.last() {
            oldest_seen = last.detail.clone();
        }
        if page.cursor == 0 {
            break;
        }
        cursor = page.cursor;
    }
    assert_eq!(
        total, AUDIT_LOG_MAX_ENTRIES,
        "ring must hold exactly the cap, not {total}"
    );

    // The `overshoot` oldest entries are the ones that should have been dropped.
    assert_eq!(oldest_seen, format!("entry {overshoot}"));
}

/// A counter seeded at open must match what's on disk, or every later insert
/// inherits the error. Covers the `Keyspace::len` seeding scan.
#[tokio::test]
async fn counters_survive_reopen() {
    let dir = tempfile::TempDir::new().expect("tempdir");

    {
        let store = Arc::new(FjallStore::open(dir.path()).expect("open"));
        store.initialize().await.expect("initialize");
        for i in 0..7 {
            store
                .audit_log_record(&audit_entry(i))
                .await
                .expect("record");
        }
        for i in 0..4 {
            store
                .forward_queue_enqueue(&forward_entry(i), 0)
                .await
                .expect("enqueue");
        }
        assert_eq!(store.forward_queue_len().await.expect("len"), 4);
    }

    // Reopen against the same directory: the counters are rebuilt by scanning.
    let store = Arc::new(FjallStore::open(dir.path()).expect("reopen"));
    store.initialize().await.expect("initialize");

    assert_eq!(
        store.forward_queue_len().await.expect("len"),
        4,
        "forward_queue counter must be reseeded from disk on reopen"
    );

    // The audit counter has no direct getter; `audit_log_list` derives its
    // terminal cursor from it, so a wrong count shows up as a wrong page.
    let page = store.audit_log_list(0, 100).await.expect("list");
    assert_eq!(page.entries.len(), 7);
    assert_eq!(
        page.cursor, 0,
        "7 entries in a 100-entry page exhausts the log"
    );
}

/// Deleting a stream ID that isn't in the queue must not move the counter.
///
/// Fjall treats removing an absent key as a no-op, so a naive `-= ids.len()`
/// would under-count. Callers really do re-delete: duplicate acks and autoclaim
/// races both replay stream IDs.
#[tokio::test]
async fn forward_queue_delete_is_idempotent() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = Arc::new(FjallStore::open(dir.path()).expect("open"));
    store.initialize().await.expect("initialize");

    let mut ids = Vec::new();
    for i in 0..3 {
        ids.push(
            store
                .forward_queue_enqueue(&forward_entry(i), 0)
                .await
                .expect("enqueue"),
        );
    }
    assert_eq!(store.forward_queue_len().await.expect("len"), 3);

    store
        .forward_queue_delete(&[ids[0].as_str()])
        .await
        .expect("delete");
    assert_eq!(store.forward_queue_len().await.expect("len"), 2);

    // Re-delete the same id, plus one that never existed.
    store
        .forward_queue_delete(&[ids[0].as_str(), "999999999999-0"])
        .await
        .expect("redelete");
    assert_eq!(
        store.forward_queue_len().await.expect("len"),
        2,
        "re-deleting an absent id must not decrement the counter"
    );

    // The counter still governs the `max_len` trim, so prove it's not just the
    // getter that's right: enqueue under a cap of 2 and expect a trim of one.
    store
        .forward_queue_enqueue(&forward_entry(99), 2)
        .await
        .expect("enqueue with cap");
    assert_eq!(
        store.forward_queue_len().await.expect("len"),
        2,
        "enqueue at max_len=2 must trim the oldest, holding the queue at 2"
    );
}
