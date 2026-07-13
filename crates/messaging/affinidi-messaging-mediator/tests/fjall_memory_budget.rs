//! Memory-budget check for the Fjall backend under sustained write load.
//!
//! `#[ignore]`d: this measures resident set size, which is meaningless in a
//! debug build (and noisy under a parallel test runner). Run it deliberately:
//!
//! ```sh
//! cargo test --release --no-default-features --features didcomm,fjall-backend \
//!     --test fjall_memory_budget -- --ignored --nocapture
//! ```
//!
//! What it pins: Fjall has **no global memtable cap**. `max_write_buffer_size`
//! exists in the API but is a dead field in 3.1.x (declared, has a setter, never
//! read), and each keyspace flushes only when *its own* memtable crosses *its
//! own* threshold. With Fjall's stock 64 MiB-per-keyspace default across the
//! mediator's 14 keyspaces, sustained writes can hold ~900 MiB of write buffer.
//!
//! So the ceiling has to come from `[storage.fjall]`: a `write_buffer` budget
//! split across keyspaces by weight, plus `max_journal`, which force-rotates the
//! keyspaces pinning the oldest journal and is therefore the only bound that
//! also applies to an already-created data directory.
//!
//! This writes far more data than the budget and asserts the process does not
//! grow to match it.

#![cfg(all(feature = "fjall-backend", feature = "didcomm"))]

use affinidi_messaging_mediator::store::FjallStore;
use affinidi_messaging_mediator_common::store::MediatorStore;
use std::sync::Arc;

/// Resident set size of this process, in bytes.
fn rss_bytes() -> u64 {
    let pid = std::process::id();
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .expect("ps");
    let kb: u64 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("rss kb");
    kb * 1024
}

const MIB: u64 = 1024 * 1024;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measures RSS; only meaningful in --release"]
async fn write_load_stays_within_the_configured_budget() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    // `open` uses FjallTuning::default() — the same tuning the mediator applies
    // when `[storage.fjall]` is absent, which is the case this must hold for.
    let store = Arc::new(FjallStore::open(dir.path()).expect("open"));
    store.initialize().await.expect("initialize");

    let baseline = rss_bytes();
    println!("baseline RSS: {:.1} MiB", baseline as f64 / MIB as f64);

    // 2 000 messages x 256 KiB = 500 MiB of message bodies pushed through the
    // store: well past the 32 MiB write-buffer budget and the 128 MiB journal
    // cap, so an unbounded write buffer would show up plainly.
    let body = "x".repeat(256 * 1024);
    let total_written = 2_000u64 * body.len() as u64;

    for i in 0..2_000u32 {
        store
            .store_message(
                &format!("msg{i}"),
                &body,
                &format!("recipient{}", i % 50),
                Some("sender"),
                0,
                0, // queue_maxlen: 0 = unbounded, so nothing trims the load away
            )
            .await
            .expect("store_message");
    }

    let peak = rss_bytes();
    let growth = peak.saturating_sub(baseline);

    println!(
        "wrote {:.0} MiB of bodies; RSS {:.1} -> {:.1} MiB (growth {:.1} MiB)",
        total_written as f64 / MIB as f64,
        baseline as f64 / MIB as f64,
        peak as f64 / MIB as f64,
        growth as f64 / MIB as f64,
    );

    // The whole point: RSS must track the *budget*, not the data volume. A
    // generous ceiling — this asserts "bounded", not a precise figure, so it
    // won't flake on allocator or page-cache noise.
    assert!(
        peak < 256 * MIB,
        "RSS {:.1} MiB exceeded the 256 MiB budget after writing {:.0} MiB",
        peak as f64 / MIB as f64,
        total_written as f64 / MIB as f64,
    );
}
