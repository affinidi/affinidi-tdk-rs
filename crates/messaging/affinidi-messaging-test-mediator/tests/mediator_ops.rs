//! End-to-end: the mediator-operations Trust Tasks an operator console runs on
//! (`messaging/stats/show`, `messaging/queue/list`), sent through the SDK to a
//! live in-process mediator.

use std::time::Duration;

use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_test_mediator::{TestEnvironment, TestUser};

/// A mediator and an administrator connected with a live stream.
///
/// The admin is an ordinary test user promoted to `Admin` in the store before
/// it authenticates (a session takes its role at authentication). An
/// `add_admin` identity would not do: it authenticates by DID resolution but
/// has no streaming-registered account, so the synchronous reply path that
/// request/response Trust Tasks use cannot be established on this harness.
async fn with_admin() -> (TestEnvironment, TestUser) {
    let env = TestEnvironment::spawn().await.expect("environment");
    let admin = env.add_user("operator").await.expect("add operator");
    env.mediator
        .store()
        .account_set_role(&admin.did_hash(), &AccountType::Admin)
        .await
        .expect("promote operator to admin");
    env.atm
        .profile_add(&admin.profile, true)
        .await
        .expect("enable websocket for the admin");
    (env, admin)
}

#[tokio::test]
async fn an_admin_reads_mediator_stats() {
    let (env, admin) = with_admin().await;

    let stats = env
        .atm
        .trust_tasks()
        .stats_show(&admin.profile)
        .await
        .expect("admin reads stats");

    assert!(!stats.version.is_empty());
    assert!(
        stats.connections.websocket_active >= 1,
        "the admin's own live stream is counted"
    );
    // Trust Tasks addressed to the mediator are answered, not stored, so the
    // stored-message counters can still be zero here; the start time is not.
    let started = stats.started_at.expect("startedAt is reported");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(started.timestamp() <= now);
    assert!(stats.uptime_seconds as i64 <= now - started.timestamp() + 1);
}

#[tokio::test]
async fn an_admin_ranks_queues_from_the_survey() {
    let (env, admin) = with_admin().await;

    // The first survey runs as the mediator starts; allow it to land.
    let mut result = None;
    for _ in 0..20 {
        match env
            .atm
            .trust_tasks()
            .queue_list(&admin.profile, None, None, Some(0), None, Some(10))
            .await
        {
            Ok(page) => {
                result = Some(page);
                break;
            }
            Err(e) if format!("{e:?}").contains("unavailable") => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => panic!("queue/list failed: {e:?}"),
        }
    }
    let page = result.expect("a survey completed within five seconds");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(page.snapshot_at.timestamp() <= now);
    assert!(page.queues.len() <= 10);
}

#[tokio::test]
async fn a_standard_account_cannot_read_mediator_wide_views() {
    let env = TestEnvironment::spawn().await.expect("environment");
    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");

    // Refused either way; as elsewhere in this suite, the refusal surfaces as
    // an error without its problem-report detail on this harness.
    let stats = env.atm.trust_tasks().stats_show(&alice.profile).await;
    assert!(stats.is_err(), "stats/show must be refused: {stats:?}");
    let queues = env
        .atm
        .trust_tasks()
        .queue_list(&alice.profile, None, None, None, None, None)
        .await;
    assert!(queues.is_err(), "queue/list must be refused: {queues:?}");
}
