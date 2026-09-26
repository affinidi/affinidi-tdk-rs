//! End-to-end: the mediator-operations Trust Tasks an operator console runs on
//! (`messaging/stats/show`, `messaging/queue/list`), sent through the SDK to a
//! live in-process mediator.

mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use affinidi_messaging_didcomm::Message;
use serde_json::json;
use uuid::Uuid;

use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_test_mediator::{TestEnvironment, TestUser};
use common::await_monitor_event;

/// A mediator and an administrator connected with a live stream.
///
/// The admin is an ordinary test user promoted to `Admin` in the store before
/// it authenticates. An
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

/// A role change reaches a socket that is already open — both ways.
///
/// A socket's session is built at upgrade and lives until its token expires,
/// and authorisation reads the role off it. REST re-joins the account on every
/// request; a socket did not, so a promotion was refused on the socket the
/// account already had, and a demotion left an ex-administrator with its old
/// authority until the token ran out.
#[tokio::test]
async fn a_role_change_reaches_a_live_socket() {
    let env = TestEnvironment::spawn().await.expect("environment");
    let alice = env.add_user("alice").await.expect("alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("alice live");
    let tasks = env.atm.trust_tasks();

    assert!(
        tasks.stats_show(&alice.profile).await.is_err(),
        "a standard account is refused"
    );

    // Promoted while the socket is open: served on that same socket.
    env.mediator
        .store()
        .account_set_role(&alice.did_hash(), &AccountType::Admin)
        .await
        .expect("promote");
    tasks
        .stats_show(&alice.profile)
        .await
        .expect("a promotion is honoured without reconnecting");

    // Demoted while the socket is open: refused on that same socket.
    env.mediator
        .store()
        .account_set_role(&alice.did_hash(), &AccountType::Standard)
        .await
        .expect("demote");
    assert!(
        tasks.stats_show(&alice.profile).await.is_err(),
        "a demotion must take effect on a live socket, not when its token expires"
    );
}

/// A refusal comes back as the answer to the request that provoked it — at
/// once, carrying its reason — rather than as an unmatched problem report the
/// caller waits out and reports as "no response".
#[tokio::test]
async fn a_refused_trust_task_is_answered_at_once_with_its_reason() {
    let env = direct_env().await;
    let alice = env.add_user("alice").await.expect("alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("alice live");

    let started = std::time::Instant::now();
    let refused = env
        .atm
        .trust_tasks()
        .stats_show(&alice.profile)
        .await
        .expect_err("stats/show is admin-only");
    let elapsed = started.elapsed();
    let text = refused.to_string();
    assert!(
        !text.contains("No response"),
        "the refusal must be matched to the request: {text}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "answered in {elapsed:?}, not after the reply timeout"
    );
}

/// Authcrypt a basic message from `sender` to `recipient` and hand it to the
/// mediator for direct delivery. The recipient does not collect it, so it
/// stays in the recipient's receive queue and the sender's send queue.
async fn send_direct(env: &TestEnvironment, sender: &TestUser, recipient: &TestUser) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/basicmessage/2.0/message".to_string(),
        json!({ "content": "queue status probe" }),
    )
    .to(recipient.did.clone())
    .from(sender.did.clone())
    .created_time(now)
    .expires_time(now + 600)
    .finalize();
    let msg_id = msg.id.clone();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &recipient.did, Some(&sender.did), Some(&sender.did))
        .await
        .expect("pack");
    env.atm
        .send_message(&sender.profile, &packed, &msg_id, false, false)
        .await
        .expect("direct delivery accepted");
}

/// An environment with direct delivery on, so messages queue between users.
async fn direct_env() -> TestEnvironment {
    TestEnvironment::spawn_with_direct_delivery()
        .await
        .expect("environment")
}

#[tokio::test]
async fn queue_status_shows_who_has_not_collected() {
    let env = direct_env().await;
    let alice = env.add_user("alice").await.expect("alice");
    let bob = env.add_user("bob").await.expect("bob");
    let carol = env.add_user("carol").await.expect("carol");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("alice live");

    for _ in 0..3 {
        send_direct(&env, &alice, &bob).await;
    }
    send_direct(&env, &alice, &carol).await;

    // Alice reads her own queues (no admin rights needed) with the breakdown.
    let status = env
        .atm
        .trust_tasks()
        .queue_status(&alice.profile, None, Some(5))
        .await
        .expect("alice reads her own queue status");

    assert_eq!(status.queues.did.as_str(), alice.did_hash().as_str());
    assert_eq!(
        status.queues.send.count, 4,
        "held against alice until collected"
    );
    let send_peers = status.send_peers;
    assert_eq!(send_peers.len(), 2);
    assert_eq!(
        send_peers[0].peer.as_str(),
        bob.did_hash().as_str(),
        "bob holds the most uncollected messages"
    );
    assert_eq!(send_peers[0].count, 3);
    assert_eq!(send_peers[1].count, 1);
    assert!(status.queues.send.oldest_age_seconds.is_some());
}

#[tokio::test]
async fn a_standard_account_cannot_read_another_accounts_queue() {
    let env = direct_env().await;
    let alice = env.add_user("alice").await.expect("alice");
    let bob = env.add_user("bob").await.expect("bob");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("alice live");

    let denied = env
        .atm
        .trust_tasks()
        .queue_status(&alice.profile, Some(bob.did_hash()), None)
        .await;
    assert!(
        denied.is_err(),
        "alice must not read bob's queues: {denied:?}"
    );
}

#[tokio::test]
async fn an_admin_reads_any_accounts_queue() {
    let (env, admin) = with_admin().await;
    let bob = env.add_user("bob").await.expect("bob");

    let status = env
        .atm
        .trust_tasks()
        .queue_status(&admin.profile, Some(bob.did_hash()), Some(3))
        .await
        .expect("an admin reads bob's queues");
    assert_eq!(status.queues.did.as_str(), bob.did_hash().as_str());
    assert_eq!(status.queues.receive.count, 0);
    assert!(status.receive_peers.is_empty());
}

/// An account promoted to `role` in the store before it authenticates, with a
/// live stream for request/response Trust Tasks.
async fn promoted(env: &TestEnvironment, alias: &str, role: AccountType) -> TestUser {
    let user = env.add_user(alias).await.expect("add user");
    env.mediator
        .store()
        .account_set_role(&user.did_hash(), &role)
        .await
        .expect("promote");
    env.atm
        .profile_add(&user.profile, true)
        .await
        .expect("enable websocket");
    user
}

#[tokio::test]
async fn an_account_lists_and_reads_its_own_messages() {
    use trust_tasks_rs::specs::messaging::message::list::v0_1::Queue;

    let env = direct_env().await;
    let alice = env.add_user("alice").await.expect("alice");
    let carol = env.add_user("carol").await.expect("carol");
    let bob = env.add_user("bob").await.expect("bob");
    env.atm
        .profile_add(&bob.profile, true)
        .await
        .expect("bob live");
    send_direct(&env, &alice, &bob).await;
    send_direct(&env, &carol, &bob).await;
    send_direct(&env, &alice, &bob).await;

    // Page one message at a time, filtered to alice.
    let tt = env.atm.trust_tasks();
    let first = tt
        .message_list(
            &bob.profile,
            None,
            Queue::Receive,
            Some(alice.did_hash()),
            None,
            Some(1),
        )
        .await
        .expect("bob lists his receive queue");
    assert_eq!(first.messages.len(), 1);
    assert_eq!(
        first.messages[0].from.as_ref().map(|f| f.as_str()),
        Some(alice.did_hash().as_str())
    );
    let cursor = first
        .next_cursor
        .expect("a second alice message remains")
        .to_string();
    let second = tt
        .message_list(
            &bob.profile,
            None,
            Queue::Receive,
            Some(alice.did_hash()),
            Some(cursor),
            Some(1),
        )
        .await
        .expect("second page");
    assert_eq!(second.messages.len(), 1);
    assert_ne!(first.messages[0].msg_id, second.messages[0].msg_id);

    // Unfiltered, all three are there, oldest first.
    let all = tt
        .message_list(&bob.profile, None, Queue::Receive, None, None, None)
        .await
        .expect("full listing");
    assert_eq!(all.messages.len(), 3);

    // Bob fetches one raw: the stored envelope, still encrypted.
    let id = all.messages[0].msg_id.to_string();
    let got = tt
        .message_get(&bob.profile, None, &id)
        .await
        .expect("bob reads his own message");
    assert_eq!(got.meta.msg_id.to_string(), id);
    assert!(got.message.contains("ciphertext"), "an authcrypted JWE");

    // Reading is not a pickup: it is still listed afterwards.
    let again = tt
        .message_list(&bob.profile, None, Queue::Receive, None, None, None)
        .await
        .expect("relist");
    assert_eq!(again.messages.len(), 3);
}

#[tokio::test]
async fn only_a_root_admin_reads_another_accounts_message_and_it_is_audited() {
    use trust_tasks_rs::specs::messaging::message::list::v0_1::Queue;

    let env = direct_env().await;
    let alice = env.add_user("alice").await.expect("alice");
    let bob = env.add_user("bob").await.expect("bob");
    send_direct(&env, &alice, &bob).await;
    let admin = promoted(&env, "admin", AccountType::Admin).await;
    let root = promoted(&env, "root", AccountType::RootAdmin).await;
    let tt = env.atm.trust_tasks();

    // A plain admin may list bob's queue (metadata)…
    let listed = tt
        .message_list(
            &admin.profile,
            Some(bob.did_hash()),
            Queue::Receive,
            None,
            None,
            None,
        )
        .await
        .expect("an admin lists bob's metadata");
    let id = listed.messages[0].msg_id.to_string();

    // …but not read the message itself.
    let denied = tt
        .message_get(&admin.profile, Some(bob.did_hash()), &id)
        .await;
    assert!(denied.is_err(), "a plain admin must not read bob's message");

    // A rootAdmin can, and the read is audited.
    let got = tt
        .message_get(&root.profile, Some(bob.did_hash()), &id)
        .await
        .expect("a rootAdmin reads bob's message");
    assert_eq!(got.meta.msg_id.to_string(), id);
    let audit = tt
        .audit_list(&root.profile, None, None)
        .await
        .expect("read the audit log");
    let text = format!("{audit:?}");
    assert!(
        text.contains("messageRead"),
        "cross-account read audited: {text}"
    );
}

async fn receive_ids(env: &TestEnvironment, user: &TestUser) -> Vec<String> {
    use trust_tasks_rs::specs::messaging::message::list::v0_1::Queue;
    env.atm
        .trust_tasks()
        .message_list(&user.profile, None, Queue::Receive, None, None, None)
        .await
        .expect("list")
        .messages
        .iter()
        .map(|m| m.msg_id.to_string())
        .collect()
}

#[tokio::test]
async fn an_account_deletes_its_own_messages_and_each_id_is_reported() {
    let env = direct_env().await;
    let alice = env.add_user("alice").await.expect("alice");
    let bob = env.add_user("bob").await.expect("bob");
    env.atm
        .profile_add(&bob.profile, true)
        .await
        .expect("bob live");
    send_direct(&env, &alice, &bob).await;
    send_direct(&env, &alice, &bob).await;

    let ids = receive_ids(&env, &bob).await;
    let request = vec![ids[0].clone(), "no-such-message".to_string()];
    let result = env
        .atm
        .trust_tasks()
        .message_delete(&bob.profile, None, &request)
        .await
        .expect("bob deletes from his own queue");

    assert_eq!(result.results.len(), 2, "one result per id, in order");
    assert!(result.results[0].deleted);
    assert!(
        !result.results[1].deleted,
        "an unknown id is not reported deleted"
    );
    assert_eq!(receive_ids(&env, &bob).await, vec![ids[1].clone()]);
}

#[tokio::test]
async fn deleting_another_accounts_messages_needs_admin_and_is_audited() {
    let env = direct_env().await;
    let alice = env.add_user("alice").await.expect("alice");
    let bob = env.add_user("bob").await.expect("bob");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("alice live");
    env.atm
        .profile_add(&bob.profile, true)
        .await
        .expect("bob live");
    send_direct(&env, &alice, &bob).await;
    let ids = receive_ids(&env, &bob).await;
    let tt = env.atm.trust_tasks();

    let denied = tt
        .message_delete(&alice.profile, Some(bob.did_hash()), &ids)
        .await;
    assert!(
        denied.is_err(),
        "a standard account must not delete bob's messages"
    );

    let admin = promoted(&env, "admin", AccountType::Admin).await;
    let done = tt
        .message_delete(&admin.profile, Some(bob.did_hash()), &ids)
        .await
        .expect("an admin deletes bob's message");
    assert!(done.results[0].deleted);
    assert!(receive_ids(&env, &bob).await.is_empty());

    let audit = tt
        .audit_list(&admin.profile, None, None)
        .await
        .expect("audit");
    assert!(format!("{audit:?}").contains("messageDelete"));
}

#[tokio::test]
async fn a_privileged_accounts_queue_needs_a_root_admin() {
    use trust_tasks_rs::specs::messaging::queue::purge::v0_1::Queue;

    let env = direct_env().await;
    let admin = promoted(&env, "admin", AccountType::Admin).await;
    let other = promoted(&env, "other-admin", AccountType::Admin).await;
    let root = promoted(&env, "root", AccountType::RootAdmin).await;
    let tt = env.atm.trust_tasks();

    let denied = tt
        .queue_purge(
            &admin.profile,
            Some(other.did_hash()),
            Queue::Receive,
            None,
            None,
            true,
        )
        .await;
    assert!(
        denied.is_err(),
        "an admin must not purge another admin's queue"
    );

    let allowed = tt
        .queue_purge(
            &root.profile,
            Some(other.did_hash()),
            Queue::Receive,
            None,
            None,
            true,
        )
        .await
        .expect("a rootAdmin may");
    assert!(allowed.dry_run);
}

#[tokio::test]
async fn a_dry_run_counts_and_the_real_purge_removes_only_the_filtered_peer() {
    use trust_tasks_rs::specs::messaging::queue::purge::v0_1::Queue;

    let env = direct_env().await;
    let alice = env.add_user("alice").await.expect("alice");
    let carol = env.add_user("carol").await.expect("carol");
    let bob = env.add_user("bob").await.expect("bob");
    env.atm
        .profile_add(&bob.profile, true)
        .await
        .expect("bob live");
    for _ in 0..3 {
        send_direct(&env, &alice, &bob).await;
    }
    send_direct(&env, &carol, &bob).await;
    let tt = env.atm.trust_tasks();

    let preview = tt
        .queue_purge(
            &bob.profile,
            None,
            Queue::Receive,
            Some(alice.did_hash()),
            None,
            true,
        )
        .await
        .expect("dry run");
    assert_eq!(preview.matched, 3);
    assert_eq!(preview.purged, 0);
    assert_eq!(
        receive_ids(&env, &bob).await.len(),
        4,
        "a dry run removes nothing"
    );

    let purged = tt
        .queue_purge(
            &bob.profile,
            None,
            Queue::Receive,
            Some(alice.did_hash()),
            None,
            false,
        )
        .await
        .expect("purge alice's messages");
    assert_eq!(purged.purged, 3);
    assert_eq!(
        receive_ids(&env, &bob).await.len(),
        1,
        "carol's message survives"
    );
}

#[tokio::test]
async fn an_admin_watches_a_message_arrive_live() {
    use trust_tasks_rs::specs::messaging::monitor::subscribe::v0_1::MonitorFilter;

    let env = direct_env().await;
    let alice = env.add_user("alice").await.expect("alice");
    let bob = env.add_user("bob").await.expect("bob");
    let admin = promoted(&env, "admin", AccountType::Admin).await;

    let filter: MonitorFilter =
        serde_json::from_value(json!({ "dids": [bob.did_hash()] })).unwrap();
    let sub = env
        .atm
        .trust_tasks()
        .monitor_subscribe(&admin.profile, Some(filter), Some(60), None, None)
        .await
        .expect("admin subscribes");

    send_direct(&env, &alice, &bob).await;

    let bob_hash = bob.did_hash();
    let stored = await_monitor_event(
        &env,
        &admin,
        |e| e["stage"] == "stored" && e["to"] == bob_hash.as_str(),
        Duration::from_secs(10),
    )
    .await
    .expect("the store of alice's message to bob is seen live");
    assert_eq!(stored["from"], alice.did_hash().as_str());
    assert_eq!(stored["protocol"], "didcomm");

    let ended = env
        .atm
        .trust_tasks()
        .monitor_unsubscribe(&admin.profile, &sub.subscription_id.to_string())
        .await
        .expect("unsubscribe");
    assert!(ended.events_sent.unwrap_or(0) >= 1);

    // An administrator's tap on other accounts' traffic is on the record.
    let audit = env
        .atm
        .trust_tasks()
        .audit_list(&admin.profile, None, None)
        .await
        .expect("audit");
    let text = format!("{audit:?}");
    assert!(
        text.contains("monitorSubscribe"),
        "subscribe audited: {text}"
    );
    assert!(
        text.contains("monitorUnsubscribe"),
        "unsubscribe audited: {text}"
    );
}

/// A message's whole life is visible to the monitor, with both parties at
/// every step: received (the recipient read from the envelope's cleartext
/// header, the channel it arrived on), delivered when the recipient fetches
/// it, and deleted when the recipient acknowledges it.
#[tokio::test]
async fn the_monitor_follows_a_message_from_arrival_to_deletion() {
    use affinidi_messaging_sdk::messages::{DeleteMessageRequest, fetch::FetchOptions};
    use trust_tasks_rs::specs::messaging::monitor::subscribe::v0_1::MonitorFilter;

    let env = direct_env().await;
    let alice = env.add_user("alice").await.expect("alice");
    let bob = env.add_user("bob").await.expect("bob");
    let admin = promoted(&env, "admin", AccountType::Admin).await;

    let filter: MonitorFilter =
        serde_json::from_value(json!({ "dids": [bob.did_hash()] })).unwrap();
    env.atm
        .trust_tasks()
        .monitor_subscribe(&admin.profile, Some(filter), Some(60), None, None)
        .await
        .expect("admin subscribes");

    send_direct(&env, &alice, &bob).await;

    let alice_hash = alice.did_hash();
    let bob_hash = bob.did_hash();
    let received = await_monitor_event(
        &env,
        &admin,
        |e| e["stage"] == "received" && e["to"] == bob_hash.as_str(),
        Duration::from_secs(10),
    )
    .await
    .expect("the arrival names its recipient");
    assert_eq!(received["channel"], "rest");
    assert_eq!(received["protocol"], "didcomm");

    let fetched = env
        .atm
        .fetch_messages(&bob.profile, &FetchOptions::default())
        .await
        .expect("bob fetches");
    let ids: Vec<String> = fetched.success.iter().map(|m| m.msg_id.clone()).collect();
    assert_eq!(ids.len(), 1);

    let delivered = await_monitor_event(
        &env,
        &admin,
        |e| e["stage"] == "delivered" && e["to"] == bob_hash.as_str(),
        Duration::from_secs(10),
    )
    .await
    .expect("a REST fetch is a delivery");
    assert_eq!(delivered["from"], alice_hash.as_str());
    assert_eq!(delivered["channel"], "rest");

    env.atm
        .delete_messages_direct(&bob.profile, &DeleteMessageRequest { message_ids: ids })
        .await
        .expect("bob deletes");

    let deleted = await_monitor_event(
        &env,
        &admin,
        |e| e["stage"] == "deleted" && e["to"] == bob_hash.as_str(),
        Duration::from_secs(10),
    )
    .await
    .expect("the delete is seen");
    assert_eq!(deleted["from"], alice_hash.as_str());
}

/// A message the expiry sweep removes is reported `expired`, with both
/// parties and its size.
#[tokio::test]
async fn the_monitor_sees_a_message_expire() {
    use affinidi_messaging_test_mediator::{TestClock, TestMediator};
    use std::sync::Arc;
    use trust_tasks_rs::specs::messaging::monitor::subscribe::v0_1::MonitorFilter;

    let clock = TestClock::now();
    let mediator = TestMediator::builder()
        .local_direct_delivery(true, false)
        .enable_message_expiry(true)
        .clock(Arc::new(clock.clone()))
        .spawn()
        .await
        .expect("mediator");
    let env = TestEnvironment::new(mediator).await.expect("environment");
    let alice = env.add_user("alice").await.expect("alice");
    let bob = env.add_user("bob").await.expect("bob");
    let admin = promoted(&env, "admin", AccountType::Admin).await;
    // Authenticate alice now, at the real time.
    env.atm
        .profile_add(&alice.profile, false)
        .await
        .expect("alice");

    let filter: MonitorFilter =
        serde_json::from_value(json!({ "dids": [bob.did_hash()], "stages": ["expired"] })).unwrap();
    env.atm
        .trust_tasks()
        .monitor_subscribe(&admin.profile, Some(filter), Some(60), None, None)
        .await
        .expect("admin subscribes");

    // Stored while the mediator's clock is a year behind, the message's
    // expiry is already past in real time, which is what the sweep runs on.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    clock.set_secs(now - 365 * 24 * 3600);
    send_direct(&env, &alice, &bob).await;
    clock.set_secs(now);

    let bob_hash = bob.did_hash();
    let expired = await_monitor_event(
        &env,
        &admin,
        |e| e["stage"] == "expired" && e["to"] == bob_hash.as_str(),
        Duration::from_secs(10),
    )
    .await
    .expect("the sweep's removal is seen");
    assert_eq!(expired["from"], alice.did_hash().as_str());
    assert!(expired["size"].as_u64().unwrap() > 0);
    assert!(expired["msgId"].is_string());
    env.atm
        .profile_add(&bob.profile, true)
        .await
        .expect("bob live");
    assert!(receive_ids(&env, &bob).await.is_empty(), "it is gone");
}

#[tokio::test]
async fn a_standard_account_monitors_only_itself() {
    use trust_tasks_rs::specs::messaging::monitor::subscribe::v0_1::MonitorFilter;

    let env = direct_env().await;
    let alice = env.add_user("alice").await.expect("alice");
    let bob = env.add_user("bob").await.expect("bob");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("alice live");
    let tt = env.atm.trust_tasks();

    let other: MonitorFilter = serde_json::from_value(json!({ "dids": [bob.did_hash()] })).unwrap();
    let refused = tt
        .monitor_subscribe(&alice.profile, Some(other), None, None, None)
        .await;
    assert!(
        refused.is_err(),
        "naming another account is refused, not narrowed"
    );

    let own = tt
        .monitor_subscribe(&alice.profile, None, None, None, None)
        .await
        .expect("alice may watch her own traffic");
    let dids: Vec<String> = own
        .filter
        .dids
        .clone()
        .unwrap_or_default()
        .iter()
        .map(|d| d.to_string())
        .collect();
    assert_eq!(dids, vec![alice.did_hash()], "narrowed to her own account");

    // Someone else cannot end it.
    let bob_live = promoted(&env, "bob-watcher", AccountType::Standard).await;
    let stolen = tt
        .monitor_unsubscribe(&bob_live.profile, &own.subscription_id.to_string())
        .await;
    assert!(stolen.is_err());
}

/// A monitor subscription made over TSP is served, like every other
/// management task. It used to be refused: monitor batches are live-only and
/// a raw-TSP socket discards an ordinary push, so a subscription made over TSP
/// would have been accepted and then silent. Batches are sealed to the
/// subscriber's VID and pushed verbatim now — `tsp_monitor` drives the
/// delivery end to end; this pins that the mediator accepts the subscription.
#[cfg(feature = "tsp")]
#[tokio::test]
async fn a_monitor_subscription_over_tsp_is_served() {
    let env = direct_env().await;
    let alice = env.add_user("alice").await.expect("alice");
    let mediator_did = env.mediator.did().to_string();

    let task = |type_uri: &str, payload: serde_json::Value| {
        serde_json::to_vec(&json!({
            "id": format!("urn:uuid:{}", Uuid::new_v4()),
            "type": type_uri,
            "issuer": alice.did,
            "recipient": mediator_did,
            "payload": payload,
        }))
        .unwrap()
    };

    env.atm
        .tsp()
        .send(
            &alice.profile,
            &mediator_did,
            &task(
                "https://trusttasks.org/spec/messaging/monitor/subscribe/0.1",
                json!({}),
            ),
        )
        .await
        .expect("monitor/subscribe over TSP is served");

    // And the rest of TSP management still works alongside it.
    env.atm
        .tsp()
        .send(
            &alice.profile,
            &mediator_did,
            &task(
                "https://trusttasks.org/spec/messaging/account/get/0.1",
                json!({ "did": alice.did_hash() }),
            ),
        )
        .await
        .expect("account/get over TSP is still served");
}

/// Patch a mediator's limits as `user` (who must be live).
async fn patch(
    env: &TestEnvironment,
    user: &TestUser,
    overrides: serde_json::Value,
) -> Result<serde_json::Value, affinidi_messaging_sdk::errors::ATMError> {
    env.atm
        .trust_tasks()
        .config_patch(&user.profile, overrides.as_object().unwrap().clone())
        .await
        .map(|r| serde_json::to_value(r).unwrap())
}

/// One key's field from `config/show`.
async fn shown(env: &TestEnvironment, user: &TestUser, key: &str) -> serde_json::Value {
    let fields = env
        .atm
        .trust_tasks()
        .config_show(&user.profile, Some(vec![key.to_string()]))
        .await
        .expect("config/show");
    serde_json::to_value(&fields.fields[0]).unwrap()
}

/// A live key takes effect at once; a restart-gated one is stored for the next
/// start; a bad or unknown one is refused with its reason — each on its own.
#[tokio::test]
async fn a_root_admin_patches_limits_and_each_key_is_answered() {
    use affinidi_messaging_sdk::messages::{DeleteMessageRequest, fetch::FetchOptions};

    let env = direct_env().await;
    let alice = env.add_user("alice").await.expect("alice");
    let bob = env.add_user("bob").await.expect("bob");
    let root = promoted(&env, "root", AccountType::RootAdmin).await;
    send_direct(&env, &alice, &bob).await;
    send_direct(&env, &alice, &bob).await;

    let answer = patch(
        &env,
        &root,
        json!({
            "limits.deleted_messages": 1,
            "limits.rate_limit_per_ip": 50,
            "limits.queued_send_messages_hard": 1,
            "limits.listed_messages": 100_000,
            "limits.message_size": 10,
            "security.use_ssl": true,
        }),
    )
    .await
    .expect("config/patch");
    assert_eq!(answer["applied"], json!(["limits.deleted_messages"]));
    assert_eq!(
        answer["pendingRestart"],
        json!(["limits.rate_limit_per_ip"])
    );
    let rejected: Vec<&str> = answer["rejected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["key"].as_str().unwrap())
        .collect();
    assert_eq!(rejected.len(), 4, "{answer}");
    for key in [
        "limits.queued_send_messages_hard", // below its soft limit
        "limits.listed_messages",           // looser than configured
        "limits.message_size",              // not patchable
        "security.use_ssl",                 // not a limit
    ] {
        assert!(rejected.contains(&key), "{key} must be rejected: {answer}");
    }

    // The live change is enforced now: bob may delete one message per request.
    let ids: Vec<String> = env
        .atm
        .fetch_messages(&bob.profile, &FetchOptions::default())
        .await
        .expect("fetch")
        .success
        .iter()
        .map(|m| m.msg_id.clone())
        .collect();
    assert_eq!(ids.len(), 2);
    let too_many = env
        .atm
        .delete_messages_direct(
            &bob.profile,
            &DeleteMessageRequest {
                message_ids: ids.clone(),
            },
        )
        .await;
    assert!(too_many.is_err(), "two ids exceed the patched limit of one");

    // config/show reports the override, live.
    let field = shown(&env, &root, "limits.deleted_messages").await;
    assert_eq!(field["value"], 1);
    assert_eq!(field["source"], "override");
    assert_eq!(field["requiresRestart"], false);
    let field = shown(&env, &root, "limits.rate_limit_per_ip").await;
    assert_eq!(field["requiresRestart"], true);

    // null removes the override: the limit is back to the configured value.
    patch(&env, &root, json!({ "limits.deleted_messages": null }))
        .await
        .expect("reset");
    env.atm
        .delete_messages_direct(&bob.profile, &DeleteMessageRequest { message_ids: ids })
        .await
        .expect("two ids are within the configured limit again");
    assert_eq!(
        shown(&env, &root, "limits.deleted_messages").await["source"],
        "mediator"
    );

    // Every patch is on the record.
    let audit = format!(
        "{:?}",
        env.atm
            .trust_tasks()
            .audit_list(&root.profile, None, None)
            .await
            .expect("audit")
    );
    assert!(audit.contains("configPatch"), "{audit}");
}

/// Changing the mediator for every account is a rootAdmin's call.
#[tokio::test]
async fn an_admin_may_not_patch_the_configuration() {
    let env = direct_env().await;
    let admin = promoted(&env, "admin", AccountType::Admin).await;
    let refused = patch(&env, &admin, json!({ "limits.deleted_messages": 1 })).await;
    assert!(refused.is_err(), "{refused:?}");
}

/// A stored override is applied when the mediator next starts on the same
/// store, restart-gated keys included.
#[tokio::test]
async fn a_patch_survives_a_restart() {
    use affinidi_messaging_test_mediator::TestMediator;

    let first = direct_env().await;
    let root = promoted(&first, "root", AccountType::RootAdmin).await;
    patch(
        &first,
        &root,
        json!({ "limits.listed_messages": 7, "limits.rate_limit_per_ip": 32 }),
    )
    .await
    .expect("patch");
    let store = first.mediator.store();
    first.shutdown().await.expect("shutdown");

    let second = TestEnvironment::new(
        TestMediator::builder()
            .local_direct_delivery(true, false)
            .store(store)
            .spawn()
            .await
            .expect("restart on the same store"),
    )
    .await
    .expect("environment");
    let root = promoted(&second, "root2", AccountType::RootAdmin).await;
    let listed = shown(&second, &root, "limits.listed_messages").await;
    assert_eq!(listed["value"], 7);
    assert_eq!(listed["source"], "override");
    assert_eq!(
        shown(&second, &root, "limits.rate_limit_per_ip").await["value"],
        32,
        "a restart-gated override is in force after the restart"
    );
}

/// `messaging/message/status`: a sender learns, on evidence, which of its
/// messages its recipient collected — and nobody else learns anything.
#[tokio::test]
async fn a_sender_learns_which_of_its_messages_were_collected() {
    use trust_tasks_rs::specs::messaging::message::status::v0_1::MessageState;

    let env = direct_env().await;
    let alice = env.add_user("alice").await.expect("alice");
    let bob = env.add_user("bob").await.expect("bob");
    env.atm
        .profile_add(&bob.profile, true)
        .await
        .expect("bob live");
    // Sent before Alice's live stream is on, so each send goes over REST and
    // returns once the mediator has stored the message. Over the websocket a
    // send returns on writing the frame, and the listing below could run
    // before the second message is stored.
    send_direct(&env, &alice, &bob).await;
    send_direct(&env, &alice, &bob).await;
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("alice live");
    let ids = receive_ids(&env, &bob).await;
    assert_eq!(ids.len(), 2);

    let states = |user: &TestUser| {
        let (env, profile, ids) = (&env, user.profile.clone(), ids.clone());
        async move {
            env.atm
                .trust_tasks()
                .message_status(&profile, &ids)
                .await
                .expect("message status")
                .statuses
                .into_iter()
                .map(|s| s.state)
                .collect::<Vec<_>>()
        }
    };

    assert_eq!(
        states(&alice).await,
        vec![MessageState::Queued, MessageState::Queued]
    );
    // Bob holds them, but did not send them.
    assert_eq!(
        states(&bob).await,
        vec![MessageState::Unknown, MessageState::Unknown]
    );

    // Bob takes the first; Alice withdraws the second.
    env.atm
        .trust_tasks()
        .message_delete(&bob.profile, None, &ids[..1])
        .await
        .expect("bob removes the first");
    env.atm
        .trust_tasks()
        .message_delete(&alice.profile, None, &ids[1..])
        .await
        .expect("alice withdraws the second");

    assert_eq!(
        states(&alice).await,
        vec![MessageState::Collected, MessageState::Withdrawn]
    );
    assert_eq!(
        states(&bob).await,
        vec![MessageState::Unknown, MessageState::Unknown],
        "the receipts are alice's alone"
    );

    // The same answer through the transport the delivery layer reads it from,
    // keyed by the id each status names.
    use affinidi_messaging_core::{MessageTransport, OutboxStatus};
    let transport = affinidi_messaging_sdk::transport_adapter::DidCommTransport::new(
        env.atm.clone(),
        alice.profile.clone(),
    )
    .await
    .expect("alice's transport");
    let reported = transport
        .outbox_status(&ids)
        .await
        .expect("outbox status")
        .expect("the mediator keeps receipts");
    assert_eq!(reported.get(&ids[0]), Some(&OutboxStatus::Collected));
    assert_eq!(reported.get(&ids[1]), Some(&OutboxStatus::Withdrawn));
}
