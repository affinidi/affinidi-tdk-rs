//! End-to-end Trust Tasks round-trip: the SDK sends a `messaging/ping` Trust Task
//! to a live mediator over the DIDComm binding envelope; the mediator consumes it
//! through the Trust Tasks framework and returns a typed `ping` response.
//!
//! Exercises the whole path — `atm.trust_tasks().ping()` → pack + `/inbound` →
//! the mediator's `trust_tasks` consumer → response → the SDK's typed reply — over
//! a real in-process HTTP mediator (memory backend, no Redis).

use affinidi_messaging_test_mediator::TestEnvironment;

#[tokio::test]
async fn ping_trust_task_round_trips_through_the_mediator() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    // Enable the WebSocket live-stream so the synchronous request/response
    // (`send_message` with wait) can correlate the reply by thread id.
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");

    let response = env
        .atm
        .trust_tasks()
        .ping(&alice.profile, Some("nonce-42".to_string()))
        .await
        .expect("alice pings the mediator via a Trust Task");

    // The mediator reports healthy, echoes the nonce, and advertises the protocols
    // it speaks — all from the typed response, no message inspection by the caller.
    assert_eq!(response.status.to_string(), "ok");
    assert_eq!(response.nonce.as_deref(), Some("nonce-42"));
    assert!(
        response.protocols.iter().any(|p| p == "didcomm"),
        "advertises DIDComm: {:?}",
        response.protocols
    );
    assert!(
        response.protocols.iter().any(|p| p == "tsp"),
        "advertises TSP: {:?}",
        response.protocols
    );
}

#[tokio::test]
async fn account_get_self_returns_the_callers_account() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");

    // Alice fetches her OWN account — self-authorized, no admin rights needed.
    let account = env
        .atm
        .trust_tasks()
        .account_get(&alice.profile, None)
        .await
        .expect("alice reads her own account");

    // Identity is carried as the mediator's account hash (a valid Vid per the
    // messaging spec's privacy note), and the decoded view matches a standard
    // allow-all account as minted by `add_user`.
    assert_eq!(account.did.as_str(), alice.did_hash().as_str());
    assert_eq!(account.account_type.to_string(), "standard");
    assert_eq!(account.acl.send_messages, Some(true));
    assert_eq!(account.acl.receive_messages, Some(true));
}

#[tokio::test]
async fn account_list_denies_a_non_admin() {
    // `account/list` is admin-only. A standard account must be refused — the
    // mediator returns an error rather than leaking the account listing.
    //
    // (The admin happy-path listing isn't exercised here: an `add_admin` identity
    // authenticates by DID resolution but isn't a streaming-registered account, so
    // the synchronous WebSocket response path can't be established on the in-memory
    // harness. The account view itself round-trips end-to-end via the `account/get`
    // test above — `account/list` reuses the very same mapping.)
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");

    let denied = env
        .atm
        .trust_tasks()
        .account_list(&alice.profile, None, None)
        .await;
    assert!(denied.is_err(), "a non-admin must not list accounts");
}

#[tokio::test]
async fn account_change_queue_limits_self_applies_caps_and_persists() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");

    // Alice self-manages her queue limits (allow_all). A normal value is applied;
    // `-1` means unlimited.
    let updated = env
        .atm
        .trust_tasks()
        .account_change_queue_limits(&alice.profile, None, Some(42), Some(-1))
        .await
        .expect("alice changes her own queue limits");
    let q = updated.queue_limits.expect("queue limits present");
    assert_eq!(q.send_queue_limit, Some(42));
    assert_eq!(q.receive_queue_limit, Some(-1));

    // Persisted across a fresh read.
    let account = env
        .atm
        .trust_tasks()
        .account_get(&alice.profile, None)
        .await
        .expect("re-read alice's account");
    assert_eq!(
        account.queue_limits.and_then(|q| q.send_queue_limit),
        Some(42)
    );

    // A standard account's request above the hard maximum (1000) is capped.
    let capped = env
        .atm
        .trust_tasks()
        .account_change_queue_limits(&alice.profile, None, Some(5000), None)
        .await
        .expect("over-limit request is accepted but capped");
    assert_eq!(
        capped.queue_limits.and_then(|q| q.send_queue_limit),
        Some(1000),
        "a standard account is capped at the hard maximum"
    );
}

#[tokio::test]
async fn account_remove_self_removes_the_account() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");

    // Sanity: alice's account exists.
    env.atm
        .trust_tasks()
        .account_get(&alice.profile, None)
        .await
        .expect("alice's account exists before removal");

    // Alice removes her own account (self-authorized); the store reports a record
    // was removed. (We don't assert a follow-up read fails: the mediator
    // re-registers the sender's account on her next authenticated request, so alice
    // sending anything else would re-create it — the removal itself is the contract.)
    let removed = env
        .atm
        .trust_tasks()
        .account_remove(&alice.profile, None)
        .await
        .expect("alice removes her own account");
    assert!(removed, "a record should have been removed");
}

#[tokio::test]
async fn account_change_type_denies_a_non_admin() {
    use trust_tasks_rs::specs::messaging::account::change_type::v0_1::AccountType;

    // `account/change-type` is admin-only. A standard account must be refused.
    // (The admin happy-path — promotion/demotion across the admin set — isn't driven
    // here: an admin authenticates by DID resolution but isn't a streaming-registered
    // account, so the synchronous WebSocket response can't be established on the
    // in-memory harness. The handler is a faithful port of the legacy admin-set logic.)
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");
    let bob = env.add_user("bob").await.expect("add bob");

    let denied = env
        .atm
        .trust_tasks()
        .account_change_type(&alice.profile, bob.did_hash(), AccountType::Admin)
        .await;
    assert!(denied.is_err(), "a non-admin must not change account types");
}

#[tokio::test]
async fn acl_get_self_returns_the_decoded_acl() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");

    let page = env
        .atm
        .trust_tasks()
        .acl_get(&alice.profile, vec![alice.did_hash()])
        .await
        .expect("alice reads her own ACL");

    assert!(page.unknown.is_empty(), "alice's account is known");
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].did.as_str(), alice.did_hash());
    // add_user grants allow_all → the decoded flags reflect it.
    assert_eq!(page.entries[0].acl.send_messages, Some(true));
    assert_eq!(page.entries[0].acl.receive_messages, Some(true));
}

#[tokio::test]
async fn acl_set_denies_a_non_admin() {
    use trust_tasks_rs::specs::messaging::acl::set::v0_1::MediatorAcl;

    // A non-admin may set its *own* ACL (self-service, covered below), but never
    // another account's. (The reverse mapping is covered by the mediator's
    // `acl_reverse_map_round_trips` unit test.)
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");
    let bob = env.add_user("bob").await.expect("add bob");

    let acl = MediatorAcl {
        blocked: Some(true),
        ..Default::default()
    };
    let denied = env
        .atm
        .trust_tasks()
        .acl_set(&alice.profile, bob.did_hash(), acl)
        .await;
    assert!(denied.is_err(), "a non-admin must not set ACLs");
}

#[tokio::test]
async fn account_add_self_register_creates_a_standard_account() {
    use trust_tasks_rs::specs::messaging::account::add::v0_1::AccountType;

    // The fixture defaults to `ExplicitDeny`, so a standard account may add accounts.
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");

    let new_hash = "tt-add-standard-account".to_string();
    let account = env
        .atm
        .trust_tasks()
        .account_add(
            &alice.profile,
            new_hash.clone(),
            AccountType::Standard,
            None,
        )
        .await
        .expect("alice adds a new standard account");

    assert_eq!(account.did.as_str(), new_hash);
    assert_eq!(account.account_type.to_string(), "standard");
}

#[tokio::test]
async fn account_add_denies_a_non_admin_creating_an_admin() {
    use trust_tasks_rs::specs::messaging::account::add::v0_1::AccountType;

    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");

    let denied = env
        .atm
        .trust_tasks()
        .account_add(
            &alice.profile,
            "tt-add-admin-attempt".to_string(),
            AccountType::Admin,
            None,
        )
        .await;
    assert!(
        denied.is_err(),
        "a non-admin must not create an admin account"
    );
}

#[tokio::test]
async fn access_list_self_lifecycle() {
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");
    let bob = env.add_user("bob").await.expect("add bob");
    let carol = env.add_user("carol").await.expect("add carol");

    // Add bob + carol to alice's own access list (allow_all grants self-manage).
    let added = env
        .atm
        .trust_tasks()
        .access_list_add(&alice.profile, None, vec![bob.did_hash(), carol.did_hash()])
        .await
        .expect("add to access list");
    assert_eq!(added.added.len(), 2);
    assert_eq!(added.access_list_count, 2);

    // Get: bob is present, an unknown hash is absent.
    let got = env
        .atm
        .trust_tasks()
        .access_list_get(
            &alice.profile,
            None,
            vec![bob.did_hash(), "not-in-the-list".to_string()],
        )
        .await
        .expect("query access list");
    assert!(got.present.iter().any(|v| v.as_str() == bob.did_hash()));
    assert!(got.absent.iter().any(|v| v.as_str() == "not-in-the-list"));

    // List: both entries, single page.
    let listed = env
        .atm
        .trust_tasks()
        .access_list_list(&alice.profile, None, None, None)
        .await
        .expect("list access list");
    assert_eq!(listed.access_list_count, 2);
    assert_eq!(listed.entries.len(), 2);
    assert!(listed.next_cursor.is_none());

    // Remove bob.
    let removed = env
        .atm
        .trust_tasks()
        .access_list_remove(&alice.profile, None, vec![bob.did_hash()])
        .await
        .expect("remove from access list");
    assert_eq!(removed.removed.len(), 1);
    assert_eq!(removed.access_list_count, 1);

    // Clear.
    let cleared = env
        .atm
        .trust_tasks()
        .access_list_clear(&alice.profile, None)
        .await
        .expect("clear access list");
    assert_eq!(cleared.access_list_count, 0);
}

#[tokio::test]
async fn admin_family_denies_a_non_admin() {
    // Every messaging/admin/* task is admin-only. A standard account must be refused
    // for all of them. (The admin happy paths aren't exercised: an add_admin identity
    // isn't a streaming-registered account, so admin-over-WS doesn't run on the
    // in-memory harness — the handlers mirror the legacy admin-management protocol.)
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");
    let bob = env.add_user("bob").await.expect("add bob");

    assert!(
        env.atm
            .trust_tasks()
            .admin_add(&alice.profile, vec![bob.did_hash()])
            .await
            .is_err(),
        "non-admin admin/add must be refused"
    );
    assert!(
        env.atm
            .trust_tasks()
            .admin_strip(&alice.profile, vec![bob.did_hash()])
            .await
            .is_err(),
        "non-admin admin/strip must be refused"
    );
    assert!(
        env.atm
            .trust_tasks()
            .admin_list(&alice.profile, None, None)
            .await
            .is_err(),
        "non-admin admin/list must be refused"
    );
    assert!(
        env.atm
            .trust_tasks()
            .admin_audit_log(&alice.profile, None, None)
            .await
            .is_err(),
        "non-admin admin/audit-log must be refused"
    );
    assert!(
        env.atm
            .trust_tasks()
            .admin_config(&alice.profile)
            .await
            .is_err(),
        "non-admin admin/config must be refused"
    );
}

#[tokio::test]
async fn acl_set_self_service_changes_a_self_manageable_flag() {
    use trust_tasks_rs::specs::messaging::acl::set::v0_1::MediatorAcl;

    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");

    // allow_all grants alice the self-change bits, so she may change her own
    // `anonReceive` (a self-manageable capability) from true to false.
    let acl = MediatorAcl {
        anon_receive: Some(false),
        ..Default::default()
    };
    let updated = env
        .atm
        .trust_tasks()
        .acl_set(&alice.profile, alice.did_hash(), acl)
        .await
        .expect("alice self-manages her own ACL");
    assert_eq!(updated.anon_receive, Some(false));

    // Persisted across a fresh read.
    let got = env
        .atm
        .trust_tasks()
        .acl_get(&alice.profile, vec![alice.did_hash()])
        .await
        .expect("re-read alice's ACL");
    assert_eq!(got.entries[0].acl.anon_receive, Some(false));
}

#[tokio::test]
async fn acl_set_self_service_refuses_an_admin_only_flag() {
    use trust_tasks_rs::specs::messaging::acl::set::v0_1::MediatorAcl;

    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");

    // `blocked` is admin-only — alice may not set it even on her own account.
    let acl = MediatorAcl {
        blocked: Some(true),
        ..Default::default()
    };
    let denied = env
        .atm
        .trust_tasks()
        .acl_set(&alice.profile, alice.did_hash(), acl)
        .await;
    assert!(
        denied.is_err(),
        "a non-admin may not change an admin-only flag"
    );
}
