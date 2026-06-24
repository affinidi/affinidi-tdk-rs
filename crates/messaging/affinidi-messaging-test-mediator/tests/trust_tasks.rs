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
