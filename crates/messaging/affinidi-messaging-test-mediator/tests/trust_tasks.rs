//! End-to-end Trust Tasks round-trip: the SDK sends a `messaging/ping` Trust Task
//! to a live mediator over the DIDComm binding envelope; the mediator consumes it
//! through the Trust Tasks framework and returns a typed `ping` response.
//!
//! Exercises the whole path — `atm.trust_tasks().ping()` → pack + `/inbound` →
//! the mediator's `trust_tasks` consumer → response → the SDK's typed reply — over
//! a real in-process HTTP mediator (memory backend, no Redis).

use affinidi_messaging_mediator::common::config::limits::LimitsConfig;
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
        .account_list(&alice.profile, None, None, None)
        .await;
    assert!(denied.is_err(), "a non-admin must not list accounts");
}

#[tokio::test]
async fn account_update_queue_limits_self_applies_caps_and_persists() {
    use trust_tasks_rs::specs::messaging::account::update::v0_1::QueueLimits;

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
        .account_update(
            &alice.profile,
            None,
            None,
            None,
            Some(
                QueueLimits::builder()
                    .send_queue_limit(Some(42))
                    .receive_queue_limit(Some(-1))
                    .try_into()
                    .expect("QueueLimits has no required member"),
            ),
        )
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

    // A standard account's request above the hard maximum is capped.
    //
    // The maximum is read from the mediator's own default config rather than
    // written here as a literal: this assertion previously pinned 1000, and
    // silently became a no-op assertion about an *accepted* value the moment
    // the default moved. Asking for `hard + 1` keeps the request above the cap
    // whatever the cap becomes.
    // `i64` to match the wire type; the config carries it as `i32`.
    let hard = i64::from(LimitsConfig::default().queued_send_messages_hard);
    let capped = env
        .atm
        .trust_tasks()
        .account_update(
            &alice.profile,
            None,
            None,
            None,
            Some(
                QueueLimits::builder()
                    .send_queue_limit(Some(hard + 1))
                    .try_into()
                    .expect("QueueLimits has no required member"),
            ),
        )
        .await
        .expect("over-limit request is accepted but capped");
    assert_eq!(
        capped.queue_limits.and_then(|q| q.send_queue_limit),
        Some(hard),
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
async fn account_update_role_denies_a_non_admin() {
    use trust_tasks_rs::specs::messaging::account::update::v0_1::AccountType;

    // A role change through `account/update` is admin-only. A standard account
    // must be refused.
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
        .account_update(
            &alice.profile,
            Some(bob.did_hash()),
            Some(AccountType::Admin),
            None,
            None,
        )
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
async fn account_update_acl_denies_a_non_admin() {
    use trust_tasks_rs::specs::messaging::account::update::v0_1::MediatorAcl;

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

    let acl: MediatorAcl = MediatorAcl::builder()
        .blocked(Some(true))
        .try_into()
        .expect("MediatorAcl has no required member");
    let denied = env
        .atm
        .trust_tasks()
        .account_update(&alice.profile, Some(bob.did_hash()), None, Some(acl), None)
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
        .access_list_update(
            &alice.profile,
            None,
            false,
            vec![bob.did_hash(), carol.did_hash()],
            vec![],
        )
        .await
        .expect("add to access list");
    assert_eq!(added.added.len(), 2);
    assert_eq!(added.access_list_count, 2);

    // Membership filter (the retired access-list/get): bob is present, an unknown
    // hash is absent from the filtered entries.
    let got = env
        .atm
        .trust_tasks()
        .access_list_list(
            &alice.profile,
            None,
            None,
            None,
            Some(vec![bob.did_hash(), "not-in-the-list".to_string()]),
        )
        .await
        .expect("query access list membership");
    assert!(got.entries.iter().any(|v| v.as_str() == bob.did_hash()));
    assert!(!got.entries.iter().any(|v| v.as_str() == "not-in-the-list"));
    assert_eq!(got.access_list_count, 2, "count stays the whole-list total");

    // List: both entries, single page.
    let listed = env
        .atm
        .trust_tasks()
        .access_list_list(&alice.profile, None, None, None, None)
        .await
        .expect("list access list");
    assert_eq!(listed.access_list_count, 2);
    assert_eq!(listed.entries.len(), 2);
    assert!(listed.next_cursor.is_none());

    // Remove bob.
    let removed = env
        .atm
        .trust_tasks()
        .access_list_update(&alice.profile, None, false, vec![], vec![bob.did_hash()])
        .await
        .expect("remove from access list");
    assert_eq!(removed.removed.len(), 1);
    assert_eq!(removed.access_list_count, 1);

    // Clear.
    let cleared = env
        .atm
        .trust_tasks()
        .access_list_update(&alice.profile, None, true, vec![], vec![])
        .await
        .expect("clear access list");
    assert_eq!(cleared.access_list_count, 0);
}

#[tokio::test]
async fn audit_and_config_readers_deny_a_non_admin() {
    // The generic audit/list and config/show consumers (which replaced the
    // retired messaging/admin/* readers) are admin-only. A standard account must
    // be refused for both. (Role grants/strips are account/update, whose
    // non-admin denial is covered above; admin/list is the accountType filter on
    // account/list, whose non-admin denial is covered above too.)
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");

    assert!(
        env.atm
            .trust_tasks()
            .audit_list(&alice.profile, None, None)
            .await
            .is_err(),
        "non-admin audit/list must be refused"
    );
    assert!(
        env.atm
            .trust_tasks()
            .config_show(&alice.profile, None)
            .await
            .is_err(),
        "non-admin config/show must be refused"
    );
}

#[tokio::test]
async fn account_update_acl_self_service_changes_a_self_manageable_flag() {
    use trust_tasks_rs::specs::messaging::account::update::v0_1::MediatorAcl;

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
    let acl: MediatorAcl = MediatorAcl::builder()
        .anon_receive(Some(false))
        .try_into()
        .expect("MediatorAcl has no required member");
    let updated = env
        .atm
        .trust_tasks()
        .account_update(&alice.profile, None, None, Some(acl), None)
        .await
        .expect("alice self-manages her own ACL");
    assert_eq!(updated.acl.anon_receive, Some(false));

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
async fn account_update_acl_self_service_refuses_an_admin_only_flag() {
    use trust_tasks_rs::specs::messaging::account::update::v0_1::MediatorAcl;

    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");

    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");

    // `blocked` is admin-only — alice may not set it even on her own account.
    let acl: MediatorAcl = MediatorAcl::builder()
        .blocked(Some(true))
        .try_into()
        .expect("MediatorAcl has no required member");
    let denied = env
        .atm
        .trust_tasks()
        .account_update(&alice.profile, None, None, Some(acl), None)
        .await;
    assert!(
        denied.is_err(),
        "a non-admin may not change an admin-only flag"
    );
}

#[tokio::test]
async fn a_signed_task_is_accepted_when_the_mediator_enforces_proofs() {
    // With `trust_task_verification = enforce`, a proof-required task from the
    // SDK must still succeed: the SDK stamps `issuedAt` and signs with the
    // profile's Ed25519 key, and the mediator verifies that proof against the
    // profile's DID document. If either side drifted, this refuses with
    // `message.trust_task.proof_required` / `proof_invalid`.
    use affinidi_messaging_test_mediator::{TestMediator, TrustTaskVerification};
    use trust_tasks_rs::specs::messaging::account::update::v0_1::QueueLimits;

    let mediator = TestMediator::builder()
        .trust_task_verification(TrustTaskVerification::Enforce)
        .spawn()
        .await
        .expect("spawn enforcing mediator");
    let env = TestEnvironment::new(mediator)
        .await
        .expect("wire the SDK to the mediator");

    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");

    let updated = env
        .atm
        .trust_tasks()
        .account_update(
            &alice.profile,
            None,
            None,
            None,
            Some(
                QueueLimits::builder()
                    .send_queue_limit(Some(7))
                    .try_into()
                    .expect("QueueLimits has no required member"),
            ),
        )
        .await
        .expect("a signed, fresh account/update is accepted under enforce");
    assert_eq!(
        updated.queue_limits.and_then(|q| q.send_queue_limit),
        Some(7)
    );
}

#[tokio::test]
async fn a_trust_task_response_is_signed_by_the_mediator() {
    // Send a Trust Task by hand so the raw response body is visible, then
    // verify its proof over the JSON exactly as received, against the
    // mediator's own DID document.
    use affinidi_data_integrity::VerifyOptions;
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use affinidi_messaging_didcomm::message::Message;
    use affinidi_messaging_sdk::protocols::trust_tasks::ENVELOPE_TYPE;
    use affinidi_messaging_sdk::transports::SendMessageResponse;
    use std::sync::Arc;
    use trust_tasks_proof::affinidi::{
        CachedDidResolver, ProofPurpose, PurposeBound, parse_data_integrity_proof,
    };

    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");
    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");
    let mediator_did = env.mediator.did().to_string();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let task = serde_json::json!({
        "id": "urn:uuid:7c1e0a1e-0000-4000-8000-000000000042",
        "type": "https://trusttasks.org/spec/messaging/ping/0.1",
        "issuer": alice.did,
        "recipient": mediator_did,
        "payload": { "nonce": "signed-response" },
    });
    let msg = Message::build(
        "urn:uuid:7c1e0a1e-0000-4000-8000-0000000000ff".to_string(),
        ENVELOPE_TYPE.to_string(),
        task,
    )
    .to(mediator_did.clone())
    .from(alice.did.clone())
    .created_time(now)
    .expires_time(now + 60)
    .finalize();
    let msg_id = msg.id.clone();
    let (packed, _) = env
        .atm
        .pack_encrypted(&msg, &mediator_did, Some(&alice.did), None)
        .await
        .expect("authcrypt the ping");

    let SendMessageResponse::Message(reply) = env
        .atm
        .send_message(&alice.profile, &packed, &msg_id, true, true)
        .await
        .expect("mediator answers the ping")
    else {
        panic!("expected a response message");
    };
    let body = reply.body;

    assert_eq!(body["issuer"].as_str(), Some(mediator_did.as_str()));
    let proof = parse_data_integrity_proof(body.get("proof").expect("the response is signed"))
        .expect("a Data Integrity proof");
    assert_eq!(
        proof.verification_method.split('#').next(),
        Some(mediator_did.as_str()),
        "signed with the mediator's own key"
    );

    let mut unsigned = body.as_object().unwrap().clone();
    unsigned.remove("proof");
    // Bound to the purpose the proof declares, so the mediator's key must be
    // listed under that relationship in its DID document.
    let resolver = PurposeBound::new(
        CachedDidResolver::new(Arc::new(
            DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
                .await
                .unwrap(),
        )),
        ProofPurpose::parse(&proof.proof_purpose).expect("a known proofPurpose"),
    );
    proof
        .verify(
            &serde_json::Value::Object(unsigned),
            &resolver,
            VerifyOptions::new(),
        )
        .await
        .expect("the response proof verifies against the mediator DID");
}

#[tokio::test]
async fn request_response_survives_a_concurrent_live_stream_reader() {
    // A console reads its live stream (monitor events, pushed messages) while it
    // makes request/response Trust Task calls on the same connection. The reply
    // to a call must reach that call, not the reader: `send_message` registers
    // interest in the reply before transmitting, and the websocket task offers
    // an inbound message to a registered reply before any pending `next`.
    // Registering after transmitting let a fast reply fall to the reader, and
    // the call timed out ten seconds later.
    let env = TestEnvironment::spawn()
        .await
        .expect("spawn test environment");
    let alice = env.add_user("alice").await.expect("add alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("enable websocket for alice");

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = {
        let atm = env.atm.clone();
        let profile = alice.profile.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut stolen = Vec::new();
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                // Unsolicited traffic (e.g. the pickup `status` sent when live
                // delivery is enabled) is the reader's to take; a Trust Task
                // reply is not.
                if let Ok(Some((m, _))) = atm
                    .message_pickup()
                    .live_stream_next(&profile, Some(std::time::Duration::from_millis(100)), false)
                    .await
                    && m.typ == affinidi_messaging_sdk::protocols::trust_tasks::ENVELOPE_TYPE
                {
                    stolen.push(format!("{} thid={:?}", m.typ, m.thid));
                }
            }
            stolen
        })
    };

    for i in 0..20 {
        let started = std::time::Instant::now();
        env.atm
            .trust_tasks()
            .account_get(&alice.profile, None)
            .await
            .unwrap_or_else(|e| panic!("call {i} lost its reply to the live-stream reader: {e:?}"));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "call {i} only completed after a timeout"
        );
    }

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let stolen = reader.await.expect("reader task");
    assert!(
        stolen.is_empty(),
        "no reply was handed to the reader: {stolen:?}"
    );
}
