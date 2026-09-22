//! The legacy admin surface is served while `security.legacy_admin_protocols`
//! is `warn` (the default), and refused when it is `off`, while the Trust Tasks
//! that replace it keep working.

#![allow(deprecated)] // the legacy SDK calls under test are deprecated

use affinidi_messaging_test_mediator::{LegacyAdminProtocols, TestEnvironment, TestMediator};

async fn env(mode: Option<LegacyAdminProtocols>) -> TestEnvironment {
    let mut builder = TestMediator::builder();
    if let Some(mode) = mode {
        builder = builder.legacy_admin_protocols(mode);
    }
    TestEnvironment::new(builder.spawn().await.expect("mediator"))
        .await
        .expect("environment")
}

#[tokio::test]
async fn by_default_the_legacy_surface_is_still_served() {
    let env = env(None).await;
    let alice = env.add_user("alice").await.expect("alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("alice live");

    let own = env
        .atm
        .mediator()
        .account_get(&alice.profile, None)
        .await
        .expect("legacy account-management answers");
    assert!(own.is_some());
    env.atm
        .queue_status(&alice.profile)
        .await
        .expect("legacy GET /queue/status answers");
}

#[tokio::test]
async fn switched_off_the_legacy_surface_is_refused_and_trust_tasks_are_not() {
    let env = env(Some(LegacyAdminProtocols::Off)).await;
    let alice = env.add_user("alice").await.expect("alice");
    env.atm
        .profile_add(&alice.profile, true)
        .await
        .expect("alice live");

    let started = std::time::Instant::now();
    let refused = env
        .atm
        .mediator()
        .account_get(&alice.profile, None)
        .await
        .expect_err("legacy account-management is refused");
    assert!(
        refused.to_string().contains("legacy_admin.disabled"),
        "{refused}"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "answered with the refusal, not a timeout"
    );
    assert!(
        env.atm.queue_status(&alice.profile).await.is_err(),
        "legacy GET /queue/status is refused"
    );

    env.atm
        .trust_tasks()
        .account_get(&alice.profile, None)
        .await
        .expect("the Trust Task that replaces it still answers");
}
