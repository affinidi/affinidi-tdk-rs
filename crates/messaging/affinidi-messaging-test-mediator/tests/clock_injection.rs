//! TI4b-1 — the injected clock governs token-expiry validation end-to-end.
//!
//! Authenticate against an embedded mediator wired with a [`TestClock`], then
//! advance that clock past the token's lifetime — *no real time passes* — and
//! confirm the mediator now rejects the previously-valid token. This is the
//! fast, deterministic alternative to sleeping out a real expiry window.

mod common;

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_sdk::messages::Folder;
use affinidi_messaging_test_mediator::{TestClock, TestEnvironment, TestMediator};
use common::init_tracing;

#[tokio::test]
async fn access_token_expires_against_the_injected_clock() {
    init_tracing();

    // Seed the mediator's clock from real time so a freshly-issued token still
    // looks valid to the SDK client (which reads the real wall clock). Clones of
    // a TestClock share their time, so advancing `clock` advances the mediator's.
    let clock = TestClock::now();
    let access = Duration::from_secs(300);
    let refresh = Duration::from_secs(1_800);

    let mediator = TestMediator::builder()
        .clock(Arc::new(clock.clone()))
        .jwt_expiry(access, refresh)
        .spawn()
        .await
        .expect("spawn mediator with an injected clock");
    let env = TestEnvironment::new(mediator)
        .await
        .expect("wire test environment");
    let alice = env.add_user("Alice").await.expect("add Alice");

    // Fresh token: an authenticated REST call succeeds.
    env.atm
        .list_messages(&alice.profile, Folder::Inbox)
        .await
        .expect("authenticated call succeeds with a fresh token");

    // Advance ONLY the mediator clock past BOTH the access and refresh
    // lifetimes (+ the 60s validation leeway). Past refresh expiry too, so the
    // call fails whether the SDK reuses the cached token or tries to refresh it.
    clock.advance_secs(refresh.as_secs() + 60 + 5);

    // The same authenticated call is now rejected: the token the mediator issued
    // is expired against the advanced clock.
    let result = env.atm.list_messages(&alice.profile, Folder::Inbox).await;
    assert!(
        result.is_err(),
        "the access token must be rejected once the injected clock passes its expiry"
    );

    env.shutdown().await.expect("shutdown");
}
