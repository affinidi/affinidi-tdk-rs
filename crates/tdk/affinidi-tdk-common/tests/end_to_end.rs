//! End-to-end integration test for `affinidi-tdk-common`.
//!
//! Exercises the public API as a downstream consumer would:
//! [`TDKConfig::builder`] → [`TDKSharedState::new`] → `add_profile` →
//! `KeyringStore` → `shutdown`. The keyring default store is set to the
//! `keyring_core` mock so the test does not write to the host OS keychain.

use affinidi_secrets_resolver::SecretsResolver;
use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk_common::{
    TDKSharedState,
    config::TDKConfig,
    environments::TDKEnvironment,
    profiles::TDKProfile,
    secrets::{KeyringStore, init_keyring},
};
use keyring_core::mock::Store as MockStore;
use std::sync::Mutex;

/// `keyring_core::set_default_store` is process-global; serialise even
/// across a single integration-test binary.
static SERIALISE: Mutex<()> = Mutex::new(());

// `_g` is held across `.await` points. Safe here because:
// - This is the only mutex this test acquires (no nested locks → no
//   ordering-deadlock risk),
// - The lock is purely for `keyring_core::set_default_store` ordering;
//   no work happens while waiting,
// - Tests run sequentially via this mutex by design.
// `tokio::sync::Mutex` would also work but adds an unnecessary
// async-aware lock for a sync state-mutation guard.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn full_lifecycle_via_public_api() {
    let _g = SERIALISE.lock().unwrap();
    keyring_core::set_default_store(MockStore::new().unwrap());

    // Build a state without touching disk for environment loading.
    let config = TDKConfig::builder()
        .with_load_environment(false)
        .with_environment(TDKEnvironment::default())
        .build()
        .expect("config builds");
    let state = TDKSharedState::new(config).await.expect("state builds");

    // Add a profile with a secret; resolver should be able to find it.
    let kid = "did:example:e2e#key-1";
    let secret = Secret::generate_ed25519(Some(kid), Some(&[3u8; 32]));
    let profile = TDKProfile::new(
        "e2e",
        "did:example:e2e",
        Some("did:web:mediator.example"),
        vec![secret.clone()],
    );
    state.add_profile(&profile).await;
    assert!(
        state.secrets_resolver().get_secret(kid).await.is_some(),
        "resolver returns the inserted secret",
    );

    // KeyringStore round-trip via the mock.
    init_keyring().expect("init_keyring respects mock-store registration");
    let store = KeyringStore::new("tdk-e2e");
    store.save(&profile.did, profile.secrets()).expect("save");
    let loaded = store.read(&profile.did).expect("read");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].id, secret.id);
    store.delete(&profile.did).expect("delete");

    // resolve_mediator: profile-mediator wins.
    assert_eq!(
        state.resolve_mediator(&profile),
        Some("did:web:mediator.example")
    );

    state.shutdown().await;
}

/// Smoke test for `affinidi_tdk_common::create_http_client(&[])` — covers
/// the no-extra-roots path that `TDKSharedState::new` takes when no
/// `ssl_certificates` are configured.
#[test]
fn create_http_client_default_succeeds() {
    let client =
        affinidi_tdk_common::create_http_client(&[]).expect("client builds with empty extras");
    // Client is opaque; just verify we got one. The user-agent assertion
    // would require sending a request, which we avoid in unit-style tests.
    drop(client);
}
