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

/// `create_guarded_http_client` builds on the same TLS setup and carries the
/// policy it was given, which refuses internal targets before any I/O.
#[test]
fn create_guarded_http_client_default_succeeds() {
    use affinidi_tdk_common::net_guard::{EgressError, EgressPolicy};

    let policy = EgressPolicy::public_internet();
    let client = affinidi_tdk_common::create_guarded_http_client(&[], &policy)
        .expect("guarded client builds with empty extras");
    assert!(!client.policy().is_dev_loopback());
    assert!(matches!(
        client
            .policy()
            .vet("https://169.254.169.254/latest/meta-data/"),
        Err(EgressError::BlockedAddress { .. })
    ));
    assert!(matches!(
        client.policy().vet("https://localhost/"),
        Err(EgressError::BlockedName(_))
    ));
    assert!(
        client
            .get(&policy.vet("https://example.com/").unwrap())
            .is_ok()
    );
}

#[test]
fn service_endpoints_must_be_https_or_loopback_http() {
    use affinidi_tdk_common::check_service_endpoint;

    for accepted in [
        "https://mediator.example.com/mediator/v1/authenticate",
        "http://localhost:7037/mediator/v1",
        "http://LOCALHOST./api",
        "http://app.localhost/api",
        "http://127.0.0.1:7037",
        "http://127.10.0.1/",
        "http://[::1]:7037/",
    ] {
        assert!(
            check_service_endpoint(accepted, false).is_ok(),
            "{accepted}"
        );
    }
    for refused in [
        "http://mediator.example.com/mediator/v1",
        "http://10.0.0.5/api",
        "http://localhost.example.com/api",
        "ftp://mediator.example.com/",
        "file:///etc/passwd",
        "not a url",
    ] {
        assert!(check_service_endpoint(refused, false).is_err(), "{refused}");
    }
    assert!(check_service_endpoint("http://mediator:7037/api", true).is_ok());
    assert!(check_service_endpoint("ftp://mediator.example.com/", true).is_err());
}

#[test]
fn insecure_http_endpoints_are_opt_in() {
    let config = TDKConfig::builder().build().unwrap();
    assert!(!config.allow_insecure_http_endpoints());
    let config = TDKConfig::builder()
        .with_allow_insecure_http_endpoints(true)
        .build()
        .unwrap();
    assert!(config.allow_insecure_http_endpoints());
}

fn environment_file_config(path: &std::path::Path) -> TDKConfig {
    TDKConfig::builder()
        .with_environment_path(path.to_string_lossy().into_owned())
        .with_environment_name("local".to_string())
        .with_use_atm(false)
        .build()
        .unwrap()
}

/// A missing environment file, or one without the named environment, still
/// starts with the default environment.
#[tokio::test]
async fn missing_environment_file_or_name_uses_the_default() {
    let dir = tempfile::TempDir::new().unwrap();

    let missing = dir.path().join("missing.json");
    let state = TDKSharedState::new(environment_file_config(&missing))
        .await
        .expect("a missing file is not an error");
    assert!(state.environment().profiles().is_empty());
    state.shutdown().await;

    let other = dir.path().join("other.json");
    std::fs::write(&other, br#"{"environments":{"dev":{}}}"#).unwrap();
    let state = TDKSharedState::new(environment_file_config(&other))
        .await
        .expect("a file without the environment is not an error");
    assert!(state.environment().profiles().is_empty());
    state.shutdown().await;
}

/// A file that exists but cannot be parsed is an error, rather than starting
/// without its profiles and trust roots.
#[tokio::test]
async fn unreadable_environment_file_is_an_error() {
    let dir = tempfile::TempDir::new().unwrap();
    let corrupt = dir.path().join("corrupt.json");
    std::fs::write(&corrupt, b"{\"environments\": {\"local\": ").unwrap();

    let result = TDKSharedState::new(environment_file_config(&corrupt)).await;
    assert!(result.is_err());
}
