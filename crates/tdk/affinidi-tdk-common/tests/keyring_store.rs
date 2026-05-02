//! Integration tests for [`affinidi_tdk_common::secrets::KeyringStore`].
//!
//! These run in their own binary, so the lib's `ensure_default_store`
//! `OnceLock<()>` starts fresh — no cross-pollination with unit tests.
//!
//! Within this binary, every test still installs a fresh
//! [`keyring_core::mock::Store`] before doing keyring work and serialises
//! through `SERIALISE` because `keyring_core::set_default_store` is
//! process-global. This is the only place in the workspace that touches
//! the keyring default store; any new keyring tests should live here.

use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk_common::secrets::{KeyringStore, init_keyring};
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use keyring_core::{Entry, mock::Store as MockStore};
use std::sync::Mutex;

static SERIALISE: Mutex<()> = Mutex::new(());

fn install_mock_store() {
    keyring_core::set_default_store(MockStore::new().unwrap());
}

fn sample_secret(id: &str) -> Secret {
    Secret::generate_ed25519(Some(id), Some(&[7u8; 32]))
}

#[test]
fn save_read_roundtrip() {
    let _g = SERIALISE.lock().unwrap();
    install_mock_store();
    let store = KeyringStore::new("tdk-test-roundtrip");
    let did = "did:example:roundtrip";
    let secrets = vec![sample_secret(&format!("{did}#key-1"))];

    store.save(did, &secrets).unwrap();
    let loaded = store.read(did).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].id, secrets[0].id);
    store.delete(did).unwrap();
}

#[test]
fn delete_missing_entry_is_ok() {
    let _g = SERIALISE.lock().unwrap();
    install_mock_store();
    let store = KeyringStore::new("tdk-test-delete-missing");
    store.delete("did:example:never-saved").unwrap();
}

#[test]
fn read_legacy_base64_entry_migrates() {
    let _g = SERIALISE.lock().unwrap();
    install_mock_store();
    let service = "tdk-test-legacy";
    let did = "did:example:legacy";
    let secrets = vec![sample_secret(&format!("{did}#key-1"))];

    // Mimic the 0.5.x on-disk format: base64(json_bytes).
    let json_bytes = serde_json::to_vec(&secrets).unwrap();
    let legacy_payload = BASE64_STANDARD_NO_PAD.encode(&json_bytes);
    Entry::new(service, did)
        .unwrap()
        .set_secret(legacy_payload.as_bytes())
        .unwrap();

    let store = KeyringStore::new(service);
    let loaded = store.read(did).unwrap();
    assert_eq!(loaded[0].id, secrets[0].id);

    // After read, the entry should be in raw-JSON format.
    let raw_after = Entry::new(service, did).unwrap().get_secret().unwrap();
    assert!(serde_json::from_slice::<Vec<Secret>>(&raw_after).is_ok());
    store.delete(did).unwrap();
}

/// Smoke test for the public `init_keyring()` entry point: when a default
/// store is already registered (the mock), `init_keyring` should succeed
/// without overriding it.
#[test]
fn init_keyring_respects_existing_default() {
    let _g = SERIALISE.lock().unwrap();
    install_mock_store();
    init_keyring().expect("init_keyring is a no-op when a store is already registered");

    // Subsequent keyring ops should still target the mock.
    let store = KeyringStore::new("tdk-test-init");
    let secrets = vec![sample_secret("did:example:init#k1")];
    store.save("did:example:init", &secrets).unwrap();
    store.delete("did:example:init").unwrap();
}
