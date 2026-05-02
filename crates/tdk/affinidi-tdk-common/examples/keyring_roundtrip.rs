//! `KeyringStore` save → read → delete round-trip.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example keyring_roundtrip
//! ```
//!
//! This example uses [`keyring_core::mock::Store`] so it does **not** touch
//! the host OS keychain. To run against the real platform store, delete the
//! `keyring_core::set_default_store(...)` line — `affinidi-tdk-common`
//! registers the platform-native store lazily on the first secret op.

use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk_common::secrets::KeyringStore;
use keyring_core::mock::Store as MockStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Production: drop the next line; tdk-common registers the platform
    // store automatically on first use.
    keyring_core::set_default_store(MockStore::new()?);

    let store = KeyringStore::new("affinidi-tdk-example");
    let did = "did:example:alice";

    let secret = Secret::generate_ed25519(Some(&format!("{did}#key-1")), None);
    println!("Generated secret with id = {}", secret.id);

    store.save(did, std::slice::from_ref(&secret))?;
    println!("Saved secret to the keyring under service_id=affinidi-tdk-example");

    let loaded = store.read(did)?;
    println!("Read back {} secret(s)", loaded.len());
    assert_eq!(loaded[0].id, secret.id);

    store.delete(did)?;
    println!("Deleted the entry");

    Ok(())
}
