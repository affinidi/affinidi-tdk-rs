//! The configured `admin_did` is the mediator's root admin, and the mediator's
//! own DID holds the `Mediator` role, on every storage backend: not only the
//! Redis one, whose bootstrap used to be the only place they were set.

use affinidi_messaging_mediator_common::types::accounts::AccountType;
use affinidi_messaging_test_mediator::{TestMediator, TestMediatorBuilder};

async fn assert_seeded(builder: TestMediatorBuilder) {
    let admin = TestMediator::random_admin_identity().expect("admin identity");
    let mediator = builder
        .admin_identity(admin.clone())
        .spawn()
        .await
        .expect("spawn");
    let store = mediator.store();

    let root = store
        .account_get(&sha256::digest(&admin.did))
        .await
        .expect("account_get")
        .expect("the configured admin has an account before it ever connects");
    assert_eq!(root._type, AccountType::RootAdmin);

    let own = store
        .account_get(&sha256::digest(mediator.did()))
        .await
        .expect("account_get")
        .expect("the mediator has its own account");
    assert_eq!(own._type, AccountType::Mediator);
}

#[tokio::test]
async fn the_configured_admin_is_root_on_the_memory_store() {
    assert_seeded(TestMediator::builder()).await;
}

#[cfg(feature = "fjall-backend")]
#[tokio::test]
async fn the_configured_admin_is_root_on_the_fjall_store() {
    assert_seeded(TestMediator::builder().fjall_backend().expect("fjall")).await;
}
