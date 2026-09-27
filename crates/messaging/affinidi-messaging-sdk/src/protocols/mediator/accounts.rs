//! Mediator account vocabulary.
//!
//! The definitions live in
//! [`affinidi-messaging-mediator-common`](https://docs.rs/affinidi-messaging-mediator-common)
//! so the mediator's storage trait can describe its API without depending on
//! the SDK; they are re-exported here so existing call sites resolve. Accounts
//! are managed over the `messaging/account/*` Trust Tasks: see
//! [`crate::protocols::trust_tasks`].

pub use affinidi_messaging_mediator_common::types::accounts::{
    Account, AccountType, MediatorAccountList,
};
