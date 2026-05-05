//! Shared protocol-vocabulary types for the Affinidi mediator.
//!
//! These types describe the messages and storage records exchanged
//! between the mediator, its storage backends, and the SDK that
//! clients use. They live here (rather than in
//! [`affinidi-messaging-sdk`](https://docs.rs/affinidi-messaging-sdk))
//! so the mediator's storage trait — [`crate::store::MediatorStore`]
//! — can describe its API without forcing every storage implementor
//! to depend on the client SDK.
//!
//! The SDK re-exports these types from their original module paths
//! (`affinidi_messaging_sdk::protocols::mediator::*`,
//! `affinidi_messaging_sdk::messages::*`) so existing call-sites
//! continue to compile unchanged.

pub mod accounts;
pub mod acls;
pub mod acls_handler;
pub mod administration;
pub mod messages;
pub mod problem_report;
