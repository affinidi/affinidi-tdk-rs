//! Protocol-vocabulary types shared by the Affinidi mediator and its clients.
//!
//! These types describe the messages and storage records exchanged
//! between the mediator, its storage backends, and the SDK that
//! clients use: ACL bits, problem reports, message-pickup envelopes,
//! account and audit records, and the injectable [`clock::Clock`].
//! They live in their own crate so the client SDK and the mediator
//! server can share them without either depending on the other — the
//! SDK does not pull the mediator's server stack, and the mediator's
//! storage trait can describe its API without depending on the SDK.
//!
//! The SDK re-exports each type from its original module paths
//! (`affinidi_messaging_sdk::protocols::mediator::*`,
//! `affinidi_messaging_sdk::messages::*`), and
//! `affinidi-messaging-mediator-common` re-exports this crate as its
//! `types` module, so existing call-sites compile unchanged.
//!
//! Dependencies are deliberately lean: `serde`, `serde_json`,
//! `thiserror` and `regex`.

pub mod accounts;
pub mod acls;
pub mod acls_handler;
pub mod audit;
pub mod clock;
pub mod messages;
pub mod problem_report;
