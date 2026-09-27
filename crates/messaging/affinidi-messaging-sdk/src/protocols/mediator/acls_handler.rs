//! Mediator ACL and access-list response vocabulary.
//!
//! The definitions live in
//! [`affinidi-messaging-mediator-common`](https://docs.rs/affinidi-messaging-mediator-common);
//! they are re-exported here so call sites under
//! `affinidi_messaging_sdk::protocols::mediator::acls_handler::*` resolve to the
//! canonical types. ACLs and access lists are managed over the
//! `messaging/account/*` Trust Tasks: see [`crate::protocols::trust_tasks`].

pub use affinidi_messaging_mediator_common::types::acls_handler::{
    MediatorACLExpanded, MediatorACLGetResponse, MediatorAccessListAddResponse,
    MediatorAccessListGetResponse, MediatorAccessListListResponse,
};
