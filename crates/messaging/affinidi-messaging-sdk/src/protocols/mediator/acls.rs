/*!
 * ACL Management structs used by the mediator to control permissions.
 *
 * The actual definitions live in
 * [`affinidi-messaging-mediator-common`](https://docs.rs/affinidi-messaging-mediator-common)
 * so the mediator's storage trait can describe its API without
 * pulling in the SDK. This module re-exports them so existing call
 * sites under `affinidi_messaging_sdk::protocols::mediator::acls::*`
 * keep resolving to the canonical type.
 */

pub use affinidi_messaging_mediator_common::types::acls::{
    ACLError, AccessListModeType, MediatorACLSet,
};
