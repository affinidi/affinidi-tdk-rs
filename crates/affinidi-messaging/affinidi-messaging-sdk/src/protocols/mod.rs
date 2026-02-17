//! This module contains the implementation of the DIDComm protocols supported by the SDK.
//!
//! ## Usage
//!
//! Access protocol methods directly through the [`crate::ATM`] instance:
//!
//! ```rust,ignore
//! atm.trust_ping().send_ping(&profile, &did, true, true, false).await?;
//! atm.message_pickup().live_stream_get(&profile, &msg_id, dur, true).await?;
//! atm.mediator().get_config(&profile).await?;
//! ```

use crate::messages::GenericDataStruct;
use mediator::administration::Mediator;

/// **Deprecated**: Use `atm.trust_ping()`, `atm.message_pickup()`, etc. instead.
#[deprecated(
    note = "Use ATM accessor methods instead: atm.trust_ping(), atm.message_pickup(), etc."
)]
#[derive(Default)]
pub struct Protocols {
    pub message_pickup: message_pickup::MessagePickup,
    pub trust_ping: trust_ping::TrustPing,
    pub routing: routing::Routing,
    pub mediator: Mediator,
    pub oob_discovery: oob_discovery::OOBDiscovery,
}

pub mod discover_features;
pub mod mediator;
pub mod message_pickup;
pub mod oob_discovery;
pub mod routing;
pub mod trust_ping;

type MessageString = String;
impl GenericDataStruct for MessageString {}

#[allow(deprecated)]
impl Protocols {
    /// **Deprecated**: Use `atm.trust_ping()`, `atm.message_pickup()`, etc. instead.
    #[deprecated(
        note = "Use ATM accessor methods instead: atm.trust_ping(), atm.message_pickup(), etc."
    )]
    pub fn new() -> Protocols {
        Protocols {
            message_pickup: message_pickup::MessagePickup::default(),
            trust_ping: trust_ping::TrustPing::default(),
            routing: routing::Routing::default(),
            mediator: Mediator::default(),
            oob_discovery: oob_discovery::OOBDiscovery::default(),
        }
    }
}
