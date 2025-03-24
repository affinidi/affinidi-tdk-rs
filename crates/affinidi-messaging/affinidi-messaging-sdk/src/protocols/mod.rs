//! This module contains the implementation of the DIDComm protocols supported by the SDK.

use crate::messages::GenericDataStruct;
use mediator::administration::Mediator;

#[derive(Default)]
pub struct Protocols {
    pub message_pickup: message_pickup::MessagePickup,
    pub trust_ping: trust_ping::TrustPing,
    pub routing: routing::Routing,
    pub mediator: Mediator,
    pub oob_discovery: oob_discovery::OOBDiscovery,
}

pub mod mediator;
pub mod message_pickup;
pub mod oob_discovery;
pub mod routing;
pub mod trust_ping;

type MessageString = String;
impl GenericDataStruct for MessageString {}

impl Protocols {
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
