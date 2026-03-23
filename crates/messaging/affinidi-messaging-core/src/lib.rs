//! # affinidi-messaging-core
//!
//! Protocol-agnostic messaging traits for the Affinidi TDK.
//!
//! This crate defines the unified API that both DIDComm and TSP implement,
//! allowing application code to work with either protocol through a single
//! set of traits.
//!
//! ## Core Traits
//!
//! - [`MessagingProtocol`] — Pack/unpack messages (encrypt, sign, encode)
//! - [`IdentityResolver`] — Resolve identifiers to keys and endpoints
//! - [`RelationshipManager`] — Manage relationship lifecycle
//! - [`Transport`] — Send messages over the network
//!
//! ## Protocol Differences
//!
//! | Aspect | DIDComm | TSP |
//! |---|---|---|
//! | Relationships | Implicit (always `Bidirectional`) | Explicit (RFI→RFA handshake) |
//! | Anonymous send | Supported (anoncrypt) | Not supported (always authenticated) |
//! | Encoding | JSON (JWM) | CESR (binary/text) |
//! | Relay | Forward messages through mediators | Nested/routed through intermediaries |

pub mod error;
pub mod traits;
pub mod types;

pub use error::MessagingError;
pub use traits::{IdentityResolver, MessagingProtocol, RelationshipManager, Transport};
pub use types::{Protocol, ReceivedMessage, RelationshipState, ResolvedIdentity};
