//! Redis-specific implementation modules for [`crate::store::redis::RedisStore`].
//!
//! Each submodule houses one topic's worth of Redis operations
//! (accounts, ACLs, sessions, streaming, etc.) implemented as inherent
//! methods on [`crate::store::redis::RedisStore`]. The
//! [`MediatorStore`](crate::store::MediatorStore)
//! trait impl in [`crate::store::redis::store`] delegates to these
//! methods. Splitting by topic keeps each file under ~500 lines.

pub mod accounts;
pub(crate) mod acls;
pub mod admin_accounts;
pub mod fetch;
pub mod forwarding;
pub mod get;
pub mod handlers;
pub(crate) mod initialization;
pub mod list;
pub(crate) mod messages;
pub(crate) mod migrations;
#[cfg(feature = "didcomm")]
pub(crate) mod oob_discovery;
pub mod session;
pub mod stats;
pub mod store;
pub mod streaming;

/// Compatibility alias preserved during the Database → RedisStore fold.
/// External callers that still hold `&Database` references see
/// the same type. New code should use `RedisStore` directly.
pub use crate::store::redis::RedisStore as Database;
