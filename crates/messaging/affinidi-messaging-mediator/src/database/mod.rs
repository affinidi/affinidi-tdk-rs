//! All Redis related database methods are handled by `DatabaseHandler` module

use affinidi_messaging_mediator_common::database::DatabaseHandler;

pub mod accounts;
pub(crate) mod acls;
pub mod admin_accounts;
pub mod fetch;
pub mod get;
pub mod handlers;
pub(crate) mod initialization;
pub mod list;
pub(crate) mod messages;
pub(crate) mod oob_discovery;
pub mod session;
pub mod stats;
pub mod store;
pub mod streaming;
pub(crate) mod upgrades;

#[derive(Clone)]
pub struct Database(pub DatabaseHandler);
