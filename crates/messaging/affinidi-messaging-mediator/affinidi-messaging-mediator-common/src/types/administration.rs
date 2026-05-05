//! Wire-shape types for the mediator administration DIDComm protocol.
//! The client-side `Mediator` / `MediatorOps` handler types live in the
//! SDK and use these vocabulary types directly.

use super::accounts::AccountType;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize)]
pub enum MediatorAdminRequest {
    #[serde(rename = "admin_add")]
    AdminAdd(Vec<String>),
    #[serde(rename = "admin_strip")]
    AdminStrip(Vec<String>),
    #[serde(rename = "admin_list")]
    AdminList {
        cursor: u32,
        limit: u32,
    },
    Configuration(Value),
}

/// A list of admins in the mediator
/// - `accounts` - The list of admins (SHA256 Hashed DIDs)
/// - `cursor` - The offset to use for the next request
#[derive(Serialize, Deserialize)]
pub struct MediatorAdminList {
    pub accounts: Vec<AdminAccount>,
    pub cursor: u32,
}

#[derive(Serialize, Deserialize)]
pub struct AdminAccount {
    pub did_hash: String,
    #[serde(rename = "type")]
    pub _type: AccountType,
}
