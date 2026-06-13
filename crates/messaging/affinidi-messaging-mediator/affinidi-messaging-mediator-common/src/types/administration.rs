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
    /// Page through the privileged-change audit log (newest-first). Admin-only,
    /// like every other request in this protocol. The response is a
    /// [`MediatorAuditLogList`](crate::types::audit::MediatorAuditLogList).
    #[serde(rename = "audit_log_list")]
    AuditLogList {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards the SDK↔mediator wire contract: the SDK's `list_audit_log` sends
    /// `{"audit_log_list": {"cursor": N, "limit": M}}` and the mediator handler
    /// deserializes it into the `AuditLogList` variant. A rename drift here would
    /// otherwise only surface as a runtime parse failure.
    #[test]
    fn audit_log_list_request_wire_format() {
        let json = serde_json::json!({"audit_log_list": {"cursor": 5, "limit": 25}});
        let req: MediatorAdminRequest =
            serde_json::from_value(json).expect("deserialize audit_log_list");
        match req {
            MediatorAdminRequest::AuditLogList { cursor, limit } => {
                assert_eq!(cursor, 5);
                assert_eq!(limit, 25);
            }
            _ => panic!("expected AuditLogList variant"),
        }
    }
}
