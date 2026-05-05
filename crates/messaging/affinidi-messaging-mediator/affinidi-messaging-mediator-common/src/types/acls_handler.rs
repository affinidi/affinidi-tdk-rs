//! Wire-shape types for the mediator ACL DIDComm protocol — request
//! enums and response structs. The client-side handler methods that
//! send these messages live in the SDK; the mediator's storage trait
//! and request handlers reference these types directly.

use super::acls::{AccessListModeType, MediatorACLSet};
use serde::{Deserialize, Serialize};

/// Used in lists to show DID Hash and ACLs
#[derive(Debug, Serialize, Deserialize)]
pub struct MediatorACLExpanded {
    pub did_hash: String,
    pub acl_value: String,
    pub acls: MediatorACLSet,
}

/// DIDComm message body for requesting ACLs for a list of DID Hashes
#[derive(Serialize, Deserialize)]
pub enum MediatorACLRequest {
    #[serde(rename = "acl_get")]
    GetACL(Vec<String>),
    #[serde(rename = "acl_set")]
    SetACL { did_hash: String, acls: u64 },
    #[serde(rename = "access_list_list")]
    AccessListList {
        did_hash: String,
        cursor: Option<u64>,
    },
    #[serde(rename = "access_list_get")]
    AccessListGet {
        did_hash: String,
        hashes: Vec<String>,
    },
    #[serde(rename = "access_list_add")]
    AccessListAdd {
        did_hash: String,
        hashes: Vec<String>,
    },
    #[serde(rename = "access_list_remove")]
    AccessListRemove {
        did_hash: String,
        hashes: Vec<String>,
    },
    #[serde(rename = "access_list_clear")]
    AccessListClear { did_hash: String },
}

/// DIDComm message body for responding with a set of ACLs for a list of DID Hashes
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "acl_get_response")]
pub struct MediatorACLGetResponse {
    pub acl_response: Vec<MediatorACLExpanded>,
    pub mediator_acl_mode: AccessListModeType,
}

/// DIDComm message body for responding with a set of ACLs for a list of DID Hashes
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "acl_set_response")]
pub struct MediatorACLSetResponse {
    pub acls: MediatorACLSet,
}

/// DIDComm message body for responding with Access List List for a given DID
/// `did_hashes`: List of DID Hashes
/// `cursor`: Cursor for pagination
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "access_list_list_response")]
pub struct MediatorAccessListListResponse {
    pub did_hashes: Vec<String>,
    pub cursor: Option<u64>,
}

/// DIDComm message body for responding with Access List Add for a given DID
/// `did_hashes`: List of DID Hashes that were added
/// `truncated`: access_list is at limit, truncated is true
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "access_list_add_response")]
pub struct MediatorAccessListAddResponse {
    pub did_hashes: Vec<String>,
    pub truncated: bool,
}

/// DIDComm message body for responding with Access List Get for a given DID
/// `did_hashes`: List of DID Hashes that matched the search criteria
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "access_list_get_response")]
pub struct MediatorAccessListGetResponse {
    pub did_hashes: Vec<String>,
}
