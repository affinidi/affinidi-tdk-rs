//! Account-management protocol vocabulary — request shapes,
//! account records, and the `AccountType` taxonomy. The data side of
//! the SDK's `Mediator::account_*` client methods.

use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};

#[derive(Debug, Serialize, Deserialize)]
pub enum MediatorAccountRequest {
    #[serde(rename = "account_get")]
    AccountGet(String),
    #[serde(rename = "account_list")]
    AccountList { cursor: u32, limit: u32 },
    #[serde(rename = "account_add")]
    AccountAdd { did_hash: String, acls: Option<u64> },
    #[serde(rename = "account_remove")]
    AccountRemove(String),
    #[serde(rename = "account_change_type")]
    AccountChangeType {
        did_hash: String,
        #[serde(alias = "type")]
        _type: AccountType,
    },
    #[serde(rename = "account_change_queue_limits")]
    AccountChangeQueueLimits {
        did_hash: String,
        send_queue_limit: Option<i32>,
        receive_queue_limit: Option<i32>,
    },
}

/// Different levels of accounts in the mediator
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq)]
pub enum AccountType {
    /// The DID refers to the mediator itself
    Mediator,
    /// The root admin DID, used to manage other admins.
    RootAdmin,
    /// Admin accounts, can modify other accounts
    Admin,
    /// Standard accounts, can only modify their own account
    #[default]
    Standard,
    /// Unknown account type
    Unknown,
}
impl AccountType {
    pub fn is_admin(&self) -> bool {
        matches!(
            self,
            AccountType::Admin | AccountType::RootAdmin | AccountType::Mediator
        )
    }

    pub fn iterator() -> impl Iterator<Item = AccountType> {
        [
            AccountType::Standard,
            AccountType::Admin,
            AccountType::RootAdmin,
            AccountType::Mediator,
            AccountType::Unknown,
        ]
        .iter()
        .copied()
    }
}

impl Display for AccountType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AccountType::Mediator => write!(f, "Mediator"),
            AccountType::RootAdmin => write!(f, "Root Admin"),
            AccountType::Admin => write!(f, "Admin"),
            AccountType::Standard => write!(f, "Standard"),
            AccountType::Unknown => write!(f, "Unknown"),
        }
    }
}

impl From<&str> for AccountType {
    fn from(role_type: &str) -> Self {
        match role_type {
            "0" => AccountType::Standard,
            "1" => AccountType::Admin,
            "2" => AccountType::RootAdmin,
            "3" => AccountType::Mediator,
            _ => AccountType::Unknown,
        }
    }
}

impl From<u32> for AccountType {
    fn from(role_type: u32) -> Self {
        match role_type {
            0 => AccountType::Standard,
            1 => AccountType::Admin,
            2 => AccountType::RootAdmin,
            3 => AccountType::Mediator,
            _ => AccountType::Unknown,
        }
    }
}

impl From<String> for AccountType {
    fn from(role_type: String) -> Self {
        role_type.as_str().into()
    }
}

impl From<AccountType> for String {
    fn from(role_type: AccountType) -> Self {
        match role_type {
            AccountType::Mediator => "3".to_owned(),
            AccountType::RootAdmin => "2".to_owned(),
            AccountType::Admin => "1".to_owned(),
            AccountType::Standard => "0".to_owned(),
            AccountType::Unknown => "-1".to_owned(),
        }
    }
}

/// An account in the mediator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub did_hash: String,
    pub acls: u64,
    #[serde(rename = "type")]
    pub _type: AccountType,
    pub access_list_count: u32,
    /// Number of messages that can be in the queue for this account
    pub queue_send_limit: Option<i32>,
    pub queue_receive_limit: Option<i32>,
    pub send_queue_count: u32,
    pub send_queue_bytes: u64,
    pub receive_queue_count: u32,
    pub receive_queue_bytes: u64,
}

impl Default for Account {
    fn default() -> Self {
        Account {
            did_hash: "".to_owned(),
            acls: 0,
            _type: AccountType::Standard,
            access_list_count: 0,
            queue_send_limit: None,
            queue_receive_limit: None,
            send_queue_count: 0,
            send_queue_bytes: 0,
            receive_queue_count: 0,
            receive_queue_bytes: 0,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct MediatorAccountList {
    pub accounts: Vec<Account>,
    pub cursor: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountChangeQueueLimitsResponse {
    pub send_queue_limit: Option<i32>,
    pub receive_queue_limit: Option<i32>,
}
