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

/// When an account was last active, as the mediator recorded it. Each field is
/// Unix epoch seconds, or `None` when nothing has been recorded — for an
/// account older than the recording, or a store that does not keep it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AccountActivity {
    /// The last message the mediator accepted for this account. Recorded at
    /// most once a minute per account, so it can lag by up to a minute.
    pub last_received: Option<u64>,
    /// The account's last completed authentication, over any transport.
    pub last_authenticated: Option<u64>,
}

/// What an account has sent and received over its lifetime, as the mediator
/// counted it.
///
/// Counters are cumulative and survive restarts; reading them does not reset
/// them, and removing an account discards them. A store that keeps nothing
/// reports [`AccountStats::default`] — all zeroes — which is why the wire
/// form marks every member optional: "not kept" and "none yet" are different
/// answers, and only the store knows which it is giving.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AccountStats {
    /// Messages the mediator accepted addressed to this account.
    pub messages_received: u64,
    /// Messages the mediator accepted from this account.
    pub messages_sent: u64,
    /// Total size of the messages counted by `messages_received`.
    pub bytes_received: u64,
    /// Total size of the messages counted by `messages_sent`.
    pub bytes_sent: u64,
    /// `messages_received`, split by the wire each message arrived in.
    pub received_by_protocol: ProtocolCounts,
    /// `messages_sent`, split by the wire each message was sent in.
    pub sent_by_protocol: ProtocolCounts,
}

/// Message counts split by wire protocol, matching the protocols the traffic
/// monitor reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ProtocolCounts {
    /// DIDComm v2 (JWE/JWS).
    pub didcomm: u64,
    /// A DIDComm v1 envelope.
    pub didcomm_v1: u64,
    /// A Trust Spanning Protocol message.
    pub tsp: u64,
    /// Anything the mediator could not classify.
    pub other: u64,
}

impl ProtocolCounts {
    /// The counter for `wire`, to add to.
    pub fn slot(&mut self, wire: StatsWire) -> &mut u64 {
        match wire {
            StatsWire::DidComm => &mut self.didcomm,
            StatsWire::DidCommV1 => &mut self.didcomm_v1,
            StatsWire::Tsp => &mut self.tsp,
            StatsWire::Other => &mut self.other,
        }
    }
}

/// The wire a counted message travelled in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatsWire {
    DidComm,
    DidCommV1,
    Tsp,
    Other,
}

/// Which side of an account one counted message falls on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatsDirection {
    /// The mediator accepted it addressed to the account.
    Received,
    /// The mediator accepted it from the account.
    Sent,
}

/// One message to count against an account: which way it went, how big it
/// was, and the wire it travelled in.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct AccountStatsDelta {
    pub direction: StatsDirection,
    pub wire: StatsWire,
    pub bytes: u64,
}

impl AccountStatsDelta {
    pub fn new(direction: StatsDirection, wire: StatsWire, bytes: u64) -> Self {
        Self {
            direction,
            wire,
            bytes,
        }
    }
}

impl AccountStats {
    /// Add one counted message.
    pub fn apply(&mut self, delta: AccountStatsDelta) {
        let (messages, bytes, by_protocol) = match delta.direction {
            StatsDirection::Received => (
                &mut self.messages_received,
                &mut self.bytes_received,
                &mut self.received_by_protocol,
            ),
            StatsDirection::Sent => (
                &mut self.messages_sent,
                &mut self.bytes_sent,
                &mut self.sent_by_protocol,
            ),
        };
        *messages = messages.saturating_add(1);
        *bytes = bytes.saturating_add(delta.bytes);
        let slot = by_protocol.slot(delta.wire);
        *slot = slot.saturating_add(1);
    }
}

/// Which of an account's [`AccountActivity`] times to record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ActivityKind {
    /// A message addressed to it was accepted.
    Received,
    /// It completed authentication.
    Authenticated,
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
