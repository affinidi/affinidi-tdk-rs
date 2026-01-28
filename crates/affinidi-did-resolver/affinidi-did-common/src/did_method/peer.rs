//! did:peer specific types and validation
//!
//! Implements validation for did:peer method per the spec:
//! https://identity.foundation/peer-did-method-spec/

use serde::{Deserialize, Serialize};

/// Peer DID algorithm number (numalgo)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerNumAlgo {
    /// Type 0: Inception key (wraps a did:key)
    InceptionKey = 0,
    /// Type 1: Genesis document (not widely supported)
    GenesisDoc = 1,
    /// Type 2: Multiple inline keys
    MultipleKeys = 2,
}

impl PeerNumAlgo {
    /// Parse numalgo from the first character of method-specific-id
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            '0' => Some(PeerNumAlgo::InceptionKey),
            '1' => Some(PeerNumAlgo::GenesisDoc),
            '2' => Some(PeerNumAlgo::MultipleKeys),
            _ => None,
        }
    }

    /// Convert to character representation
    pub fn to_char(self) -> char {
        match self {
            PeerNumAlgo::InceptionKey => '0',
            PeerNumAlgo::GenesisDoc => '1',
            PeerNumAlgo::MultipleKeys => '2',
        }
    }
}

/// Purpose codes for did:peer type 2 key entries
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerPurpose {
    /// Assertion method
    Assertion,
    /// Capability delegation
    Delegation,
    /// Key agreement (encryption)
    Encryption,
    /// Capability invocation
    Invocation,
    /// Authentication (verification)
    Verification,
    /// Service endpoint
    Service,
}

impl PeerPurpose {
    /// Parse purpose from character
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'A' => Some(PeerPurpose::Assertion),
            'D' => Some(PeerPurpose::Delegation),
            'E' => Some(PeerPurpose::Encryption),
            'I' => Some(PeerPurpose::Invocation),
            'V' => Some(PeerPurpose::Verification),
            'S' => Some(PeerPurpose::Service),
            _ => None,
        }
    }

    /// Convert to character representation
    pub fn to_char(self) -> char {
        match self {
            PeerPurpose::Assertion => 'A',
            PeerPurpose::Delegation => 'D',
            PeerPurpose::Encryption => 'E',
            PeerPurpose::Invocation => 'I',
            PeerPurpose::Verification => 'V',
            PeerPurpose::Service => 'S',
        }
    }

    /// Returns true if this purpose represents a key (not a service)
    pub fn is_key(&self) -> bool {
        !matches!(self, PeerPurpose::Service)
    }
}
