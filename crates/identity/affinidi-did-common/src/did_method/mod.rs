use std::fmt;

use affinidi_encoding::Codec;
use serde::{Deserialize, Serialize};

pub(crate) mod identifier;
pub mod key;
pub(crate) mod parse;
pub(crate) mod peer;
pub(crate) mod resolve;

use crate::did_method::peer::PeerNumAlgo;

/// DID method identifiers per W3C DID Core 1.0
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DIDMethod {
    Key {
        /// Raw identifier for Display ("z6MkhaX...")
        identifier: String,
        /// Multicodec indicating key type
        codec: Codec,
        /// Raw public key bytes
        key_bytes: Vec<u8>,
    },
    Peer {
        /// Raw identifier for Display
        identifier: String,
        /// Algorithm number (0, 1, 2)
        numalgo: PeerNumAlgo,
    },
    Web {
        /// Raw identifier for Display ("example.com:user:alice")
        identifier: String,
        /// Domain (first segment)
        domain: String,
        /// Path segments after domain
        path_segments: Vec<String>,
    },
    Jwk {
        /// Raw identifier (base64url encoded JWK)
        identifier: String,
        // Could add parsed JWK later if needed
    },
    /// Ethereum DID method (did:ethr)
    Ethr {
        /// Raw identifier for Display (hex address)
        identifier: String,
    },
    /// Public Key Hash DID method (did:pkh)
    /// Format: <chain_namespace>:<chain_reference>:<account_address>
    Pkh {
        /// Raw identifier for Display
        identifier: String,
        /// Chain namespace (e.g., "eip155", "solana", "bip122")
        chain_namespace: String,
        /// Chain reference (network identifier)
        chain_reference: String,
        /// Account address
        account_address: String,
    },
    /// WebVH DID method with versioned history (did:webvh)
    /// Format: <scid>:<domain>:<path_segments>
    Webvh {
        /// Raw identifier for Display
        identifier: String,
        /// Self-Certifying IDentifier (hash)
        scid: String,
        /// Domain (first segment after SCID)
        domain: String,
        /// Path segments after domain
        path_segments: Vec<String>,
    },
    /// Cheqd DID method (did:cheqd)
    /// Format: <network>:<uuid>
    Cheqd {
        /// Raw identifier for Display
        identifier: String,
        /// Network (mainnet, testnet)
        network: String,
        /// UUID identifier
        uuid: String,
    },
    /// SCID DID method - maps to other methods (did:scid)
    /// Format: <underlying_method>:<version>:<scid>
    Scid {
        /// Raw identifier for Display
        identifier: String,
        /// Underlying method type (e.g., "vh" for webvh)
        underlying_method: String,
        /// Version number
        version: String,
        /// Self-Certifying IDentifier
        scid: String,
    },
    /// Catch-all for methods we don't explicitly model
    Other {
        /// Method name (e.g., "example")
        method: String,
        /// Raw identifier (opaque)
        identifier: String,
    },
}

impl DIDMethod {
    /// Returns the method name ("key", "peer", "web", etc.)
    pub fn name(&self) -> &str {
        match self {
            DIDMethod::Key { .. } => "key",
            DIDMethod::Peer { .. } => "peer",
            DIDMethod::Web { .. } => "web",
            DIDMethod::Jwk { .. } => "jwk",
            DIDMethod::Ethr { .. } => "ethr",
            DIDMethod::Pkh { .. } => "pkh",
            DIDMethod::Webvh { .. } => "webvh",
            DIDMethod::Cheqd { .. } => "cheqd",
            DIDMethod::Scid { .. } => "scid",
            DIDMethod::Other { method, .. } => method,
        }
    }

    /// Returns the raw method-specific identifier
    pub fn identifier(&self) -> &str {
        match self {
            DIDMethod::Key { identifier, .. } => identifier,
            DIDMethod::Peer { identifier, .. } => identifier,
            DIDMethod::Web { identifier, .. } => identifier,
            DIDMethod::Jwk { identifier, .. } => identifier,
            DIDMethod::Ethr { identifier, .. } => identifier,
            DIDMethod::Pkh { identifier, .. } => identifier,
            DIDMethod::Webvh { identifier, .. } => identifier,
            DIDMethod::Cheqd { identifier, .. } => identifier,
            DIDMethod::Scid { identifier, .. } => identifier,
            DIDMethod::Other { identifier, .. } => identifier,
        }
    }
}

impl fmt::Display for DIDMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use crate::DID;

    #[test]
    fn name_returns_correct_method() {
        let cases = [
            (
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                "key",
            ),
            (
                "did:peer:0z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                "peer",
            ),
            ("did:web:example.com", "web"),
            (
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
                "ethr",
            ),
            (
                "did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a",
                "pkh",
            ),
            ("did:example:custom123", "example"),
        ];
        for (did_str, expected_name) in cases {
            let did: DID = did_str.parse().unwrap();
            assert_eq!(did.method().name(), expected_name, "failed for {did_str}");
        }
    }

    #[test]
    fn identifier_returns_raw_id() {
        let did: DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();
        assert_eq!(
            did.method().identifier(),
            "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
    }

    #[test]
    fn display_matches_name() {
        let did: DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();
        assert_eq!(format!("{}", did.method()), "key");
    }

    #[test]
    fn display_other_method() {
        let did: DID = "did:example:abc123".parse().unwrap();
        assert_eq!(format!("{}", did.method()), "example");
    }
}
