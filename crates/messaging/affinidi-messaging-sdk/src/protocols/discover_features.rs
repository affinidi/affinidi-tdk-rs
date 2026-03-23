//! # Discover Features 2.0 Protocol
//!
//! Implementation of the [DIDComm Discover Features 2.0](https://identity.foundation/didcomm-messaging/spec/#discover-features-protocol-20)
//! protocol, which allows agents to query each other for supported protocols,
//! goal codes, and headers.
//!
//! ## Overview
//!
//! The protocol defines two message types:
//!
//! - **Query** (`discover-features/2.0/queries`) — sent by an agent to ask
//!   another agent what features it supports.
//! - **Disclosure** (`discover-features/2.0/disclose`) — the response,
//!   listing the matching features.
//!
//! Queries support exact matching and trailing-wildcard prefix matching
//! (e.g. `"https://didcomm.org/coordinate-mediation/*"`). Invalid patterns
//! (wildcard anywhere other than at the end) silently produce empty
//! disclosures to prevent leaking protocol information.
//!
//! ## Setup
//!
//! Register the protocols, goal codes, and headers your agent supports at
//! SDK construction time via the config builder:
//!
//! ```rust,ignore
//! use affinidi_messaging_sdk::config::ATMConfig;
//! use affinidi_messaging_sdk::protocols::discover_features::DiscoverFeatures;
//!
//! let features = DiscoverFeatures {
//!     protocols: vec![
//!         "https://didcomm.org/trust-ping/2.0".into(),
//!         "https://didcomm.org/messagepickup/3.0".into(),
//!         "https://didcomm.org/discover-features/2.0".into(),
//!     ],
//!     goal_codes: vec![
//!         "com.example.sell".into(),
//!     ],
//!     headers: vec![
//!         "return_route".into(),
//!     ],
//! };
//!
//! let config = ATMConfig::builder()
//!     .with_discovery_features(features)
//!     .build()?;
//!
//! let atm = ATM::new(config, tdk).await?;
//! ```
//!
//! You can also update the discoverable state at runtime:
//!
//! ```rust,ignore
//! let state = atm.discover_features().get_discoverable_state();
//! let mut features = state.write().await;
//! features.protocols.push("https://didcomm.org/my-protocol/1.0".into());
//! ```
//!
//! ## Handling an incoming query
//!
//! When you receive a Discover Features query message from another agent,
//! use the current state to calculate and send back a disclosure:
//!
//! ```rust,ignore
//! // `query_msg` is the incoming DIDComm Message of type discover-features/2.0/queries
//! let state = atm.discover_features().get_discoverable_state();
//! let features = state.read().await;
//!
//! // Build a disclosure response — passing `None` for the response body
//! // lets the SDK auto-calculate the disclosure from the query and current state.
//! let disclosure_msg = features.generate_disclosure_message(
//!     my_did,           // from
//!     &query_msg.from.unwrap(),  // to (the querying agent)
//!     &query_msg,       // the original query (used for thid)
//!     None,             // auto-calculate disclosure from state
//! )?;
//! ```
//!
//! ## Sending a query
//!
//! To discover what features a remote agent supports:
//!
//! ```rust,ignore
//! use affinidi_messaging_sdk::protocols::discover_features::{
//!     DiscoverFeaturesQuery, Query, FeatureType,
//! };
//!
//! // Ask the remote agent which protocols it supports (wildcard = all)
//! let query_msg = atm.discover_features().generate_query_message(
//!     my_did,
//!     remote_did,
//!     DiscoverFeaturesQuery {
//!         queries: vec![
//!             Query { feature_type: FeatureType::Protocol, match_: "*".into() },
//!         ],
//!     },
//! )?;
//!
//! // Pack and send `query_msg` via atm.send_message(...), then
//! // parse the disclosure response from the remote agent.
//! ```

use crate::{ATM, errors::ATMError};
use affinidi_messaging_didcomm::Message;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{fmt::Display, sync::Arc, time::SystemTime};
use tokio::sync::RwLock;
use tracing::{Level, debug, span};
use uuid::Uuid;

/// Holds state of the Discover Features protocol
/// State is Feature Types that need to be supported
#[derive(Default)]
pub struct DiscoverFeatures {
    /// DIDComm Protocols that this agent supports
    /// Format of the String is a URI that identifies the protocol, for example
    /// "https://didcomm.org/trust-ping/2.0/ping"
    pub protocols: Vec<String>,

    /// DIDComm Goal Codes that this agent supports
    /// Goal Codes are user defined and reside in the body of a message
    /// They are formatted as reverse domain name notatin, for example
    /// "com.example.myprotocol.myspecificgoal"
    pub goal_codes: Vec<String>,

    /// This isn't well defined in the spec, it exists here for completeness but it's not clear how
    /// this would be used in practice
    pub headers: Vec<String>,
}

// ****************************************************************************
// Message Bodies
// ****************************************************************************

/// Supported Discover Features Query Types
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum FeatureType {
    Protocol,
    GoalCode,
    Header,
}

impl Display for FeatureType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeatureType::Protocol => write!(f, "protocol"),
            FeatureType::GoalCode => write!(f, "goal_code"),
            FeatureType::Header => write!(f, "header"),
        }
    }
}

/// Query structure
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Query {
    pub feature_type: FeatureType,
    #[serde(rename = "match")]
    pub match_: String,
}

/// The Discover Features Query message body
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DiscoverFeaturesQuery {
    pub queries: Vec<Query>,
}

/// Individual Disclosure Record
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Disclosure {
    pub feature_type: FeatureType,
    pub id: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub roles: Vec<String>,
}

/// Discovery Features Disclosure message body
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct DiscoverFeaturesDisclosure {
    pub disclosures: Vec<Disclosure>,
}

impl DiscoverFeatures {
    /// Generate a DIDComm PlainText Discover Features Query Message
    /// - `from_did` - The DID to send the query from
    /// - `to_did` - The DID to send the query to
    /// - `query_body` - The query to the recipient
    ///
    /// Returns: Plaintext DIDComm Message
    pub fn generate_query_message(
        &self,
        from_did: &str,
        to_did: &str,
        query_body: DiscoverFeaturesQuery,
    ) -> Result<Message, ATMError> {
        let _span = span!(Level::DEBUG, "generate_query_message",).entered();
        debug!(
            "Discover Features Query ({}) from ({:?}) query({:#?})",
            to_did, from_did, query_body
        );

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Message::build(
            Uuid::new_v4().into(),
            "https://didcomm.org/discover-features/2.0/queries".to_owned(),
            json!(query_body),
        )
        .to(to_did.to_owned())
        .from(from_did.to_string())
        .created_time(now)
        .expires_time(now + 300)
        .finalize())
    }

    /// Generate a DIDComm PlainText Discover Features Disclosures (response) Message
    /// - `from_did` - The DID to send the disclosure from
    /// - `to_did` - The DID to send the disclosure to
    /// - `query` - The Discover Features Query to process and respond to
    /// - `response_body` - Optional user defined disclosure response body. If not supplied then
    ///   the existing state will be used to try and generate a response based on the query
    ///
    /// Returns: Plaintext DIDComm Message
    pub fn generate_disclosure_message(
        &self,
        from_did: &str,
        to_did: &str,
        query: &Message,
        response_body: Option<DiscoverFeaturesDisclosure>,
    ) -> Result<Message, ATMError> {
        let _span = span!(Level::DEBUG, "generate_disclosure_message",).entered();
        debug!(
            "Discover Features Disclosure ({}) from ({:?}) query({:#?}) response({:#?})",
            to_did, from_did, query, response_body
        );

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let body = if let Some(body) = response_body {
            body
        } else {
            // Need to calculate a response based on the query and the current state
            match serde_json::from_value(query.body.clone()) {
                Ok(q) => self.calculate_disclosure(&q),
                Err(e) => {
                    debug!(
                        "Failed to parse query body for disclosure calculation: {:#?}",
                        e
                    );
                    DiscoverFeaturesDisclosure {
                        disclosures: vec![],
                    }
                }
            }
        };

        Ok(Message::build(
            Uuid::new_v4().into(),
            "https://didcomm.org/discover-features/2.0/disclose".to_owned(),
            json!(body),
        )
        .to(to_did.to_owned())
        .from(from_did.to_string())
        .created_time(now)
        .expires_time(now + 300)
        .thid(query.id.clone())
        .finalize())
    }

    /// Takes a query and the current state and generates a disclosure response body.
    ///
    /// Matching rules per the Discover Features 2.0 spec:
    /// - A `*` wildcard is only valid at the end of the match string (prefix matching)
    /// - No `*` means exact match
    /// - A `*` anywhere other than the end is treated as an invalid query and silently
    ///   produces no disclosures (to prevent leaking protocol information)
    pub fn calculate_disclosure(
        &self,
        query: &DiscoverFeaturesQuery,
    ) -> DiscoverFeaturesDisclosure {
        let _span = span!(Level::DEBUG, "calculate_disclosure").entered();
        let mut disclosures = DiscoverFeaturesDisclosure::default();

        for q in &query.queries {
            let features = match q.feature_type {
                FeatureType::Protocol => &self.protocols,
                FeatureType::GoalCode => &self.goal_codes,
                FeatureType::Header => &self.headers,
            };

            // Determine matching mode: prefix (trailing `*`) or exact
            let matcher: fn(&str, &str) -> bool;
            let pattern: &str;

            if let Some(prefix) = q.match_.strip_suffix('*') {
                // Wildcard in the prefix portion is invalid — skip silently
                if prefix.contains('*') {
                    debug!("Invalid wildcard in match pattern: {}", q.match_);
                    continue;
                }
                pattern = prefix;
                matcher = |feature, pat| feature.starts_with(pat);
            } else {
                pattern = &q.match_;
                matcher = |feature, pat| feature == pat;
            }

            disclosures
                .disclosures
                .extend(
                    features
                        .iter()
                        .filter(|f| matcher(f, pattern))
                        .map(|f| Disclosure {
                            feature_type: q.feature_type,
                            id: f.clone(),
                            roles: vec![],
                        }),
                );
        }

        disclosures
    }
}

/// Wrapper struct that holds a reference to ATM, enabling the `atm.discover_features().method()` pattern
pub struct DiscoverfeaturesOps<'a> {
    pub(crate) atm: &'a ATM,
}

impl<'a> DiscoverfeaturesOps<'a> {
    /// Generate a DIDComm PlainText Discover Features Query message
    /// See [`DiscoverFeatures::generate_query_message`] for full documentation
    pub fn generate_query_message(
        &self,
        from_did: &str,
        to_did: &str,
        query_body: DiscoverFeaturesQuery,
    ) -> Result<Message, ATMError> {
        DiscoverFeatures::default().generate_query_message(from_did, to_did, query_body)
    }

    /// Generate a Discover Features Disclosure response DIDComm PlainText message
    /// See [`DiscoverFeatures::generate_disclosure_message`] for full documentation
    pub fn generate_disclosure_message(
        &self,
        from_did: &str,
        to_did: &str,
        query: &Message,
        response_body: Option<DiscoverFeaturesDisclosure>,
    ) -> Result<Message, ATMError> {
        DiscoverFeatures::default().generate_disclosure_message(
            from_did,
            to_did,
            query,
            response_body,
        )
    }

    /// Returns the shared discoverable state of this agent.
    ///
    /// The returned [`DiscoverFeatures`] holds the protocols, goal codes, and headers
    /// that this agent advertises when responding to
    /// [Discover Features 2.0](https://identity.foundation/didcomm-messaging/spec/#discover-features-protocol-20)
    /// queries. Because it is wrapped in an `Arc<RwLock<…>>`, the state can be read
    /// or modified at any time — even while the agent is running.
    ///
    /// The initial state is set via
    /// [`ATMConfigBuilder::with_discovery_features()`](crate::config::ATMConfigBuilder::with_discovery_features)
    /// at SDK construction time. This method gives you a handle to inspect or update
    /// that state later.
    ///
    /// # Examples
    ///
    /// **Reading the current state:**
    ///
    /// ```rust,ignore
    /// let state = atm.discover_features().get_discoverable_state();
    /// let features = state.read().await;
    ///
    /// println!("Supported protocols:");
    /// for protocol in &features.protocols {
    ///     println!("  {}", protocol);
    /// }
    /// ```
    ///
    /// **Adding a new protocol at runtime:**
    ///
    /// ```rust,ignore
    /// let state = atm.discover_features().get_discoverable_state();
    /// {
    ///     let mut features = state.write().await;
    ///     features.protocols.push(
    ///         "https://didcomm.org/coordinate-mediation/3.0".to_string()
    ///     );
    /// }
    /// ```
    ///
    /// **Using the state to generate a disclosure response:**
    ///
    /// ```rust,ignore
    /// let state = atm.discover_features().get_discoverable_state();
    /// let features = state.read().await;
    ///
    /// // Calculate a disclosure based on the incoming query
    /// let disclosure = features.calculate_disclosure(&query_body);
    ///
    /// // Build the response DIDComm message
    /// let response = features.generate_disclosure_message(
    ///     &my_did,
    ///     &their_did,
    ///     &query_message,
    ///     Some(disclosure),
    /// )?;
    /// ```
    pub fn get_discoverable_state(&self) -> Arc<RwLock<DiscoverFeatures>> {
        self.atm.inner.config.discover_features.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> DiscoverFeatures {
        DiscoverFeatures {
            protocols: vec![
                "https://didcomm.org/trust-ping/2.0".to_string(),
                "https://didcomm.org/discover-features/2.0".to_string(),
                "https://didcomm.org/messagepickup/3.0".to_string(),
                "https://didcomm.org/coordinate-mediation/2.0".to_string(),
                "https://didcomm.org/coordinate-mediation/3.0".to_string(),
            ],
            goal_codes: vec![
                "com.example.sell".to_string(),
                "com.example.buy".to_string(),
                "org.didcomm.negotiate".to_string(),
            ],
            headers: vec!["return_route".to_string()],
        }
    }

    /// Run a single query against test_state() and return the disclosures
    fn disclose(feature_type: FeatureType, match_: &str) -> Vec<Disclosure> {
        test_state()
            .calculate_disclosure(&DiscoverFeaturesQuery {
                queries: vec![Query {
                    feature_type,
                    match_: match_.to_string(),
                }],
            })
            .disclosures
    }

    // --- Exact matching ---

    #[test]
    fn exact_match_hit() {
        let results = disclose(FeatureType::Protocol, "https://didcomm.org/trust-ping/2.0");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "https://didcomm.org/trust-ping/2.0");
    }

    #[test]
    fn exact_match_miss() {
        assert!(disclose(FeatureType::Protocol, "https://didcomm.org/nonexistent/1.0").is_empty());
    }

    // --- Wildcard (prefix) matching ---

    #[test]
    fn wildcard_prefix_multiple_hits() {
        let results = disclose(
            FeatureType::Protocol,
            "https://didcomm.org/coordinate-mediation/*",
        );
        assert_eq!(results.len(), 2);
        assert!(
            results
                .iter()
                .any(|d| d.id == "https://didcomm.org/coordinate-mediation/2.0")
        );
        assert!(
            results
                .iter()
                .any(|d| d.id == "https://didcomm.org/coordinate-mediation/3.0")
        );
    }

    #[test]
    fn wildcard_match_all() {
        assert_eq!(disclose(FeatureType::Protocol, "*").len(), 5);
    }

    #[test]
    fn wildcard_no_match() {
        assert!(disclose(FeatureType::Protocol, "https://example.com/*").is_empty());
    }

    // --- Invalid wildcard positions ---

    #[test]
    fn wildcard_in_middle_rejected() {
        assert!(disclose(FeatureType::Protocol, "https://didcomm.org/*/2.0").is_empty());
    }

    #[test]
    fn multiple_wildcards_rejected() {
        assert!(disclose(FeatureType::Protocol, "https://didcomm.org/*/*.0").is_empty());
    }

    // --- All feature types ---

    #[test]
    fn goal_code_exact_match() {
        let results = disclose(FeatureType::GoalCode, "org.didcomm.negotiate");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "org.didcomm.negotiate");
    }

    #[test]
    fn goal_code_prefix_match() {
        let results = disclose(FeatureType::GoalCode, "com.example.*");
        assert_eq!(results.len(), 2);
        assert!(results.iter().any(|d| d.id == "com.example.sell"));
        assert!(results.iter().any(|d| d.id == "com.example.buy"));
    }

    #[test]
    fn header_exact_match() {
        let results = disclose(FeatureType::Header, "return_route");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "return_route");
    }

    #[test]
    fn header_wildcard_match() {
        let results = disclose(FeatureType::Header, "return*");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "return_route");
    }

    // --- Multi-query and edge cases ---

    #[test]
    fn multiple_queries_preserve_feature_type() {
        let result = test_state().calculate_disclosure(&DiscoverFeaturesQuery {
            queries: vec![
                Query {
                    feature_type: FeatureType::Protocol,
                    match_: "https://didcomm.org/trust-ping/2.0".to_string(),
                },
                Query {
                    feature_type: FeatureType::GoalCode,
                    match_: "org.didcomm.*".to_string(),
                },
            ],
        });
        assert_eq!(result.disclosures.len(), 2);
        assert!(
            result
                .disclosures
                .iter()
                .any(|d| matches!(d.feature_type, FeatureType::Protocol)
                    && d.id == "https://didcomm.org/trust-ping/2.0")
        );
        assert!(
            result
                .disclosures
                .iter()
                .any(|d| matches!(d.feature_type, FeatureType::GoalCode)
                    && d.id == "org.didcomm.negotiate")
        );
    }

    #[test]
    fn invalid_query_does_not_suppress_valid_sibling() {
        let result = test_state().calculate_disclosure(&DiscoverFeaturesQuery {
            queries: vec![
                Query {
                    feature_type: FeatureType::Protocol,
                    match_: "https://didcomm.org/*/2.0".to_string(), // invalid
                },
                Query {
                    feature_type: FeatureType::Header,
                    match_: "return_route".to_string(), // valid
                },
            ],
        });
        assert_eq!(result.disclosures.len(), 1);
        assert_eq!(result.disclosures[0].id, "return_route");
    }

    #[test]
    fn empty_state_returns_empty() {
        let result = DiscoverFeatures::default().calculate_disclosure(&DiscoverFeaturesQuery {
            queries: vec![Query {
                feature_type: FeatureType::Protocol,
                match_: "*".to_string(),
            }],
        });
        assert!(result.disclosures.is_empty());
    }

    #[test]
    fn empty_queries_returns_empty() {
        let result = test_state().calculate_disclosure(&DiscoverFeaturesQuery { queries: vec![] });
        assert!(result.disclosures.is_empty());
    }
}
