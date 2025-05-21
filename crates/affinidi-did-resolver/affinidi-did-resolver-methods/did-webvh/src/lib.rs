/*!
*   DID method for Web with Verifiable History
*   See [WebVH Spec](https://identity.foundation/didwebvh/v1.0)
*/

use ahash::AHashSet;
use serde::{Deserialize, Serialize};
use ssi::dids::{
    DIDMethod, DIDMethodResolver, Document,
    resolution::{Error, Options, Output},
};
use thiserror::Error;
use url::{URLType, WebVHURL};

pub mod create;
pub mod url;

/// Error types for WebVH method
#[derive(Error, Debug)]
pub enum DIDWebVHError {
    #[error("UnsupportedMethod: Must be did:webvh")]
    UnsupportedMethod,
    #[error("Invalid method identifier: {0}")]
    InvalidMethodIdentifier(String),
    #[error("ServerError: {0}")]
    ServerError(String),
    #[error("NotImplemented: {0}")]
    NotImplemented(String),
}

/// Each version of the DID gets a new log entry
/// [Log Entries](https://identity.foundation/didwebvh/v1.0/#the-did-log-file)
pub struct LogEntry {
    /// format integer-prev_hash
    pub version_id: String,

    /// ISO 8601 date format
    pub version_time: String,

    /// configuration options from the controller
    pub parameters: Parameters,

    /// DID document
    pub state: Document,
    // /// Data Integrity Proof
    // TODO: pub proof:
}

/// webvh parameters can be missing(Empty), Cancelled(null) or contain Content
#[derive(Debug, Deserialize, Serialize)]
pub enum FieldAction<T> {
    Empty,
    Cancel,
    Content(T),
}

impl<T> FieldAction<T> {
    pub fn is_empty(&self) -> bool {
        matches!(self, FieldAction::Empty)
    }
}

fn se_field_action<T, S>(field: &FieldAction<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: serde::Serializer,
{
    match field {
        FieldAction::Empty => serializer.serialize_none(),
        FieldAction::Cancel => serializer.serialize_none(),
        FieldAction::Content(content) => content.serialize(serializer),
    }
}

/// [https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters]
/// Parameters that help with the resolution of a webvh DID
#[derive(Debug, Deserialize, Serialize)]
pub struct Parameters {
    /// DID version specification
    /// Default: `did:webvh:1.0`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Self Certifying Identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scid: Option<String>,

    /// Keys that are authorized to update future log entries
    #[serde(
        skip_serializing_if = "FieldAction::is_empty",
        serialize_with = "se_field_action"
    )]
    pub update_keys: FieldAction<Vec<String>>,

    /// Can you change the web address for this DID?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portable: Option<bool>,

    /// pre-rotation keys that must be shared prior to updating update keys
    #[serde(
        skip_serializing_if = "FieldAction::is_empty",
        serialize_with = "se_field_action"
    )]
    pub next_key_hashes: FieldAction<Vec<String>>,

    /// Parameters for witness nodes
    #[serde(
        skip_serializing_if = "FieldAction::is_empty",
        serialize_with = "se_field_action"
    )]
    pub witness: FieldAction<Witnesses>,

    /// DID watchers for this DID
    #[serde(
        skip_serializing_if = "FieldAction::is_empty",
        serialize_with = "se_field_action"
    )]
    pub watchers: FieldAction<Vec<String>>,

    /// Has this DID been revoked?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,

    /// time to live in seconds for a resolved DID document
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

/// Witness nodes
#[derive(Debug, Deserialize, Serialize)]
pub struct Witnesses {
    /// Number of witnesses required to witness a change
    /// Must be 1 or greater
    pub threshold: u32,

    /// Set of witness nodes
    pub witnesses: AHashSet<Witness>,
}

#[derive(Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Witness {
    pub id: String,
}

pub struct DIDWebVH;

impl DIDMethodResolver for DIDWebVH {
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: Options,
    ) -> Result<Output<Vec<u8>>, Error> {
        let parsed_did_url = WebVHURL::parse_did_url(method_specific_id)
            .map_err(|err| Error::Internal(format!("webvh error: {}", err)))?;

        if parsed_did_url.type_ == URLType::WhoIs {
            // TODO: whois is not implemented yet
            return Err(Error::RepresentationNotSupported(
                "WhoIs is not implemented yet".to_string(),
            ));
        }

        Err(Error::NotFound)
    }
}

impl DIDMethod for DIDWebVH {
    const DID_METHOD_NAME: &'static str = "webvh";
}

#[cfg(test)]
mod tests {
    use crate::{FieldAction, Parameters};

    #[test]
    fn check_serialization_field_action() {
        let params = Parameters {
            method: None,
            scid: None,
            update_keys: FieldAction::Empty,
            portable: None,
            next_key_hashes: FieldAction::Empty,
            witness: FieldAction::Cancel,
            watchers: FieldAction::Content(vec!["url".to_string()]),
            deactivated: None,
            ttl: None,
        };

        let parsed = serde_json::to_value(&params).expect("Couldn't parse parameters");
        let pretty = serde_json::to_string_pretty(&params).expect("Couldn't parse parameters");

        println!("Parsed: {}", pretty);

        assert_eq!(parsed.get("next_key_hashes"), None);
        assert!(parsed.get("witness").is_some_and(|s| s.is_null()));
        assert!(parsed.get("watchers").is_some_and(|s| s.is_array()));
    }
}
