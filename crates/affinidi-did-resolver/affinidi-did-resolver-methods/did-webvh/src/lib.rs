/*!
*   DID method for Web with Verifiable History
*   See [WebVH Spec](https://identity.foundation/didwebvh/v1.0)
*/

use serde::{Deserialize, Serialize};
use ssi::dids::{
    DIDMethod, DIDMethodResolver,
    resolution::{Error, Options, Output},
};
use thiserror::Error;
use url::{URLType, WebVHURL};
use witness::Witnesses;

pub mod log_entry;
pub mod parameters;
pub mod url;
pub mod witness;

pub const SCID_HOLDER: &str = "{SCID}";

/// Error types for WebVH method
#[derive(Error, Debug)]
pub enum DIDWebVHError {
    #[error("DID Query NotFound")]
    NotFound,
    #[error("UnsupportedMethod: Must be did:webvh")]
    UnsupportedMethod,
    #[error("Invalid method identifier: {0}")]
    InvalidMethodIdentifier(String),
    #[error("ServerError: {0}")]
    ServerError(String),
    #[error("NotImplemented: {0}")]
    NotImplemented(String),
    #[error("SCIDError: {0}")]
    SCIDError(String),
    #[error("LogEntryError: {0}")]
    LogEntryError(String),
    #[error("ParametersError: {0}")]
    ParametersError(String),
    /// There was an error in validating the DID
    #[error("ValidationError: {0}")]
    ValidationError(String),
    #[error("DeactivatedError: {0}")]
    DeactivatedError(String),
}

pub struct DIDWebVH;

/// Resolved Document MetaData
/// Returned as reolved Document MetaData on a successful resolve
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetaData {
    pub version_id: String,
    pub version_time: String,
    pub created: String,
    pub updated: String,
    pub scid: String,
    pub portable: bool,
    pub deactivated: bool,
    pub witness: Option<Witnesses>,
    pub watchers: Option<Vec<String>>,
}

impl DIDMethodResolver for DIDWebVH {
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        _: Options,
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
    use crate::parameters::Parameters;

    #[test]
    fn check_serialization_field_action() {
        let watchers = vec!["did:webvh:watcher1".to_string()];
        let params = Parameters {
            pre_rotation_active: false,
            method: None,
            scid: None,
            update_keys: None,
            active_update_keys: Vec::new(),
            portable: None,
            next_key_hashes: None,
            witness: Some(None),
            active_witness: Some(None),
            watchers: Some(Some(watchers)),
            deactivated: false,
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
