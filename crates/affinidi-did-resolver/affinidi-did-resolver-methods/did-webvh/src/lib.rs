/*!
*   DID method for Web with Verifiable History
*   See [WebVH Spec](https://identity.foundation/didwebvh/v1.0)
*/

use ssi::dids::{
    DIDMethod, DIDMethodResolver,
    resolution::{Error, Options, Output},
};
use thiserror::Error;
use url::{URLType, WebVHURL};

pub mod create;
pub mod log_entry;
pub mod parameters;
pub mod url;
pub mod witness;

pub const SCID_HOLDER: &str = "{SCID}";

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
    #[error("SCIDError: {0}")]
    SCIDError(String),
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
    use crate::parameters::{FieldAction, Parameters};

    #[test]
    fn check_serialization_field_action() {
        let params = Parameters {
            method: None,
            scid: None,
            update_keys: FieldAction::Absent,
            portable: None,
            next_key_hashes: FieldAction::Absent,
            witness: FieldAction::None,
            watchers: FieldAction::Value(vec!["url".to_string()]),
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
