/*!
*   DID method for Web with Verifiable History
*   See [WebVH Spec](https://identity.foundation/didwebvh/v1.0)
*/

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

    // /// configuration options from the controller
    // TODO: pub parameters: Parameters,
    /// DID document
    pub state: Document,
    // /// Data Integrity Proof
    // TODO: pub proof:
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
