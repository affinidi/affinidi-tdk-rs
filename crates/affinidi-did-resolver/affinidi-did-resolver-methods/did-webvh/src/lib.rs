/*!
*   DID method for Web with Verifiable History
*   See [WebVH Spec](https://identity.foundation/didwebvh/v1.0)
*/

use ssi::dids::{
    DIDMethod, DIDMethodResolver,
    resolution::{Error, Options, Output},
};
use thiserror::Error;
use url::WebVHURL;

pub mod url;

#[derive(Error, Debug)]
pub enum DIDWebVHError {
    #[error("UnsupportedMethod: Must be did:webvh")]
    UnsupportedMethod,
    #[error("Invalid method identifier: {0}")]
    InvalidMethodIdentifier(String),
    #[error("ServerError: {0}")]
    ServerError(String),
}

pub struct DIDWebVH;

impl DIDMethodResolver for DIDWebVH {
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: Options,
    ) -> Result<Output<Vec<u8>>, Error> {
        WebVHURL::parse_url(method_specific_id).map_err(|_| Error::NotFound)?;

        Err(Error::NotFound)
    }
}

impl DIDMethod for DIDWebVH {
    const DID_METHOD_NAME: &'static str = "webvh";
}
