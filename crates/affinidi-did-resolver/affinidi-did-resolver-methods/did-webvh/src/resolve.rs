/*!
*   Resolver trait methods for webvh
*/

use crate::url::{URLType, WebVHURL};
use ssi::dids::{
    DIDMethod, DIDMethodResolver,
    resolution::{Error, Options},
};

pub struct DIDWebVH;

impl DIDMethodResolver for DIDWebVH {
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        _: Options,
    ) -> Result<ssi::dids::resolution::Output<Vec<u8>>, Error> {
        let parsed_did_url = WebVHURL::parse_did_url(method_specific_id)
            .map_err(|err| Error::Internal(format!("webvh error: {err}",)))?;

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
