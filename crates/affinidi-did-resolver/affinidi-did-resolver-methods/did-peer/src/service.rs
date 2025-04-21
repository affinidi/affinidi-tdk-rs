/*!
 * DID Service specific methods for Peer DID
 */

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use iref::UriBuf;
use ssi::dids::document::Service;

use crate::{DIDPeerError, DIDPeerService};

pub(crate) fn convert_service(
    did: &str,
    encoded: &str,
    service_idx: u32,
) -> Result<Service, DIDPeerError> {
    let raw = match BASE64_URL_SAFE_NO_PAD.decode(&encoded.as_bytes()[1..]) {
        Ok(raw) => raw,
        Err(e) => {
            return Err(DIDPeerError::SyntaxErrorServiceDefinition(format!(
                "Failed to decode base64 string: ({}) Reason: {}",
                &encoded[1..],
                e
            )));
        }
    };

    let service = match serde_json::from_slice::<DIDPeerService>(raw.as_slice()) {
        Ok(service) => service, // Deserialize the service
        Err(e) => {
            return Err(DIDPeerError::SyntaxErrorServiceDefinition(format!(
                "Failed to deserialize service: ({}) Reason: {}",
                String::from_utf8_lossy(raw.as_slice()),
                e
            )));
        }
    };

    let mut service: Service = DIDPeerService::convert(did, service)?;
    if service_idx > 0 && service.id.as_str() == "did:peer:#service" {
        service.id =
            UriBuf::new([did, "#service-", &service_idx.to_string()].concat().into()).unwrap();
    }

    Ok(service)
}

#[cfg(test)]
mod test {
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
    use iref::UriBuf;
    use ssi::{dids::document::service::Endpoint, verification_methods::ssi_core::OneOrMany};

    #[test]
    fn service_single() {
        let encoded = format!(
            "S{}",
            BASE64_URL_SAFE_NO_PAD.encode(r#"{"t":"dm","s":"http://test.com/test"}"#)
        );

        let service =
            super::convert_service("did:peer:", &encoded, 0).expect("Failed to convert service");
        assert_eq!(service.id.as_str(), "did:peer:#service");
        assert_eq!(
            service.service_endpoint,
            Some(OneOrMany::One(Endpoint::Uri(
                UriBuf::new("http://test.com/test".as_bytes().to_vec()).unwrap()
            )))
        );
    }

    #[test]
    fn service_single_id() {
        let encoded = format!(
            "S{}",
            BASE64_URL_SAFE_NO_PAD
                .encode(r##"{"id":"#test","t":"dm","s":"http://test.com/test"}"##)
        );

        let service =
            super::convert_service("did:peer:", &encoded, 0).expect("Failed to convert service");
        assert_eq!(service.id.as_str(), "did:peer:#test");
        assert_eq!(
            service.service_endpoint,
            Some(OneOrMany::One(Endpoint::Uri(
                UriBuf::new("http://test.com/test".as_bytes().to_vec()).unwrap()
            )))
        );
    }

    #[test]
    fn service_multi() {
        let encoded = format!(
            "S{}",
            BASE64_URL_SAFE_NO_PAD.encode(r##"{"t":"dm","s":"http://test.com/test"}"##)
        );

        let service =
            super::convert_service("did:peer:", &encoded, 1).expect("Failed to convert service");
        assert_eq!(service.id.as_str(), "did:peer:#service-1");
    }
}
