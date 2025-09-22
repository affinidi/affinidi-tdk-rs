/*!
 * DID Service specific methods for Peer DID
 */

use std::str::FromStr;

use crate::{DIDPeerError, DIDPeerService};
use affinidi_did_common::service::Service;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use url::Url;

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
    if let Some(id) = &service.id
        && service_idx > 0
        && id.as_str() == "did:peer:#service"
    {
        service.id =
            Some(Url::from_str(&[did, "#service-", &service_idx.to_string()].concat()).unwrap());
    }

    Ok(service)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use affinidi_did_common::service::{Endpoint, Service};
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
    use url::Url;

    #[test]
    fn service_single() {
        let encoded = format!(
            "S{}",
            BASE64_URL_SAFE_NO_PAD.encode(r#"{"t":"dm","s":"http://test.com/test"}"#)
        );

        let service =
            super::convert_service("did:peer:", &encoded, 0).expect("Failed to convert service");
        assert!(
            service
                .id
                .is_some_and(|s| s.as_str() == "did:peer:#service")
        );

        if let Endpoint::Url(url) = service.service_endpoint {
            assert_eq!(url.as_str(), "http://test.com/test");
        } else {
            panic!("Expected service endpoint to be a URL");
        }
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
        assert!(service.id.is_some_and(|id| id.as_str() == "did:peer:#test"));
        assert_eq!(
            service.service_endpoint,
            Endpoint::Url(Url::from_str("http://test.com/test").unwrap())
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
        assert!(
            service
                .id
                .is_some_and(|id| id.as_str() == "did:peer:#service-1")
        );
    }

    #[test]
    fn service_full_map() {
        let encoded = format!(
            "S{}",
            BASE64_URL_SAFE_NO_PAD.encode(r##"{"t":"dm","s":{"uri":"http://example.com/didcomm","a":["didcomm/v2"],"r":["did:example:123456789abcdefghi#key-1"]}}"##)
        );

        let compare: Service = serde_json::from_str(
            r##"{
                "id": "did:peer:#service",
                "type": "DIDCommMessaging",
                "serviceEndpoint": {
                    "uri": "http://example.com/didcomm",
                    "accept": [
                    "didcomm/v2"
                    ],
                    "routing_keys": [
                    "did:example:123456789abcdefghi#key-1"
                    ]
                }
            }"##,
        )
        .expect("Could not parse JSON");

        let service =
            super::convert_service("did:peer:", &encoded, 0).expect("Failed to convert service");
        assert!(
            service
                .id
                .as_ref()
                .is_some_and(|id| id.as_str() == "did:peer:#service")
        );
        assert_eq!(service, compare);
    }
}
