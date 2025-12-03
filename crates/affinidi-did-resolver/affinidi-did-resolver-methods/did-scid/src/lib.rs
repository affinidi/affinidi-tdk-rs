/*! Implementation of the
*/

use crate::errors::DIDSCIDError;
use affinidi_did_common::Document;
use didwebvh_rs::{DIDWebVHState, log_entry::LogEntryMethods};
use regex::Regex;
use std::time::Duration;
use tracing::{debug, error};

pub mod errors;

#[derive(Clone, Debug)]
pub enum ScidMethod {
    WebVH(String),

    #[cfg(feature = "did-cheqd")]
    Cheqd(String),
}

/// Resolve a SCID DID Method
/// did: id of the DID to resolve
/// peer_src: Optional Source when did:scid is being used as a peer DID
///   webvh: peer_src should be the path that gets concatenated to the SCID
///   (did:webvh:{SCID}:<domain:path>)
///   cheqd: peer_src should be mainnet or testnet
/// timeout: Optional Time for timeout
pub async fn resolve(
    did: &str,
    peer_src: Option<ScidMethod>,
    timeout: Option<Duration>,
) -> Result<Document, DIDSCIDError> {
    if did.starts_with("did:scid:vh:1") {
        // Implement the resolution logic here
        match convert_scid_to_method(did, peer_src)? {
            ScidMethod::WebVH(webvh_did) => {
                debug!("Resolving WebVH DID: {}", webvh_did);
                let mut method = DIDWebVHState::default();
                match method.resolve(&webvh_did, timeout).await {
                    Ok((log_entry, _)) => {
                        Ok(serde_json::from_value(log_entry.get_did_document()?)?)
                    }
                    Err(e) => {
                        error!("Error: {:?}", e);
                        Err(DIDSCIDError::WebVHError(e))
                    }
                }
            }
            #[cfg(feature = "did-cheqd")]
            ScidMethod::Cheqd(cheqd_did) => {
                use did_resolver_cheqd::DIDCheqd;
                use ssi_dids_core::{DID, DIDResolver};

                debug!("Resolving Cheqd DID: {}", cheqd_did);
                match DIDCheqd::default()
                    .resolve(DID::new::<str>(&cheqd_did).unwrap())
                    .await
                {
                    Ok(res) => {
                        let doc_value = serde_json::to_value(res.document.into_document())?;
                        Ok(serde_json::from_value(doc_value)?)
                    }
                    Err(e) => {
                        error!("Error: {:?}", e);
                        Err(DIDSCIDError::CheqdError(e.to_string()))
                    }
                }
            }
        }
    } else {
        Err(DIDSCIDError::UnsupportedFormat)
    }
}

/// Converts a SCID DID to a valid Method DID Identifier
/// peer_src: Optional meta_data if operating in peer mode
fn convert_scid_to_method(
    id: &str,
    peer_src: Option<ScidMethod>,
) -> Result<ScidMethod, DIDSCIDError> {
    let re = Regex::new(r"^did:scid:vh:1:([^\?]*)(?:\?src=(.*))?$").unwrap();
    if let Some(caps) = re.captures(id) {
        if let Some(src) = caps.get(2).map(|m| m.as_str()) {
            // Has source
            if src.starts_with("did:cheqd") {
                // Cheqd Method
                let mut cheqd = String::new();
                cheqd.push_str(src);
                cheqd.push(':');
                cheqd.push_str(&caps[1]);

                debug!("derived cheqd DID: {cheqd}");
                Ok(ScidMethod::Cheqd(cheqd))
            } else if src.starts_with("did:") {
                // Invalid DID method as source
                Err(DIDSCIDError::UnsupportedFormat)
            } else {
                // WebVH URL
                let mut webvh = String::new();
                webvh.push_str("did:webvh:");
                webvh.push_str(&caps[1]);
                webvh.push(':');
                webvh.push_str(&src.replace("/", ":"));

                debug!("derived webvh DID: {webvh}");
                Ok(ScidMethod::WebVH(webvh))
            }
        } else {
            // Peer Mode
            match peer_src {
                Some(ScidMethod::WebVH(src)) => {
                    let mut webvh = String::new();
                    webvh.push_str("did:webvh:");
                    webvh.push_str(&caps[1]);
                    webvh.push(':');
                    webvh.push_str(&src);

                    debug!("derived peer webvh DID: {webvh}");
                    Ok(ScidMethod::WebVH(webvh))
                }
                Some(ScidMethod::Cheqd(src)) => {
                    let mut cheqd = String::new();
                    cheqd.push_str("did:cheqd:");
                    cheqd.push_str(&src);
                    cheqd.push(':');
                    cheqd.push_str(&caps[1]);

                    debug!("derived peer cheqd DID: {cheqd}");
                    Ok(ScidMethod::Cheqd(cheqd))
                }
                None => Err(DIDSCIDError::MissingPeerSource),
            }
        }
    } else {
        Err(DIDSCIDError::UnsupportedFormat)
    }
}

#[cfg(test)]
mod tests {
    use crate::{convert_scid_to_method, errors::DIDSCIDError, resolve};

    #[test]
    fn test_cheqd_conversion() {
        match convert_scid_to_method("did:scid:vh:1:abcde?src=did:cheqd:mainnet", None) {
            Ok(crate::ScidMethod::Cheqd(did)) => assert_eq!(did, "did:cheqd:mainnet:abcde"),
            _ => panic!("Incorrect conversion"),
        }
    }

    #[test]
    fn test_cheqd_peer_conversion() {
        match convert_scid_to_method(
            "did:scid:vh:1:abcde",
            Some(crate::ScidMethod::Cheqd("mainnet".to_string())),
        ) {
            Ok(crate::ScidMethod::Cheqd(did)) => assert_eq!(did, "did:cheqd:mainnet:abcde"),
            _ => panic!("Incorrect conversion"),
        }
    }

    #[test]
    fn test_webvh_conversion() {
        match convert_scid_to_method(
            "did:scid:vh:1:abcde?src=stormer78.github.io/identity/fpp",
            None,
        ) {
            Ok(crate::ScidMethod::WebVH(did)) => {
                assert_eq!(did, "did:webvh:abcde:stormer78.github.io:identity:fpp")
            }
            _ => panic!("Incorrect conversion"),
        }
    }

    #[test]
    fn test_webvhpeer_conversion() {
        match convert_scid_to_method(
            "did:scid:vh:1:abcde",
            Some(crate::ScidMethod::WebVH("stormer78.github.io".to_string())),
        ) {
            Ok(crate::ScidMethod::WebVH(did)) => {
                assert_eq!(did, "did:webvh:abcde:stormer78.github.io")
            }
            _ => panic!("Incorrect conversion"),
        }
    }

    #[test]
    fn test_missing_peer() {
        match convert_scid_to_method("did:scid:vh:1:abcde", None) {
            Err(DIDSCIDError::MissingPeerSource) => {}
            _ => panic!("Incorrect conversion"),
        }
    }

    #[test]
    fn test_bad_did_method() {
        match convert_scid_to_method("did:scid:vh:1:abcde?src=did:example:abcd", None) {
            Err(DIDSCIDError::UnsupportedFormat) => {}
            _ => panic!("Incorrect conversion"),
        }
    }

    #[test]
    fn test_bad_id() {
        match convert_scid_to_method("did:scid:invalid:1:abcde?src=did:example:abcd", None) {
            Err(DIDSCIDError::UnsupportedFormat) => {}
            _ => panic!("Incorrect conversion"),
        }
    }

    #[tokio::test]
    async fn test_scid_webvh_resolution() {
        match resolve("did:scid:vh:1:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai?src=identity.foundation/didwebvh-implementations/implementations/affinidi-didwebvh-rs", None, None).await {
            Ok(doc) => {
                assert_eq!(doc.id.as_str(), "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs");
            }
            Err(_) => panic!("Couldn't resolve SCID WebVH DID")
        }
    }

    #[tokio::test]
    async fn test_scid_cheqd_resolution() {
        match resolve(
            "did:scid:vh:1:cad53e1d-71e0-48d2-9352-39cc3d0fac99?src=did:cheqd:testnet",
            None,
            None,
        )
        .await
        {
            Ok(doc) => {
                assert_eq!(
                    doc.id.as_str(),
                    "did:cheqd:testnet:cad53e1d-71e0-48d2-9352-39cc3d0fac99"
                );
            }
            Err(_) => panic!("Couldn't resolve SCID Cheqd DID"),
        }
    }
}
