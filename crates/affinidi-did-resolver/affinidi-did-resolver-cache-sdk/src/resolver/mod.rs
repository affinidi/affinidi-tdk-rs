use crate::{DIDCacheClient, errors::DIDCacheError};
use affinidi_did_common::{DID, DIDMethod, Document, DocumentExt};
use did_ethr::DIDEthr;
#[cfg(feature = "did-jwk")]
use did_jwk::DIDJWK;
use did_pkh::DIDPKH;
#[cfg(feature = "did-cheqd")]
use did_resolver_cheqd::DIDCheqd;
use did_web::DIDWeb;
#[cfg(feature = "did-webvh")]
use didwebvh_rs::{DIDWebVHState, log_entry::LogEntryMethods};
use ssi_dids_core::{
    DID as SSIDID, DIDMethodResolver, DIDResolver,
    resolution::{self},
};
use tracing::error;

impl DIDCacheClient {
    /// Resolves a DID to a DID Document
    pub(crate) async fn local_resolve(&self, did: &DID) -> Result<Document, DIDCacheError> {
        // Match the DID method

        match did.method() {
            DIDMethod::Ethr { identifier, .. } => {
                let method = DIDEthr;

                match method
                    .resolve_method_representation(identifier, resolution::Options::default())
                    .await
                {
                    Ok(res) => Ok(serde_json::from_str(&String::from_utf8(res.document)?)?),
                    Err(e) => {
                        error!("Error: {:?}", e);
                        Err(DIDCacheError::DIDError(e.to_string()))
                    }
                }
            }
            #[cfg(feature = "did-jwk")]
            "jwk" => {
                // This method isn't working as the VM references are relatative and not valid
                // URL's
                let method = DIDJWK;

                match method
                    .resolve_method_representation(
                        parts[parts.len() - 1],
                        resolution::Options::default(),
                    )
                    .await
                {
                    Ok(res) => Ok(serde_json::from_str(&String::from_utf8(res.document)?)?),
                    Err(e) => {
                        error!("Error: {:?}", e);
                        Err(DIDCacheError::DIDError(e.to_string()))
                    }
                }
            }
            DIDMethod::Key { .. } => match did.resolve() {
                Ok(doc) => Ok(doc),
                Err(e) => {
                    error!("Error: {:?}", e);
                    Err(DIDCacheError::DIDError(e.to_string()))
                }
            },
            DIDMethod::Peer { .. } => match did.resolve() {
                Ok(doc) => {
                    // DID Peer will resolve to MultiKey, which confuses key matching
                    // Expand the keys to raw keys
                    doc.expand_peer_keys()
                        .map_err(|e| DIDCacheError::DIDError(e.to_string()))
                }
                Err(e) => {
                    error!("Error: {:?}", e);
                    Err(DIDCacheError::DIDError(e.to_string()))
                }
            }
            DIDMethod::Pkh { .. } => {
                let method = DIDPKH;

                match method.resolve(DID::new::<str>(did).unwrap()).await {
                    Ok(res) => {
                        let doc_value = serde_json::to_value(res.document.into_document())?;
                        Ok(serde_json::from_value(doc_value)?)
                    }
                    Err(e) => {
                        error!("Error: {:?}", e);
                        Err(DIDCacheError::DIDError(e.to_string()))
                    }
                }
            }
            DIDMethod::Web { .. } => {
                let method = DIDWeb;

                match method.resolve(DID::new::<str>(did).unwrap()).await {
                    Ok(res) => {
                        let doc_value = serde_json::to_value(res.document.into_document())?;
                        Ok(serde_json::from_value(doc_value)?)
                    }
                    Err(e) => {
                        error!("Error: {:?}", e);
                        Err(DIDCacheError::DIDError(e.to_string()))
                    }
                }
            }
            DIDMethod::WebVH { .. } => {
                #[cfg(feature = "did-webvh")]
                {
                    let mut method = DIDWebVHState::default();

                    match method.resolve(did, None).await {
                        Ok((log_entry, _)) => {
                            Ok(serde_json::from_value(log_entry.get_did_document().map_err(|e| DIDCacheError::DIDError(format!("Successfully resolved webvh DID, but couldn't convert to a valid DID Document: {e}")))?)?)
                        }
                        Err(e) => {
                            error!("Error: {:?}", e);
                            Err(DIDCacheError::DIDError(e.to_string()))
                        }
                    }
                }

                #[cfg(not(feature = "did-webvh"))]
                Err(DIDCacheError::UnsupportedMethod(
                    "did:webvh is not enabled".to_string(),
                ))
            }
            DIDMethod::Cheqd { .. } => {
                #[cfg(feature = "did-cheqd")]
                match DIDCheqd::default()
                    .resolve(DID::new::<str>(did).unwrap())
                    .await
                {
                    Ok(res) => {
                        let doc_value = serde_json::to_value(res.document.into_document())?;
                        Ok(serde_json::from_value(doc_value)?)
                    }
                    Err(e) => {
                        error!("Error: {:?}", e);
                        Err(DIDCacheError::DIDError(e.to_string()))
                    }
                }

                #[cfg(not(feature = "did-cheqd"))]
                Err(DIDCacheError::UnsupportedMethod(
                    "did:cheqd is not enabled".to_string(),
                ))
            }
            DIDMethod::Scid { .. } => {
                #[cfg(feature = "did-scid")]
                {
                    did_scid::resolve(did, None, None)
                        .await
                        .map_err(|e| DIDCacheError::DIDError(e.to_string()))
                }

                #[cfg(not(feature = "did-scid"))]
                Err(DIDCacheError::UnsupportedMethod(
                    "did:scid is not enabled".to_string(),
                ))
            }
            _ => Err(DIDCacheError::DIDError(format!(
                "DID Method ({}) not supported",
                parts[1]
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{DIDCacheClient, config};
    use std::str::FromStr;
    use url::Url;

    const DID_ETHR: &str = "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a";
    #[cfg(feature = "did-jwk")]
    const DID_JWK: &str = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";
    // ED25519
    const DID_KEY: &str = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";
    const DID_PEER: &str = "did:peer:2.Vz6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv.EzQ3shQLqRUza6AMJFbPuMdvFRFWm1wKviQRnQSC1fScovJN4s.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cHM6Ly8xMjcuMC4wLjE6NzAzNyIsImEiOlsiZGlkY29tbS92MiJdLCJyIjpbXX19";
    const DID_PKH: &str = "did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev";
    #[cfg(feature = "did-webvh")]
    const DID_WEBVH: &str = "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs";
    #[cfg(feature = "did-cheqd")]
    const DID_CHEQD: &str = "did:cheqd:testnet:cad53e1d-71e0-48d2-9352-39cc3d0fac99";
    #[cfg(feature = "did-scid")]
    const DID_SCID: &str = "did:scid:vh:1:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai?src=identity.foundation/didwebvh-implementations/implementations/affinidi-didwebvh-rs";

    #[tokio::test]
    async fn local_resolve_ethr() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config).await.unwrap();

        let parts: Vec<&str> = DID_ETHR.split(':').collect();
        let did_document = client.local_resolve(DID_ETHR, &parts).await.unwrap();

        assert_eq!(did_document.id, Url::from_str(DID_ETHR).unwrap());

        assert_eq!(did_document.authentication.len(), 2);
        assert_eq!(did_document.assertion_method.len(), 2);

        assert_eq!(did_document.verification_method.len(), 2,);
    }

    #[tokio::test]
    #[cfg(feature = "did-jwk")]
    async fn local_resolve_jwk() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config).await.unwrap();

        let parts: Vec<&str> = DID_JWK.split(':').collect();
        let did_document = client.local_resolve(DID_JWK, &parts).await.unwrap();

        assert_eq!(did_document.id.as_str(), DID_JWK);

        assert_eq!(did_document.authentication.len(), 1);
        assert_eq!(did_document.assertion_method.len(), 1);
        assert_eq!(did_document.key_agreement.len(), 1);
        assert_eq!(did_document.capability_invocation.len(), 1);
        assert_eq!(did_document.capability_delegation.len(), 1);

        assert_eq!(did_document.verification_method.len(), 1);
        assert_eq!(
            did_document
                .verification_method
                .first()
                .unwrap()
                .property_set["publicKeyMultibase"],
            "zDnaepnC2eBkx4oZkNLGDnVK8ofKzoGk1Yui8fzC6FLoV1F1e"
        );
    }

    #[tokio::test]
    async fn local_resolve_key() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config).await.unwrap();

        let parts: Vec<&str> = DID_KEY.split(':').collect();
        let did_document = client.local_resolve(DID_KEY, &parts).await.unwrap();

        assert_eq!(did_document.id.as_str(), DID_KEY);

        assert_eq!(did_document.authentication.len(), 1);
        assert_eq!(did_document.assertion_method.len(), 1);
        assert_eq!(did_document.key_agreement.len(), 1);

        assert_eq!(did_document.verification_method.len(), 2);
    }

    #[tokio::test]
    async fn local_resolve_peer() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config).await.unwrap();

        let parts: Vec<&str> = DID_PEER.split(':').collect();
        let did_document = client.local_resolve(DID_PEER, &parts).await.unwrap();
        let verification_method = did_document.verification_method;
        let service = did_document.service;

        assert_eq!(did_document.id.as_str(), DID_PEER);

        assert_eq!(did_document.authentication.len(), 1);
        assert_eq!(did_document.assertion_method.len(), 1);
        assert_eq!(did_document.key_agreement.len(), 1);

        assert_eq!(verification_method.len(), 2);
        let first_public_key =
            &verification_method.first().unwrap().property_set["publicKeyMultibase"];

        let last_public_key =
            &verification_method.last().unwrap().property_set["publicKeyMultibase"];

        assert_eq!(
            first_public_key.as_str().expect("Not a string"),
            "z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv"
        );
        assert_eq!(
            last_public_key.as_str().expect("Not a string"),
            "zQ3shQLqRUza6AMJFbPuMdvFRFWm1wKviQRnQSC1fScovJN4s"
        );

        assert_eq!(service.len(), 1);
        assert!(
            service
                .first()
                .unwrap()
                .id
                .as_ref()
                .is_some_and(|u| u.as_str() == [DID_PEER, "#service"].concat())
        );
    }

    #[tokio::test]
    async fn local_resolve_pkh() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config).await.unwrap();
        let parts: Vec<&str> = DID_PKH.split(':').collect();

        let did_document = client.local_resolve(DID_PKH, &parts).await.unwrap();
        let verification_method = did_document.verification_method;
        let vm_properties_first = verification_method.first().unwrap().property_set.clone();
        let vm_properties_last = verification_method.last().unwrap().property_set.clone();

        assert_eq!(did_document.id.as_str(), DID_PKH);

        assert_eq!(did_document.authentication.len(), 2);
        assert_eq!(did_document.assertion_method.len(), 2);

        assert_eq!(verification_method.len(), 2);
        assert_eq!(
            vm_properties_first["publicKeyBase58"],
            parts.last().unwrap().to_string()
        );
        assert_eq!(
            vm_properties_first["blockchainAccountId"],
            parts[2..parts.len()].join(":")
        );
        assert_eq!(
            vm_properties_last["blockchainAccountId"],
            parts[2..parts.len()].join(":")
        );
        assert!(vm_properties_last["publicKeyJwk"].is_object(),);
    }

    #[tokio::test]
    #[cfg(feature = "did-webvh")]
    async fn local_resolve_webvh() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config).await.unwrap();
        let parts: Vec<&str> = DID_WEBVH.split(':').collect();

        let did_document = client.local_resolve(DID_WEBVH, &parts).await.unwrap();

        assert_eq!(did_document.id.as_str(), DID_WEBVH);
    }

    #[tokio::test]
    #[cfg(feature = "did-cheqd")]
    async fn local_resolve_cheqd() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config).await.unwrap();

        let did_document = client.resolve(DID_CHEQD).await.unwrap();

        assert_eq!(did_document.did.as_str(), DID_CHEQD);

        assert_eq!(did_document.doc.authentication.len(), 1);
        assert_eq!(did_document.doc.assertion_method.len(), 0);

        assert_eq!(did_document.doc.verification_method.len(), 1);
    }

    #[tokio::test]
    #[cfg(feature = "did-scid")]
    async fn local_resolve_scid() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config).await.unwrap();

        let did_document = client.resolve(DID_SCID).await.unwrap();
        assert_eq!(
            did_document.did.as_str(),
            "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs"
        );
    }
}
