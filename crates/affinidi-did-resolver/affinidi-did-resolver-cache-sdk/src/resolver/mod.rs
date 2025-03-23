use crate::{DIDCacheClient, errors::DIDCacheError};
use did_peer::DIDPeer;
use ssi::dids::{DID, DIDEthr, DIDJWK, DIDKey, DIDPKH, DIDResolver, DIDWeb, Document};
use tracing::error;

impl DIDCacheClient {
    /// Resolves a DID to a DID Document
    pub(crate) async fn local_resolve(
        &self,
        did: &str,
        parts: &[&str],
    ) -> Result<Document, DIDCacheError> {
        // Match the DID method

        match parts[1] {
            "ethr" => {
                let method = DIDEthr;

                match method.resolve(DID::new::<str>(did).unwrap()).await {
                    Ok(res) => Ok(res.document.into_document()),
                    Err(e) => {
                        error!("Error: {:?}", e);
                        Err(DIDCacheError::DIDError(e.to_string()))
                    }
                }
            }
            "jwk" => {
                let method = DIDJWK;

                match method.resolve(DID::new::<str>(did).unwrap()).await {
                    Ok(res) => Ok(res.document.into_document()),
                    Err(e) => {
                        error!("Error: {:?}", e);
                        Err(DIDCacheError::DIDError(e.to_string()))
                    }
                }
            }
            "key" => {
                let method = DIDKey;

                match method.resolve(DID::new::<str>(did).unwrap()).await {
                    Ok(res) => {
                        // SSI Library isn't populating keyAgreement, manually add it if it's empty
                        if res
                            .document
                            .verification_relationships
                            .key_agreement
                            .is_empty()
                        {
                            let key_id =
                                res.document.verification_relationships.authentication[0].clone();

                            let mut doc = res.document.into_document();
                            doc.verification_relationships.key_agreement.push(key_id);

                            Ok(doc)
                        } else {
                            Ok(res.document.into_document())
                        }
                    }
                    Err(e) => {
                        error!("Error: {:?}", e);
                        Err(DIDCacheError::DIDError(e.to_string()))
                    }
                }
            }
            "peer" => {
                let method = DIDPeer;

                match method.resolve(DID::new::<str>(did).unwrap()).await {
                    Ok(res) => {
                        // DID Peer will resolve to MultiKey, which confuses key matching
                        // Expand the keys to raw keys
                        DIDPeer::expand_keys(&res.document.into_document())
                            .await
                            .map_err(|e| DIDCacheError::DIDError(e.to_string()))
                    }
                    Err(e) => {
                        error!("Error: {:?}", e);
                        Err(DIDCacheError::DIDError(e.to_string()))
                    }
                }
            }
            "pkh" => {
                let method = DIDPKH;

                match method.resolve(DID::new::<str>(did).unwrap()).await {
                    Ok(res) => Ok(res.document.into_document()),
                    Err(e) => {
                        error!("Error: {:?}", e);
                        Err(DIDCacheError::DIDError(e.to_string()))
                    }
                }
            }
            "web" => {
                let method = DIDWeb;

                match method.resolve(DID::new::<str>(did).unwrap()).await {
                    Ok(res) => Ok(res.document.into_document()),
                    Err(e) => {
                        error!("Error: {:?}", e);
                        Err(DIDCacheError::DIDError(e.to_string()))
                    }
                }
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

    const DID_ETHR: &str = "did:ethr:0x1:0xb9c5714089478a327f09197987f16f9e5d936e8a";
    const DID_JWK: &str = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";
    const DID_KEY: &str = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";
    const DID_PEER: &str = "did:peer:2.Vz6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv.EzQ3shQLqRUza6AMJFbPuMdvFRFWm1wKviQRnQSC1fScovJN4s.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cHM6Ly8xMjcuMC4wLjE6NzAzNyIsImEiOlsiZGlkY29tbS92MiJdLCJyIjpbXX19";
    const DID_PKH: &str = "did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev";

    #[tokio::test]
    async fn local_resolve_ethr() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config).await.unwrap();

        let parts: Vec<&str> = DID_ETHR.split(':').collect();
        let did_document = client.local_resolve(DID_ETHR, &parts).await.unwrap();
        let verification_relationships = did_document.verification_relationships;

        assert_eq!(did_document.id, DID_ETHR);

        assert_eq!(verification_relationships.authentication.len(), 2);
        assert_eq!(verification_relationships.assertion_method.len(), 2);

        assert_eq!(did_document.verification_method.len(), 2,);
    }

    #[tokio::test]
    async fn local_resolve_jwk() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config).await.unwrap();

        let parts: Vec<&str> = DID_JWK.split(':').collect();
        let did_document = client.local_resolve(DID_JWK, &parts).await.unwrap();
        let verification_relationships = did_document.verification_relationships;

        assert_eq!(did_document.id, DID_JWK);

        assert_eq!(verification_relationships.authentication.len(), 1);
        assert_eq!(verification_relationships.assertion_method.len(), 1);
        assert_eq!(verification_relationships.key_agreement.len(), 1);
        assert_eq!(verification_relationships.capability_invocation.len(), 1);
        assert_eq!(verification_relationships.capability_delegation.len(), 1);

        assert_eq!(did_document.verification_method.len(), 1);
        assert_eq!(
            did_document.verification_method.first().unwrap().properties["publicKeyMultibase"],
            "zDnaepnC2eBkx4oZkNLGDnVK8ofKzoGk1Yui8fzC6FLoV1F1e"
        );
    }

    #[tokio::test]
    async fn local_resolve_key() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config).await.unwrap();

        let parts: Vec<&str> = DID_KEY.split(':').collect();
        let did_document = client.local_resolve(DID_KEY, &parts).await.unwrap();
        let verification_relationships = did_document.verification_relationships;

        assert_eq!(did_document.id, DID_KEY);

        assert_eq!(verification_relationships.authentication.len(), 1);
        assert_eq!(verification_relationships.assertion_method.len(), 1);

        assert_eq!(did_document.verification_method.len(), 1);
        assert_eq!(
            did_document.verification_method.first().unwrap().properties["publicKeyMultibase"],
            parts.last().unwrap().to_string()
        );
    }
    #[tokio::test]
    async fn local_resolve_peer() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config).await.unwrap();

        let parts: Vec<&str> = DID_PEER.split(':').collect();
        let did_document = client.local_resolve(DID_PEER, &parts).await.unwrap();
        let verification_relationships = did_document.verification_relationships;
        let verification_method = did_document.verification_method;
        let service = did_document.service;

        assert_eq!(did_document.id, DID_PEER);

        assert_eq!(verification_relationships.authentication.len(), 1);
        assert_eq!(verification_relationships.assertion_method.len(), 1);
        assert_eq!(verification_relationships.key_agreement.len(), 1);

        assert_eq!(verification_method.len(), 2);
        let first_public_key_jwk = &verification_method.first().unwrap().properties["publicKeyJwk"];
        let last_public_key_jwk = &verification_method.last().unwrap().properties["publicKeyJwk"];
        assert_eq!(first_public_key_jwk["crv"], "Ed25519");
        assert_eq!(first_public_key_jwk["kty"], "OKP");
        assert_eq!(
            first_public_key_jwk["x"],
            "O5KzVvRLtJzv8xzpkBjaM3mmUBNF7WE_6e9tGGIM1T8"
        );
        assert_eq!(last_public_key_jwk["crv"], "secp256k1");
        assert_eq!(last_public_key_jwk["kty"], "EC");
        assert_eq!(
            last_public_key_jwk["x"],
            "K4_AlZahXcLOtqnvH45WAMUi97aqQLVs51erkqXP88w"
        );
        assert_eq!(
            last_public_key_jwk["y"],
            "QhrSDu7yD1ZKkHBRiuzQkiNppajd1q56Z1s_5Hi8dkA"
        );

        assert_eq!(service.len(), 1);
        assert_eq!(service.first().unwrap().id, "did:peer:#service");
    }

    #[tokio::test]
    async fn local_resolve_pkh() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config).await.unwrap();
        let parts: Vec<&str> = DID_PKH.split(':').collect();

        let did_document = client.local_resolve(DID_PKH, &parts).await.unwrap();
        let verification_relationships = did_document.verification_relationships;
        let verification_method = did_document.verification_method;
        let vm_properties_first = verification_method.first().unwrap().properties.clone();
        let vm_properties_last = verification_method.last().unwrap().properties.clone();

        assert_eq!(did_document.id, DID_PKH);

        assert_eq!(verification_relationships.authentication.len(), 2);
        assert_eq!(verification_relationships.assertion_method.len(), 2);

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
}
