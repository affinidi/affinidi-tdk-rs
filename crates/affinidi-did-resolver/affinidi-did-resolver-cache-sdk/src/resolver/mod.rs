pub mod network_resolvers;
use crate::{DIDCacheClient, MethodName, errors::DIDCacheError};
#[cfg(any(
    not(feature = "did-webvh"),
    not(feature = "did-cheqd"),
    not(feature = "did-scid")
))]
use affinidi_did_common::DIDMethod;
use affinidi_did_common::{DID, Document};

impl DIDCacheClient {
    /// Resolves a DID to a DID Document by looking up the method's resolver chain.
    ///
    /// Resolvers for the method are tried front-to-back. Each returns `None` if
    /// it declines, `Some(Ok(doc))` on success, or `Some(Err(e))` on failure.
    /// The first resolver that returns `Some` wins.
    pub(crate) async fn local_resolve(&self, did: &DID) -> Result<Document, DIDCacheError> {
        let method_name: MethodName = MethodName::from(&did.method());

        if let Some(chain) = self.resolvers.get(&method_name) {
            for resolver in chain.iter() {
                if let Some(result) = resolver.resolve(did).await {
                    return result.map_err(|e| DIDCacheError::DIDError(e.to_string()));
                }
            }
        }

        // Preserve UnsupportedMethod errors for known but feature-disabled methods
        match did.method() {
            #[cfg(not(feature = "did-webvh"))]
            DIDMethod::Webvh { .. } => Err(DIDCacheError::UnsupportedMethod(
                "did:webvh is not enabled".to_string(),
            )),
            #[cfg(not(feature = "did-cheqd"))]
            DIDMethod::Cheqd { .. } => Err(DIDCacheError::UnsupportedMethod(
                "did:cheqd is not enabled".to_string(),
            )),
            #[cfg(not(feature = "did-scid"))]
            DIDMethod::Scid { .. } => Err(DIDCacheError::UnsupportedMethod(
                "did:scid is not enabled".to_string(),
            )),
            _ => Err(DIDCacheError::DIDError(format!(
                "No resolver registered for DID method '{}'",
                did.method()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{DIDCacheClient, MethodName, config};
    use affinidi_did_common::DID;
    use affinidi_did_common::Document;
    use affinidi_did_resolver_traits::{AsyncResolver, Resolution, ResolverError};
    use std::future::Future;
    use std::pin::Pin;

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

        let did: DID = DID_ETHR.parse().unwrap();
        let did_document = client.local_resolve(&did).await.unwrap();

        assert_eq!(did_document.id.as_str(), DID_ETHR);

        assert_eq!(did_document.authentication.len(), 2);
        assert_eq!(did_document.assertion_method.len(), 2);

        assert_eq!(did_document.verification_method.len(), 2,);
    }

    #[tokio::test]
    #[cfg(feature = "did-jwk")]
    async fn local_resolve_jwk() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config).await.unwrap();

        let did: DID = DID_JWK.parse().unwrap();
        let did_document = client.local_resolve(&did).await.unwrap();

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

        let did: DID = DID_KEY.parse().unwrap();
        let did_document = client.local_resolve(&did).await.unwrap();

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

        let did: DID = DID_PEER.parse().unwrap();
        let did_document = client.local_resolve(&did).await.unwrap();
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

        let did: DID = DID_PKH.parse().unwrap();
        let did_document = client.local_resolve(&did).await.unwrap();
        let verification_method = did_document.verification_method;
        let vm_properties_first = verification_method.first().unwrap().property_set.clone();
        let vm_properties_last = verification_method.last().unwrap().property_set.clone();

        assert_eq!(did_document.id.as_str(), DID_PKH);

        assert_eq!(did_document.authentication.len(), 2);
        assert_eq!(did_document.assertion_method.len(), 2);

        assert_eq!(verification_method.len(), 2);
        // The last part of the DID is the public key
        let parts: Vec<&str> = DID_PKH.split(':').collect();
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
    #[ignore = "requires external network (identity.foundation)"]
    async fn local_resolve_webvh() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config).await.unwrap();

        let did: DID = DID_WEBVH.parse().unwrap();
        let did_document = client.local_resolve(&did).await.unwrap();

        assert_eq!(did_document.id.as_str(), DID_WEBVH);
    }

    #[tokio::test]
    #[cfg(feature = "did-cheqd")]
    #[ignore = "requires external network (cheqd.net)"]
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
    #[ignore = "requires external network (identity.foundation)"]
    async fn local_resolve_scid() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config).await.unwrap();

        let did_document = client.resolve(DID_SCID).await.unwrap();
        assert_eq!(
            did_document.did.as_str(),
            "did:webvh:Qmd1FCL9Vj2vJ433UDfC9MBstK6W6QWSQvYyeNn8va2fai:identity.foundation:didwebvh-implementations:implementations:affinidi-didwebvh-rs"
        );
    }

    // -----------------------------------------------------------------------
    // Test resolvers
    // -----------------------------------------------------------------------

    /// A test resolver that handles `did:test:*` DIDs.
    struct TestResolver;

    impl AsyncResolver for TestResolver {
        fn name(&self) -> &str {
            "TestResolver"
        }

        fn resolve<'a>(
            &'a self,
            did: &'a DID,
        ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
            Box::pin(async move {
                let did_str = did.to_string();
                if !did_str.starts_with("did:test:") {
                    return None;
                }
                // Return a minimal valid document
                let doc_json = format!(
                    r#"{{"id":"{}","verificationMethod":[],"authentication":[],"assertionMethod":[],"keyAgreement":[],"capabilityInvocation":[],"capabilityDelegation":[],"service":[]}}"#,
                    did_str
                );
                Some(
                    serde_json::from_str::<Document>(&doc_json)
                        .map_err(|e| ResolverError::InvalidDocument(e.to_string())),
                )
            })
        }
    }

    /// A resolver that intercepts did:key and returns a stub document,
    /// proving custom resolvers take priority over built-ins.
    struct OverrideKeyResolver;

    impl AsyncResolver for OverrideKeyResolver {
        fn name(&self) -> &str {
            "OverrideKeyResolver"
        }

        fn resolve<'a>(
            &'a self,
            did: &'a DID,
        ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
            Box::pin(async move {
                let did_str = did.to_string();
                if !did_str.starts_with("did:key:") {
                    return None;
                }
                // Return a stub document with 0 verification methods
                // (built-in KeyResolver returns 2 for Ed25519)
                let doc_json = format!(
                    r#"{{"id":"{}","verificationMethod":[],"authentication":[],"assertionMethod":[],"keyAgreement":[],"capabilityInvocation":[],"capabilityDelegation":[],"service":[]}}"#,
                    did_str
                );
                Some(
                    serde_json::from_str::<Document>(&doc_json)
                        .map_err(|e| ResolverError::InvalidDocument(e.to_string())),
                )
            })
        }
    }

    // -----------------------------------------------------------------------
    // API tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn custom_resolver_for_new_method() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let mut client = DIDCacheClient::new(config).await.unwrap();

        // Register a resolver for a method with no built-in
        client.set_resolver(
            MethodName::Other("test".to_string()),
            Box::new(TestResolver),
        );
        let did: DID = "did:test:alice".parse().unwrap();
        let doc = client.local_resolve(&did).await.unwrap();
        assert_eq!(doc.id.as_str(), "did:test:alice");
    }

    #[tokio::test]
    async fn custom_resolver_overrides_builtin() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let mut client = DIDCacheClient::new(config).await.unwrap();

        // Built-in KeyResolver returns 2 verification methods for Ed25519
        let did: DID = DID_KEY.parse().unwrap();
        let doc = client.local_resolve(&did).await.unwrap();
        assert_eq!(doc.verification_method.len(), 2);

        // Replace built-in with override that returns 0 verification methods
        client.set_resolver(MethodName::Key, Box::new(OverrideKeyResolver));
        let doc = client.local_resolve(&did).await.unwrap();
        // Custom resolver wins — 0 VMs instead of 2
        assert_eq!(doc.verification_method.len(), 0);
        assert_eq!(doc.id.as_str(), DID_KEY);
    }

    #[tokio::test]
    async fn unregistered_method_returns_error() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let client = DIDCacheClient::new(config).await.unwrap();

        // did:test is not registered by default
        let did: DID = "did:test:alice".parse().unwrap();
        let result = client.local_resolve(&did).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn prepend_resolver_enforces_uniqueness() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let mut client = DIDCacheClient::new(config).await.unwrap();

        // First registration succeeds
        let result = client.prepend_resolver(
            MethodName::Other("test".to_string()),
            Box::new(TestResolver),
        );
        assert!(result.is_ok());

        // Duplicate name fails
        let result = client.prepend_resolver(
            MethodName::Other("test".to_string()),
            Box::new(TestResolver),
        );
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn append_resolver_enforces_uniqueness() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let mut client = DIDCacheClient::new(config).await.unwrap();

        let result = client.append_resolver(
            MethodName::Other("test".to_string()),
            Box::new(TestResolver),
        );
        assert!(result.is_ok());

        let result = client.append_resolver(
            MethodName::Other("test".to_string()),
            Box::new(TestResolver),
        );
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn find_and_remove_resolver() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let mut client = DIDCacheClient::new(config).await.unwrap();

        // KeyResolver is registered at construction
        let idx = client.find_resolver(&MethodName::Key, "KeyResolver");
        assert_eq!(idx, Some(0));

        // Remove it
        let removed = client.remove_resolver(&MethodName::Key, 0);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name(), "KeyResolver");

        // Now it's gone
        assert!(
            client
                .find_resolver(&MethodName::Key, "KeyResolver")
                .is_none()
        );

        // did:key resolution should fail
        let did: DID = DID_KEY.parse().unwrap();
        assert!(client.local_resolve(&did).await.is_err());
    }

    #[tokio::test]
    async fn clear_resolvers_removes_all() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let mut client = DIDCacheClient::new(config).await.unwrap();

        // Verify key resolution works
        let did: DID = DID_KEY.parse().unwrap();
        assert!(client.local_resolve(&did).await.is_ok());

        // Clear and verify it fails
        client.clear_resolvers(&MethodName::Key);
        assert!(client.local_resolve(&did).await.is_err());
    }

    #[tokio::test]
    async fn prepend_gives_priority_over_existing() {
        let config = config::DIDCacheConfigBuilder::default().build();
        let mut client = DIDCacheClient::new(config).await.unwrap();

        // Built-in KeyResolver returns 2 VMs
        let did: DID = DID_KEY.parse().unwrap();
        let doc = client.local_resolve(&did).await.unwrap();
        assert_eq!(doc.verification_method.len(), 2);

        // Prepend override (0 VMs) — it goes before built-in
        client
            .prepend_resolver(MethodName::Key, Box::new(OverrideKeyResolver))
            .unwrap();
        let doc = client.local_resolve(&did).await.unwrap();
        assert_eq!(doc.verification_method.len(), 0);

        // Built-in is still there at index 1
        assert_eq!(
            client.find_resolver(&MethodName::Key, "KeyResolver"),
            Some(1)
        );
        assert_eq!(
            client.find_resolver(&MethodName::Key, "OverrideKeyResolver"),
            Some(0)
        );
    }
}
