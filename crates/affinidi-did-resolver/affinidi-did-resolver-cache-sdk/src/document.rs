//! Extends the SSI Crate Document with new methods and functions

use ssi::{
    dids::{
        DIDURL, Document,
        document::{DIDVerificationMethod, ResourceRef},
    },
    verification_methods::ProofPurposes,
};
use tracing::warn;

pub trait DocumentExt {
    /// Does this DID contain authentication verification_method with the given id?
    fn contains_authentication(&self, id: &str) -> bool;

    /// Does this DID contain a key agreement with the given id?
    fn contains_key_agreement(&self, id: &str) -> bool;

    /// find_key_agreement or return all
    /// Returns fully defined Vec of key_agreement id's
    fn find_key_agreement(&self, id: Option<&str>) -> Vec<String>;

    /// Returns a DID Verification Method if found by ID
    fn get_verification_method(&self, id: &str) -> Option<&DIDVerificationMethod>;
}

impl DocumentExt for Document {
    fn contains_authentication(&self, id: &str) -> bool {
        let id = if let Ok(id) = DIDURL::new(id.as_bytes()) {
            id
        } else {
            return false;
        };

        self.verification_relationships.contains(
            &self.id,
            id,
            ProofPurposes {
                assertion_method: false,
                authentication: true,
                key_agreement: false,
                capability_delegation: false,
                capability_invocation: false,
            },
        )
    }

    fn contains_key_agreement(&self, id: &str) -> bool {
        let id = if let Ok(id) = DIDURL::new(id.as_bytes()) {
            id
        } else {
            return false;
        };

        self.verification_relationships.contains(
            &self.id,
            id,
            ProofPurposes {
                assertion_method: false,
                authentication: false,
                key_agreement: true,
                capability_delegation: false,
                capability_invocation: false,
            },
        )
    }

    fn find_key_agreement(&self, id: Option<&str>) -> Vec<String> {
        if let Some(id) = id {
            // Does this id exist in key_agreements?
            if self.contains_key_agreement(id) {
                vec![id.to_string()]
            } else {
                vec![]
            }
        } else {
            let did = self.id.as_did();
            self.verification_relationships
                .key_agreement
                .iter()
                .map(|ka| ka.id().resolve(did).to_string())
                .collect()
        }
    }

    fn get_verification_method(&self, id: &str) -> Option<&DIDVerificationMethod> {
        let id_url = match DIDURL::new(id.as_bytes()) {
            Ok(id) => id,
            Err(_) => {
                warn!("Invalid DID URL: {}", id);
                return None;
            }
        };

        if let Some(resource) = self.find_resource(id_url) {
            match resource {
                ResourceRef::VerificationMethod(method) => Some(method),
                _ => {
                    warn!("Resource is not a verification method: {}", id);
                    None
                }
            }
        } else {
            warn!("Resource not found: {}", id);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{DIDCacheClient, config};

    use super::*;

    const TEST_DID: &str = "did:peer:2.Vz6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv.EzQ3shQLqRUza6AMJFbPuMdvFRFWm1wKviQRnQSC1fScovJN4s.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cHM6Ly8xMjcuMC4wLjE6NzAzNyIsImEiOlsiZGlkY29tbS92MiJdLCJyIjpbXX19";

    async fn basic_local_client() -> DIDCacheClient {
        let config = config::DIDCacheConfigBuilder::default().build();
        DIDCacheClient::new(config).await.unwrap()
    }

    #[tokio::test]
    async fn key_agreement_id_exists() {
        let client = basic_local_client().await;

        // Resolve a DID which automatically adds it to the cache
        let response = client.resolve(TEST_DID).await.unwrap();
        assert!(
            response
                .doc
                .contains_key_agreement(&[TEST_DID, "#key-2"].concat())
        );
    }

    #[tokio::test]
    async fn key_agreement_id_missing() {
        let client = basic_local_client().await;

        // Resolve a DID which automatically adds it to the cache
        let response = client.resolve(TEST_DID).await.unwrap();
        assert!(
            !response
                .doc
                .contains_key_agreement(&[TEST_DID, "#key-3"].concat())
        );
    }

    #[tokio::test]
    async fn invalid_key_agreement() {
        let client = basic_local_client().await;

        // Resolve a DID which automatically adds it to the cache
        let response = client.resolve(TEST_DID).await.unwrap();
        assert!(!response.doc.contains_key_agreement("BAD_DID:TEST#FAIL"));
    }
}
