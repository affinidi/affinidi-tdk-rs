/*!
 * Affinidi Trust Development Kit
 *
 * Instantiate a TDK client with the `new` function
 */

#[cfg(feature = "data-integrity")]
use affinidi_data_integrity::{
    DataIntegrityError, DataIntegrityProof, verification_proof::VerificationProof,
};
use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
#[cfg(feature = "messaging")]
use affinidi_messaging_sdk::ATM;
#[cfg(feature = "messaging")]
use affinidi_messaging_sdk::config::ATMConfigBuilder;
use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver};
use affinidi_tdk_common::{
    TDKSharedState, create_http_client, environments::TDKEnvironments, errors::Result,
    profiles::TDKProfile, tasks::authentication::AuthenticationCache,
};
use common::{config::TDKConfig, environments::TDKEnvironment};
#[cfg(feature = "data-integrity")]
use serde::Serialize;
use std::sync::Arc;

pub mod dids;
pub mod secrets;

// Re-export required crates for convenience to applications
#[cfg(feature = "meeting-place")]
pub use affinidi_meeting_place as meeting_place;

#[cfg(feature = "messaging")]
pub use affinidi_messaging_didcomm as didcomm;
#[cfg(feature = "messaging")]
pub use affinidi_messaging_sdk as messaging;

// did-peer functionality is now integrated into affinidi_did_common
// Use affinidi_tdk::dids module for DID generation

#[cfg(feature = "data-integrity")]
pub use affinidi_data_integrity as data_integrity;

// Always exported
pub use affinidi_did_common as did_common;
pub use affinidi_secrets_resolver as secrets_resolver;
pub use affinidi_tdk_common as common;

/// TDK instance that can be used to interact with Affinidi services
#[derive(Clone)]
pub struct TDK {
    pub(crate) inner: Arc<TDKSharedState>,
    #[cfg(feature = "messaging")]
    pub atm: Option<ATM>,
    #[cfg(feature = "meeting-place")]
    pub meeting_place: Option<meeting_place::MeetingPlace>,
}

/// Affinidi Trusted Development Kit (TDK)
///
/// Use this to instantiate everything required to easily interact with Affinidi services
/// If you are self hosting the services, you can use your own service URL's where required
///
/// Example:
/// ```ignore
/// use affinidi_tdk::TDK;
/// use affinidi_tdk_common::config::TDKConfig;
///
/// let config = TDKConfig::new().build();
/// let mut tdk = TDK::new(config).await?;
///
///
/// ```
/// NOTE: If feature-flag "messaging" is enabled, then there is an option to bring a
/// pre-configgured ATM instance to the TDK. If none is specified then ATM is automatically setup
/// for you.
impl TDK {
    pub async fn new(
        config: TDKConfig,
        #[cfg(feature = "messaging")] atm: Option<ATM>,
    ) -> Result<Self> {
        let client = create_http_client();

        // Instantiate the DID resolver for TDK
        let did_resolver = if let Some(did_resolver) = &config.did_resolver {
            did_resolver.to_owned()
        } else if let Some(did_resolver_config) = &config.did_resolver_config {
            DIDCacheClient::new(did_resolver_config.to_owned()).await?
        } else {
            DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?
        };

        // Instantiate the SecretsManager for TDK
        let secrets_resolver = if let Some(secrets_resolver) = &config.secrets_resolver {
            secrets_resolver.to_owned()
        } else {
            ThreadedSecretsResolver::new(None).await.0
        };

        // Instantiate the authentication cache
        let (authentication, _) = AuthenticationCache::new(
            config.authentication_cache_limit as u64,
            &did_resolver,
            secrets_resolver.clone(),
            &client,
            config.custom_auth_handlers.clone(),
        );

        authentication.start().await;

        // Load Environment
        // Adds secrets to the secrets resolver
        // Removes secrets from the environment itself
        let environment = if config.load_environment {
            let mut environment = TDKEnvironments::fetch_from_file(
                Some(&config.environment_path),
                &config.environment_name,
            )?;
            for (_, profile) in environment.profiles.iter_mut() {
                secrets_resolver
                    .insert_vec(profile.secrets.as_slice())
                    .await;

                // Remove secrets from profile after adding them to the secrets resolver
                profile.secrets.clear();
            }
            environment
        } else {
            TDKEnvironment::default()
        };

        // Create the shared state, then we can use this inside other Affinidi Crates
        let shared_state = Arc::new(TDKSharedState {
            config,
            did_resolver,
            secrets_resolver,
            client,
            environment,
            authentication,
        });

        #[cfg(feature = "messaging")]
        // Instantiate Affinidi Messaging
        let atm = if shared_state.config.use_atm {
            if let Some(atm) = atm {
                Some(atm.to_owned())
            } else {
                // Use the same DID Resolver for ATM
                Some(ATM::new(ATMConfigBuilder::default().build()?, shared_state.clone()).await?)
            }
        } else {
            None
        };

        Ok(TDK {
            inner: shared_state,
            #[cfg(feature = "messaging")]
            atm,
            #[cfg(feature = "meeting-place")]
            meeting_place: None,
        })
    }

    /// Get the shared state of the TDK
    pub fn get_shared_state(&self) -> Arc<TDKSharedState> {
        self.inner.clone()
    }

    /// Adds a TDK Profile to the shared state
    /// Which is really just adding the secrets to the secrets resolver
    /// For the moment...
    pub async fn add_profile(&self, profile: &TDKProfile) {
        self.inner
            .secrets_resolver
            .insert_vec(&profile.secrets)
            .await;
    }

    /// Access shared DID resolver
    pub fn did_resolver(&self) -> &DIDCacheClient {
        &self.inner.did_resolver
    }

    /// Verify a signed JSON Schema document which includes a DID lookup resolution step.
    /// If you already have public key bytes, call [verify_data_with_public_key] instead.
    /// You must strip `proof` from the document as needed
    /// Context is a copy of any context that needs to be passed in
    #[cfg(feature = "data-integrity")]
    pub async fn verify_data<S>(
        &self,
        signed_doc: &S,
        context: Option<Vec<String>>,
        proof: &DataIntegrityProof,
    ) -> Result<VerificationProof>
    where
        S: Serialize,
    {
        // Create public key bytes from Verification Material

        use affinidi_data_integrity::verification_proof::verify_data_with_public_key;
        use affinidi_did_common::document::DocumentExt;
        use affinidi_tdk_common::errors::TDKError;
        let did = if let Some((did, _)) = proof.verification_method.split_once("#") {
            did
        } else {
            use affinidi_tdk_common::errors::TDKError;

            return Err(TDKError::DataIntegrity(DataIntegrityError::InputDataError(
                "Invalid proof:verificationMethod. Must be DID#key-id format".to_string(),
            )));
        };

        let resolved = self.inner.did_resolver.resolve(did).await?;
        let public_bytes = if let Some(vm) = resolved
            .doc
            .get_verification_method(&proof.verification_method)
        {
            vm.get_public_key_bytes().map_err(|e| {
                DataIntegrityError::InputDataError(format!(
                    "Failed to get public key bytes from verification method: {e}"
                ))
            })?
        } else {
            return Err(TDKError::DataIntegrity(DataIntegrityError::InputDataError(
                format!(
                    "Couldn't find key-id ({}) in resolved DID Document",
                    proof.verification_method
                ),
            )));
        };

        verify_data_with_public_key(signed_doc, context, proof, public_bytes.as_slice())
            .map_err(TDKError::DataIntegrity)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use affinidi_data_integrity::{DataIntegrityError, crypto_suites::CryptoSuite};
    use affinidi_tdk_common::{config::TDKConfig, errors::TDKError};

    use crate::TDK;

    #[tokio::test]
    async fn invalid_verification_method() {
        let proof = crate::DataIntegrityProof {
                type_: "DataIntegrityProof".to_string(),
                cryptosuite: CryptoSuite::EddsaJcs2022,
                created: Some("2025-01-01T00:00:00Z".to_string()),
                verification_method: "test".to_string(),
                proof_purpose: "test".to_string(),
                proof_value: Some("z2RPk8MWLoULfcbtpULoEsgfDsaAvyfD1PvQC2v3BjqqNtzGu8YJ4Nxq8CmJCZpPqA49uJhkxmxSztUQhBxqnVrYj".to_string()),
                context: None,
        };

        let tdk = TDK::new(
            TDKConfig::builder()
                .with_load_environment(false)
                .build()
                .unwrap(),
            None,
        )
        .await
        .unwrap();
        let result = tdk
            .verify_data(&HashMap::<String, String>::new(), None, &proof)
            .await;
        assert!(result.is_err());
        match result {
            Err(TDKError::DataIntegrity(DataIntegrityError::InputDataError(txt))) => {
                assert_eq!(
                    txt,
                    "Invalid proof:verificationMethod. Must be DID#key-id format".to_string()
                );
            }
            _ => panic!("Invalid return type"),
        }
    }

    #[tokio::test]
    async fn invalid_verification_method_2() {
        let proof = crate::DataIntegrityProof {
                type_: "DataIntegrityProof".to_string(),
                cryptosuite: CryptoSuite::EddsaJcs2022,
                created: Some("2025-01-01T00:00:00Z".to_string()),
                verification_method: "did:key:not_a_key".to_string(),
                proof_purpose: "test".to_string(),
                proof_value: Some("z2RPk8MWLoULfcbtpULoEsgfDsaAvyfD1PvQC2v3BjqqNtzGu8YJ4Nxq8CmJCZpPqA49uJhkxmxSztUQhBxqnVrYj".to_string()),
                context: None,
        };

        let tdk = TDK::new(
            TDKConfig::builder()
                .with_load_environment(false)
                .build()
                .unwrap(),
            None,
        )
        .await
        .unwrap();
        let result = tdk
            .verify_data(&HashMap::<String, String>::new(), None, &proof)
            .await;
        assert!(result.is_err());
        match result {
            Err(TDKError::DataIntegrity(DataIntegrityError::InputDataError(txt))) => {
                assert_eq!(
                    txt,
                    "Invalid proof:verificationMethod. Must be DID#key-id format".to_string()
                );
            }
            _ => panic!("Invalid return type"),
        }
    }

    #[tokio::test]
    async fn invalid_verification_method_3() {
        let proof = crate::DataIntegrityProof {
                type_: "DataIntegrityProof".to_string(),
                cryptosuite: CryptoSuite::EddsaJcs2022,
                created: Some("2025-01-01T00:00:00Z".to_string()),
                verification_method: "did:key:test#test".to_string(),
                proof_purpose: "test".to_string(),
                proof_value: Some("z2RPk8MWLoULfcbtpULoEsgfDsaAvyfD1PvQC2v3BjqqNtzGu8YJ4Nxq8CmJCZpPqA49uJhkxmxSztUQhBxqnVrYj".to_string()),
                context: None,
        };

        let tdk = TDK::new(
            TDKConfig::builder()
                .with_load_environment(false)
                .build()
                .unwrap(),
            None,
        )
        .await
        .unwrap();
        let result = tdk
            .verify_data(&HashMap::<String, String>::new(), None, &proof)
            .await;
        assert!(result.is_err());
        match result {
            Err(TDKError::DIDResolver(txt)) => {
                assert_eq!(
                    txt,
                    "DID error: Invalid DID (did:key:test) Error: DID Url doesn't start with did:key:z"
                        .to_string()
                );
            }
            _ => panic!("Invalid return type {:#?}", result),
        }
    }
}
