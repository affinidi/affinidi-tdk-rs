/*!
 * Affinidi Trust Development Kit
 *
 * Umbrella crate that wires together [`affinidi_tdk_common::TDKSharedState`]
 * (DID resolver, secrets resolver, HTTPS client, authentication cache) with
 * the optional Affinidi Messaging SDK ([`messaging::ATM`]) and Meeting Place
 * client ([`meeting_place::MeetingPlace`]).
 *
 * Construct with [`TDK::new`]; the heavy lifting is delegated to
 * [`TDKSharedState::new`].
 */

#![forbid(unsafe_code)]

#[cfg(feature = "data-integrity")]
use affinidi_data_integrity::{
    DataIntegrityError, DataIntegrityProof, VerifyOptions, verification_proof::VerificationProof,
};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
#[cfg(feature = "messaging")]
use affinidi_messaging_sdk::{ATM, config::ATMConfigBuilder};
use affinidi_tdk_common::{
    TDKSharedState, config::TDKConfig, errors::Result, profiles::TDKProfile,
};
#[cfg(feature = "data-integrity")]
use serde::Serialize;
use std::sync::Arc;

pub mod dids;
pub mod secrets;

// Re-exports for application convenience.
#[cfg(feature = "meeting-place")]
pub use affinidi_meeting_place as meeting_place;

pub use affinidi_messaging_didcomm as didcomm;
#[cfg(feature = "messaging")]
pub use affinidi_messaging_sdk as messaging;

#[cfg(feature = "data-integrity")]
pub use affinidi_data_integrity as data_integrity;

pub use affinidi_crypto;
pub use affinidi_did_authentication as did_authentication;
pub use affinidi_did_common as did_common;
pub use affinidi_secrets_resolver as secrets_resolver;
pub use affinidi_tdk_common as common;

/// TDK instance — a thin orchestrator over [`TDKSharedState`] plus optional
/// messaging and meeting-place clients.
///
/// Cloning is cheap; the inner shared state is `Arc`-backed.
#[derive(Clone)]
pub struct TDK {
    inner: Arc<TDKSharedState>,
    #[cfg(feature = "messaging")]
    pub atm: Option<ATM>,
    #[cfg(feature = "meeting-place")]
    pub meeting_place: Option<meeting_place::MeetingPlace>,
}

impl TDK {
    /// Build a new `TDK` from the supplied configuration.
    ///
    /// Delegates state construction to [`TDKSharedState::new`] (which loads
    /// the on-disk environment when `config.load_environment()` is `true`),
    /// then loads each profile's secrets into the shared resolver and
    /// optionally instantiates [`ATM`] when `config.use_atm()` is set.
    ///
    /// Pass `Some(atm)` to bring a pre-built `ATM` instance (the config's
    /// `use_atm` is still honoured — it gates whether `atm` is retained at
    /// all). Pass `None` to let `TDK` construct one for you.
    pub async fn new(
        config: TDKConfig,
        #[cfg(feature = "messaging")] atm: Option<ATM>,
    ) -> Result<Self> {
        let shared = Arc::new(TDKSharedState::new(config).await?);

        // Hand each environment profile's secrets to the shared resolver so
        // signing/auth flows can find them. The environment retains the
        // canonical copy on disk; this is the in-memory load step.
        for profile in shared.environment().profiles().values() {
            shared.add_profile(profile).await;
        }

        #[cfg(feature = "messaging")]
        let atm = if shared.config().use_atm() {
            Some(match atm {
                Some(atm) => atm,
                None => ATM::new(ATMConfigBuilder::default().build()?, shared.clone()).await?,
            })
        } else {
            None
        };

        Ok(TDK {
            inner: shared,
            #[cfg(feature = "messaging")]
            atm,
            #[cfg(feature = "meeting-place")]
            meeting_place: None,
        })
    }

    /// Shared state handle. Cheap to clone.
    pub fn get_shared_state(&self) -> Arc<TDKSharedState> {
        self.inner.clone()
    }

    /// Borrow the shared state without bumping its refcount.
    pub fn shared(&self) -> &TDKSharedState {
        &self.inner
    }

    /// Add a [`TDKProfile`]'s secrets to the shared resolver. Convenience
    /// passthrough to [`TDKSharedState::add_profile`].
    pub async fn add_profile(&self, profile: &TDKProfile) {
        self.inner.add_profile(profile).await;
    }

    /// Borrow the shared DID resolver.
    pub fn did_resolver(&self) -> &DIDCacheClient {
        self.inner.did_resolver()
    }

    /// Verify a Data Integrity proof, resolving the public key from the
    /// `proof.verification_method` DID URL.
    ///
    /// If you already hold the public key bytes, prefer
    /// [`DataIntegrityProof::verify_with_public_key`] to skip the resolver
    /// hop. The `context` argument, when set, is checked against the proof's
    /// `@context` array.
    ///
    /// `signed_doc` must already have its `proof` field stripped — the proof
    /// is supplied separately.
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
        use affinidi_did_common::document::DocumentExt;
        use affinidi_tdk_common::errors::TDKError;

        let (did, _) = proof.verification_method.split_once('#').ok_or_else(|| {
            TDKError::DataIntegrity(DataIntegrityError::MalformedProof(
                "Invalid proof:verificationMethod. Must be DID#key-id format".to_string(),
            ))
        })?;

        let resolved = self.inner.did_resolver().resolve(did).await?;
        let vm = resolved
            .doc
            .get_verification_method(&proof.verification_method)
            .ok_or_else(|| {
                TDKError::DataIntegrity(DataIntegrityError::MalformedProof(format!(
                    "Couldn't find key-id ({}) in resolved DID Document",
                    proof.verification_method
                )))
            })?;

        let public_bytes =
            vm.get_public_key_bytes()
                .map_err(|e| DataIntegrityError::InvalidPublicKey {
                    codec: None,
                    len: 0,
                    reason: format!("Failed to get public key bytes from verification method: {e}"),
                })?;

        let mut options = VerifyOptions::new();
        if let Some(ctx) = context {
            options = options.with_expected_context(ctx);
        }
        proof
            .verify_with_public_key(signed_doc, public_bytes.as_slice(), options)
            .map_err(TDKError::DataIntegrity)?;

        Ok(VerificationProof {
            verified: true,
            verified_document: None,
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "data-integrity")]
    mod data_integrity {
        use std::collections::HashMap;

        use affinidi_data_integrity::{DataIntegrityError, crypto_suites::CryptoSuite};
        use affinidi_tdk_common::{config::TDKConfig, errors::TDKError};

        use crate::{DataIntegrityProof, TDK};

        async fn tdk() -> TDK {
            TDK::new(
                TDKConfig::builder()
                    .with_load_environment(false)
                    .with_use_atm(false)
                    .build()
                    .expect("config builds"),
                #[cfg(feature = "messaging")]
                None,
            )
            .await
            .expect("tdk builds")
        }

        fn proof_with_vm(verification_method: &str) -> DataIntegrityProof {
            DataIntegrityProof {
                type_: "DataIntegrityProof".to_string(),
                cryptosuite: CryptoSuite::EddsaJcs2022,
                created: Some("2025-01-01T00:00:00Z".to_string()),
                verification_method: verification_method.to_string(),
                proof_purpose: "assertionMethod".to_string(),
                proof_value: Some(
                    "z2RPk8MWLoULfcbtpULoEsgfDsaAvyfD1PvQC2v3BjqqNtzGu8YJ4Nxq8CmJCZpPqA49uJhkxmxSztUQhBxqnVrYj"
                        .to_string(),
                ),
                context: None,
            }
        }

        #[tokio::test]
        async fn verify_rejects_vm_without_fragment() {
            let proof = proof_with_vm("test");
            let result = tdk()
                .await
                .verify_data(&HashMap::<String, String>::new(), None, &proof)
                .await;
            match result {
                Err(TDKError::DataIntegrity(DataIntegrityError::MalformedProof(txt))) => {
                    assert_eq!(
                        txt,
                        "Invalid proof:verificationMethod. Must be DID#key-id format"
                    );
                }
                other => panic!("expected MalformedProof, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn verify_rejects_did_without_fragment_separator() {
            let proof = proof_with_vm("did:key:not_a_key");
            let result = tdk()
                .await
                .verify_data(&HashMap::<String, String>::new(), None, &proof)
                .await;
            match result {
                Err(TDKError::DataIntegrity(DataIntegrityError::MalformedProof(txt))) => {
                    assert_eq!(
                        txt,
                        "Invalid proof:verificationMethod. Must be DID#key-id format"
                    );
                }
                other => panic!("expected MalformedProof, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn verify_propagates_resolver_error_on_invalid_did() {
            let proof = proof_with_vm("did:key:test#test");
            let result = tdk()
                .await
                .verify_data(&HashMap::<String, String>::new(), None, &proof)
                .await;
            assert!(
                matches!(result, Err(TDKError::DIDResolver(_))),
                "expected DIDResolver error, got {result:?}"
            );
        }
    }
}
