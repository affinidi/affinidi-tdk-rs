/*!
 * This module is a simple example of a DID resolver that uses a cache to store DID documents.
 *
 * Should only be used for local testing and development
 *
 * Enable using the did_example feature flag
 */

use std::collections::HashMap;

use affinidi_did_common::service::{Endpoint, Service};
use affinidi_did_common::verification_method::VerificationRelationship;
use affinidi_did_common::{Document, verification_method::VerificationMethod};
use did_cheqd::resolution::resolver::{DidCheqdResolver, DidCheqdResolverConfiguration};
use did_resolver::did_doc::schema::verification_method::{PublicKeyField, VerificationMethodKind};
use did_resolver::did_parser_nom::{Did, DidUrl};
use thiserror::Error;
use url::Url;

pub struct DIDCheqd;

#[derive(Error, Debug)]
pub enum DIDCheqdError {
    #[error("Error parsing DID document: {0}")]
    DocumentParseError(String),
    #[error("Error parsing DID: {0}")]
    DIDParseError(String),
}

impl DIDCheqd {
    pub async fn resolve(did: &str) -> Result<Option<Document>, DIDCheqdError> {
        // Initialize resolver
        let resolver = DidCheqdResolver::new(DidCheqdResolverConfiguration::default());
        let did_obj = match Did::try_from(did) {
            Ok(d) => d,
            Err(e) => {
                return Err(DIDCheqdError::DIDParseError(format!(
                    "Failed to resolve DID: {e}"
                )));
            }
        };

        // If not found in cache, attempt to resolve using did_cheqd crate
        match resolver.resolve_did(&did_obj).await {
            Ok(doc) => {
                let verification_method = doc
                    .did_document
                    .verification_method()
                    .iter()
                    .map(|vm| {
                        let mut property_set: HashMap<String, serde_json::Value> = HashMap::new();
                        match vm.public_key_field() {
                            PublicKeyField::Multibase {
                                public_key_multibase,
                            } => {
                                property_set.insert(
                                    "publicKeyMultibase".to_string(),
                                    serde_json::Value::String(public_key_multibase.clone()),
                                );
                            }
                            PublicKeyField::Jwk { public_key_jwk } => {
                                property_set.insert(
                                    "publicKeyJwk".to_string(),
                                    serde_json::to_value(public_key_jwk)
                                        .unwrap_or(serde_json::Value::Null),
                                );
                            }
                            _ => {}
                        }
                        VerificationMethod {
                            id: Url::parse(vm.id().did_url()).unwrap(),
                            type_: vm.verification_method_type().to_string(),
                            controller: Url::parse(vm.controller().did()).unwrap(),
                            expires: None,
                            revoked: None,
                            property_set,
                        }
                    })
                    .collect();
                Ok(Some(Document {
                    id: Url::parse(did).map_err(|e| DIDCheqdError::DIDParseError(e.to_string()))?,
                    verification_method,
                    authentication: doc
                        .did_document
                        .authentication()
                        .iter()
                        .map(|a| match a {
                            VerificationMethodKind::Resolved(vm) => {
                                VerificationRelationship::Reference(
                                    Url::parse(vm.id().did_url()).unwrap(),
                                )
                            }
                            VerificationMethodKind::Resolvable(did_url) => {
                                VerificationRelationship::Reference(
                                    Url::parse(did_url.did_url()).unwrap(),
                                )
                            }
                        })
                        .collect::<Vec<_>>(),
                    assertion_method: doc
                        .did_document
                        .assertion_method()
                        .iter()
                        .map(|a| match a {
                            VerificationMethodKind::Resolved(vm) => {
                                VerificationRelationship::Reference(
                                    Url::parse(vm.id().did_url()).unwrap(),
                                )
                            }
                            VerificationMethodKind::Resolvable(did_url) => {
                                VerificationRelationship::Reference(
                                    Url::parse(did_url.did_url()).unwrap(),
                                )
                            }
                        })
                        .collect::<Vec<_>>(),
                    key_agreement: doc
                        .did_document
                        .key_agreement()
                        .iter()
                        .map(|a| match a {
                            VerificationMethodKind::Resolved(vm) => {
                                VerificationRelationship::Reference(
                                    Url::parse(vm.id().did_url()).unwrap(),
                                )
                            }
                            VerificationMethodKind::Resolvable(did_url) => {
                                VerificationRelationship::Reference(
                                    Url::parse(did_url.did_url()).unwrap(),
                                )
                            }
                        })
                        .collect::<Vec<_>>(),
                    capability_invocation: doc
                        .did_document
                        .capability_invocation()
                        .iter()
                        .map(|a| match a {
                            VerificationMethodKind::Resolved(vm) => {
                                VerificationRelationship::Reference(
                                    Url::parse(vm.id().did_url()).unwrap(),
                                )
                            }
                            VerificationMethodKind::Resolvable(did_url) => {
                                VerificationRelationship::Reference(
                                    Url::parse(did_url.did_url()).unwrap(),
                                )
                            }
                        })
                        .collect::<Vec<_>>(),
                    capability_delegation: doc
                        .did_document
                        .capability_delegation()
                        .iter()
                        .map(|a| match a {
                            VerificationMethodKind::Resolved(vm) => {
                                VerificationRelationship::Reference(
                                    Url::parse(vm.id().did_url()).unwrap(),
                                )
                            }
                            VerificationMethodKind::Resolvable(did_url) => {
                                VerificationRelationship::Reference(
                                    Url::parse(did_url.did_url()).unwrap(),
                                )
                            }
                        })
                        .collect::<Vec<_>>(),
                    service: doc
                        .did_document
                        .service()
                        .iter()
                        .map(|s| Service {
                            id: Url::parse(s.id().to_string().as_str()).ok(),
                            type_: vec![s.service_type().to_string()],
                            service_endpoint: Endpoint::Url(
                                Url::parse(s.service_endpoint().to_string().as_str()).unwrap(),
                            ),
                            property_set: HashMap::new(),
                        })
                        .collect(),
                    parameters_set: HashMap::new(),
                }))
            }
            Err(e) => Err(DIDCheqdError::DocumentParseError(format!(
                "Failed to resolve DID: {e}"
            ))),
        }
    }

    pub async fn resolve_resource(did_url: &str) -> Result<Option<Vec<u8>>, DIDCheqdError> {
        // Initialize resolver
        let resolver = DidCheqdResolver::new(DidCheqdResolverConfiguration::default());
        let did_url = match DidUrl::try_from(Did::try_from(did_url).unwrap()) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Failed to parse DID Url: {:?}", e);
                return Ok(None);
            }
        };

        // If not found in cache, attempt to resolve using did_cheqd crate
        match resolver.resolve_resource(&did_url).await {
            Ok(doc) => Ok(Some(doc.content)),
            Err(e) => Err(DIDCheqdError::DocumentParseError(format!(
                "Failed to resolve DID: {e}"
            ))),
        }
    }
}
