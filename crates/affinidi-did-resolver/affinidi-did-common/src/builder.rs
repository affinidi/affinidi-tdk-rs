//! Builder pattern for DID Documents and Verification Methods

use std::collections::HashMap;

use serde_json::Value;
use url::Url;

use crate::{
    Document, DocumentError,
    service::{Endpoint, Service},
    verification_method::{VerificationMethod, VerificationRelationship},
};

/// Builder for constructing a [`Document`] using a fluent API.
pub struct DocumentBuilder {
    id: Url,
    verification_method: Vec<VerificationMethod>,
    authentication: Vec<VerificationRelationship>,
    assertion_method: Vec<VerificationRelationship>,
    key_agreement: Vec<VerificationRelationship>,
    capability_invocation: Vec<VerificationRelationship>,
    capability_delegation: Vec<VerificationRelationship>,
    service: Vec<Service>,
    parameters_set: HashMap<String, Value>,
}

impl DocumentBuilder {
    /// Create a new builder with the given DID identifier.
    ///
    /// The `id` string is parsed as a URL; returns an error if parsing fails.
    pub fn new(id: &str) -> Result<Self, DocumentError> {
        Ok(Self::from_url(Url::parse(id)?))
    }

    /// Create a new builder from a pre-parsed [`Url`].
    pub fn from_url(id: Url) -> Self {
        Self {
            id,
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            capability_invocation: Vec::new(),
            capability_delegation: Vec::new(),
            service: Vec::new(),
            parameters_set: HashMap::new(),
        }
    }

    /// Set an arbitrary `@context` value, replacing any existing context.
    pub fn context(mut self, value: Value) -> Self {
        self.parameters_set
            .insert("@context".to_string(), value);
        self
    }

    /// Append a context URL string to the `@context` array, deduplicating.
    fn append_context(mut self, ctx: &str) -> Self {
        let entry = self
            .parameters_set
            .entry("@context".to_string())
            .or_insert_with(|| Value::Array(Vec::new()));

        if let Value::Array(arr) = entry {
            let val = Value::String(ctx.to_string());
            if !arr.contains(&val) {
                arr.push(val);
            }
        }
        self
    }

    /// Add `https://www.w3.org/ns/did/v1` to `@context`.
    pub fn context_did_v1(self) -> Self {
        self.append_context("https://www.w3.org/ns/did/v1")
    }

    /// Add `https://w3id.org/security/multikey/v1` to `@context`.
    pub fn context_multikey_v1(self) -> Self {
        self.append_context("https://w3id.org/security/multikey/v1")
    }

    /// Add `https://www.w3.org/ns/did/v1.1` to `@context`.
    pub fn context_did_v1_1(self) -> Self {
        self.append_context("https://www.w3.org/ns/did/v1.1")
    }

    /// Add a single verification method.
    pub fn verification_method(mut self, vm: VerificationMethod) -> Self {
        self.verification_method.push(vm);
        self
    }

    /// Add multiple verification methods.
    pub fn verification_methods(mut self, vms: Vec<VerificationMethod>) -> Self {
        self.verification_method.extend(vms);
        self
    }

    // --- Authentication ---

    /// Add a URL reference to `authentication`.
    pub fn authentication_reference(mut self, url: &str) -> Result<Self, DocumentError> {
        self.authentication
            .push(VerificationRelationship::Reference(Url::parse(url)?));
        Ok(self)
    }

    /// Add an embedded verification method to `authentication`.
    pub fn authentication_embedded(mut self, vm: VerificationMethod) -> Self {
        self.authentication
            .push(VerificationRelationship::VerificationMethod(Box::new(vm)));
        self
    }

    /// Add a pre-built [`VerificationRelationship`] to `authentication`.
    pub fn authentication(mut self, rel: VerificationRelationship) -> Self {
        self.authentication.push(rel);
        self
    }

    // --- Assertion Method ---

    /// Add a URL reference to `assertion_method`.
    pub fn assertion_method_reference(mut self, url: &str) -> Result<Self, DocumentError> {
        self.assertion_method
            .push(VerificationRelationship::Reference(Url::parse(url)?));
        Ok(self)
    }

    /// Add an embedded verification method to `assertion_method`.
    pub fn assertion_method_embedded(mut self, vm: VerificationMethod) -> Self {
        self.assertion_method
            .push(VerificationRelationship::VerificationMethod(Box::new(vm)));
        self
    }

    /// Add a pre-built [`VerificationRelationship`] to `assertion_method`.
    pub fn assertion_method(mut self, rel: VerificationRelationship) -> Self {
        self.assertion_method.push(rel);
        self
    }

    // --- Key Agreement ---

    /// Add a URL reference to `key_agreement`.
    pub fn key_agreement_reference(mut self, url: &str) -> Result<Self, DocumentError> {
        self.key_agreement
            .push(VerificationRelationship::Reference(Url::parse(url)?));
        Ok(self)
    }

    /// Add an embedded verification method to `key_agreement`.
    pub fn key_agreement_embedded(mut self, vm: VerificationMethod) -> Self {
        self.key_agreement
            .push(VerificationRelationship::VerificationMethod(Box::new(vm)));
        self
    }

    /// Add a pre-built [`VerificationRelationship`] to `key_agreement`.
    pub fn key_agreement(mut self, rel: VerificationRelationship) -> Self {
        self.key_agreement.push(rel);
        self
    }

    // --- Capability Invocation ---

    /// Add a URL reference to `capability_invocation`.
    pub fn capability_invocation_reference(mut self, url: &str) -> Result<Self, DocumentError> {
        self.capability_invocation
            .push(VerificationRelationship::Reference(Url::parse(url)?));
        Ok(self)
    }

    /// Add an embedded verification method to `capability_invocation`.
    pub fn capability_invocation_embedded(mut self, vm: VerificationMethod) -> Self {
        self.capability_invocation
            .push(VerificationRelationship::VerificationMethod(Box::new(vm)));
        self
    }

    /// Add a pre-built [`VerificationRelationship`] to `capability_invocation`.
    pub fn capability_invocation(mut self, rel: VerificationRelationship) -> Self {
        self.capability_invocation.push(rel);
        self
    }

    // --- Capability Delegation ---

    /// Add a URL reference to `capability_delegation`.
    pub fn capability_delegation_reference(mut self, url: &str) -> Result<Self, DocumentError> {
        self.capability_delegation
            .push(VerificationRelationship::Reference(Url::parse(url)?));
        Ok(self)
    }

    /// Add an embedded verification method to `capability_delegation`.
    pub fn capability_delegation_embedded(mut self, vm: VerificationMethod) -> Self {
        self.capability_delegation
            .push(VerificationRelationship::VerificationMethod(Box::new(vm)));
        self
    }

    /// Add a pre-built [`VerificationRelationship`] to `capability_delegation`.
    pub fn capability_delegation(mut self, rel: VerificationRelationship) -> Self {
        self.capability_delegation.push(rel);
        self
    }

    // --- Services ---

    /// Add a single service.
    pub fn service(mut self, svc: Service) -> Self {
        self.service.push(svc);
        self
    }

    /// Add multiple services.
    pub fn services(mut self, svcs: Vec<Service>) -> Self {
        self.service.extend(svcs);
        self
    }

    /// Set an arbitrary parameter in the document's flattened parameter set.
    pub fn parameter(mut self, key: impl Into<String>, value: Value) -> Self {
        self.parameters_set.insert(key.into(), value);
        self
    }

    /// Consume the builder and produce a [`Document`].
    pub fn build(self) -> Document {
        Document {
            id: self.id,
            verification_method: self.verification_method,
            authentication: self.authentication,
            assertion_method: self.assertion_method,
            key_agreement: self.key_agreement,
            capability_invocation: self.capability_invocation,
            capability_delegation: self.capability_delegation,
            service: self.service,
            parameters_set: self.parameters_set,
        }
    }
}

/// Builder for constructing a [`VerificationMethod`] using a fluent API.
pub struct VerificationMethodBuilder {
    id: Url,
    type_: String,
    controller: Url,
    expires: Option<String>,
    revoked: Option<String>,
    property_set: HashMap<String, Value>,
}

impl VerificationMethodBuilder {
    /// Create a new builder with required fields.
    ///
    /// Parses `id` and `controller` as URLs; returns an error if parsing fails.
    pub fn new(id: &str, type_: &str, controller: &str) -> Result<Self, DocumentError> {
        Ok(Self::from_urls(
            Url::parse(id)?,
            type_.to_string(),
            Url::parse(controller)?,
        ))
    }

    /// Create a new builder from pre-parsed values.
    pub fn from_urls(id: Url, type_: String, controller: Url) -> Self {
        Self {
            id,
            type_,
            controller,
            expires: None,
            revoked: None,
            property_set: HashMap::new(),
        }
    }

    /// Set the `expires` field.
    pub fn expires(mut self, s: impl Into<String>) -> Self {
        self.expires = Some(s.into());
        self
    }

    /// Set the `revoked` field.
    pub fn revoked(mut self, s: impl Into<String>) -> Self {
        self.revoked = Some(s.into());
        self
    }

    /// Set an arbitrary property.
    pub fn property(mut self, key: impl Into<String>, value: Value) -> Self {
        self.property_set.insert(key.into(), value);
        self
    }

    /// Set multiple properties at once.
    pub fn properties(mut self, map: HashMap<String, Value>) -> Self {
        self.property_set.extend(map);
        self
    }

    /// Convenience: set `publicKeyMultibase`.
    pub fn public_key_multibase(self, s: impl Into<String>) -> Self {
        self.property("publicKeyMultibase", Value::String(s.into()))
    }

    /// Convenience: set `publicKeyJwk`.
    pub fn public_key_jwk(self, value: Value) -> Self {
        self.property("publicKeyJwk", value)
    }

    /// Consume the builder and produce a [`VerificationMethod`].
    pub fn build(self) -> VerificationMethod {
        VerificationMethod {
            id: self.id,
            type_: self.type_,
            controller: self.controller,
            expires: self.expires,
            revoked: self.revoked,
            property_set: self.property_set,
        }
    }
}

/// Builder for constructing a [`Service`] using a fluent API.
///
/// Per the [CID spec](https://www.w3.org/TR/cid-1.0/#services), a service requires
/// `type` (one or more strings) and `serviceEndpoint`. The `id` is optional.
pub struct ServiceBuilder {
    id: Option<Url>,
    type_: Vec<String>,
    service_endpoint: Endpoint,
    property_set: HashMap<String, Value>,
}

impl ServiceBuilder {
    /// Create a new builder with the required `type` and `serviceEndpoint`.
    ///
    /// `type_` is the initial service type string (at least one is required).
    /// `endpoint` is the service endpoint.
    pub fn new(type_: impl Into<String>, endpoint: Endpoint) -> Self {
        Self {
            id: None,
            type_: vec![type_.into()],
            service_endpoint: endpoint,
            property_set: HashMap::new(),
        }
    }

    /// Convenience: create a builder with a URL string endpoint.
    ///
    /// Parses `endpoint_url` as a URL; returns an error if parsing fails.
    pub fn new_with_url(
        type_: impl Into<String>,
        endpoint_url: &str,
    ) -> Result<Self, DocumentError> {
        Ok(Self::new(type_, Endpoint::Url(Url::parse(endpoint_url)?)))
    }

    /// Convenience: create a builder with a map/JSON endpoint.
    pub fn new_with_map(type_: impl Into<String>, endpoint_map: Value) -> Self {
        Self::new(type_, Endpoint::Map(endpoint_map))
    }

    /// Set the optional `id` field by parsing a URL string.
    pub fn id(mut self, url: &str) -> Result<Self, DocumentError> {
        self.id = Some(Url::parse(url)?);
        Ok(self)
    }

    /// Set the optional `id` field from a pre-parsed [`Url`].
    pub fn id_url(mut self, url: Url) -> Self {
        self.id = Some(url);
        self
    }

    /// Add an additional type string.
    pub fn add_type(mut self, type_: impl Into<String>) -> Self {
        self.type_.push(type_.into());
        self
    }

    /// Replace the type list with the given types.
    pub fn types(mut self, types: Vec<String>) -> Self {
        self.type_ = types;
        self
    }

    /// Set an arbitrary property.
    pub fn property(mut self, key: impl Into<String>, value: Value) -> Self {
        self.property_set.insert(key.into(), value);
        self
    }

    /// Set multiple properties at once.
    pub fn properties(mut self, map: HashMap<String, Value>) -> Self {
        self.property_set.extend(map);
        self
    }

    /// Consume the builder and produce a [`Service`].
    pub fn build(self) -> Service {
        Service {
            id: self.id,
            type_: self.type_,
            service_endpoint: self.service_endpoint,
            property_set: self.property_set,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn minimal_document_build() {
        let doc = DocumentBuilder::new("did:example:123").unwrap().build();
        assert_eq!(doc.id.as_str(), "did:example:123");
        assert!(doc.verification_method.is_empty());
        assert!(doc.authentication.is_empty());
        assert!(doc.assertion_method.is_empty());
        assert!(doc.key_agreement.is_empty());
        assert!(doc.capability_invocation.is_empty());
        assert!(doc.capability_delegation.is_empty());
        assert!(doc.service.is_empty());
        assert!(doc.parameters_set.is_empty());
    }

    #[test]
    fn invalid_id_returns_error() {
        assert!(DocumentBuilder::new("not a url").is_err());
    }

    #[test]
    fn context_convenience_methods() {
        let doc = DocumentBuilder::new("did:example:123")
            .unwrap()
            .context_did_v1()
            .context_multikey_v1()
            .build();

        let ctx = doc.parameters_set.get("@context").unwrap();
        let arr = ctx.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], "https://www.w3.org/ns/did/v1");
        assert_eq!(arr[1], "https://w3id.org/security/multikey/v1");
    }

    #[test]
    fn context_deduplication() {
        let doc = DocumentBuilder::new("did:example:123")
            .unwrap()
            .context_did_v1()
            .context_did_v1()
            .build();

        let ctx = doc.parameters_set.get("@context").unwrap();
        let arr = ctx.as_array().unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn adding_verification_methods() {
        let vm1 = VerificationMethodBuilder::new(
            "did:example:123#key-1",
            "Multikey",
            "did:example:123",
        )
        .unwrap()
        .build();

        let vm2 = VerificationMethodBuilder::new(
            "did:example:123#key-2",
            "Multikey",
            "did:example:123",
        )
        .unwrap()
        .build();

        let vm3 = VerificationMethodBuilder::new(
            "did:example:123#key-3",
            "Multikey",
            "did:example:123",
        )
        .unwrap()
        .build();

        let doc = DocumentBuilder::new("did:example:123")
            .unwrap()
            .verification_method(vm1)
            .verification_methods(vec![vm2, vm3])
            .build();

        assert_eq!(doc.verification_method.len(), 3);
    }

    #[test]
    fn authentication_reference_and_embedded() {
        let vm = VerificationMethodBuilder::new(
            "did:example:123#key-1",
            "Multikey",
            "did:example:123",
        )
        .unwrap()
        .build();

        let doc = DocumentBuilder::new("did:example:123")
            .unwrap()
            .authentication_reference("did:example:123#key-1")
            .unwrap()
            .authentication_embedded(vm)
            .build();

        assert_eq!(doc.authentication.len(), 2);
        assert!(matches!(
            doc.authentication[0],
            VerificationRelationship::Reference(_)
        ));
        assert!(matches!(
            doc.authentication[1],
            VerificationRelationship::VerificationMethod(_)
        ));
    }

    #[test]
    fn assertion_method_reference_and_embedded() {
        let vm = VerificationMethodBuilder::new(
            "did:example:123#key-1",
            "Multikey",
            "did:example:123",
        )
        .unwrap()
        .build();

        let doc = DocumentBuilder::new("did:example:123")
            .unwrap()
            .assertion_method_reference("did:example:123#key-1")
            .unwrap()
            .assertion_method_embedded(vm)
            .build();

        assert_eq!(doc.assertion_method.len(), 2);
    }

    #[test]
    fn key_agreement_reference_and_embedded() {
        let vm = VerificationMethodBuilder::new(
            "did:example:123#key-1",
            "Multikey",
            "did:example:123",
        )
        .unwrap()
        .build();

        let doc = DocumentBuilder::new("did:example:123")
            .unwrap()
            .key_agreement_reference("did:example:123#key-1")
            .unwrap()
            .key_agreement_embedded(vm)
            .build();

        assert_eq!(doc.key_agreement.len(), 2);
    }

    #[test]
    fn full_chained_build() {
        let vm = VerificationMethodBuilder::new(
            "did:example:123#key-1",
            "Multikey",
            "did:example:123",
        )
        .unwrap()
        .public_key_multibase("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
        .build();

        let doc = DocumentBuilder::new("did:example:123")
            .unwrap()
            .context_did_v1()
            .context_multikey_v1()
            .verification_method(vm)
            .authentication_reference("did:example:123#key-1")
            .unwrap()
            .assertion_method_reference("did:example:123#key-1")
            .unwrap()
            .key_agreement_reference("did:example:123#key-1")
            .unwrap()
            .capability_invocation_reference("did:example:123#key-1")
            .unwrap()
            .capability_delegation_reference("did:example:123#key-1")
            .unwrap()
            .parameter("custom", json!("value"))
            .build();

        assert_eq!(doc.id.as_str(), "did:example:123");
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.assertion_method.len(), 1);
        assert_eq!(doc.key_agreement.len(), 1);
        assert_eq!(doc.capability_invocation.len(), 1);
        assert_eq!(doc.capability_delegation.len(), 1);
        assert_eq!(
            doc.parameters_set.get("custom").unwrap(),
            &json!("value")
        );
    }

    #[test]
    fn verification_method_builder_minimal() {
        let vm = VerificationMethodBuilder::new(
            "did:example:123#key-1",
            "Multikey",
            "did:example:123",
        )
        .unwrap()
        .build();

        assert_eq!(vm.id.as_str(), "did:example:123#key-1");
        assert_eq!(vm.type_, "Multikey");
        assert_eq!(vm.controller.as_str(), "did:example:123");
        assert!(vm.expires.is_none());
        assert!(vm.revoked.is_none());
        assert!(vm.property_set.is_empty());
    }

    #[test]
    fn verification_method_builder_with_properties() {
        let mut extra = HashMap::new();
        extra.insert("extra".to_string(), json!("data"));

        let vm = VerificationMethodBuilder::new(
            "did:example:123#key-1",
            "Multikey",
            "did:example:123",
        )
        .unwrap()
        .public_key_multibase("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
        .public_key_jwk(json!({"kty": "OKP"}))
        .expires("2025-12-31T00:00:00Z")
        .revoked("2025-06-01T00:00:00Z")
        .properties(extra)
        .build();

        assert!(vm.property_set.contains_key("publicKeyMultibase"));
        assert!(vm.property_set.contains_key("publicKeyJwk"));
        assert!(vm.property_set.contains_key("extra"));
        assert_eq!(vm.expires.as_deref(), Some("2025-12-31T00:00:00Z"));
        assert_eq!(vm.revoked.as_deref(), Some("2025-06-01T00:00:00Z"));
    }

    #[test]
    fn verification_method_builder_invalid_id() {
        assert!(VerificationMethodBuilder::new("not a url", "Multikey", "did:example:123").is_err());
    }

    // --- ServiceBuilder tests ---

    #[test]
    fn service_builder_minimal_with_url_endpoint() {
        let svc = ServiceBuilder::new_with_url(
            "LinkedDomains",
            "https://example.com",
        )
        .unwrap()
        .build();

        assert!(svc.id.is_none());
        assert_eq!(svc.type_, vec!["LinkedDomains"]);
        assert_eq!(
            svc.service_endpoint,
            Endpoint::Url(Url::parse("https://example.com").unwrap())
        );
        assert!(svc.property_set.is_empty());
    }

    #[test]
    fn service_builder_with_map_endpoint() {
        let map = json!({"uri": "https://example.com", "accept": ["didcomm/v2"]});
        let svc = ServiceBuilder::new_with_map("DIDCommMessaging", map.clone()).build();

        assert_eq!(svc.service_endpoint, Endpoint::Map(map));
    }

    #[test]
    fn service_builder_with_id() {
        let svc = ServiceBuilder::new_with_url(
            "LinkedDomains",
            "https://example.com",
        )
        .unwrap()
        .id("did:example:123#linked-domain")
        .unwrap()
        .build();

        assert_eq!(
            svc.id.as_ref().unwrap().as_str(),
            "did:example:123#linked-domain"
        );
    }

    #[test]
    fn service_builder_invalid_id_returns_error() {
        let result = ServiceBuilder::new_with_url(
            "LinkedDomains",
            "https://example.com",
        )
        .unwrap()
        .id("not a url");

        assert!(result.is_err());
    }

    #[test]
    fn service_builder_invalid_endpoint_url_returns_error() {
        assert!(ServiceBuilder::new_with_url("LinkedDomains", "not a url").is_err());
    }

    #[test]
    fn service_builder_multiple_types() {
        let svc = ServiceBuilder::new_with_url(
            "LinkedDomains",
            "https://example.com",
        )
        .unwrap()
        .add_type("CredentialRepository")
        .build();

        assert_eq!(svc.type_.len(), 2);
        assert_eq!(svc.type_[0], "LinkedDomains");
        assert_eq!(svc.type_[1], "CredentialRepository");
    }

    #[test]
    fn service_builder_replace_types() {
        let svc = ServiceBuilder::new_with_url(
            "LinkedDomains",
            "https://example.com",
        )
        .unwrap()
        .types(vec!["TypeA".to_string(), "TypeB".to_string()])
        .build();

        assert_eq!(svc.type_, vec!["TypeA", "TypeB"]);
    }

    #[test]
    fn service_builder_with_properties() {
        let mut extra = HashMap::new();
        extra.insert("routingKeys".to_string(), json!(["did:example:123#key-1"]));

        let svc = ServiceBuilder::new_with_url(
            "DIDCommMessaging",
            "https://example.com/didcomm",
        )
        .unwrap()
        .id("did:example:123#didcomm")
        .unwrap()
        .property("accept", json!(["didcomm/v2"]))
        .properties(extra)
        .build();

        assert!(svc.property_set.contains_key("accept"));
        assert!(svc.property_set.contains_key("routingKeys"));
    }

    #[test]
    fn service_builder_integrates_with_document_builder() {
        let svc = ServiceBuilder::new_with_url(
            "LinkedDomains",
            "https://example.com",
        )
        .unwrap()
        .id("did:example:123#linked-domain")
        .unwrap()
        .build();

        let doc = DocumentBuilder::new("did:example:123")
            .unwrap()
            .service(svc)
            .build();

        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.service[0].type_, vec!["LinkedDomains"]);
    }
}
