//! # DID Peer Method
//!
//! The `did-peer` method is a DID method that is designed to be used for peer-to-peer communication.
//! It is based on did:key which can be used for Verification (V) and Encryption (E) purposes.
//! It also supports services (S) which can be used to define endpoints for communication.
//!
//! Example:
//! ```ignore
//! let peer = DIDPeer;
//! match peer.resolve(DID::new::<str>("did:peer:2.Vabc...").unwrap()).await {
//!    Ok(res) => {
//!        println!("DID DOcument: {:#?}", res.document.into_document()),
//!    },
//!    Err(e) => {
//!      println!("Error: {:?}", e);
//!   }
//! }
//! ```
//!
use base64::prelude::*;
use iref::UriBuf;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi::{
    OneOrMany,
    dids::{
        DID, DIDBuf, DIDKey, DIDMethod, DIDMethodResolver, DIDURL, DIDURLBuf, DIDURLReferenceBuf,
        Document, RelativeDIDURLBuf,
        document::{
            self, DIDVerificationMethod, Resource, Service, VerificationRelationships,
            representation::{self, MediaType},
            service::Endpoint,
            verification_method,
        },
        key::VerificationMethodType,
        resolution::{self, Content, Error, Options, Output, Parameters},
    },
    jwk::Params,
    prelude::*,
};
use std::{collections::BTreeMap, fmt};
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Error, Debug)]
pub enum DIDPeerError {
    #[error("Unsupported key type")]
    UnsupportedKeyType,
    #[error("Unsupported curve: {0}")]
    UnsupportedCurve(String),
    #[error("Unsupported source")]
    UnsupportedSource,
    #[error("Syntax error on Service definition: {0}")]
    SyntaxErrorServiceDefinition(String),
    #[error("Unsupported Method. Must be method 2")]
    MethodNotSupported,
    #[error("Key Parsing error {0}")]
    KeyParsingError(String),
    #[error("DID Document doesn't contain any verificationMethod items")]
    MissingVerificationMethods,
    #[error("JSON Parsing error: {0}")]
    JsonParsingError(String),
    #[error("Internal error: {0}")]
    InternalError(String),
}

// Converts DIDPeerError to JsValue which is required for propagating errors to WASM
impl From<DIDPeerError> for JsValue {
    fn from(err: DIDPeerError) -> JsValue {
        JsValue::from(err.to_string())
    }
}

pub struct DIDPeer;

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum PeerServiceEndPoint {
    Short(PeerServiceEndPointShort),
    Long(PeerServiceEndPointLong),
}

impl PeerServiceEndPoint {
    pub fn to_short(&self) -> PeerServiceEndPointShort {
        match self {
            PeerServiceEndPoint::Short(short) => short.clone(),
            PeerServiceEndPoint::Long(long) => PeerServiceEndPointShort {
                uri: long.uri.clone(),
                a: long.accept.clone(),
                r: long.routing_keys.clone(),
            },
        }
    }

    pub fn to_long(&self) -> PeerServiceEndPointLong {
        match self {
            PeerServiceEndPoint::Short(short) => PeerServiceEndPointLong::from(short.clone()),
            PeerServiceEndPoint::Long(long) => long.clone(),
        }
    }
}

/// DID serviceEndPoint structure in short format
#[derive(Clone, Serialize, Deserialize)]
pub struct PeerServiceEndPointShort {
    pub uri: String,
    pub a: Vec<String>,
    pub r: Vec<String>,
}

/// DID serviceEndPoint structure in long format
#[derive(Clone, Serialize, Deserialize)]
pub struct PeerServiceEndPointLong {
    pub uri: String,
    pub accept: Vec<String>,
    pub routing_keys: Vec<String>,
}

impl From<PeerServiceEndPointShort> for PeerServiceEndPointLong {
    fn from(service: PeerServiceEndPointShort) -> Self {
        PeerServiceEndPointLong {
            uri: service.uri,
            accept: service.a,
            routing_keys: service.r,
        }
    }
}
/// DID Service structure in abbreviated format
#[derive(Serialize, Deserialize)]
pub struct DIDPeerService {
    #[serde(rename = "t")]
    #[serde(alias = "t")]
    pub _type: String,
    #[serde(rename = "s")]
    #[serde(alias = "s")]
    pub service_end_point: PeerServiceEndPoint, // serviceEndPoint
    pub id: Option<String>,
}

impl From<DIDPeerService> for Service {
    fn from(service: DIDPeerService) -> Self {
        let service_endpoint =
            match serde_json::to_value(PeerServiceEndPoint::to_long(&service.service_end_point)) {
                Ok(value) => Some(OneOrMany::One(Endpoint::Map(value))),
                Err(_) => None,
            };

        let id = if let Some(id) = service.id {
            UriBuf::new(id.into()).unwrap()
        } else {
            // TODO: Should be #service
            // SSI Crate expects a URI for the service ID
            UriBuf::new("did:peer:#service".into()).unwrap()
        };

        Service {
            id,
            type_: OneOrMany::One("DIDCommMessaging".into()),
            service_endpoint,
            property_set: BTreeMap::new(),
        }
    }
}

#[derive(Clone)]
#[wasm_bindgen]
/// DID Peer Key Purpose (used to create a new did:peer: string)
///   Verification: Keys are referenced in the authentication and assertionMethod fields
///   Encryption: Keys are referenced in the keyAgreement field
pub enum DIDPeerKeys {
    Verification,
    Encryption,
}

impl fmt::Display for DIDPeerKeys {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DIDPeerKeys::Verification => write!(f, "verification"),
            DIDPeerKeys::Encryption => write!(f, "encryption"),
        }
    }
}

#[derive(Clone)]
#[wasm_bindgen]
/// Supported DID Peer Key Types (used to create a new did:peer: string)
pub enum DIDPeerKeyType {
    Ed25519,
    Secp256k1,
    P256,
}

impl fmt::Display for DIDPeerKeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DIDPeerKeyType::Ed25519 => write!(f, "ed25519"),
            DIDPeerKeyType::Secp256k1 => write!(f, "secp256k1"),
            DIDPeerKeyType::P256 => write!(f, "p256"),
        }
    }
}

#[derive(Clone)]
#[wasm_bindgen(getter_with_clone)]
/// Structure to help with creating a new did:peer: string
///    purpose: ENUM (DIDPeerKeys) - Verification or Encryption
///    public_key_multibase: String - Optional: Multibase encoded public key (did:key:(.*))
///                                   If None, then auto-create and return the private key
pub struct DIDPeerCreateKeys {
    pub purpose: DIDPeerKeys,
    pub type_: Option<DIDPeerKeyType>,
    pub public_key_multibase: Option<String>,
}

#[wasm_bindgen]
impl DIDPeerCreateKeys {
    #[wasm_bindgen(constructor)]
    pub fn new(
        purpose: DIDPeerKeys,
        type_: Option<DIDPeerKeyType>,
        public_key_multibase: Option<String>,
    ) -> Self {
        DIDPeerCreateKeys {
            purpose,
            type_,
            public_key_multibase,
        }
    }
}

/// DIDPeerCreatedKeys, contains information related to any keys that were created
///
/// key_multibase: `String`, the multibase_58 encoded key value (e.g. did:key:(.*))
/// curve: `String`, the elliptic curve method used
/// d: `String`, private key value in Base64URL_NOPAD
/// x: `String`, public key value in Base64URL_NOPAD
/// y: `Option<String>`, Optional: Y coordinate for EC keys in Base64URL_NOPAD
#[derive(Clone, Debug, Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct DIDPeerCreatedKeys {
    pub key_multibase: String,
    pub curve: String,
    pub d: String,
    pub x: String,
    pub y: Option<String>,
}

/// Converts a public key into a DID VerificationMethod
fn process_key(did: &str, id: &str, public_key: &str) -> Result<DIDVerificationMethod, Error> {
    let mut properties = BTreeMap::new();

    properties.insert(
        "publicKeyMultibase".to_string(),
        Value::String(public_key.to_string()),
    );

    Ok(DIDVerificationMethod {
        id: DIDURLBuf::from_string(["did:peer:", did, id].concat()).unwrap(),
        type_: "Multikey".to_string(),
        controller: DIDBuf::from_string(["did:peer:", did].concat()).unwrap(),
        properties,
    })
}

impl DIDMethodResolver for DIDPeer {
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: Options,
    ) -> Result<Output<Vec<u8>>, Error> {
        // If did:peer is type 0, then treat it as a did:key
        if let Some(id) = method_specific_id.strip_prefix('0') {
            return DIDKey.resolve_method_representation(id, options).await;
        }

        // Only supports method 2 for did:peer
        if !method_specific_id.starts_with('2') {
            return Err(Error::MethodNotSupported(
                "did:peer version 2 supported only".to_string(),
            ));
        }

        let mut context = BTreeMap::new();
        context.insert("@base".to_string(), serde_json::json!(method_specific_id));

        let mut verification_methods: Vec<DIDVerificationMethod> = Vec::new();
        let mut verification_relationships: VerificationRelationships =
            VerificationRelationships::default();

        //let mut key_agreements: Vec<DIDVerificationMethod> = Vec::new();
        //let mut key_authentications: Vec<DIDVerificationMethod> = Vec::new();
        //let mut key_assertion_methods: Vec<DIDVerificationMethod> = Vec::new();
        let mut services: Vec<Service> = Vec::new();

        // Split the DID for peer on '.'s, we skip the first one
        // did:peer:2.(process from here)
        let parts: Vec<&str> = method_specific_id[2..].split('.').collect();
        let mut key_count: u32 = 1;
        let mut service_idx: u32 = 0;

        for part in parts {
            let ch = part.chars().next();
            match ch {
                Some(e) => {
                    match e {
                        'A' => {
                            // Assertion Method
                            verification_methods.push(process_key(
                                method_specific_id,
                                &["#key-", &key_count.to_string()].concat(),
                                &part[1..],
                            )?);

                            verification_relationships.assertion_method.push(
                                verification_method::ValueOrReference::Reference(
                                    DIDURLReferenceBuf::Relative(
                                        RelativeDIDURLBuf::new(
                                            ["#key-", &key_count.to_string()]
                                                .concat()
                                                .as_bytes()
                                                .to_vec(),
                                        )
                                        .unwrap(),
                                    ),
                                ),
                            );
                            key_count += 1;
                        }
                        'D' => {
                            // Capability Delegation
                            verification_methods.push(process_key(
                                method_specific_id,
                                &["#key-", &key_count.to_string()].concat(),
                                &part[1..],
                            )?);

                            verification_relationships.capability_delegation.push(
                                verification_method::ValueOrReference::Reference(
                                    DIDURLReferenceBuf::Relative(
                                        RelativeDIDURLBuf::new(
                                            ["#key-", &key_count.to_string()]
                                                .concat()
                                                .as_bytes()
                                                .to_vec(),
                                        )
                                        .unwrap(),
                                    ),
                                ),
                            );
                            key_count += 1;
                        }
                        'E' => {
                            // Key Agreement (Encryption)
                            verification_methods.push(process_key(
                                method_specific_id,
                                &["#key-", &key_count.to_string()].concat(),
                                &part[1..],
                            )?);
                            verification_relationships.key_agreement.push(
                                verification_method::ValueOrReference::Reference(
                                    DIDURLReferenceBuf::Relative(
                                        RelativeDIDURLBuf::new(
                                            ["#key-", &key_count.to_string()]
                                                .concat()
                                                .as_bytes()
                                                .to_vec(),
                                        )
                                        .unwrap(),
                                    ),
                                ),
                            );
                            key_count += 1;
                        }
                        'I' => {
                            // Capability Invocation
                            verification_methods.push(process_key(
                                method_specific_id,
                                &["#key-", &key_count.to_string()].concat(),
                                &part[1..],
                            )?);

                            verification_relationships.capability_invocation.push(
                                verification_method::ValueOrReference::Reference(
                                    DIDURLReferenceBuf::Relative(
                                        RelativeDIDURLBuf::new(
                                            ["#key-", &key_count.to_string()]
                                                .concat()
                                                .as_bytes()
                                                .to_vec(),
                                        )
                                        .unwrap(),
                                    ),
                                ),
                            );
                            key_count += 1;
                        }
                        'V' => {
                            // Authentication (Verification)
                            verification_methods.push(process_key(
                                method_specific_id,
                                &["#key-", &key_count.to_string()].concat(),
                                &part[1..],
                            )?);

                            verification_relationships.authentication.push(
                                verification_method::ValueOrReference::Reference(
                                    DIDURLReferenceBuf::Relative(
                                        RelativeDIDURLBuf::new(
                                            ["#key-", &key_count.to_string()]
                                                .concat()
                                                .as_bytes()
                                                .to_vec(),
                                        )
                                        .unwrap(),
                                    ),
                                ),
                            );
                            verification_relationships.assertion_method.push(
                                verification_method::ValueOrReference::Reference(
                                    DIDURLReferenceBuf::Relative(
                                        RelativeDIDURLBuf::new(
                                            ["#key-", &key_count.to_string()]
                                                .concat()
                                                .as_bytes()
                                                .to_vec(),
                                        )
                                        .unwrap(),
                                    ),
                                ),
                            );

                            key_count += 1;
                        }
                        'S' => {
                            // Service
                            let raw = match BASE64_URL_SAFE_NO_PAD.decode(part[1..].as_bytes()) {
                                Ok(raw) => raw,
                                Err(e) => {
                                    return Err(Error::Internal(format!(
                                        "Failed to decode base64 string: ({}) Reason: {}",
                                        &part[1..],
                                        e
                                    )));
                                }
                            };
                            let service = if let Ok(service) =
                                serde_json::from_slice::<DIDPeerService>(raw.as_slice())
                            {
                                service
                            } else {
                                return Err(Error::Internal(format!(
                                    "JSON parsing error on service. raw string ({})",
                                    String::from_utf8(raw).unwrap_or("".to_string())
                                )));
                            };

                            let mut service: Service = service.into();
                            if service_idx > 0 {
                                // TODO: Should be #service-1, #service-2, etc
                                // SSI Crate expects a URI for the service ID
                                service.id = UriBuf::new(
                                    ["did:peer:#service-", &service_idx.to_string()]
                                        .concat()
                                        .into(),
                                )
                                .unwrap();
                            }
                            services.push(service);
                            service_idx += 1;
                        }
                        other => {
                            return Err(Error::RepresentationNotSupported(format!(
                                "An invalid Purpose Code ({}) was found in the DID",
                                other
                            )));
                        }
                    }
                }
                None => {
                    // We shouldn't really get here
                    // But it is ok if we do, we just skip it
                }
            }
        }

        let vm_type = match options.parameters.public_key_format {
            Some(name) => VerificationMethodType::from_name(&name).ok_or_else(|| {
                Error::Internal(format!(
                    "verification method type `{name}` unsupported by did:peer"
                ))
            })?,
            None => VerificationMethodType::Multikey,
        };

        let mut doc =
            Document::new(DIDBuf::from_string(["did:peer:", method_specific_id].concat()).unwrap());
        doc.verification_method = verification_methods;
        doc.verification_relationships = verification_relationships;
        doc.service = services;

        let mut json_ld_context = Vec::new();
        if let Some(context) = vm_type.context_entry() {
            json_ld_context.push(context)
        }

        let content_type = options.accept.unwrap_or(MediaType::JsonLd);

        let represented = doc.into_representation(representation::Options::from_media_type(
            content_type,
            move || representation::json_ld::Options {
                context: representation::json_ld::Context::array(
                    representation::json_ld::DIDContext::V1,
                    json_ld_context,
                ),
            },
        ));

        Ok(resolution::Output::new(
            represented.to_bytes(),
            document::Metadata::default(),
            resolution::Metadata::from_content_type(Some(content_type.to_string())),
        ))
    }
}

impl DIDMethod for DIDPeer {
    const DID_METHOD_NAME: &'static str = "peer";
}

impl DIDPeer {
    /// Creates a new did:peer DID
    ///
    /// This will preserve the order of the keys and services in creating the did:peer string
    ///
    /// # Examples
    /// ```ignore
    ///
    /// // Create a did:peer with pre-existing encryption key (Multibase base58-btc e.g: z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK)
    /// let keys = vec![DIDPeerCreateKeys {
    ///     type_: Some(DIDPeerKeyType::Ed25519),
    ///     purpose: DIDPeerKeys::Encryption,
    ///     public_key_multibase: Some("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into()),
    /// }];
    /// let did_peer = DIDPeer::create_peer_did(&keys, None).expect("Failed to create did:peer");
    ///
    /// // Create a random did:peer with services
    /// let keys = vec![DIDPeerCreateKeys {
    ///    type_: Some(DIDPeerKeyType::Secp256k1),
    ///    purpose: DIDPeerKeys::Encryption,
    ///    public_key_multibase: Some("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into()),
    ///  }];
    /// let services: Vec<DIDPeerService> = vec![DIDPeerService {
    ///    _type: "dm".into(),
    ///    id: None,
    ///    service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong {
    ///        uri: "http://example.com/didcomm".into(),
    ///        accept: vec!["didcomm/v2".into()],
    ///        routing_keys: vec!["did:example:123456789abcdefghi#key-1".into()],
    ///    }),
    /// }];
    ///
    /// let did_peer =
    ///    DIDPeer::create_peer_did(&keys, Some(&services)).expect("Failed to create did:peer");
    ///
    /// // How to create a key prior to creating a did:peer
    /// let did =
    ///     DIDKey::generate(&JWK::generate_ed25519().unwrap()).expect("Failed to create did:key");
    ///
    /// let keys = vec![DIDPeerCreateKeys {
    ///     type_: Some(DIDPeerKeyType::Ed25519),
    ///     purpose: DIDPeerKeys::Verification,
    ///     public_key_multibase: Some(did[8..].to_string()),
    /// }];
    ///
    /// let did_peer = DIDPeer::create_peer_did(&keys, None).expect("Failed to create did:peer");
    /// ```
    pub fn create_peer_did(
        keys: &Vec<DIDPeerCreateKeys>,
        services: Option<&Vec<DIDPeerService>>,
    ) -> Result<(String, Vec<DIDPeerCreatedKeys>), DIDPeerError> {
        let mut result = String::from("did:peer:2");

        let mut private_keys: Vec<DIDPeerCreatedKeys> = vec![];
        for key in keys {
            // Create new keys if not provided
            let public_key = if let Some(key) = key.public_key_multibase.as_ref() {
                key.clone()
            } else {
                let jwk = match &key.type_ {
                    Some(type_) => match type_ {
                        DIDPeerKeyType::Ed25519 => match JWK::generate_ed25519() {
                            Ok(k) => k,
                            Err(e) => {
                                return Err(DIDPeerError::InternalError(format!(
                                    "Failed to generate ed25519 key. Reason: {}",
                                    e
                                )));
                            }
                        },
                        DIDPeerKeyType::Secp256k1 => JWK::generate_secp256k1(),
                        DIDPeerKeyType::P256 => JWK::generate_p256(),
                    },
                    None => return Err(DIDPeerError::UnsupportedKeyType),
                };
                let did = if let Ok(output) = ssi::dids::DIDKey::generate(&jwk) {
                    output.to_string()
                } else {
                    return Err(DIDPeerError::InternalError(
                        "Couldn't create did:key".to_string(),
                    ));
                };

                match jwk.params {
                    Params::OKP(map) => {
                        let d = if let Some(d) = &map.private_key {
                            d
                        } else {
                            return Err(DIDPeerError::KeyParsingError(
                                "Missing private key".to_string(),
                            ));
                        };
                        private_keys.push(DIDPeerCreatedKeys {
                            key_multibase: did[8..].to_string(),
                            curve: map.curve.clone(),
                            d: String::from(d),
                            x: String::from(map.public_key.clone()),
                            y: None,
                        })
                    }
                    Params::EC(map) => {
                        let curve = if let Some(curve) = &map.curve {
                            curve
                        } else {
                            return Err(DIDPeerError::KeyParsingError("Missing curve".to_string()));
                        };
                        let d = if let Some(d) = &map.ecc_private_key {
                            d
                        } else {
                            return Err(DIDPeerError::KeyParsingError(
                                "Missing private key".to_string(),
                            ));
                        };

                        let x = if let Some(x) = &map.x_coordinate {
                            x
                        } else {
                            return Err(DIDPeerError::KeyParsingError(
                                "Missing public key (x)".to_string(),
                            ));
                        };
                        let y = if let Some(y) = &map.y_coordinate {
                            y
                        } else {
                            return Err(DIDPeerError::KeyParsingError(
                                "Missing public key (y)".to_string(),
                            ));
                        };

                        private_keys.push(DIDPeerCreatedKeys {
                            key_multibase: did[8..].to_string(),
                            curve: curve.into(),
                            d: String::from(d),
                            x: String::from(x),
                            y: Some(String::from(y)),
                        })
                    }
                    _ => return Err(DIDPeerError::UnsupportedKeyType),
                }

                did[8..].to_string()
            };

            // Place based on key types
            match key.purpose {
                DIDPeerKeys::Verification => {
                    result.push_str(&format!(".V{}", public_key));
                }
                DIDPeerKeys::Encryption => {
                    result.push_str(&format!(".E{}", public_key));
                }
            }
        }

        if let Some(services) = services {
            for service in services {
                let service = serde_json::to_string(&service).map_err(|e| {
                    DIDPeerError::SyntaxErrorServiceDefinition(format!(
                        "Error parsing service: {}",
                        e
                    ))
                })?;
                result.push_str(&format!(".S{}", BASE64_URL_SAFE_NO_PAD.encode(service)));
            }
        }

        Ok((result, private_keys))
    }

    /// Expands an existing DID Document from the did:key Multikeys to full JWT keys
    /// This is useful for when you want to resolve a did:peer DID Document to a full JWT included DID Document
    /// Converts base58 multi-keys to full JWTs in verificationMethod
    pub async fn expand_keys(doc: &Document) -> Result<Document, DIDPeerError> {
        let mut new_doc = doc.clone();

        let mut new_vms: Vec<DIDVerificationMethod> = vec![];
        for v_method in &doc.verification_method {
            new_vms.push(Self::_convert_vm(v_method).await?);
        }

        new_doc.verification_method = new_vms;
        Ok(new_doc)
    }

    // Converts
    async fn _convert_vm(
        method: &DIDVerificationMethod,
    ) -> Result<DIDVerificationMethod, DIDPeerError> {
        let current_controller = method.controller.clone();
        let current_id = method.id.clone();
        let did_key = if let Some(key) = method.properties.get("publicKeyBase58") {
            ["did:key:", key.as_str().unwrap()].concat()
        } else if let Some(key) = method.properties.get("publicKeyMultibase") {
            ["did:key:", key.as_str().unwrap()].concat()
        } else {
            return Err(DIDPeerError::KeyParsingError(
                "Failed to convert verification_method. Reason: Missing publicKeyBase58"
                    .to_string(),
            ));
        };

        let key_method = DIDKey;

        let output = match key_method
            .dereference_with(
                DIDURL::new::<String>(&did_key.clone()).unwrap(),
                Options {
                    accept: None,
                    parameters: Parameters {
                        public_key_format: Some("JsonWebKey2020".to_string()),
                        ..Default::default()
                    },
                },
            )
            .await
        {
            Ok(output) => output.content,
            Err(e) => {
                return Err(DIDPeerError::KeyParsingError(format!(
                    "Failed to resolve key ({}). Reason: {}",
                    did_key, e
                )));
            }
        };

        if let Content::Resource(Resource::Document(doc)) = output {
            if let Some(vm) = doc.into_any_verification_method() {
                let mut new_vm = vm.clone();
                new_vm.controller = current_controller;
                new_vm.id = current_id;
                return Ok(new_vm);
            }
        }

        Err(DIDPeerError::KeyParsingError(
            "Failed to convert verification_method. Reason: Missing verification_method"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod test {
    use crate::{
        DIDPeer, DIDPeerCreateKeys, DIDPeerKeyType, DIDPeerKeys, DIDPeerService,
        PeerServiceEndPoint, PeerServiceEndPointLong,
    };

    use ssi::{
        JWK,
        dids::{DID, DIDBuf, DIDResolver, document::DIDVerificationMethod},
    };

    const DID_PEER: &str = "did:peer:2.Vz6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv.EzQ3shQLqRUza6AMJFbPuMdvFRFWm1wKviQRnQSC1fScovJN4s.SeyJ0IjoiRElEQ29tbU1lc3NhZ2luZyIsInMiOnsidXJpIjoiaHR0cHM6Ly8xMjcuMC4wLjE6NzAzNyIsImEiOlsiZGlkY29tbS92MiJdLCJyIjpbXX19";

    #[should_panic(
        expected = "Failed to convert verification_method. Reason: Missing publicKeyBase58"
    )]
    #[tokio::test]
    async fn expand_keys_throws_key_parsing_missing_pbk58_error() {
        let peer = DIDPeer;
        let output = peer
            .resolve(DID::new::<String>(&DID_PEER.to_string()).unwrap())
            .await
            .unwrap();

        let mut document = output.document.document().clone();
        let mut new_vms: Vec<DIDVerificationMethod> = vec![];
        for mut vm in document.verification_method {
            vm.properties.remove("publicKeyMultibase");
            new_vms.push(vm);
        }

        document.verification_method = new_vms;
        let _expanded_doc = DIDPeer::expand_keys(&document).await.unwrap();
    }

    #[tokio::test]
    async fn expand_keys_works() {
        let peer = DIDPeer;
        let document = peer
            .resolve(DID::new::<String>(&DID_PEER.to_string()).unwrap())
            .await
            .unwrap();

        let vm_before_expansion = document.clone().document.verification_method.clone();
        let expanded_doc = DIDPeer::expand_keys(&document.document).await.unwrap();
        let vms_after_expansion = expanded_doc.verification_method;

        for vm in vms_after_expansion.clone() {
            assert!(vm.id.starts_with("did:peer"));
        }
        assert_eq!(vm_before_expansion.len(), vms_after_expansion.len())
    }

    #[tokio::test]
    async fn create_peer_did_without_keys_and_services() {
        let keys: Vec<DIDPeerCreateKeys> = vec![];
        let services: Vec<DIDPeerService> = vec![];

        let (did, _) = DIDPeer::create_peer_did(&keys, Some(&services)).unwrap();
        let parts: Vec<&str> = did.split(":").collect();

        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1], "peer");
        assert!(parts[2].len() == 1);
    }

    #[tokio::test]
    async fn create_peer_did_without_keys() {
        let keys: Vec<DIDPeerCreateKeys> = vec![];
        let services = vec![DIDPeerService {
            _type: "dm".into(),
            service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong {
                uri: "https://localhost:7037".into(),
                accept: vec!["didcomm/v2".into()],
                routing_keys: vec![],
            }),
            id: None,
        }];

        let (did, _) = DIDPeer::create_peer_did(&keys, Some(&services)).unwrap();
        let parts: Vec<&str> = did.split(":").collect();
        let method_ids: Vec<&str> = parts[2].split(".").collect();

        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1], "peer");
        assert!(method_ids.len() > 1);
        assert!(method_ids[1].len() > 1);
    }

    #[tokio::test]
    async fn create_peer_did_without_services() {
        let (e_did_key, v_did_key, keys) = _get_keys(Some(DIDPeerKeyType::Ed25519), true);
        let services: Vec<DIDPeerService> = vec![];

        let (did, _) = DIDPeer::create_peer_did(&keys, Some(&services)).unwrap();
        let parts: Vec<&str> = did.split(":").collect();
        let mut method_ids: Vec<&str> = parts[2].split(".").collect();
        method_ids = method_ids[1..].to_vec();
        let keys_multibase = [v_did_key[8..].to_string(), e_did_key[8..].to_string()];

        method_ids.iter().take(2).for_each(|id| {
            assert!(keys_multibase.contains(&id[1..].to_string()));
        });
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1], "peer");
    }

    #[should_panic(expected = "UnsupportedKeyType")]
    #[tokio::test]
    async fn create_peer_did_should_throw_unsupported_key_error_p384() {
        let (_, _, keys) = _get_keys(None, false);
        // Create a service definition
        let services = vec![DIDPeerService {
            _type: "dm".into(),
            service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong {
                uri: "https://localhost:7037".into(),
                accept: vec!["didcomm/v2".into()],
                routing_keys: vec![],
            }),
            id: None,
        }];

        DIDPeer::create_peer_did(&keys, Some(&services)).unwrap();
    }

    #[tokio::test]
    async fn create_peer_did_works_ed25519_without_passing_pub_key() {
        let (_, _, keys) = _get_keys(Some(DIDPeerKeyType::Ed25519), false);

        // Create a service definition
        let services = vec![DIDPeerService {
            _type: "dm".into(),
            service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong {
                uri: "https://localhost:7037".into(),
                accept: vec!["didcomm/v2".into()],
                routing_keys: vec![],
            }),
            id: None,
        }];

        let (did, keys) = DIDPeer::create_peer_did(&keys, Some(&services)).unwrap();
        let parts: Vec<&str> = did.split(":").collect();
        let method_ids: Vec<&str> = parts[2].split(".").collect();

        assert_eq!(keys.len(), 2);
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1], "peer");
        assert_eq!(method_ids.first().unwrap().parse::<i32>().unwrap(), 2);
        assert_eq!(method_ids.len(), 4);
    }

    #[tokio::test]
    async fn create_peer_did_works_p256_without_passing_pub_key() {
        let (_, _, keys) = _get_keys(Some(DIDPeerKeyType::P256), false);

        // Create a service definition
        let services = vec![DIDPeerService {
            _type: "dm".into(),
            service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong {
                uri: "https://localhost:7037".into(),
                accept: vec!["didcomm/v2".into()],
                routing_keys: vec![],
            }),
            id: None,
        }];

        let (did, keys) = DIDPeer::create_peer_did(&keys, Some(&services)).unwrap();
        let parts: Vec<&str> = did.split(":").collect();
        let method_ids: Vec<&str> = parts[2].split(".").collect();

        assert_eq!(keys.len(), 2);
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1], "peer");
        assert_eq!(method_ids.first().unwrap().parse::<i32>().unwrap(), 2);
        assert_eq!(method_ids.len(), 4);
    }

    #[tokio::test]
    async fn create_peer_did_works_secp256k1_without_passing_pub_key() {
        let (_, _, keys) = _get_keys(Some(DIDPeerKeyType::Secp256k1), false);

        // Create a service definition
        let services = vec![DIDPeerService {
            _type: "dm".into(),
            service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong {
                uri: "https://localhost:7037".into(),
                accept: vec!["didcomm/v2".into()],
                routing_keys: vec![],
            }),
            id: None,
        }];

        let (did, keys) = DIDPeer::create_peer_did(&keys, Some(&services)).unwrap();

        let parts: Vec<&str> = did.split(":").collect();
        let method_ids: Vec<&str> = parts[2].split(".").collect();

        assert_eq!(keys.len(), 2);
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1], "peer");
        assert_eq!(method_ids.first().unwrap().parse::<i32>().unwrap(), 2);
        assert_eq!(method_ids.len(), 4);
    }

    #[tokio::test]
    async fn create_peer_did_works_ed25519() {
        let (e_did_key, v_did_key, keys) = _get_keys(Some(DIDPeerKeyType::Ed25519), true);

        // Create a service definition
        let services = vec![DIDPeerService {
            _type: "dm".into(),
            service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong {
                uri: "https://localhost:7037".into(),
                accept: vec!["didcomm/v2".into()],
                routing_keys: vec![],
            }),
            id: None,
        }];

        let (did, _) = DIDPeer::create_peer_did(&keys, Some(&services)).unwrap();
        let parts: Vec<&str> = did.split(":").collect();
        let mut method_ids: Vec<&str> = parts[2].split(".").collect();
        method_ids = method_ids[1..].to_vec();
        let keys_multibase = [v_did_key[8..].to_string(), e_did_key[8..].to_string()];

        method_ids.iter().take(2).for_each(|id| {
            assert!(keys_multibase.contains(&id[1..].to_string()));
        });

        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1], "peer");
    }

    #[tokio::test]
    async fn create_peer_did_works_p256() {
        let (e_did_key, v_did_key, keys) = _get_keys(Some(DIDPeerKeyType::P256), true);
        // Create a service definition
        let services = vec![DIDPeerService {
            _type: "dm".into(),
            service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong {
                uri: "https://localhost:7037".into(),
                accept: vec!["didcomm/v2".into()],
                routing_keys: vec![],
            }),
            id: None,
        }];

        let (did, _) = DIDPeer::create_peer_did(&keys, Some(&services)).unwrap();
        let parts: Vec<&str> = did.split(":").collect();
        let mut method_ids: Vec<&str> = parts[2].split(".").collect();
        method_ids = method_ids[1..].to_vec();
        let keys_multibase = [v_did_key[8..].to_string(), e_did_key[8..].to_string()];

        method_ids.iter().take(2).for_each(|id| {
            assert!(keys_multibase.contains(&id[1..].to_string()));
        });
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1], "peer");
    }

    #[tokio::test]
    async fn create_peer_did_works_secp256k1() {
        let (e_did_key, v_did_key, keys) = _get_keys(Some(DIDPeerKeyType::Secp256k1), true);
        // Create a service definition
        let services = vec![DIDPeerService {
            _type: "dm".into(),
            service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong {
                uri: "https://localhost:7037".into(),
                accept: vec!["didcomm/v2".into()],
                routing_keys: vec![],
            }),
            id: None,
        }];

        let (did, _) = DIDPeer::create_peer_did(&keys, Some(&services)).unwrap();
        let parts: Vec<&str> = did.split(":").collect();
        let mut method_ids: Vec<&str> = parts[2].split(".").collect();
        method_ids = method_ids[1..].to_vec();
        let keys_multibase = [v_did_key[8..].to_string(), e_did_key[8..].to_string()];

        method_ids.iter().take(2).for_each(|id| {
            assert!(keys_multibase.contains(&id[1..].to_string()));
        });
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1], "peer");
    }

    fn _get_keys(
        key_type: Option<DIDPeerKeyType>,
        with_pub_key: bool,
    ) -> (DIDBuf, DIDBuf, Vec<DIDPeerCreateKeys>) {
        let encryption_key = match key_type {
            Some(DIDPeerKeyType::Ed25519) => JWK::generate_ed25519().unwrap(),
            Some(DIDPeerKeyType::P256) => JWK::generate_p256(),
            Some(DIDPeerKeyType::Secp256k1) => JWK::generate_secp256k1(),
            None => JWK::generate_p384(),
        };
        let verification_key = match key_type {
            Some(DIDPeerKeyType::Ed25519) => JWK::generate_ed25519().unwrap(),
            Some(DIDPeerKeyType::P256) => JWK::generate_p256(),
            Some(DIDPeerKeyType::Secp256k1) => JWK::generate_secp256k1(),
            None => JWK::generate_p384(),
        };
        //  Create the did:key DID's for each key above
        let e_did_key = ssi::dids::DIDKey::generate(&encryption_key).unwrap();
        let v_did_key = ssi::dids::DIDKey::generate(&verification_key).unwrap();

        // Put these keys in order and specify the type of each key (we strip the did:key: from the front)
        let keys = vec![
            DIDPeerCreateKeys {
                purpose: DIDPeerKeys::Verification,
                type_: key_type.clone(),
                public_key_multibase: if with_pub_key {
                    Some(v_did_key[8..].to_string())
                } else {
                    None
                },
            },
            DIDPeerCreateKeys {
                purpose: DIDPeerKeys::Encryption,
                type_: key_type.clone(),
                public_key_multibase: if with_pub_key {
                    Some(e_did_key[8..].to_string())
                } else {
                    None
                },
            },
        ];

        (e_did_key, v_did_key, keys)
    }
}

// **********************************************************************************************************************************
// WASM Specific structs and code
// **********************************************************************************************************************************

/// DIDService structure, input into the DidPeerCreate structure
///
/// DIDService {
///         _type: `Option<String>` (Optional: If not specified, defaults to 'DIDCommMessaging')
///           uri: `String`         (Required: Service endpoint URI. E.g. https://localhost:7130/)
///        accept: `Vec<String>`    (Array of possible message types this service accepts)
///  routing_keys: `Vec<String>`    (Array of possible keys this Service endpoint can use)
///            id: `Option<String>` (Optional: ID of the service. If not specified, defaults to #service)
/// }
#[wasm_bindgen(getter_with_clone)]
#[derive(Clone, Serialize, Deserialize)]
pub struct DIDService {
    pub _type: Option<String>,
    pub uri: String,
    pub accept: Vec<String>,
    pub routing_keys: Vec<String>,
    pub id: Option<String>,
}

#[wasm_bindgen]
impl DIDService {
    #[wasm_bindgen(constructor)]
    pub fn new(
        uri: String,
        accept: Vec<String>,
        routing_keys: Vec<String>,
        id: Option<String>,
    ) -> Self {
        DIDService {
            _type: None,
            uri,
            accept,
            routing_keys,
            id,
        }
    }
}

impl From<DIDService> for DIDPeerService {
    fn from(service: DIDService) -> Self {
        DIDPeerService {
            _type: service._type.unwrap_or("DIDCommMessaging".into()),
            service_end_point: PeerServiceEndPoint::Short(PeerServiceEndPointShort {
                uri: service.uri,
                a: service.accept,
                r: service.routing_keys,
            }),
            id: service.id,
        }
    }
}

impl From<&DIDService> for DIDPeerService {
    fn from(service: &DIDService) -> Self {
        service.clone().into()
    }
}

/// DidPeerCreate structure,  input from JS into [create_did_peer] call
/// Contains the required keys and optional services to create a new did:peer DID
///
/// DIDPeerCreate {
///       keys: Vec<[DIDPeerCreateKeys]> (Required: Must contain at least one key for Encryption and another key for Verification)
///   services: Option<Vec<[DIDService]> (Optional: Array of DIDService structs to add to the DID Document)
/// }
#[derive(Clone)]
#[wasm_bindgen(getter_with_clone)]
pub struct DidPeerCreate {
    pub keys: Vec<DIDPeerCreateKeys>,
    pub services: Option<Vec<DIDService>>,
}

#[wasm_bindgen]
impl DidPeerCreate {
    #[wasm_bindgen(constructor)]
    pub fn new(keys: Vec<DIDPeerCreateKeys>, services: Option<Vec<DIDService>>) -> Self {
        DidPeerCreate { keys, services }
    }
}

#[derive(Serialize, Deserialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct DIDPeerResult {
    pub did: String,
    pub keys: Vec<DIDPeerCreatedKeys>,
}

#[wasm_bindgen]
/// create_did_peer() wasm wrapper for [DIDPeer::create_peer_did]
/// Input: reference to [DidPeerCreate] struct
/// Returns: Error or String of the newly created did:peer DID
///
/// Notes:
///   [DidPeerCreate] contains an array of keys and an optional array of Services
///   These arrays are processed in order (as in element 0 is processed first, then element 1, etc)
///   This means the key and service identifiers are auto-generated in the order they are provided
///   i.e. #service, #service-1, #service-2 and #key-1, #key-2, #key-3 ...
pub fn create_did_peer(input: &DidPeerCreate) -> Result<DIDPeerResult, DIDPeerError> {
    // Convert DIDService to DIDPeerService
    let mut new_services: Vec<DIDPeerService> = vec![];
    if let Some(services) = input.services.as_ref() {
        for service in services {
            new_services.push(service.into());
        }
    }

    // Create the did:peer DID
    let response = DIDPeer::create_peer_did(&input.keys, Some(&new_services));

    if let Ok((did, keys)) = response {
        Ok(DIDPeerResult { did, keys })
    } else {
        Err(response.unwrap_err())
    }
}

#[wasm_bindgen]
/// resolve_did_peer() resolves a DID Peer method DID to a full DID Document represented by a JS object
/// Input: String of the DID Peer method DID (did:peer:2...)
/// Returns: Error or JSON String of the resolved DID Document
///
/// NOTE: This is an async call, so you must await the result
pub async fn resolve_did_peer(did: &str) -> Result<String, DIDPeerError> {
    let peer = DIDPeer;

    match peer
        .resolve(DID::new::<String>(&did.to_string()).unwrap())
        .await
    {
        Ok(output) => match serde_json::to_string_pretty(&output.document) {
            Ok(json) => Ok(json),
            Err(e) => Err(DIDPeerError::JsonParsingError(format!(
                "Couldn't convert DID Document to JSON. Reason: {}",
                e
            ))),
        },
        Err(e) => Err(DIDPeerError::KeyParsingError(format!(
            "Failed to resolve key ({}). Reason: {}",
            did, e
        ))),
    }
}
