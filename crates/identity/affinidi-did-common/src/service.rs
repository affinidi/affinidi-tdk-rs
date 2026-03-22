//! https://www.w3.org/TR/cid-1.0/#services

use std::{collections::HashMap, fmt};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};
use serde_json::Value;
use url::Url;

use crate::Document;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Url>,

    /// Must have at least one entry
    #[serde(rename = "type")]
    #[serde(deserialize_with = "de_type")]
    pub type_: Vec<String>,

    /// serviceEndpoint
    pub service_endpoint: Endpoint,

    /// Each Service can have multiple other properties
    #[serde(flatten)]
    pub property_set: HashMap<String, Value>,
}

fn de_type<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrVecVisitor;

    impl<'de> Visitor<'de> for StringOrVecVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string or a sequence of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![value.to_owned()])
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(elem) = seq.next_element()? {
                vec.push(elem);
            }
            Ok(vec)
        }
    }

    deserializer.deserialize_any(StringOrVecVisitor)
}

impl Document {
    /// Returns a refernce to the first service with the given id, if it exists
    /// id: the fragment text after the `#` in the full service id URL
    pub fn find_service(&self, id: &str) -> Option<&Service> {
        self.service.iter().find(|s| {
            if let Some(sid) = &s.id {
                sid.as_str().ends_with(&["#", id].concat())
            } else {
                false
            }
        })
    }
}

/// Service Endpoint definitions
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum Endpoint {
    /// Single String (URL)
    Url(Url),

    /// Can be either a Map or a Set of Strings/Maps
    Map(Value),
}

impl Endpoint {
    /// Returns the first URI String for a service Endpoint, if available
    /// This may not be what you always want
    pub fn get_uri(&self) -> Option<String> {
        match self {
            Endpoint::Url(uri) => Some(uri.to_string()),
            Endpoint::Map(map) => match map {
                Value::Array(array) => {
                    if let Some(first) = array.first() {
                        first.get("uri").map(|u| u.to_string())
                    } else {
                        None
                    }
                }
                Value::Object(obj) => obj.get("uri").map(|u| u.to_string()),
                _ => None,
            },
        }
    }

    /// Returns all found URI's within a service Endpoint
    pub fn get_uris(&self) -> Vec<String> {
        match self {
            Endpoint::Url(uri) => vec![uri.to_string()],
            Endpoint::Map(map) => {
                let mut uris = Vec::new();
                match map {
                    Value::Array(array) => {
                        for sep in array {
                            if let Some(uri) = sep.get("uri") {
                                uris.push(uri.to_string());
                            }
                        }
                    }
                    Value::Object(obj) => {
                        if let Some(uri) = obj.get("uri") {
                            uris.push(uri.to_string());
                        }
                    }
                    _ => {}
                }
                uris
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    fn make_doc_with_services(services: Vec<Service>) -> Document {
        Document {
            id: Url::parse("did:test:1234").unwrap(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: services,
            parameters_set: HashMap::new(),
        }
    }

    // --- Endpoint::get_uri ---

    #[test]
    fn get_uri_from_url_endpoint() {
        let ep = Endpoint::Url(Url::parse("https://example.com").unwrap());
        assert_eq!(ep.get_uri().unwrap(), "https://example.com/");
    }

    #[test]
    fn get_uri_from_map_object() {
        let ep = Endpoint::Map(json!({"uri": "https://example.com"}));
        assert_eq!(ep.get_uri().unwrap(), "\"https://example.com\"");
    }

    #[test]
    fn get_uri_from_map_array() {
        let ep = Endpoint::Map(json!([
            {"uri": "https://first.example.com"},
            {"uri": "https://second.example.com"}
        ]));
        assert_eq!(ep.get_uri().unwrap(), "\"https://first.example.com\"");
    }

    #[test]
    fn get_uri_from_map_empty_array() {
        let ep = Endpoint::Map(json!([]));
        assert!(ep.get_uri().is_none());
    }

    #[test]
    fn get_uri_from_map_object_missing_uri_key() {
        let ep = Endpoint::Map(json!({"endpoint": "https://example.com"}));
        assert!(ep.get_uri().is_none());
    }

    #[test]
    fn get_uri_from_map_non_object_non_array() {
        let ep = Endpoint::Map(json!("just a string"));
        assert!(ep.get_uri().is_none());
    }

    // --- Endpoint::get_uris ---

    #[test]
    fn get_uris_from_url_endpoint() {
        let ep = Endpoint::Url(Url::parse("https://example.com").unwrap());
        assert_eq!(ep.get_uris(), vec!["https://example.com/"]);
    }

    #[test]
    fn get_uris_from_map_object() {
        let ep = Endpoint::Map(json!({"uri": "https://example.com"}));
        assert_eq!(ep.get_uris(), vec!["\"https://example.com\""]);
    }

    #[test]
    fn get_uris_from_map_array() {
        let ep = Endpoint::Map(json!([
            {"uri": "https://first.example.com"},
            {"uri": "https://second.example.com"}
        ]));
        let uris = ep.get_uris();
        assert_eq!(uris.len(), 2);
        assert!(uris[0].contains("first.example.com"));
        assert!(uris[1].contains("second.example.com"));
    }

    #[test]
    fn get_uris_from_map_array_with_missing_uri() {
        let ep = Endpoint::Map(json!([
            {"uri": "https://example.com"},
            {"other": "no-uri-here"}
        ]));
        let uris = ep.get_uris();
        assert_eq!(uris.len(), 1);
    }

    #[test]
    fn get_uris_from_map_empty_array() {
        let ep = Endpoint::Map(json!([]));
        assert!(ep.get_uris().is_empty());
    }

    #[test]
    fn get_uris_from_map_non_object_non_array() {
        let ep = Endpoint::Map(json!(42));
        assert!(ep.get_uris().is_empty());
    }

    // --- Document::find_service ---

    #[test]
    fn find_service_found() {
        let svc = Service {
            id: Some(Url::parse("did:test:1234#my-service").unwrap()),
            type_: vec!["LinkedDomains".to_string()],
            service_endpoint: Endpoint::Url(Url::parse("https://example.com").unwrap()),
            property_set: HashMap::new(),
        };
        let doc = make_doc_with_services(vec![svc]);
        assert!(doc.find_service("my-service").is_some());
    }

    #[test]
    fn find_service_not_found() {
        let svc = Service {
            id: Some(Url::parse("did:test:1234#my-service").unwrap()),
            type_: vec!["LinkedDomains".to_string()],
            service_endpoint: Endpoint::Url(Url::parse("https://example.com").unwrap()),
            property_set: HashMap::new(),
        };
        let doc = make_doc_with_services(vec![svc]);
        assert!(doc.find_service("other-service").is_none());
    }

    #[test]
    fn find_service_no_id() {
        let svc = Service {
            id: None,
            type_: vec!["LinkedDomains".to_string()],
            service_endpoint: Endpoint::Url(Url::parse("https://example.com").unwrap()),
            property_set: HashMap::new(),
        };
        let doc = make_doc_with_services(vec![svc]);
        assert!(doc.find_service("anything").is_none());
    }

    #[test]
    fn find_service_empty_services() {
        let doc = make_doc_with_services(vec![]);
        assert!(doc.find_service("anything").is_none());
    }

    // --- Service deserialization (type as string or array) ---

    #[test]
    fn deserialize_service_type_as_string() {
        let json = r#"{
            "type": "LinkedDomains",
            "serviceEndpoint": "https://example.com"
        }"#;
        let svc: Service = serde_json::from_str(json).unwrap();
        assert_eq!(svc.type_, vec!["LinkedDomains"]);
    }

    #[test]
    fn deserialize_service_type_as_array() {
        let json = r#"{
            "type": ["LinkedDomains", "CredentialRepository"],
            "serviceEndpoint": "https://example.com"
        }"#;
        let svc: Service = serde_json::from_str(json).unwrap();
        assert_eq!(svc.type_.len(), 2);
        assert_eq!(svc.type_[0], "LinkedDomains");
        assert_eq!(svc.type_[1], "CredentialRepository");
    }

    #[test]
    fn deserialize_service_with_map_endpoint() {
        let json = r#"{
            "id": "did:test:1234#svc",
            "type": "DIDCommMessaging",
            "serviceEndpoint": {"uri": "https://example.com/didcomm", "accept": ["didcomm/v2"]}
        }"#;
        let svc: Service = serde_json::from_str(json).unwrap();
        assert!(svc.id.is_some());
        assert!(matches!(svc.service_endpoint, Endpoint::Map(_)));
    }

    #[test]
    fn serialize_service_roundtrip() {
        let svc = Service {
            id: Some(Url::parse("did:test:1234#svc").unwrap()),
            type_: vec!["LinkedDomains".to_string()],
            service_endpoint: Endpoint::Url(Url::parse("https://example.com").unwrap()),
            property_set: HashMap::new(),
        };
        let json = serde_json::to_string(&svc).unwrap();
        let back: Service = serde_json::from_str(&json).unwrap();
        assert_eq!(svc, back);
    }
}
