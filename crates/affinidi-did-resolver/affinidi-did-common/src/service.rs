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
    /// Returns the URI String for a service Endpoint, if available
    pub fn get_uri(&self) -> Option<String> {
        match self {
            Endpoint::Url(uri) => Some(uri.to_string()),
            Endpoint::Map(map) => {
                if let Some(uri) = map.get("uri") {
                    uri.as_str().map(|s| s.to_string())
                } else {
                    None
                }
            }
        }
    }
}
