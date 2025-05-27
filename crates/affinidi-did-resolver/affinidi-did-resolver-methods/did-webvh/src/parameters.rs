/*!
*   Contains the parameters that define DID processing parameters
*   used when processing the current and previous Log Entry
*/

use crate::witness::Witnesses;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::{DeserializeAs, de::DeserializeAsWrap};

/// This helps with serializing parameters into null, skipping or content
/// webvh parameters can be missing(Absent), None(null) or contains content(Value)
#[derive(Clone, Debug, Default, Serialize)]
pub enum FieldAction<T> {
    #[default]
    Absent,
    None,
    Value(T),
}

impl<T> FieldAction<T>
where
    T: Serialize,
{
    pub fn is_absent(&self) -> bool {
        matches!(self, FieldAction::Absent)
    }
}
fn se_field_action<T, S>(field: &FieldAction<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: serde::Serializer,
{
    match field {
        FieldAction::None => serializer.serialize_none(),
        FieldAction::Absent => serializer.serialize_none(),
        FieldAction::Value(content) => content.serialize(serializer),
    }
}

pub(crate) struct FieldActionVisitor<T> {
    marker: std::marker::PhantomData<T>,
}
impl<'de, T> Deserialize<'de> for FieldAction<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_option(FieldActionVisitor::<T> {
            marker: std::marker::PhantomData,
        })
    }
}
impl<'de, T> serde::de::Visitor<'de> for FieldActionVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = FieldAction<T>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("FieldAction<T>")
    }

    #[inline]
    fn visit_none<E>(self) -> Result<FieldAction<T>, E>
    where
        E: serde::de::Error,
    {
        Ok(FieldAction::None)
    }

    #[inline]
    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(FieldAction::Value)
    }

    #[inline]
    fn visit_unit<E>(self) -> Result<FieldAction<T>, E>
    where
        E: serde::de::Error,
    {
        Ok(FieldAction::None)
    }
}

impl<'de, T, U> DeserializeAs<'de, FieldAction<T>> for FieldAction<U>
where
    U: DeserializeAs<'de, T>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<FieldAction<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            match FieldAction::<DeserializeAsWrap<T, U>>::deserialize(deserializer)? {
                FieldAction::Value(v) => FieldAction::Value(v.into_inner()),
                FieldAction::None => FieldAction::None,
                FieldAction::Absent => FieldAction::Absent,
            },
        )
    }
}

/// [https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters]
/// Parameters that help with the resolution of a webvh DID
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Parameters {
    /// DID version specification
    /// Default: `did:webvh:1.0`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Self Certifying Identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scid: Option<String>,

    /// Keys that are authorized to update future log entries
    #[serde(
        skip_serializing_if = "FieldAction::is_absent",
        serialize_with = "se_field_action"
    )]
    pub update_keys: FieldAction<Vec<String>>,

    /// Can you change the web address for this DID?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portable: Option<bool>,

    /// pre-rotation keys that must be shared prior to updating update keys
    #[serde(
        skip_serializing_if = "FieldAction::is_absent",
        serialize_with = "se_field_action"
    )]
    pub next_key_hashes: FieldAction<Vec<String>>,

    /// Parameters for witness nodes
    #[serde(
        skip_serializing_if = "FieldAction::is_absent",
        serialize_with = "se_field_action"
    )]
    pub witness: FieldAction<Witnesses>,

    /// DID watchers for this DID
    #[serde(
        skip_serializing_if = "FieldAction::is_absent",
        serialize_with = "se_field_action"
    )]
    pub watchers: FieldAction<Vec<String>>,

    /// Has this DID been revoked?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,

    /// time to live in seconds for a resolved DID document
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

impl Default for Parameters {
    fn default() -> Self {
        Parameters {
            method: Some("did:webvh:1.0".to_string()),
            scid: None,
            update_keys: FieldAction::Absent,
            portable: None,
            next_key_hashes: FieldAction::Absent,
            witness: FieldAction::Absent,
            watchers: FieldAction::Absent,
            deactivated: None,
            ttl: None,
        }
    }
}
