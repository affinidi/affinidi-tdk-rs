/*!
*   Contains the parameters that define DID processing parameters
*   used when processing the current and previous Log Entry
*/

use crate::{DIDWebVHError, witness::Witnesses};
use ahash::{HashSet, HashSetExt};
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
    /// Is key pre-rotation active?
    #[serde(skip)]
    pub pre_rotation_active: bool,

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
    pub update_keys: FieldAction<HashSet<String>>,

    /// Depending on if pre-rotation is active,
    /// the set of active updateKeys can change
    #[serde(skip)]
    pub active_update_keys: HashSet<String>,

    /// Can you change the web address for this DID?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portable: Option<bool>,

    /// pre-rotation keys that must be shared prior to updating update keys
    #[serde(
        skip_serializing_if = "FieldAction::is_absent",
        serialize_with = "se_field_action"
    )]
    pub next_key_hashes: FieldAction<HashSet<String>>,

    /// Parameters for witness nodes
    #[serde(
        skip_serializing_if = "FieldAction::is_absent",
        serialize_with = "se_field_action"
    )]
    pub witness: FieldAction<Witnesses>,

    /// witness doesn't take effect till after this log entry
    /// Store the next value so it can be updated on the next log entry
    /// Only used for processing the next log entry
    #[serde(skip)]
    pub witness_after: FieldAction<Witnesses>,

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
            pre_rotation_active: false,
            method: Some("did:webvh:1.0".to_string()),
            scid: None,
            update_keys: FieldAction::Absent,
            active_update_keys: HashSet::new(),
            portable: None,
            next_key_hashes: FieldAction::Absent,
            witness: FieldAction::Absent,
            witness_after: FieldAction::Absent,
            watchers: FieldAction::Absent,
            deactivated: None,
            ttl: None,
        }
    }
}

impl Parameters {
    /// validate and update a Parameters object based on the Log Entry
    pub fn validate_udpate(
        &self,
        previous: Option<&Parameters>,
    ) -> Result<Parameters, DIDWebVHError> {
        let mut new_parameters = Parameters {
            scid: self.scid.clone(),
            ..Default::default()
        };

        // Handle previous values
        if let Some(previous) = previous {
            new_parameters.pre_rotation_active = previous.pre_rotation_active;
            new_parameters.witness = previous.witness_after.clone();
            new_parameters.portable = previous.portable;
            new_parameters.next_key_hashes = previous.next_key_hashes.clone();
        }

        // Validate and process nextKeyHashes
        match &self.next_key_hashes {
            FieldAction::Absent => {
                // If absent, keep the previous value
            }
            FieldAction::None => {
                // If None, turn off key rotation
                new_parameters.next_key_hashes = FieldAction::None;
                new_parameters.pre_rotation_active = false; // If None, pre-rotation is not active
            }
            FieldAction::Value(next_key_hashes) => {
                if next_key_hashes.is_empty() {
                    return Err(DIDWebVHError::ParametersError(
                        "nextKeyHashes cannot be empty".to_string(),
                    ));
                }
                new_parameters.next_key_hashes = FieldAction::Value(next_key_hashes.clone());
                new_parameters.pre_rotation_active = true; // If Value, pre-rotation is active
            }
        }

        // Validate and update UpdateKeys
        if previous.is_none() {
            // First Log Entry checks
            if let FieldAction::Value(update_keys) = &self.update_keys {
                if update_keys.is_empty() {
                    return Err(DIDWebVHError::ParametersError(
                        "updateKeys cannot be empty".to_string(),
                    ));
                }
                new_parameters.update_keys = FieldAction::Value(update_keys.clone());
            } else {
                return Err(DIDWebVHError::ParametersError(
                    "updateKeys must be provided on first Log Entry".to_string(),
                ));
            }
        } else if let FieldAction::Value(update_keys) = &self.update_keys {
            if update_keys.is_empty() {
                return Err(DIDWebVHError::ParametersError(
                    "updateKeys cannot be empty".to_string(),
                ));
            }
        }

        // Check Portability
        if let Some(portable) = self.portable {
            if previous.is_none() {
                new_parameters.portable = self.portable;
            } else if portable {
                return Err(DIDWebVHError::ParametersError(
                    "Portable is being set to true after the first Log Entry".to_string(),
                ));
            } else {
                // Can only be set to false after first Log Entry
                new_parameters.portable = Some(false);
            }
        } else if previous.is_none() {
            // First Log entry, if portable not specified then defaults to false
            new_parameters.portable = Some(false)
        }

        Ok(new_parameters)
    }

    /// Has this DID been deactivated?
    /// returns TRUE if deactivated
    pub fn did_deactivated(&self) -> bool {
        self.deactivated.unwrap_or(false)
    }
}
