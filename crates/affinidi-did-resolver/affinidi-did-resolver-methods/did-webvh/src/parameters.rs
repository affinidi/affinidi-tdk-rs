/*!
*   Contains the parameters that define DID processing parameters
*   used when processing the current and previous Log Entry
*/

use crate::{DIDWebVHError, witness::Witnesses};
use affinidi_secrets_resolver::secrets::Secret;
use ahash::{HashSet, HashSetExt};
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::{DeserializeAs, de::DeserializeAsWrap};
use std::ops::Not;

/// This helps with serializing parameters into null, skipping or content
/// webvh parameters can be missing(Absent), None(null) or contains content(Value)
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub enum FieldAction<T> {
    #[default]
    Absent,
    None,
    Value(T),
}

impl<T> FieldAction<T> {
    /// If possible, get the value from the FieldAction
    pub fn get_value(&self) -> Result<&T, DIDWebVHError> {
        if let FieldAction::Value(value) = self {
            Ok(value)
        } else {
            Err(DIDWebVHError::ParametersError(
                "Expecting a value, but field is missing or null".to_string(),
            ))
        }
    }

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
    /// This is the active witnesses for this log entry
    #[serde(skip)]
    pub active_witness: FieldAction<Witnesses>,

    /// DID watchers for this DID
    #[serde(
        skip_serializing_if = "FieldAction::is_absent",
        serialize_with = "se_field_action"
    )]
    pub watchers: FieldAction<Vec<String>>,

    /// Has this DID been revoked?
    #[serde(skip_serializing_if = "<&bool>::not", default)]
    pub deactivated: bool,

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
            active_witness: FieldAction::Absent,
            watchers: FieldAction::Absent,
            deactivated: false,
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
        let mut pre_rotation_previous_value: bool = false;
        if let Some(previous) = previous {
            new_parameters.pre_rotation_active = previous.pre_rotation_active;
            pre_rotation_previous_value = previous.pre_rotation_active;
            new_parameters.portable = previous.portable;
            new_parameters.next_key_hashes = previous.next_key_hashes.clone();
            if previous.deactivated {
                // If previous is deactivated, then no more log entries can be made
                return Err(DIDWebVHError::DeactivatedError(
                    "DID was deactivated previous Log Entry, no more log entries are allowed."
                        .to_string(),
                ));
            } else {
                new_parameters.deactivated = previous.deactivated
            }
        }

        // Validate and process nextKeyHashes
        match &self.next_key_hashes {
            FieldAction::Absent => {
                // If absent, but is in pre-rotation state. This is an error
                if new_parameters.pre_rotation_active {
                    return Err(DIDWebVHError::ParametersError(
                        "nextKeyHashes cannot be absent when pre-rotation is active".to_string(),
                    ));
                }
            }
            FieldAction::None => {
                // If None, turn off key rotation
                new_parameters.next_key_hashes = FieldAction::None;
                new_parameters.pre_rotation_active = false; // If None, pre-rotation is not active
            }
            FieldAction::Value(next_key_hashes) => {
                // Replace nextKeyHashes with the new value
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
        if let Some(previous) = previous {
            if let FieldAction::Value(update_keys) = &self.update_keys {
                // If pre-rotation is enabled, then validate and add immediately to active keys
                if update_keys.is_empty() {
                    return Err(DIDWebVHError::ParametersError(
                        "updateKeys cannot be empty".to_string(),
                    ));
                }
                if !new_parameters.pre_rotation_active && pre_rotation_previous_value {
                    // Key pre-rotation has been turned off
                    // Update keys must be part of the previous nextKeyHashes
                    Parameters::validate_pre_rotation_keys(
                        previous.next_key_hashes.get_value()?,
                        update_keys,
                    )?;
                    new_parameters.active_update_keys = update_keys.clone();
                } else if new_parameters.pre_rotation_active {
                    // Key pre-rotation is active
                    // Update keys must be part of the previous nextKeyHashes
                    Parameters::validate_pre_rotation_keys(
                        previous.next_key_hashes.get_value()?,
                        update_keys,
                    )?;
                    new_parameters.active_update_keys = update_keys.clone();
                } else {
                    // No Key pre-rotation is active
                    new_parameters.active_update_keys = previous.update_keys.get_value()?.clone();
                    new_parameters.update_keys = FieldAction::Value(update_keys.clone());
                }
            }
        } else {
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

        // Validate witness
        if let Some(previous) = previous {
            match &self.witness {
                FieldAction::Absent => {
                    // If absent, keep current witnesses
                    new_parameters.active_witness = previous.witness.clone();
                    new_parameters.witness = previous.witness.clone();
                }
                FieldAction::None => {
                    // If None, turn off witness
                    new_parameters.witness = FieldAction::None;
                    // Still needs to be witnessed
                    new_parameters.active_witness = previous.witness.clone();
                }
                FieldAction::Value(witnesses) => {
                    // Replace witness with the new value
                    witnesses.validate()?;
                    new_parameters.witness = FieldAction::Value(witnesses.clone());
                    new_parameters.active_witness = previous.witness.clone();
                }
            }
        } else {
            // First Log Entry
            match &self.witness {
                FieldAction::Absent | FieldAction::None => {
                    new_parameters.active_witness = FieldAction::None;
                    new_parameters.witness = FieldAction::None;
                }
                FieldAction::Value(witnesses) => {
                    // Replace witness with the new value
                    witnesses.validate()?;
                    new_parameters.witness = FieldAction::Value(witnesses.clone());
                    new_parameters.active_witness = FieldAction::Value(witnesses.clone());
                }
            }
        }

        // Validate Watchers
        if let Some(previous) = previous {
            match &self.watchers {
                FieldAction::Absent => {
                    // If absent, keep current watchers
                    new_parameters.watchers = previous.watchers.clone();
                }
                FieldAction::None => {
                    // If None, turn off watchers
                    new_parameters.watchers = FieldAction::None;
                }
                FieldAction::Value(watchers) => {
                    // Replace watchers with the new value
                    new_parameters.watchers = FieldAction::Value(watchers.clone());
                }
            }
        } else {
            // First Log Entry
            match &self.watchers {
                FieldAction::Absent | FieldAction::None => {
                    new_parameters.watchers = FieldAction::None;
                }
                FieldAction::Value(watchers) => {
                    // Replace watchers with the new value
                    if watchers.is_empty() {
                        return Err(DIDWebVHError::ParametersError(
                            "watchers cannot be empty".to_string(),
                        ));
                    }
                    new_parameters.watchers = FieldAction::Value(watchers.clone());
                }
            }
        }

        // Check deactivation status
        if self.deactivated && previous.is_none() {
            // Can't be deactivated on the first log entry
            return Err(DIDWebVHError::DeactivatedError(
                "DID cannot be deactivated on the first Log Entry".to_string(),
            ));
        } else if self.deactivated && (new_parameters.update_keys != FieldAction::None) {
            return Err(DIDWebVHError::DeactivatedError(
                "DID Parameters say deactivated, yet updateKeys are not null!".to_string(),
            ));
        }
        new_parameters.deactivated = self.deactivated;

        Ok(new_parameters)
    }

    /// When pre-rotation is enabled, check that each updateKey was defined in the previous
    /// nextKeyHashes
    /// Returns an error if validation fails
    fn validate_pre_rotation_keys(
        next_key_hashes: &HashSet<String>,
        update_keys: &HashSet<String>,
    ) -> Result<(), DIDWebVHError> {
        for key in update_keys.iter() {
            // Convert the key to the hash value
            let check_hash = Secret::hash_string(key).map_err(|e| {
                DIDWebVHError::ValidationError(format!(
                    "Couldn't hash updateKeys key ({}). Reason: {}",
                    key, e
                ))
            })?;
            if !next_key_hashes.contains(&check_hash) {
                return Err(DIDWebVHError::ValidationError(format!(
                    "updateKey ({}) hash({}) was not specified in the previous nextKeyHashes!",
                    key, check_hash
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Parameters;

    #[test]
    fn watchers_absent_serialize() {
        // Tests to ensure that watchers set to absent won't serialize
        let parameters = Parameters {
            watchers: super::FieldAction::Absent,
            ..Default::default()
        };

        println!("parameters: {:#?}", parameters);
        let values = serde_json::to_value(parameters).unwrap();

        println!("values: {:#?}", values);
        println!("watchers: {:#?}", values.get("watchers"));
        assert!(values.get("watchers").is_none())
    }
}
