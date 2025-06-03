/*!
*   Contains the parameters that define DID processing parameters
*   used when processing the current and previous Log Entry
*/

use crate::{DIDWebVHError, witness::Witnesses};
use affinidi_secrets_resolver::secrets::Secret;
use serde::{Deserialize, Serialize};
use std::ops::Not;

/// [https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters]
/// Parameters that help with the resolution of a webvh DID
///
/// Thin uses double options to allow for the following:
/// None = field wasn't specified
/// Some(None) = field was specified, but set to null
/// Some(Some(value)) = field was specified with a value
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
        default,                                    // <- important for deserialization
        skip_serializing_if = "Option::is_none",    // <- important for serialization
        with = "::serde_with::rust::double_option",
    )]
    pub update_keys: Option<Option<Vec<String>>>,

    /// Depending on if pre-rotation is active,
    /// the set of active updateKeys can change
    #[serde(skip)]
    pub active_update_keys: Vec<String>,

    /// Can you change the web address for this DID?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portable: Option<bool>,

    /// pre-rotation keys that must be shared prior to updating update keys
    #[serde(
        default,                                    // <- important for deserialization
        skip_serializing_if = "Option::is_none",    // <- important for serialization
        with = "::serde_with::rust::double_option",
    )]
    pub next_key_hashes: Option<Option<Vec<String>>>,

    /// Parameters for witness nodes
    #[serde(
        default,                                    // <- important for deserialization
        skip_serializing_if = "Option::is_none",    // <- important for serialization
        with = "::serde_with::rust::double_option",
    )]
    pub witness: Option<Option<Witnesses>>,

    /// witness doesn't take effect till after this log entry
    /// This is the active witnesses for this log entry
    #[serde(
        default,                                    // <- important for deserialization
        skip_serializing_if = "Option::is_none",    // <- important for serialization
        with = "::serde_with::rust::double_option",
    )]
    pub active_witness: Option<Option<Witnesses>>,

    /// DID watchers for this DID
    #[serde(
        default,                                    // <- important for deserialization
        skip_serializing_if = "Option::is_none",    // <- important for serialization
        with = "::serde_with::rust::double_option",
    )]
    pub watchers: Option<Option<Vec<String>>>,

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
            update_keys: None,
            active_update_keys: Vec::new(),
            portable: None,
            next_key_hashes: None,
            witness: None,
            active_witness: None,
            watchers: None,
            deactivated: false,
            ttl: None,
        }
    }
}

impl Parameters {
    /// validate and return a Parameters object based on the Log Entry that reflects the current
    /// state of the parameters
    pub fn validate(&self, previous: Option<&Parameters>) -> Result<Parameters, DIDWebVHError> {
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
            None => {
                // If absent, but is in pre-rotation state. This is an error
                if new_parameters.pre_rotation_active {
                    return Err(DIDWebVHError::ParametersError(
                        "nextKeyHashes cannot be absent when pre-rotation is active".to_string(),
                    ));
                }
            }
            Some(None) => {
                // If None, turn off key rotation
                new_parameters.next_key_hashes = None;
                new_parameters.pre_rotation_active = false; // If None, pre-rotation is not active
            }
            Some(next_key_hashes) => {
                // Replace nextKeyHashes with the new value
                if next_key_hashes.is_none() {
                    return Err(DIDWebVHError::ParametersError(
                        "nextKeyHashes cannot be empty".to_string(),
                    ));
                }
                new_parameters.next_key_hashes = Some(next_key_hashes.clone());
                new_parameters.pre_rotation_active = true; // If Value, pre-rotation is active
            }
        }

        // Validate and update UpdateKeys
        if let Some(previous) = previous {
            if let Some(Some(update_keys)) = &self.update_keys {
                // If pre-rotation is enabled, then validate and add immediately to active keys
                if update_keys.is_empty() {
                    return Err(DIDWebVHError::ParametersError(
                        "updateKeys cannot be empty".to_string(),
                    ));
                }
                if !new_parameters.pre_rotation_active && pre_rotation_previous_value {
                    // Key pre-rotation has been turned off
                    // Update keys must be part of the previous nextKeyHashes
                    Parameters::validate_pre_rotation_keys(&previous.next_key_hashes, update_keys)?;
                    new_parameters.active_update_keys = update_keys.clone();
                } else if new_parameters.pre_rotation_active {
                    // Key pre-rotation is active
                    // Update keys must be part of the previous nextKeyHashes
                    Parameters::validate_pre_rotation_keys(&previous.next_key_hashes, update_keys)?;
                    new_parameters.active_update_keys = update_keys.clone();
                } else {
                    // No Key pre-rotation is active
                    new_parameters.active_update_keys = update_keys.clone();
                    new_parameters.update_keys = Some(Some(update_keys.clone()));
                }
            }
        } else {
            // First Log Entry checks
            if let Some(Some(update_keys)) = &self.update_keys {
                if update_keys.is_empty() {
                    return Err(DIDWebVHError::ParametersError(
                        "updateKeys cannot be empty".to_string(),
                    ));
                }
                new_parameters.update_keys = Some(Some(update_keys.clone()));
                new_parameters.active_update_keys = update_keys.clone();
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
                None => {
                    // If absent, keep current witnesses
                    new_parameters.active_witness = previous.witness.clone();
                    new_parameters.witness = previous.witness.clone();
                }
                Some(None) => {
                    // If None, turn off witness
                    new_parameters.witness = None;
                    // Still needs to be witnessed
                    new_parameters.active_witness = previous.witness.clone();
                }
                Some(Some(witnesses)) => {
                    // Replace witness with the new value
                    witnesses.validate()?;
                    new_parameters.witness = Some(Some(witnesses.clone()));
                    new_parameters.active_witness = previous.witness.clone();
                }
            }
        } else {
            // First Log Entry
            match &self.witness {
                None | Some(None) => {
                    new_parameters.active_witness = None;
                    new_parameters.witness = None;
                }
                Some(Some(witnesses)) => {
                    // Replace witness with the new value
                    witnesses.validate()?;
                    new_parameters.witness = Some(Some(witnesses.clone()));
                    new_parameters.active_witness = Some(Some(witnesses.clone()));
                }
            }
        }

        // Validate Watchers
        if let Some(previous) = previous {
            match &self.watchers {
                None => {
                    // If absent, keep current watchers
                    new_parameters.watchers = previous.watchers.clone();
                }
                Some(None) => {
                    // If None, turn off watchers
                    new_parameters.watchers = None;
                }
                Some(Some(watchers)) => {
                    // Replace watchers with the new value
                    new_parameters.watchers = Some(Some(watchers.clone()));
                }
            }
        } else {
            // First Log Entry
            match &self.watchers {
                None | Some(None) => {
                    new_parameters.watchers = None;
                }
                Some(Some(watchers)) => {
                    // Replace watchers with the new value
                    if watchers.is_empty() {
                        return Err(DIDWebVHError::ParametersError(
                            "watchers cannot be empty".to_string(),
                        ));
                    }
                    new_parameters.watchers = Some(Some(watchers.clone()));
                }
            }
        }

        // Check deactivation status
        if self.deactivated && previous.is_none() {
            // Can't be deactivated on the first log entry
            return Err(DIDWebVHError::DeactivatedError(
                "DID cannot be deactivated on the first Log Entry".to_string(),
            ));
        } else if self.deactivated && (new_parameters.update_keys != Some(None)) {
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
        next_key_hashes: &Option<Option<Vec<String>>>,
        update_keys: &[String],
    ) -> Result<(), DIDWebVHError> {
        let Some(Some(next_key_hashes)) = next_key_hashes else {
            return Err(DIDWebVHError::ValidationError(
                "nextKeyHashes must be defined when pre-rotation is active".to_string(),
            ));
        };
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
            watchers: None,
            ..Default::default()
        };

        let values = serde_json::to_value(parameters).unwrap();

        assert!(values.get("watchers").is_none())
    }
}
