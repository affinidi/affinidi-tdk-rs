/*!
*   Contains the parameters that define DID processing parameters
*   used when processing the current and previous Log Entry
*/

use crate::{DIDWebVHError, witness::Witnesses};
use affinidi_secrets_resolver::secrets::Secret;
use serde::{Deserialize, Serialize};
use std::ops::Not;
use tracing::debug;

/// [https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters]
/// Parameters that help with the resolution of a webvh DID
///
/// Thin uses double options to allow for the following:
/// None = field wasn't specified
/// Some(None) = field was specified, but set to null
/// Some(Some(value)) = field was specified with a value
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_keys: Option<Vec<String>>,

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
    #[serde(skip)]
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
    #[serde(
        default,                                    // <- important for deserialization
        skip_serializing_if = "Option::is_none",    // <- important for serialization
        with = "::serde_with::rust::double_option",
    )]
    pub ttl: Option<Option<u32>>,
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
        debug!("self: {:#?}", self);
        debug!("previous: {:#?}", previous);

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
            match &self.update_keys {
                None => {
                    // If absent, keep current updateKeys
                    new_parameters.active_update_keys = previous.active_update_keys.clone();
                }
                Some(update_keys) => {
                    if update_keys.is_empty() {
                        // If empty, turn off updateKeys
                        new_parameters.update_keys = Some(Vec::new());
                        new_parameters.active_update_keys = previous.active_update_keys.clone();
                    } else {
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
                                &previous.next_key_hashes,
                                update_keys,
                            )?;
                            new_parameters.active_update_keys = update_keys.clone();
                            new_parameters.update_keys = Some(update_keys.clone());
                        } else if new_parameters.pre_rotation_active {
                            // Key pre-rotation is active
                            // Update keys must be part of the previous nextKeyHashes
                            Parameters::validate_pre_rotation_keys(
                                &previous.next_key_hashes,
                                update_keys,
                            )?;
                            new_parameters.active_update_keys = update_keys.clone();
                        } else {
                            // No Key pre-rotation is active
                            new_parameters.active_update_keys = update_keys.clone();
                            new_parameters.update_keys = Some(update_keys.clone());
                        }
                    }
                }
            }
        } else {
            // First Log Entry checks
            if let Some(update_keys) = &self.update_keys {
                if update_keys.is_empty() {
                    return Err(DIDWebVHError::ParametersError(
                        "updateKeys cannot be empty".to_string(),
                    ));
                }
                new_parameters.update_keys = Some(update_keys.clone());
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
        } else if self.deactivated {
            if let Some(update_keys) = &self.update_keys {
                if !update_keys.is_empty() {
                    return Err(DIDWebVHError::DeactivatedError(
                        "DID Parameters say deactivated, yet updateKeys are not null!".to_string(),
                    ));
                }
            }
            new_parameters.update_keys = Some(Vec::new());
        }

        new_parameters.deactivated = self.deactivated;

        // Determine TTL
        if let Some(previous) = previous {
            match &self.ttl {
                None => {
                    // If absent, keep current TTL
                    new_parameters.ttl = previous.ttl;
                }
                Some(None) => {
                    // If None, turn off TTL
                    new_parameters.ttl = None;
                }
                Some(Some(ttl)) => {
                    // Replace ttl with the new value
                    new_parameters.ttl = Some(Some(*ttl));
                }
            }
        } else {
            // First Log Entry
            match &self.ttl {
                None | Some(None) => {
                    new_parameters.ttl = None;
                }
                Some(Some(ttl)) => {
                    // Replace ttl with the new value
                    new_parameters.ttl = Some(Some(*ttl));
                }
            }
        }

        debug!("Parameters successfully validated");
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
            let check_hash = Secret::base58_hash_string(key).map_err(|e| {
                DIDWebVHError::ValidationError(format!(
                    "Couldn't hash updateKeys key ({key}). Reason: {e}",
                ))
            })?;
            if !next_key_hashes.contains(&check_hash) {
                return Err(DIDWebVHError::ValidationError(format!(
                    "updateKey ({key}) hash({check_hash}) was not specified in the previous nextKeyHashes!",
                )));
            }
        }
        Ok(())
    }

    /// Compares two sets of Parameters and returns a new Parameters object only with the
    /// differences
    /// Will check and verify to spec, will return an error if there is an issue
    pub fn diff(&self, new_params: &Parameters) -> Result<Parameters, DIDWebVHError> {
        // Only did:webvh:1.0 is supported, so set method to None to ignore any changes
        let mut diff = Parameters {
            method: None,
            ..Default::default()
        };

        // Calculated fields can be left at defaults as they are ignored in serialization
        // pre_rotation_active, active_update_keys, active_witness
        // scid can not be changed, so leave it at default None

        // updateKeys may have changed
        debug!(
            "new_params.update_keys: {:#?} :: previous.update_keys: {:#?}",
            new_params.update_keys, self.update_keys
        );
        diff.update_keys =
            Parameters::diff_update_keys(&self.update_keys, &new_params.update_keys)?;

        if self.pre_rotation_active {
            if let Some(update_keys) = diff.update_keys.as_ref() {
                if update_keys.is_empty() {
                    return Err(DIDWebVHError::ParametersError(
                        "updateKeys cannot be empty when pre-rotation is active".to_string(),
                    ));
                }
            } else {
                return Err(DIDWebVHError::ParametersError(
                    "updateKeys must be defined when pre-rotation is active".to_string(),
                ));
            }
        }

        // Check if portable has been turned off (can never be turned on except on first log entry)
        if self.portable != new_params.portable {
            if new_params.portable == Some(true) {
                return Err(DIDWebVHError::ParametersError(
                    "Portable cannot be set to true after the first Log Entry".to_string(),
                ));
            }
            diff.portable = new_params.portable;
        }

        // nextKeyHashes checks
        match new_params.next_key_hashes {
            None => {
                // If None, then keep current parameter nextKeyHashes
                diff.next_key_hashes = None;
            }
            Some(None) => {
                // If Some(None), then cancel the nextKeyHashes
                match self.next_key_hashes {
                    None => {
                        // If current nextKeyHashes is also None, then no change
                        diff.next_key_hashes = None;
                    }
                    Some(Some(_)) => {
                        // If current nextKeyHashes is Some(Some(_)), then set to None
                        diff.next_key_hashes = Some(None);
                    }
                    Some(None) => {
                        // If current nextKeyHashes is Some(None), then no change
                        diff.next_key_hashes = None;
                    }
                }
            }
            Some(Some(ref next_key_hashes)) => {
                if self.next_key_hashes == new_params.next_key_hashes {
                    // If nextKeyHashes are the same, no change
                    diff.next_key_hashes = None;
                } else {
                    // If Some(Some(next_key_hashes)), then set the new next key hashes
                    if next_key_hashes.is_empty() {
                        return Err(DIDWebVHError::ParametersError(
                            "nextKeyHashes cannot be empty".to_string(),
                        ));
                    }
                    diff.next_key_hashes = Some(Some(next_key_hashes.clone()));
                }
            }
        }

        // Witness checks
        match new_params.witness {
            None => {
                // If None, then keep current parameter witness
                diff.witness = None;
            }
            Some(None) => {
                // If Some(None), then cancel the witness
                match self.witness {
                    None => {
                        // If current witness is also None, then no change
                        diff.witness = None;
                    }
                    Some(Some(_)) => {
                        // If current witness is Some(Some(_)), then set to None
                        diff.witness = Some(None);
                    }
                    Some(None) => {
                        // If current witness is Some(None), then no change
                        diff.witness = None;
                    }
                }
            }
            Some(Some(ref witnesses)) => {
                // If Some(Some(witnesses)), then set the new witnesses
                witnesses.validate()?;
                if self.witness == new_params.witness {
                    // If witnesses are the same, no change
                    diff.witness = None;
                } else if witnesses.is_empty() {
                    return Err(DIDWebVHError::ParametersError(
                        "witnesses cannot be empty".to_string(),
                    ));
                } else {
                    // If witnesses are different, set the new witnesses
                    diff.witness = Some(Some(witnesses.clone()));
                }
            }
        }

        // Watcher checks
        match new_params.watchers {
            None => {
                // If None, then keep current parameter watchers
                diff.watchers = None;
            }
            Some(None) => {
                // If Some(None), then cancel the watchers
                match self.watchers {
                    None => {
                        // If current watchers is also None, then no change
                        diff.watchers = None;
                    }
                    Some(Some(_)) => {
                        // If current watchers is Some(Some(_)), then set to None
                        diff.watchers = Some(None);
                    }
                    Some(None) => {
                        // If current watchers is Some(None), then no change
                        diff.watchers = None;
                    }
                }
            }
            Some(Some(ref watchers)) => {
                // If Some(Some(watchers)), then set the new watchers
                if watchers.is_empty() {
                    return Err(DIDWebVHError::ParametersError(
                        "watchers cannot be empty".to_string(),
                    ));
                }
                if self.watchers == new_params.watchers {
                    // If watchers are the same, no change
                    diff.watchers = None;
                } else {
                    // If watchers are different, set the new watchers
                    diff.watchers = Some(Some(watchers.clone()));
                }
            }
        }

        // Deactivated
        if new_params.deactivated && self.pre_rotation_active {
            return Err(DIDWebVHError::DeactivatedError(
                "DID cannot be deactivated while pre-rotation is active".to_string(),
            ));
        } else {
            diff.deactivated = new_params.deactivated;
        }

        // TTL Checks
        match new_params.ttl {
            None => {
                // If None, then keep current parameter ttl
                diff.ttl = None;
            }
            Some(None) => {
                // If Some(None), then cancel the ttl
                match self.ttl {
                    None => {
                        // If current ttl is also None, then no change
                        diff.ttl = None;
                    }
                    Some(None) => {
                        // If current ttl is Some(None), then set to None
                        diff.ttl = None;
                    }
                    Some(Some(_)) => {
                        diff.ttl = Some(None);
                    }
                }
            }
            Some(Some(ttl)) => {
                // If Some(ttl), then set the new ttl
                if ttl == 0 {
                    return Err(DIDWebVHError::ParametersError(
                        "TTL cannot be zero".to_string(),
                    ));
                }
                if self.ttl == new_params.ttl {
                    // If ttl is the same, no change
                    diff.ttl = None;
                } else {
                    diff.ttl = Some(Some(ttl));
                }
            }
        }

        Ok(diff)
    }

    /// Returns the differences in update_keys
    fn diff_update_keys(
        previous: &Option<Vec<String>>,
        current: &Option<Vec<String>>,
    ) -> Result<Option<Vec<String>>, DIDWebVHError> {
        let Some(current) = current else {
            // If current is None, then keep previous update_keys
            return Ok(None);
        };

        if current.is_empty() {
            if let Some(previous) = previous {
                if previous.is_empty() {
                    // update_keys was already empty, and thus setting it again to empty would be
                    // invalid
                    return Err(DIDWebVHError::ParametersError(
                        "updateKeys cannot be empty when previous was also empty!".to_string(),
                    ));
                }
            }
            Ok(Some(Vec::new()))
        } else {
            // There are values
            if let Some(previous) = previous {
                if previous == current {
                    return Ok(None);
                }
            }
            Ok(Some(current.to_owned()))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::witness::{Witness, Witnesses};

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

    #[test]
    fn diff_no_changes_full() {
        let old_params = Parameters {
            method: Some("did:webvh:1.0".to_string()),
            scid: Some("scid123".to_string()),
            update_keys: Some(vec![
                "z6Mkp7QveNebyWs4z1kJ7Aa7CymUjRpjPYnBYh6Cr1t6JoXY".to_string(),
                "z6MkqUa1LbqZ7EpevqrFC7XHAWM8CE49AKFWVjyu543NfVAp".to_string(),
            ]),
            portable: Some(true),
            next_key_hashes: Some(Some(vec![
                "zQmS6fKbreQixpa6JueaSuDiL2VQAGosC45TDQdKHf5E155".to_string(),
                "zQmctZhRGCKrE2R58K9rkfA1aUL74mecrrJRvicz42resii".to_string(),
            ])),
            witness: Some(Some(Witnesses {
                threshold: 2,
                witnesses: vec![
                    Witness {
                        id: "witness1".to_string(),
                    },
                    Witness {
                        id: "witness2".to_string(),
                    },
                ],
            })),
            watchers: Some(Some(vec!["watcher1".to_string()])),
            deactivated: false,
            ttl: Some(Some(3600)),
            ..Default::default()
        };

        let new_params = old_params.clone();

        let result = old_params.diff(&new_params).expect("Diff failed");
        assert_eq!(serde_json::to_string(&result).unwrap(), "{}");
    }

    #[test]
    fn diff_no_changes_empty() {
        let old_params = Parameters {
            method: None,
            ..Default::default()
        };

        let new_params = old_params.clone();

        let result = old_params.diff(&new_params).expect("Diff failed");
        assert_eq!(serde_json::to_string(&result).unwrap(), "{}");
    }

    #[test]
    fn diff_no_changes_method() {
        let old_params = Parameters::default();

        let new_params = Parameters {
            method: None,
            ..Default::default()
        };

        let result = old_params.diff(&new_params).expect("Diff failed");
        assert_eq!(serde_json::to_string(&result).unwrap(), "{}");
    }

    #[test]
    fn pre_rotation_active() {
        // On first LogEntry, if next_hashes is configured, then pre-rotation is active
        let first_params = Parameters {
            update_keys: Some(vec![
                "z6Mkp7QveNebyWs4z1kJ7Aa7CymUjRpjPYnBYh6Cr1t6JoXY".to_string(),
            ]),
            next_key_hashes: Some(Some(vec![
                "zQmS6fKbreQixpa6JueaSuDiL2VQAGosC45TDQdKHf5E155".to_string(),
            ])),
            ..Default::default()
        };

        let validated = first_params
            .validate(None)
            .expect("First Log Entry should be valid");

        assert!(validated.pre_rotation_active);
    }

    #[test]
    fn diff_update_keys_absent() {
        let diff = Parameters::diff_update_keys(&None, &None);
        assert!(diff.is_ok_and(|a| a.is_none()));
    }

    #[test]
    fn diff_update_keys_empty() {
        // Absent --> Empty = Empty
        let diff = Parameters::diff_update_keys(&None, &Some(Vec::new()))
            .expect("Parameters::diff_update_keys() error");
        assert!(diff.is_some_and(|a| a.is_empty()));

        // Values --> Empty = Empty
        let diff = Parameters::diff_update_keys(&Some(vec!["test".to_string()]), &Some(Vec::new()))
            .expect("Parameters::diff_update_keys() error");
        assert!(diff.is_some_and(|a| a.is_empty()));
    }

    #[test]
    fn diff_update_keys_double_empty() {
        assert!(Parameters::diff_update_keys(&Some(Vec::new()), &Some(Vec::new())).is_err());
    }

    #[test]
    fn diff_update_keys_value() {
        // From nothing to something
        let diff = Parameters::diff_update_keys(&None, &Some(vec!["test".to_string()]))
            .expect("Parameters::diff_update_keys error");
        assert!(diff.is_some_and(|a| a == vec!["test".to_string()]));
    }

    #[test]
    fn diff_update_keys_same_value() {
        let diff = Parameters::diff_update_keys(
            &Some(vec!["test".to_string()]),
            &Some(vec!["test".to_string()]),
        )
        .expect("Parameters::diff_update_keys error");
        assert!(diff.is_none());
    }

    #[test]
    fn diff_update_keys_different_value() {
        let diff = Parameters::diff_update_keys(
            &Some(vec!["old".to_string()]),
            &Some(vec!["new".to_string()]),
        )
        .expect("Parameters::diff_update_keys error");
        assert!(diff.is_some_and(|a| a.first().unwrap().as_str() == "new"));
    }

    #[test]
    fn diff_update_keys_pre_rotation_empty() {
        let previous = Parameters {
            pre_rotation_active: true,
            ..Default::default()
        };

        let current = Parameters {
            update_keys: Some(Vec::new()),
            ..Default::default()
        };
        assert!(previous.diff(&current).is_err());
    }

    #[test]
    fn diff_update_keys_pre_rotation_none() {
        let previous = Parameters {
            pre_rotation_active: true,
            ..Default::default()
        };

        let current = Parameters {
            update_keys: None,
            ..Default::default()
        };
        assert!(previous.diff(&current).is_err());
    }
}
