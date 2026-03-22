/*!
 * SD-JWT Issuance: create SD-JWTs from claims and a disclosure frame.
 *
 * The disclosure frame mirrors the claims structure and uses:
 * - `"_sd"`: array of claim names to make selectively disclosable
 * - `"_sd_decoy"`: number of decoy digests to add
 *
 * Array element disclosures use `"_sd"` with element indices as strings.
 */

use serde_json::{Map, Value};

use crate::SdJwt;
use crate::disclosure::{Disclosure, RESERVED_CLAIM_NAMES, generate_decoy_digest};
use crate::error::{Result, SdJwtError};
use crate::hasher::SdHasher;
use crate::signer::JwtSigner;

/// Issue an SD-JWT from claims and a disclosure frame.
///
/// # Arguments
///
/// * `claims` - The full claims to include in the JWT payload
/// * `disclosure_frame` - Specifies which claims are selectively disclosable
/// * `signer` - Signs the JWT
/// * `hasher` - Hash function for disclosure digests (typically SHA-256)
/// * `holder_jwk` - Optional holder public key JWK for key binding (`cnf` claim)
///
/// # Errors
///
/// Returns [`SdJwtError::InvalidFrame`] if:
/// - `claims` is not a JSON object
/// - The disclosure frame references reserved claim names (`_sd`, `_sd_alg`, `...`)
/// - The input claims contain `"..."` as a key (reserved per RFC 9901 §5.2.1)
pub fn issue(
    claims: &Value,
    disclosure_frame: &Value,
    signer: &dyn JwtSigner,
    hasher: &dyn SdHasher,
    holder_jwk: Option<&Value>,
) -> Result<SdJwt> {
    let claims_obj = claims
        .as_object()
        .ok_or_else(|| SdJwtError::InvalidFrame("claims must be a JSON object".into()))?;

    // Validate no reserved keys in claims (C3)
    validate_no_reserved_keys(claims)?;

    let frame_obj = disclosure_frame.as_object();

    let mut disclosures = Vec::new();
    let payload_obj = process_object(claims_obj, frame_obj, hasher, &mut disclosures)?;

    let mut payload = Value::Object(payload_obj);

    // Only add _sd_alg when disclosures exist (C2)
    if !disclosures.is_empty() {
        payload.as_object_mut().unwrap().insert(
            "_sd_alg".to_string(),
            Value::String(hasher.alg_name().to_string()),
        );
    }

    // Add cnf claim for holder key binding
    if let Some(jwk) = holder_jwk {
        payload
            .as_object_mut()
            .unwrap()
            .insert("cnf".to_string(), serde_json::json!({ "jwk": jwk }));
    }

    // Build JWT header
    let mut header = serde_json::json!({
        "alg": signer.algorithm(),
        "typ": "sd+jwt",
    });
    if let Some(kid) = signer.key_id() {
        header
            .as_object_mut()
            .unwrap()
            .insert("kid".to_string(), Value::String(kid.to_string()));
    }

    let jws = signer.sign_jwt(&header, &payload)?;

    Ok(SdJwt {
        jws,
        disclosures,
        kb_jwt: None,
    })
}

/// Recursively validate that no claim key is `"..."` (reserved per RFC 9901).
fn validate_no_reserved_keys(value: &Value) -> Result<()> {
    match value {
        Value::Object(obj) => {
            if obj.contains_key("...") {
                return Err(SdJwtError::InvalidFrame(
                    "\"...\" is a reserved key and must not appear in claims".into(),
                ));
            }
            for val in obj.values() {
                validate_no_reserved_keys(val)?;
            }
        }
        Value::Array(arr) => {
            for item in arr {
                validate_no_reserved_keys(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Recursively process a claims object against a disclosure frame.
fn process_object(
    claims: &Map<String, Value>,
    frame: Option<&Map<String, Value>>,
    hasher: &dyn SdHasher,
    disclosures: &mut Vec<Disclosure>,
) -> Result<Map<String, Value>> {
    let sd_claims: Vec<String> = frame
        .and_then(|f| f.get("_sd"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Validate no reserved claim names in _sd array (S2)
    for name in &sd_claims {
        if RESERVED_CLAIM_NAMES.contains(&name.as_str()) {
            return Err(SdJwtError::InvalidFrame(format!(
                "\"{name}\" is a reserved claim name and cannot be selectively disclosed"
            )));
        }
    }

    let decoy_count: usize = frame
        .and_then(|f| f.get("_sd_decoy"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    let mut result = Map::new();
    let mut sd_digests: Vec<String> = Vec::new();

    for (key, value) in claims {
        if sd_claims.contains(key) {
            let processed_value = if let Some(sub_frame) = frame.and_then(|f| f.get(key)) {
                process_value(value, sub_frame, hasher, disclosures)?
            } else {
                value.clone()
            };

            let disclosure = Disclosure::new_claim(key, processed_value, hasher)?;
            sd_digests.push(disclosure.digest.clone());
            disclosures.push(disclosure);
        } else {
            let sub_frame = frame.and_then(|f| f.get(key));
            if sub_frame.is_some() && value.is_object() {
                let nested = process_object(
                    value.as_object().unwrap(),
                    sub_frame.and_then(|f| f.as_object()),
                    hasher,
                    disclosures,
                )?;
                result.insert(key.clone(), Value::Object(nested));
            } else if sub_frame.is_some() && value.is_array() {
                let processed = process_array(
                    value.as_array().unwrap(),
                    sub_frame.unwrap(),
                    hasher,
                    disclosures,
                )?;
                result.insert(key.clone(), processed);
            } else {
                result.insert(key.clone(), value.clone());
            }
        }
    }

    for _ in 0..decoy_count {
        sd_digests.push(generate_decoy_digest(hasher));
    }

    if !sd_digests.is_empty() {
        sd_digests.sort();
        result.insert(
            "_sd".to_string(),
            Value::Array(sd_digests.into_iter().map(Value::String).collect()),
        );
    }

    Ok(result)
}

/// Process a value that may contain nested disclosures.
fn process_value(
    value: &Value,
    frame: &Value,
    hasher: &dyn SdHasher,
    disclosures: &mut Vec<Disclosure>,
) -> Result<Value> {
    match value {
        Value::Object(obj) => {
            let nested = process_object(obj, frame.as_object(), hasher, disclosures)?;
            Ok(Value::Object(nested))
        }
        Value::Array(arr) => process_array(arr, frame, hasher, disclosures),
        _ => Ok(value.clone()),
    }
}

/// Process an array, potentially making some elements selectively disclosable.
fn process_array(
    array: &[Value],
    frame: &Value,
    hasher: &dyn SdHasher,
    disclosures: &mut Vec<Disclosure>,
) -> Result<Value> {
    let frame_obj = frame.as_object();

    let sd_indices: Vec<usize> = frame_obj
        .and_then(|f| f.get("_sd"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().and_then(|s| s.parse::<usize>().ok()))
                .collect()
        })
        .unwrap_or_default();

    let mut result = Vec::new();

    for (i, element) in array.iter().enumerate() {
        if sd_indices.contains(&i) {
            let disclosure = Disclosure::new_array_element(element.clone(), hasher)?;
            result.push(serde_json::json!({"...": disclosure.digest.clone()}));
            disclosures.push(disclosure);
        } else {
            let idx_str = i.to_string();
            if let Some(sub_frame) = frame_obj.and_then(|f| f.get(&idx_str)) {
                result.push(process_value(element, sub_frame, hasher, disclosures)?);
            } else {
                result.push(element.clone());
            }
        }
    }

    Ok(Value::Array(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::Sha256Hasher;
    use crate::signer::test_utils::HmacSha256Signer;

    fn test_signer() -> HmacSha256Signer {
        HmacSha256Signer::new(b"test-key-for-hmac-256-signing!!")
    }

    #[test]
    fn issue_simple_flat_claims() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({
            "sub": "user123",
            "given_name": "John",
            "family_name": "Doe",
            "email": "john@example.com"
        });

        let frame = serde_json::json!({
            "_sd": ["given_name", "family_name", "email"]
        });

        let sd_jwt = issue(&claims, &frame, &signer, &hasher, None).unwrap();
        assert_eq!(sd_jwt.disclosures.len(), 3);

        let payload = sd_jwt.payload().unwrap();
        assert_eq!(payload["sub"], "user123");
        assert!(payload.get("given_name").is_none());
        assert_eq!(payload["_sd"].as_array().unwrap().len(), 3);
        assert_eq!(payload["_sd_alg"], "sha-256");
    }

    #[test]
    fn issue_with_nested_object() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({
            "sub": "user123",
            "address": {
                "street": "123 Main St",
                "city": "Anytown",
                "state": "CA"
            }
        });

        let frame = serde_json::json!({
            "address": { "_sd": ["street", "city"] }
        });

        let sd_jwt = issue(&claims, &frame, &signer, &hasher, None).unwrap();
        assert_eq!(sd_jwt.disclosures.len(), 2);

        let payload = sd_jwt.payload().unwrap();
        assert_eq!(payload["address"]["state"], "CA");
        assert!(payload["address"].get("street").is_none());
    }

    #[test]
    fn issue_entire_nested_object_as_disclosure() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({
            "sub": "user123",
            "address": { "street": "123 Main St", "city": "Anytown" }
        });

        let frame = serde_json::json!({ "_sd": ["address"] });

        let sd_jwt = issue(&claims, &frame, &signer, &hasher, None).unwrap();
        assert_eq!(sd_jwt.disclosures.len(), 1);
        assert_eq!(sd_jwt.disclosures[0].claim_value["street"], "123 Main St");
    }

    #[test]
    fn issue_with_array_element_disclosures() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({ "nationalities": ["US", "DE", "FR"] });
        let frame = serde_json::json!({ "nationalities": { "_sd": ["0", "2"] } });

        let sd_jwt = issue(&claims, &frame, &signer, &hasher, None).unwrap();
        assert_eq!(sd_jwt.disclosures.len(), 2);

        let payload = sd_jwt.payload().unwrap();
        let arr = payload["nationalities"].as_array().unwrap();
        assert!(arr[0].get("...").is_some());
        assert_eq!(arr[1], "DE");
        assert!(arr[2].get("...").is_some());
    }

    #[test]
    fn issue_with_decoy_digests() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"], "_sd_decoy": 3 });

        let sd_jwt = issue(&claims, &frame, &signer, &hasher, None).unwrap();
        assert_eq!(sd_jwt.disclosures.len(), 1);
        assert_eq!(
            sd_jwt.payload().unwrap()["_sd"].as_array().unwrap().len(),
            4
        );
    }

    #[test]
    fn issue_with_holder_key_binding() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let holder_jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
            "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
        });

        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let sd_jwt = issue(&claims, &frame, &signer, &hasher, Some(&holder_jwk)).unwrap();
        let payload = sd_jwt.payload().unwrap();
        assert_eq!(payload["cnf"]["jwk"]["kty"], "EC");
    }

    #[test]
    fn issue_no_disclosures_omits_sd_alg() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({});

        let sd_jwt = issue(&claims, &frame, &signer, &hasher, None).unwrap();
        assert!(sd_jwt.disclosures.is_empty());
        let payload = sd_jwt.payload().unwrap();
        // _sd_alg should NOT be present when there are no disclosures
        assert!(payload.get("_sd_alg").is_none());
    }

    #[test]
    fn issue_rejects_reserved_claim_name_sd() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({ "_sd": "bad", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["_sd"] });

        let result = issue(&claims, &frame, &signer, &hasher, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("reserved"));
    }

    #[test]
    fn issue_rejects_reserved_claim_name_dots() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({ "...": "bad", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["..."] });

        let result = issue(&claims, &frame, &signer, &hasher, None);
        assert!(result.is_err());
    }

    #[test]
    fn issue_rejects_dots_key_in_claims() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({ "name": "John", "nested": { "...": "bad" } });
        let frame = serde_json::json!({});

        let result = issue(&claims, &frame, &signer, &hasher, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("reserved key"));
    }

    #[test]
    fn issue_serialization_format() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let sd_jwt = issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let serialized = sd_jwt.serialize();

        assert!(serialized.ends_with('~'));
        let parts: Vec<&str> = serialized.split('~').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].split('.').count(), 3);
    }
}
