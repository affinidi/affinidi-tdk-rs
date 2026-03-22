/*!
 * SD-JWT Holder operations: create presentations from an SD-JWT.
 *
 * The holder selects which disclosures to reveal and optionally
 * creates a Key Binding JWT to prove possession of the holder key.
 */

use serde_json::Value;

use crate::SdJwt;
use crate::disclosure::Disclosure;
use crate::error::Result;
use crate::hasher::SdHasher;
use crate::signer::JwtSigner;

/// Input for creating a Key Binding JWT.
pub struct KbJwtInput<'a> {
    /// The audience (verifier) for the KB-JWT
    pub audience: &'a str,
    /// A nonce provided by the verifier
    pub nonce: &'a str,
    /// The holder's signer
    pub signer: &'a dyn JwtSigner,
    /// Issued-at timestamp (Unix seconds)
    pub iat: u64,
}

/// Create a presentation from an SD-JWT, revealing only selected disclosures.
///
/// # Arguments
///
/// * `sd_jwt` - The original SD-JWT from the issuer
/// * `disclosures_to_reveal` - The subset of disclosures to include
/// * `kb_input` - Optional Key Binding JWT input
/// * `hasher` - The hash function (must match the one used during issuance)
pub fn present(
    sd_jwt: &SdJwt,
    disclosures_to_reveal: &[&Disclosure],
    kb_input: Option<&KbJwtInput>,
    hasher: &dyn SdHasher,
) -> Result<SdJwt> {
    // Build the presentation disclosures
    let revealed: Vec<Disclosure> = disclosures_to_reveal.iter().map(|d| (*d).clone()).collect();

    // Build the serialized form without KB-JWT first (needed for sd_hash)
    let mut parts = vec![sd_jwt.jws.clone()];
    for d in &revealed {
        parts.push(d.serialized.clone());
    }
    let presentation_without_kb = parts.join("~") + "~";

    // Create KB-JWT if requested
    let kb_jwt = if let Some(kb) = kb_input {
        let sd_hash = hasher.hash_b64(presentation_without_kb.as_bytes());

        let header = serde_json::json!({
            "alg": kb.signer.algorithm(),
            "typ": "kb+jwt",
        });

        let payload = serde_json::json!({
            "iat": kb.iat,
            "aud": kb.audience,
            "nonce": kb.nonce,
            "sd_hash": sd_hash,
        });

        let jws = kb.signer.sign_jwt(&header, &payload)?;
        Some(jws)
    } else {
        None
    };

    Ok(SdJwt {
        jws: sd_jwt.jws.clone(),
        disclosures: revealed,
        kb_jwt,
    })
}

/// Select disclosures by claim name from an SD-JWT.
pub fn select_disclosures<'a>(sd_jwt: &'a SdJwt, claim_names: &[&str]) -> Vec<&'a Disclosure> {
    sd_jwt
        .disclosures
        .iter()
        .filter(|d| {
            d.claim_name
                .as_deref()
                .is_some_and(|name| claim_names.contains(&name))
        })
        .collect()
}

/// Parse a serialized SD-JWT presentation string back into an SdJwt.
pub fn parse_presentation(serialized: &str, hasher: &dyn SdHasher) -> Result<SdJwt> {
    SdJwt::parse(serialized, hasher)
}

/// Resolve the disclosed claims from the JWT payload and provided disclosures.
///
/// Returns the claims object with disclosed values restored.
pub fn resolve_claims(payload: &Value, disclosures: &[Disclosure]) -> Result<Value> {
    let mut claims = payload.clone();

    if let Some(obj) = claims.as_object_mut() {
        resolve_object(obj, disclosures)?;

        // Remove SD-JWT internal claims
        obj.remove("_sd");
        obj.remove("_sd_alg");
    }

    Ok(claims)
}

/// Recursively resolve `_sd` digests in an object using the provided disclosures.
fn resolve_object(
    obj: &mut serde_json::Map<String, Value>,
    disclosures: &[Disclosure],
) -> Result<()> {
    // Build a map from digest -> disclosure for quick lookup
    let digest_map: std::collections::HashMap<&str, &Disclosure> =
        disclosures.iter().map(|d| (d.digest.as_str(), d)).collect();

    // Process _sd array: restore disclosed claims
    if let Some(sd_array) = obj.remove("_sd")
        && let Some(digests) = sd_array.as_array()
    {
        for digest_val in digests {
            if let Some(digest_str) = digest_val.as_str()
                && let Some(disclosure) = digest_map.get(digest_str)
                && let Some(name) = &disclosure.claim_name
            {
                obj.insert(name.clone(), disclosure.claim_value.clone());
            }
            // If digest not found in disclosures, it's either undisclosed or a decoy
        }
    }

    // Recurse into nested objects
    let keys: Vec<String> = obj.keys().cloned().collect();
    for key in keys {
        if let Some(value) = obj.get_mut(&key) {
            match value {
                Value::Object(nested) => resolve_object(nested, disclosures)?,
                Value::Array(arr) => resolve_array(arr, disclosures)?,
                _ => {}
            }
        }
    }

    Ok(())
}

/// Resolve `{"...": digest}` entries in arrays.
fn resolve_array(arr: &mut Vec<Value>, disclosures: &[Disclosure]) -> Result<()> {
    let digest_map: std::collections::HashMap<&str, &Disclosure> =
        disclosures.iter().map(|d| (d.digest.as_str(), d)).collect();

    let mut i = 0;
    while i < arr.len() {
        if let Some(obj) = arr[i].as_object()
            && let Some(digest_val) = obj.get("...")
            && let Some(digest_str) = digest_val.as_str()
        {
            if let Some(disclosure) = digest_map.get(digest_str) {
                arr[i] = disclosure.claim_value.clone();
            } else {
                // Undisclosed array element — remove it
                arr.remove(i);
                continue;
            }
        }

        // Recurse into nested structures
        match &mut arr[i] {
            Value::Object(nested) => resolve_object(nested, disclosures)?,
            Value::Array(nested_arr) => resolve_array(nested_arr, disclosures)?,
            _ => {}
        }
        i += 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::Sha256Hasher;
    use crate::issuer;
    use crate::signer::test_utils::HmacSha256Signer;

    fn test_signer() -> HmacSha256Signer {
        HmacSha256Signer::new(b"test-key-for-hmac-256-signing!!")
    }

    #[test]
    fn present_all_disclosures() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({
            "sub": "user123",
            "given_name": "John",
            "family_name": "Doe"
        });

        let frame = serde_json::json!({
            "_sd": ["given_name", "family_name"]
        });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();

        // Reveal all
        let all_refs: Vec<&Disclosure> = sd_jwt.disclosures.iter().collect();
        let presentation = present(&sd_jwt, &all_refs, None, &hasher).unwrap();

        assert_eq!(presentation.disclosures.len(), 2);
        assert!(presentation.kb_jwt.is_none());
    }

    #[test]
    fn present_subset_of_disclosures() {
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

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();

        // Only reveal given_name
        let selected = select_disclosures(&sd_jwt, &["given_name"]);
        assert_eq!(selected.len(), 1);

        let presentation = present(&sd_jwt, &selected, None, &hasher).unwrap();
        assert_eq!(presentation.disclosures.len(), 1);
        assert_eq!(
            presentation.disclosures[0].claim_name.as_deref(),
            Some("given_name")
        );
    }

    #[test]
    fn present_with_key_binding() {
        let hasher = Sha256Hasher;
        let signer = test_signer();
        let holder_signer = HmacSha256Signer::new(b"holder-key-for-hmac-signing!!!");

        let claims = serde_json::json!({
            "sub": "user123",
            "name": "John"
        });

        let frame = serde_json::json!({
            "_sd": ["name"]
        });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();

        let all_refs: Vec<&Disclosure> = sd_jwt.disclosures.iter().collect();
        let kb_input = KbJwtInput {
            audience: "https://verifier.example.com",
            nonce: "abc123",
            signer: &holder_signer,
            iat: 1700000000,
        };

        let presentation = present(&sd_jwt, &all_refs, Some(&kb_input), &hasher).unwrap();

        assert!(presentation.kb_jwt.is_some());
        let serialized = presentation.serialize();
        // Should end with KB-JWT (not ~)
        assert!(!serialized.ends_with('~'));
        // Should have JWS, disclosure, KB-JWT
        let parts: Vec<&str> = serialized.split('~').collect();
        assert_eq!(parts.len(), 3); // jws, disclosure, kb_jwt
    }

    #[test]
    fn resolve_claims_restores_disclosed_values() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({
            "sub": "user123",
            "given_name": "John",
            "family_name": "Doe"
        });

        let frame = serde_json::json!({
            "_sd": ["given_name", "family_name"]
        });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let payload = sd_jwt.payload().unwrap();

        // Resolve with all disclosures
        let resolved = resolve_claims(&payload, &sd_jwt.disclosures).unwrap();
        assert_eq!(resolved["sub"], "user123");
        assert_eq!(resolved["given_name"], "John");
        assert_eq!(resolved["family_name"], "Doe");
        // Internal claims should be removed
        assert!(resolved.get("_sd").is_none());
        assert!(resolved.get("_sd_alg").is_none());
    }

    #[test]
    fn resolve_claims_partial_disclosure() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({
            "sub": "user123",
            "given_name": "John",
            "family_name": "Doe"
        });

        let frame = serde_json::json!({
            "_sd": ["given_name", "family_name"]
        });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let payload = sd_jwt.payload().unwrap();

        // Only provide given_name disclosure
        let given_name_only: Vec<Disclosure> = sd_jwt
            .disclosures
            .iter()
            .filter(|d| d.claim_name.as_deref() == Some("given_name"))
            .cloned()
            .collect();

        let resolved = resolve_claims(&payload, &given_name_only).unwrap();
        assert_eq!(resolved["sub"], "user123");
        assert_eq!(resolved["given_name"], "John");
        // family_name not disclosed
        assert!(resolved.get("family_name").is_none());
    }

    #[test]
    fn parse_and_resolve_roundtrip() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({
            "sub": "user123",
            "given_name": "John",
            "email": "john@example.com"
        });

        let frame = serde_json::json!({
            "_sd": ["given_name", "email"]
        });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let serialized = sd_jwt.serialize();

        // Parse back
        let parsed = parse_presentation(&serialized, &hasher).unwrap();
        assert_eq!(parsed.disclosures.len(), 2);

        // Resolve
        let payload = parsed.payload().unwrap();
        let resolved = resolve_claims(&payload, &parsed.disclosures).unwrap();
        assert_eq!(resolved["given_name"], "John");
        assert_eq!(resolved["email"], "john@example.com");
    }
}
