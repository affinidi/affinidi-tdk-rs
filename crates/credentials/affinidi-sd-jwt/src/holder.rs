/*!
 * SD-JWT Holder operations: create presentations from an SD-JWT.
 *
 * The holder selects which disclosures to reveal and optionally
 * creates a Key Binding JWT to prove possession of the holder key.
 */

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};

use crate::SdJwt;
use crate::disclosure::Disclosure;
use crate::error::{Result, SdJwtError};
use crate::hasher::SdHasher;
use crate::signer::JwtSigner;

/// Input for creating a Key Binding JWT.
pub struct KbJwtInput<'a> {
    /// The intended audience (verifier's identifier). Must match what the verifier expects.
    pub audience: &'a str,
    /// A nonce provided by the verifier to prevent replay attacks. Must be unique per session.
    pub nonce: &'a str,
    /// The holder's signer (must correspond to the `cnf.jwk` in the SD-JWT payload).
    pub signer: &'a dyn JwtSigner,
    /// Issued-at timestamp (Unix seconds). Should be the current time.
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
    let revealed: Vec<Disclosure> = disclosures_to_reveal.iter().map(|d| (*d).clone()).collect();

    let presentation = SdJwt {
        jws: sd_jwt.jws.clone(),
        disclosures: revealed,
        kb_jwt: None,
    };

    // Create KB-JWT if requested
    let kb_jwt = if let Some(kb) = kb_input {
        let sd_hash = hasher.hash_b64(presentation.serialize_without_kb().as_bytes());

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

        Some(kb.signer.sign_jwt(&header, &payload)?)
    } else {
        None
    };

    Ok(SdJwt {
        jws: sd_jwt.jws.clone(),
        disclosures: presentation.disclosures,
        kb_jwt,
    })
}

/// Select disclosures by claim name from an SD-JWT.
///
/// Returns references to disclosures whose `claim_name` matches one of the
/// provided names. Array element disclosures (which have no claim name) are
/// not matched by this function.
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
/// Returns the claims object with disclosed values restored and SD-JWT
/// internal claims (`_sd`, `_sd_alg`) removed.
///
/// This is the processing of RFC 9901 §7.1 steps 3–5, and refuses what those
/// steps refuse:
/// - a digest that appears more than once, in the payload or in a disclosed
///   value (step 4);
/// - an object `_sd` digest whose Disclosure is not `[salt, name, value]`, or
///   names `_sd` or `...`, or a claim already present at that level
///   (step 3.c.ii);
/// - an array `{"...": digest}` whose Disclosure is not `[salt, value]`
///   (step 3.c.iii);
/// - a Disclosure no digest refers to, directly or through another Disclosure
///   (step 5), and the same Disclosure given twice.
///
/// Disclosed values are processed recursively, so a Disclosure referenced from
/// inside another one (RFC 9901 §4.2.6, Appendix A.2) resolves.
pub fn resolve_claims(payload: &Value, disclosures: &[Disclosure]) -> Result<Value> {
    let mut by_digest = HashMap::with_capacity(disclosures.len());
    for d in disclosures {
        if by_digest.insert(d.digest.as_str(), d).is_some() {
            return Err(SdJwtError::Verification(format!(
                "duplicate disclosure digest: {}",
                d.digest
            )));
        }
    }

    let mut resolver = Resolver {
        disclosures: by_digest,
        seen: HashSet::new(),
    };
    let mut claims = resolver.value(payload.clone(), 0)?;
    if let Some(obj) = claims.as_object_mut() {
        obj.remove("_sd_alg");
    }

    for d in disclosures {
        if !resolver.seen.contains(&d.digest) {
            return Err(SdJwtError::Verification(format!(
                "disclosure digest not found in payload: {}",
                d.digest
            )));
        }
    }

    Ok(claims)
}

/// Deepest nesting of objects and arrays, counted through disclosed values,
/// that [`resolve_claims`] processes. Recursive Disclosures can chain, so the
/// per-document depth limit of the JSON parser does not bound it.
const MAX_DEPTH: usize = 128;

/// One pass of RFC 9901 §7.1 over a payload and the values it discloses.
struct Resolver<'a> {
    disclosures: HashMap<&'a str, &'a Disclosure>,
    /// Every digest met so far, disclosed or not.
    seen: HashSet<String>,
}

impl<'a> Resolver<'a> {
    /// Record a digest (refusing one already met) and return its Disclosure,
    /// if one was presented.
    fn digest(&mut self, digest: &str) -> Result<Option<&'a Disclosure>> {
        if !self.seen.insert(digest.to_string()) {
            return Err(SdJwtError::Verification(format!(
                "digest appears more than once: {digest}"
            )));
        }
        Ok(self.disclosures.get(digest).copied())
    }

    fn value(&mut self, value: Value, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(SdJwtError::Verification(format!(
                "claims nested deeper than {MAX_DEPTH}"
            )));
        }
        match value {
            Value::Object(obj) => Ok(Value::Object(self.object(obj, depth)?)),
            Value::Array(arr) => Ok(Value::Array(self.array(arr, depth)?)),
            other => Ok(other),
        }
    }

    fn object(&mut self, mut obj: Map<String, Value>, depth: usize) -> Result<Map<String, Value>> {
        let sd = obj.remove("_sd");

        let mut out = Map::new();
        for (key, value) in obj {
            out.insert(key, self.value(value, depth + 1)?);
        }

        let Some(sd) = sd else {
            return Ok(out);
        };
        let Value::Array(digests) = sd else {
            return Err(SdJwtError::Verification("_sd must be an array".into()));
        };
        for digest in digests {
            let Value::String(digest) = digest else {
                return Err(SdJwtError::Verification(
                    "_sd must contain only strings".into(),
                ));
            };
            let Some(disclosure) = self.digest(&digest)? else {
                continue; // withheld or decoy
            };
            let Some(name) = &disclosure.claim_name else {
                return Err(SdJwtError::Verification(format!(
                    "digest {digest} in _sd refers to an array element disclosure"
                )));
            };
            if name == "_sd" || name == "..." {
                return Err(SdJwtError::Verification(format!(
                    "disclosure {digest} uses the reserved claim name \"{name}\""
                )));
            }
            if out.contains_key(name) {
                return Err(SdJwtError::Verification(format!(
                    "disclosed claim \"{name}\" already exists"
                )));
            }
            let value = self.value(disclosure.claim_value.clone(), depth + 1)?;
            out.insert(name.clone(), value);
        }
        Ok(out)
    }

    fn array(&mut self, arr: Vec<Value>, depth: usize) -> Result<Vec<Value>> {
        let mut out = Vec::with_capacity(arr.len());
        for element in arr {
            let Some(digest) = array_element_digest(&element) else {
                out.push(self.value(element, depth + 1)?);
                continue;
            };
            let Some(disclosure) = self.digest(digest)? else {
                continue; // withheld or decoy: the element is removed
            };
            if disclosure.claim_name.is_some() {
                return Err(SdJwtError::Verification(format!(
                    "array element digest {digest} refers to an object claim disclosure"
                )));
            }
            out.push(self.value(disclosure.claim_value.clone(), depth + 1)?);
        }
        Ok(out)
    }
}

/// The digest of an array element `{"...": digest}`: an object whose only key
/// is `...`, holding a string (RFC 9901 §4.2.4.2).
fn array_element_digest(element: &Value) -> Option<&str> {
    let obj = element.as_object()?;
    if obj.len() != 1 {
        return None;
    }
    obj.get("...")?.as_str()
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
            "sub": "user123", "given_name": "John", "family_name": "Doe"
        });
        let frame = serde_json::json!({ "_sd": ["given_name", "family_name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
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
            "sub": "user123", "given_name": "John", "family_name": "Doe", "email": "john@example.com"
        });
        let frame = serde_json::json!({ "_sd": ["given_name", "family_name", "email"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let selected = select_disclosures(&sd_jwt, &["given_name"]);
        assert_eq!(selected.len(), 1);

        let presentation = present(&sd_jwt, &selected, None, &hasher).unwrap();
        assert_eq!(
            presentation.disclosures[0].claim_name.as_deref(),
            Some("given_name")
        );
    }

    #[test]
    fn present_zero_disclosures() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let presentation = present(&sd_jwt, &[], None, &hasher).unwrap();
        assert!(presentation.disclosures.is_empty());
    }

    #[test]
    fn select_nonexistent_claims_returns_empty() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let selected = select_disclosures(&sd_jwt, &["nonexistent", "also_missing"]);
        assert!(selected.is_empty());
    }

    #[test]
    fn present_with_key_binding() {
        let hasher = Sha256Hasher;
        let signer = test_signer();
        let holder_signer = HmacSha256Signer::new(b"holder-key-for-hmac-signing!!!");

        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });

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
        assert!(!presentation.serialize().ends_with('~'));
    }

    #[test]
    fn resolve_claims_restores_disclosed_values() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims =
            serde_json::json!({ "sub": "user123", "given_name": "John", "family_name": "Doe" });
        let frame = serde_json::json!({ "_sd": ["given_name", "family_name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let payload = sd_jwt.payload().unwrap();

        let resolved = resolve_claims(&payload, &sd_jwt.disclosures).unwrap();
        assert_eq!(resolved["given_name"], "John");
        assert_eq!(resolved["family_name"], "Doe");
        assert!(resolved.get("_sd").is_none());
        assert!(resolved.get("_sd_alg").is_none());
    }

    #[test]
    fn resolve_claims_partial_disclosure() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims =
            serde_json::json!({ "sub": "user123", "given_name": "John", "family_name": "Doe" });
        let frame = serde_json::json!({ "_sd": ["given_name", "family_name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let payload = sd_jwt.payload().unwrap();

        let given_name_only: Vec<Disclosure> = sd_jwt
            .disclosures
            .iter()
            .filter(|d| d.claim_name.as_deref() == Some("given_name"))
            .cloned()
            .collect();

        let resolved = resolve_claims(&payload, &given_name_only).unwrap();
        assert_eq!(resolved["given_name"], "John");
        assert!(resolved.get("family_name").is_none());
    }

    #[test]
    fn parse_and_resolve_roundtrip() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({ "sub": "user123", "given_name": "John", "email": "john@example.com" });
        let frame = serde_json::json!({ "_sd": ["given_name", "email"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let serialized = sd_jwt.serialize();

        let parsed = parse_presentation(&serialized, &hasher).unwrap();
        let payload = parsed.payload().unwrap();
        let resolved = resolve_claims(&payload, &parsed.disclosures).unwrap();
        assert_eq!(resolved["given_name"], "John");
        assert_eq!(resolved["email"], "john@example.com");
    }
}
