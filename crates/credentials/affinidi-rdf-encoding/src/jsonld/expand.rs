use serde_json::{Map, Value, json};

use super::context::Context;
use crate::error::{RdfError, Result};

/// Expand a JSON-LD document to its expanded form (lenient mode).
///
/// The expanded form has all terms replaced with full IRIs, all context
/// processing resolved, and all values in a normalized array/object structure.
///
/// Terms not defined by the active `@context` are **silently dropped**. For
/// security-sensitive canonicalization (e.g. Data Integrity proofs) use
/// [`expand_document_safe`] instead, so undefined claims cannot ride along
/// unsigned.
pub fn expand_document(document: &Value) -> Result<Value> {
    expand_document_inner(document, false)
}

/// Expand a JSON-LD document in **safe mode**.
///
/// Identical to [`expand_document`] except that a property whose key does not
/// map to an absolute IRI or a JSON-LD keyword — i.e. a term that lenient
/// expansion would silently drop — raises an error instead.
///
/// This is required by the W3C Verifiable Credential Data Integrity algorithms:
/// canonicalization must not discard unmapped terms, otherwise a credential can
/// carry attributes that are present in the JSON envelope yet absent from the
/// signed RDF dataset (issue #381 — a holder could set an undefined attribute to
/// any value and still pass verification).
pub fn expand_document_safe(document: &Value) -> Result<Value> {
    expand_document_inner(document, true)
}

fn expand_document_inner(document: &Value, safe: bool) -> Result<Value> {
    let mut context = Context::default();

    // Process top-level @context
    if let Some(ctx_val) = document.get("@context") {
        context.process(ctx_val)?;
    }

    let result = expand_element(document, &context, safe)?;

    // Wrap in array if not already
    match result {
        Value::Array(_) => Ok(result),
        Value::Null => Ok(json!([])),
        _ => Ok(json!([result])),
    }
}

/// Expand a single JSON-LD element (object, array, or value).
fn expand_element(element: &Value, context: &Context, safe: bool) -> Result<Value> {
    match element {
        Value::Array(arr) => {
            let mut result = Vec::new();
            for item in arr {
                let expanded = expand_element(item, context, safe)?;
                match expanded {
                    Value::Array(inner) => result.extend(inner),
                    Value::Null => {} // skip nulls
                    _ => result.push(expanded),
                }
            }
            Ok(Value::Array(result))
        }
        Value::Object(_) => expand_object(element, context, safe),
        Value::Null => Ok(Value::Null),
        _ => {
            // A free-standing scalar where a node is expected is dropped per the
            // JSON-LD spec. In safe mode, refuse it rather than discard data
            // (issue #381).
            if safe {
                return Err(RdfError::expansion(format!(
                    "safe mode: scalar {element} cannot be expanded as a node and would be dropped"
                )));
            }
            Ok(Value::Null)
        }
    }
}

/// Expand a JSON-LD object node.
fn expand_object(obj: &Value, parent_context: &Context, safe: bool) -> Result<Value> {
    let map = obj
        .as_object()
        .ok_or_else(|| RdfError::expansion("expected object"))?;

    // Process local @context if present
    let mut context = parent_context.clone();
    if let Some(ctx_val) = map.get("@context") {
        context.process(ctx_val)?;
    }

    // Check if this is a value object (@value present)
    if map.contains_key("@value") {
        return expand_value_object(map, &context);
    }

    // Determine @type values and apply scoped contexts from type definitions
    let type_context = build_type_scoped_context(map, &context)?;
    let context = type_context.unwrap_or(context);

    let mut result: Map<String, Value> = Map::new();

    for (key, value) in map {
        if key == "@context" {
            continue;
        }

        if key == "@id" || key == "id" {
            if let Some(id_def) = context.get_term(key) {
                if id_def.iri == "@id" {
                    if let Some(id_str) = value.as_str() {
                        result.insert("@id".to_string(), json!(id_str));
                    }
                    continue;
                }
            } else if key == "@id" {
                if let Some(id_str) = value.as_str() {
                    result.insert("@id".to_string(), json!(id_str));
                }
                continue;
            }
        }

        if key == "@type" || key == "type" {
            if let Some(type_def) = context.get_term(key) {
                if type_def.iri == "@type" {
                    let expanded_types = expand_type_value(value, &context, safe)?;
                    result.insert("@type".to_string(), expanded_types);
                    continue;
                }
            } else if key == "@type" {
                let expanded_types = expand_type_value(value, &context, safe)?;
                result.insert("@type".to_string(), expanded_types);
                continue;
            }
        }

        // Expand the property key
        let expanded_key = match context.expand_iri(key) {
            Some(iri) if iri.starts_with('@') => {
                continue; // Skip keyword aliases
            }
            Some(iri) if iri.contains("://") || iri.starts_with("urn:") => iri,
            _ => {
                if safe {
                    // Safe mode: an unmapped term would be dropped from the RDF
                    // dataset while remaining in the JSON envelope. Refuse it so
                    // it cannot be signed/verified out-of-band (issue #381).
                    return Err(RdfError::expansion(format!(
                        "safe mode: term '{key}' is not defined by the active @context \
                         and would be dropped from the signed dataset"
                    )));
                }
                continue; // Drop unmapped terms (lenient mode)
            }
        };

        // Get term definition for type coercion and scoped context
        let term_def = context.get_term(key);
        let type_mapping = term_def.and_then(|td| td.type_mapping.as_deref());

        // Apply scoped context from the term definition
        let prop_context = if let Some(td) = term_def {
            if let Some(ref scoped_ctx) = td.context {
                context.with_scoped_context(scoped_ctx)?
            } else {
                context.clone()
            }
        } else {
            context.clone()
        };

        // Expand the value
        let expanded_value = expand_property_value(value, type_mapping, &prop_context, safe)?;

        if expanded_value != Value::Null {
            // Merge into result
            if let Some(existing) = result.get_mut(&expanded_key) {
                if let Some(arr) = existing.as_array_mut() {
                    match expanded_value {
                        Value::Array(items) => arr.extend(items),
                        _ => arr.push(expanded_value),
                    }
                }
            } else {
                // Always wrap in array (JSON-LD expanded form)
                match expanded_value {
                    Value::Array(_) => {
                        result.insert(expanded_key, expanded_value);
                    }
                    _ => {
                        result.insert(expanded_key, json!([expanded_value]));
                    }
                }
            }
        }
    }

    if result.is_empty() {
        return Ok(Value::Null);
    }

    Ok(Value::Object(result))
}

/// Build a context with scoped contexts from @type values applied.
fn build_type_scoped_context(
    map: &Map<String, Value>,
    context: &Context,
) -> Result<Option<Context>> {
    // Find the type key (could be "type" or "@type")
    let type_value = if let Some(v) = map.get("@type") {
        Some(v)
    } else {
        map.get("type")
            .filter(|_| context.get_term("type").is_some_and(|td| td.iri == "@type"))
    };

    let type_value = match type_value {
        Some(v) => v,
        None => return Ok(None),
    };

    // Collect type strings
    let types: Vec<&str> = match type_value {
        Value::String(s) => vec![s.as_str()],
        Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
        _ => return Ok(None),
    };

    // Apply scoped contexts from type term definitions
    let mut new_context = context.clone();
    let mut had_scoped = false;

    for type_name in &types {
        if let Some(term_def) = context.get_term(type_name)
            && let Some(ref scoped_ctx) = term_def.context
        {
            new_context.process(scoped_ctx)?;
            had_scoped = true;
        }
    }

    if had_scoped {
        Ok(Some(new_context))
    } else {
        Ok(None)
    }
}

/// Expand @type values to full IRIs.
fn expand_type_value(value: &Value, context: &Context, safe: bool) -> Result<Value> {
    match value {
        Value::String(s) => {
            let expanded = expand_type_iri(s, context, safe)?;
            Ok(json!([expanded]))
        }
        Value::Array(arr) => {
            let mut expanded = Vec::with_capacity(arr.len());
            for v in arr {
                match v.as_str() {
                    Some(s) => expanded.push(json!(expand_type_iri(s, context, safe)?)),
                    None if safe => {
                        return Err(RdfError::expansion(format!(
                            "safe mode: non-string @type entry {v} would be dropped"
                        )));
                    }
                    None => {} // lenient: skip non-string entries
                }
            }
            Ok(Value::Array(expanded))
        }
        _ => Err(RdfError::expansion(format!("invalid @type value: {value}"))),
    }
}

/// Expand a type name to a full IRI.
///
/// In safe mode a type that does not resolve to an absolute IRI (via a term
/// definition or `@vocab`) is an error rather than being passed through as a
/// relative IRI — a relative type would otherwise enter the signed dataset
/// ambiguously / be dropped by stricter processors (issue #381).
fn expand_type_iri(type_name: &str, context: &Context, safe: bool) -> Result<String> {
    // If already an absolute IRI, return as-is
    if type_name.contains("://") || type_name.starts_with("urn:") {
        return Ok(type_name.to_string());
    }

    // Look up in context — for types, we want the @id value
    if let Some(def) = context.get_term(type_name)
        && (def.iri.contains("://") || def.iri.starts_with("urn:"))
    {
        return Ok(def.iri.clone());
    }

    // Try vocab expansion
    if let Some(ref vocab) = context.vocab {
        return Ok(format!("{vocab}{type_name}"));
    }

    if safe {
        return Err(RdfError::expansion(format!(
            "safe mode: type '{type_name}' is not defined by the active @context \
             and would not expand to an absolute IRI"
        )));
    }

    Ok(type_name.to_string())
}

/// Expand a value object ({ "@value": ... }).
fn expand_value_object(map: &Map<String, Value>, context: &Context) -> Result<Value> {
    let mut result: Map<String, Value> = Map::new();

    if let Some(val) = map.get("@value") {
        result.insert("@value".to_string(), val.clone());
    }

    if let Some(type_val) = map.get("@type")
        && let Some(type_str) = type_val.as_str()
    {
        let expanded = context
            .expand_iri(type_str)
            .unwrap_or_else(|| type_str.to_string());
        result.insert("@type".to_string(), json!(expanded));
    }

    if let Some(lang_val) = map.get("@language") {
        result.insert("@language".to_string(), lang_val.clone());
    }

    Ok(Value::Object(result))
}

/// Expand a property value with type coercion.
fn expand_property_value(
    value: &Value,
    type_mapping: Option<&str>,
    context: &Context,
    safe: bool,
) -> Result<Value> {
    // `@json`-typed values are kept verbatim as a JSON literal (the whole value,
    // including arrays/objects, is preserved and serialized canonically later).
    if type_mapping == Some("@json") {
        return Ok(json!({"@value": value.clone(), "@type": "@json"}));
    }

    match value {
        Value::Array(arr) => {
            let mut result = Vec::new();
            for item in arr {
                let expanded = expand_property_value(item, type_mapping, context, safe)?;
                match expanded {
                    Value::Null => {}
                    Value::Array(items) => result.extend(items),
                    _ => result.push(expanded),
                }
            }
            Ok(Value::Array(result))
        }
        Value::Object(_) => {
            // Recursively expand nested objects
            expand_object(value, context, safe)
        }
        Value::String(s) => {
            // Apply type coercion
            match type_mapping {
                Some("@id") | Some("@vocab") => {
                    let expanded = context.expand_iri(s).unwrap_or_else(|| s.clone());
                    Ok(json!({"@id": expanded}))
                }
                Some(datatype) if datatype != "@json" => {
                    // Typed literal
                    let resolved_type = context
                        .expand_iri(datatype)
                        .unwrap_or_else(|| datatype.to_string());
                    Ok(json!({"@value": s, "@type": resolved_type}))
                }
                _ => {
                    // Plain string
                    Ok(json!({"@value": s}))
                }
            }
        }
        Value::Number(n) => match type_mapping {
            Some(dt) if dt != "@id" && dt != "@vocab" => {
                let resolved_type = context.expand_iri(dt).unwrap_or_else(|| dt.to_string());
                Ok(json!({"@value": n, "@type": resolved_type}))
            }
            _ => Ok(json!({"@value": n})),
        },
        Value::Bool(b) => Ok(json!({"@value": b})),
        Value::Null => Ok(Value::Null),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_simple_vc() {
        let doc = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "urn:uuid:test",
            "type": ["VerifiableCredential"],
            "issuer": "https://example.com/issuer",
            "credentialSubject": {
                "id": "did:example:123"
            }
        });

        let expanded = expand_document(&doc).unwrap();
        let arr = expanded.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let node = &arr[0];
        assert_eq!(node.get("@id").unwrap(), "urn:uuid:test");
        assert!(node.get("@type").is_some());
    }

    // --- safe-mode expansion (issue #381) ------------------------------------

    /// Lenient expansion silently drops a term the context does not define — the
    /// behaviour that made the #381 soundness break possible. Pinned as a guard.
    #[test]
    fn lenient_mode_drops_unmapped_term() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "credentialSubject": { "id": "did:example:1", "memberLevel": "gold" }
        });
        let expanded = expand_document(&doc).unwrap();
        let s = expanded.to_string();
        assert!(
            !s.contains("memberLevel") && !s.contains("gold"),
            "lenient mode is expected to drop the undefined term"
        );
    }

    /// Safe mode must REJECT a top-level property the active context does not map.
    #[test]
    fn safe_mode_rejects_unmapped_property() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "forgedProperty": "x"
        });
        let err = expand_document_safe(&doc).unwrap_err();
        assert!(
            err.to_string().contains("forgedProperty"),
            "error should name the offending term: {err}"
        );
    }

    /// Safe mode must reject an undefined term NESTED under a mapped parent
    /// (`credentialSubject.memberLevel`) — the exact shape from issue #381.
    #[test]
    fn safe_mode_rejects_nested_unmapped_term() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "credentialSubject": { "id": "did:example:1", "memberLevel": "gold" }
        });
        let err = expand_document_safe(&doc).unwrap_err();
        assert!(
            err.to_string().contains("memberLevel"),
            "error should name the nested undefined term: {err}"
        );
    }

    /// Safe mode must ACCEPT a document whose terms are all defined — here via a
    /// catch-all `@vocab`. The same custom term that fails above now maps.
    #[test]
    fn safe_mode_accepts_fully_mapped_document() {
        let doc = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                { "@vocab": "https://example.com/vocab#" }
            ],
            "type": ["VerifiableCredential"],
            "credentialSubject": { "id": "did:example:1", "memberLevel": "gold" }
        });
        let expanded =
            expand_document_safe(&doc).expect("fully-mapped document must expand in safe mode");
        assert!(expanded.to_string().contains("memberLevel"));
    }

    /// Safe mode must not trip on the standard, fully-defined VC keywords/terms.
    #[test]
    fn safe_mode_accepts_standard_vc_terms() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": "urn:uuid:test",
            "type": ["VerifiableCredential"],
            "issuer": "https://example.com/issuer",
            "validFrom": "2023-01-01T00:00:00Z",
            "credentialSubject": { "id": "did:example:123" }
        });
        assert!(expand_document_safe(&doc).is_ok());
    }

    /// Safe mode must reject a node `@type` that does not resolve to an absolute
    /// IRI (no term definition, no `@vocab`) — it would otherwise be passed
    /// through as a relative IRI into the signed dataset.
    #[test]
    fn safe_mode_rejects_unmapped_type() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "credentialSubject": { "id": "did:example:1" }
        });
        let err = expand_document_safe(&doc).unwrap_err();
        assert!(
            err.to_string().contains("MembershipCredential"),
            "error should name the unresolved type: {err}"
        );
    }

    /// A custom type that DOES resolve (here via `@vocab`) is accepted.
    #[test]
    fn safe_mode_accepts_custom_type_via_vocab() {
        let doc = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                { "@vocab": "https://example.com/vocab#" }
            ],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "credentialSubject": { "id": "did:example:1" }
        });
        assert!(expand_document_safe(&doc).is_ok());
    }

    /// Safe mode must reject a free-standing scalar at the document root, which
    /// lenient expansion would silently drop.
    #[test]
    fn safe_mode_rejects_top_level_scalar() {
        let err = expand_document_safe(&json!("not-a-node")).unwrap_err();
        assert!(
            err.to_string().contains("scalar"),
            "error should flag the dropped scalar: {err}"
        );
    }

    /// Safe mode must reject a stray scalar mixed into a top-level node array.
    #[test]
    fn safe_mode_rejects_scalar_in_node_array() {
        let doc = json!([
            {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential"]
            },
            "stray-scalar"
        ]);
        let err = expand_document_safe(&doc).unwrap_err();
        assert!(
            err.to_string().contains("scalar"),
            "error should flag the dropped scalar: {err}"
        );
    }

    #[test]
    fn expand_typed_literal() {
        let doc = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "urn:uuid:test",
            "type": ["VerifiableCredential"],
            "issuer": "https://example.com/issuer",
            "validFrom": "2023-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:123"
            }
        });

        let expanded = expand_document(&doc).unwrap();
        let node = &expanded.as_array().unwrap()[0];
        let valid_from = node
            .get("https://www.w3.org/2018/credentials#validFrom")
            .unwrap();
        let val_obj = &valid_from.as_array().unwrap()[0];
        assert_eq!(val_obj.get("@value").unwrap(), "2023-01-01T00:00:00Z");
        assert_eq!(
            val_obj.get("@type").unwrap(),
            "http://www.w3.org/2001/XMLSchema#dateTime"
        );
    }
}
