use serde_json::{Map, Value, json};

use crate::error::{RdfError, Result};
use super::context::Context;

/// Expand a JSON-LD document to its expanded form.
///
/// The expanded form has all terms replaced with full IRIs, all context
/// processing resolved, and all values in a normalized array/object structure.
pub fn expand_document(document: &Value) -> Result<Value> {
    let mut context = Context::default();

    // Process top-level @context
    if let Some(ctx_val) = document.get("@context") {
        context.process(ctx_val)?;
    }

    let result = expand_element(document, &context)?;

    // Wrap in array if not already
    match result {
        Value::Array(_) => Ok(result),
        Value::Null => Ok(json!([])),
        _ => Ok(json!([result])),
    }
}

/// Expand a single JSON-LD element (object, array, or value).
fn expand_element(element: &Value, context: &Context) -> Result<Value> {
    match element {
        Value::Array(arr) => {
            let mut result = Vec::new();
            for item in arr {
                let expanded = expand_element(item, context)?;
                match expanded {
                    Value::Array(inner) => result.extend(inner),
                    Value::Null => {} // skip nulls
                    _ => result.push(expanded),
                }
            }
            Ok(Value::Array(result))
        }
        Value::Object(_) => expand_object(element, context),
        _ => {
            // Scalars at the top level are dropped per JSON-LD spec
            Ok(Value::Null)
        }
    }
}

/// Expand a JSON-LD object node.
fn expand_object(obj: &Value, parent_context: &Context) -> Result<Value> {
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
                    let expanded_types = expand_type_value(value, &context)?;
                    result.insert("@type".to_string(), expanded_types);
                    continue;
                }
            } else if key == "@type" {
                let expanded_types = expand_type_value(value, &context)?;
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
            _ => continue, // Drop unmapped terms
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
        let expanded_value = expand_property_value(value, type_mapping, &prop_context)?;

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
        map.get("type").filter(|_| {
            context
                .get_term("type")
                .is_some_and(|td| td.iri == "@type")
        })
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
fn expand_type_value(value: &Value, context: &Context) -> Result<Value> {
    match value {
        Value::String(s) => {
            let expanded = expand_type_iri(s, context);
            Ok(json!([expanded]))
        }
        Value::Array(arr) => {
            let expanded: Vec<Value> = arr
                .iter()
                .filter_map(|v| v.as_str())
                .map(|s| json!(expand_type_iri(s, context)))
                .collect();
            Ok(Value::Array(expanded))
        }
        _ => Err(RdfError::expansion(format!("invalid @type value: {value}"))),
    }
}

/// Expand a type name to a full IRI.
fn expand_type_iri(type_name: &str, context: &Context) -> String {
    // If already an absolute IRI, return as-is
    if type_name.contains("://") || type_name.starts_with("urn:") {
        return type_name.to_string();
    }

    // Look up in context — for types, we want the @id value
    if let Some(def) = context.get_term(type_name)
        && (def.iri.contains("://") || def.iri.starts_with("urn:"))
    {
        return def.iri.clone();
    }

    // Try vocab expansion
    if let Some(ref vocab) = context.vocab {
        return format!("{vocab}{type_name}");
    }

    type_name.to_string()
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
) -> Result<Value> {
    match value {
        Value::Array(arr) => {
            let mut result = Vec::new();
            for item in arr {
                let expanded = expand_property_value(item, type_mapping, context)?;
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
            expand_object(value, context)
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
        Value::Number(n) => Ok(json!({"@value": n})),
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
