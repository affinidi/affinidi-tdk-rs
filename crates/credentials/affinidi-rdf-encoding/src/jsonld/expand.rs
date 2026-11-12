use serde_json::{Map, Value, json};

use super::context::{ContainerType, Context};
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
/// Identical to [`expand_document`] for the documents it accepts, except that
/// anything lenient expansion would silently drop or expand differently from
/// a conforming JSON-LD 1.1 processor raises an error instead:
///
/// - a property whose key does not map to an absolute IRI;
/// - a keyword used as a key, or a term aliased to a keyword, other than
///   `@context`, `@id` and `@type` (for example `@graph`, `@list`,
///   `@reverse`, `@included`, `@nest`, `@index`);
/// - an `@id` that is not a string, not a blank node identifier, not an
///   absolute IRI, or is a compact IRI;
/// - a nested object that expands to nothing;
/// - a value object with members other than `@value`, `@type` and
///   `@language`, or with a value, type or language this crate cannot convert;
/// - a term with an `@container` of `@list` or `@graph`;
/// - context features this crate does not implement (`@base`, `@language`,
///   `@import`, `@propagate`, `@direction`, map containers, `@reverse`,
///   `@nest`, `@index`, `@prefix`) and redefinitions of protected terms.
///
/// Safe mode also follows JSON-LD 1.1 for type-scoped contexts: they apply to
/// the node that carries the type and are not carried into nested nodes.
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
        process_context(&mut context, ctx_val, safe, false)?;
    }

    let result = expand_element(document, &context, safe)?;

    // Wrap in array if not already
    match result {
        Value::Array(_) => Ok(result),
        Value::Null => Ok(json!([])),
        _ => Ok(json!([result])),
    }
}

/// Process a `@context` value. Safe mode refuses features this crate does not
/// implement; `override_protected` is set for property-scoped contexts only.
fn process_context(
    context: &mut Context,
    value: &Value,
    safe: bool,
    override_protected: bool,
) -> Result<()> {
    if safe {
        context.process_strict(value, override_protected)
    } else {
        context.process(value)
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
        process_context(&mut context, ctx_val, safe, false)?;
    }

    // Check if this is a value object (@value present)
    if map.contains_key("@value") {
        return expand_value_object(map, &context, safe);
    }

    // Determine @type values and apply scoped contexts from type definitions.
    // JSON-LD 1.1 expands the types themselves, and nested node objects, with
    // the context as it was before the type-scoped contexts were applied.
    // Safe mode follows that; lenient mode keeps its historical behaviour of
    // using the type-scoped context throughout.
    let (context, pre_type_context) = match build_type_scoped_context(map, &context, safe)? {
        Some(scoped) => (scoped, Some(context)),
        None => (context, None),
    };
    let outer_context = match &pre_type_context {
        Some(pre_type) if safe => pre_type,
        _ => &context,
    };

    let mut result: Map<String, Value> = Map::new();

    for (key, value) in map {
        if key == "@context" {
            continue;
        }

        if key == "@id" || key == "id" {
            if let Some(id_def) = context.get_term(key) {
                if id_def.iri == "@id" {
                    expand_id(value, &context, safe, &mut result)?;
                    continue;
                }
            } else if key == "@id" {
                expand_id(value, &context, safe, &mut result)?;
                continue;
            }
        }

        if key == "@type" || key == "type" {
            if let Some(type_def) = context.get_term(key) {
                if type_def.iri == "@type" {
                    let expanded_types = expand_type_value(value, outer_context, safe)?;
                    result.insert("@type".to_string(), expanded_types);
                    continue;
                }
            } else if key == "@type" {
                let expanded_types = expand_type_value(value, outer_context, safe)?;
                result.insert("@type".to_string(), expanded_types);
                continue;
            }
        }

        // Expand the property key
        let expanded_key = match context.expand_iri(key) {
            Some(iri) if iri.starts_with('@') => {
                if safe {
                    return Err(RdfError::expansion(format!(
                        "safe mode: '{key}' ({iri}) is not supported here and would be dropped"
                    )));
                }
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

        if safe {
            let container = match term_def.and_then(|td| td.container.as_ref()) {
                Some(ContainerType::List) => Some("@list"),
                Some(ContainerType::Graph) => Some("@graph"),
                _ => None,
            };
            if let Some(container) = container {
                return Err(RdfError::expansion(format!(
                    "safe mode: term '{key}' has an {container} container, which is not supported"
                )));
            }
        }

        // Apply the scoped context from the term definition. Values (strings,
        // value objects) see the full active context; nested node objects see
        // the context from before any type-scoped context (safe mode).
        let scoped_ctx = term_def.and_then(|td| td.context.as_ref());
        let value_context = with_property_scope(&context, scoped_ctx, safe)?;
        let node_context = if safe && pre_type_context.is_some() {
            with_property_scope(outer_context, scoped_ctx, safe)?
        } else {
            value_context.clone()
        };

        // Expand the value
        let expanded_value =
            expand_property_value(value, type_mapping, &value_context, &node_context, safe)?;

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

/// Layer a property-scoped context, if any, over `context`.
fn with_property_scope(context: &Context, scoped: Option<&Value>, safe: bool) -> Result<Context> {
    let mut child = context.clone();
    if let Some(scoped) = scoped {
        process_context(&mut child, scoped, safe, true)?;
    }
    Ok(child)
}

/// Add a node's `@id` to `result`. Safe mode refuses an id this crate would
/// carry into the dataset differently from a conforming processor.
fn expand_id(
    value: &Value,
    context: &Context,
    safe: bool,
    result: &mut Map<String, Value>,
) -> Result<()> {
    match value.as_str() {
        Some(id) => {
            if safe {
                check_node_id(id, context)?;
            }
            result.insert("@id".to_string(), json!(id));
            Ok(())
        }
        None if safe => Err(RdfError::expansion(format!(
            "safe mode: @id {value} is not a string and would be dropped"
        ))),
        None => Ok(()),
    }
}

/// Safe mode accepts a node identifier only if it is a blank node identifier
/// or an absolute IRI. A relative IRI has no base to resolve against, and a
/// compact IRI whose prefix is a defined term would be expanded by a
/// conforming processor but is kept verbatim here.
fn check_node_id(id: &str, context: &Context) -> Result<()> {
    if let Some(label) = id.strip_prefix("_:") {
        if label.is_empty() {
            return Err(RdfError::expansion(
                "safe mode: blank node identifier '_:' has an empty label",
            ));
        }
        return Ok(());
    }
    if !has_iri_scheme(id) {
        return Err(RdfError::expansion(format!(
            "safe mode: @id '{id}' is not an absolute IRI"
        )));
    }
    if let Some((prefix, suffix)) = id.split_once(':')
        && !suffix.starts_with("//")
        && context.get_term(prefix).is_some()
    {
        return Err(RdfError::expansion(format!(
            "safe mode: @id '{id}' is a compact IRI, which is not supported"
        )));
    }
    Ok(())
}

/// True if `value` starts with an RFC 3986 scheme followed by `:`.
fn has_iri_scheme(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Build a context with scoped contexts from @type values applied.
fn build_type_scoped_context(
    map: &Map<String, Value>,
    context: &Context,
    safe: bool,
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
    let mut types: Vec<&str> = match type_value {
        Value::String(s) => vec![s.as_str()],
        Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
        _ => return Ok(None),
    };
    // JSON-LD 1.1 applies type-scoped contexts in lexicographic order of the
    // type values.
    if safe {
        types.sort_unstable();
    }

    // Apply scoped contexts from type term definitions
    let mut new_context = context.clone();
    let mut had_scoped = false;

    for type_name in &types {
        if let Some(term_def) = context.get_term(type_name)
            && let Some(ref scoped_ctx) = term_def.context
        {
            process_context(&mut new_context, scoped_ctx, safe, false)?;
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

/// Members a value object may carry in safe mode.
const VALUE_OBJECT_MEMBERS: &[&str] = &["@value", "@type", "@language"];

/// Expand a value object ({ "@value": ... }).
fn expand_value_object(map: &Map<String, Value>, context: &Context, safe: bool) -> Result<Value> {
    if safe {
        check_value_object(map, context)?;
    }

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

/// Safe mode accepts only value objects that convert to exactly one RDF
/// literal the way a conforming processor would.
fn check_value_object(map: &Map<String, Value>, context: &Context) -> Result<()> {
    if let Some(extra) = map
        .keys()
        .find(|key| !VALUE_OBJECT_MEMBERS.contains(&key.as_str()))
    {
        return Err(RdfError::expansion(format!(
            "safe mode: value object member '{extra}' is not supported and would be dropped"
        )));
    }

    let value = map.get("@value");
    let type_value = map.get("@type");
    let language = map.get("@language");

    if type_value.is_some() && language.is_some() {
        return Err(RdfError::expansion(
            "safe mode: a value object cannot have both @type and @language",
        ));
    }

    let is_json = match type_value {
        None => false,
        Some(Value::String(t)) if t == "@json" => true,
        Some(Value::String(t)) => {
            let datatype = context.expand_iri(t).unwrap_or_default();
            if datatype.starts_with('@') || !has_iri_scheme(&datatype) {
                return Err(RdfError::expansion(format!(
                    "safe mode: value object @type '{t}' does not expand to an absolute IRI"
                )));
            }
            false
        }
        Some(other) => {
            return Err(RdfError::expansion(format!(
                "safe mode: value object @type {other} is not a string"
            )));
        }
    };

    match language {
        None => {}
        Some(Value::String(_)) if value.is_some_and(Value::is_string) => {}
        Some(Value::String(_)) => {
            return Err(RdfError::expansion(
                "safe mode: a value object with @language must have a string @value",
            ));
        }
        Some(other) => {
            return Err(RdfError::expansion(format!(
                "safe mode: value object @language {other} is not a string"
            )));
        }
    }

    let is_scalar = value.is_some_and(|v| v.is_string() || v.is_number() || v.is_boolean());
    if !is_json && !is_scalar {
        return Err(RdfError::expansion(
            "safe mode: value object @value is not a string, number or boolean",
        ));
    }

    Ok(())
}

/// Expand a property value with type coercion.
///
/// `context` is used for values; `node_context` for nested node objects,
/// which in safe mode do not inherit the parent's type-scoped contexts.
fn expand_property_value(
    value: &Value,
    type_mapping: Option<&str>,
    context: &Context,
    node_context: &Context,
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
                let expanded =
                    expand_property_value(item, type_mapping, context, node_context, safe)?;
                match expanded {
                    Value::Null => {}
                    Value::Array(items) => result.extend(items),
                    _ => result.push(expanded),
                }
            }
            Ok(Value::Array(result))
        }
        Value::Object(map) => {
            // Recursively expand nested objects. Value objects and bare node
            // references keep the active context (JSON-LD 1.1 expansion,
            // step 7).
            let is_reference =
                map.len() == 1 && (map.contains_key("@id") || map.contains_key("id"));
            let object_context = if map.contains_key("@value") || is_reference {
                context
            } else {
                node_context
            };
            let expanded = expand_object(value, object_context, safe)?;
            if safe && expanded.is_null() {
                return Err(RdfError::expansion(
                    "safe mode: a nested object expands to nothing and would be dropped",
                ));
            }
            Ok(expanded)
        }
        Value::String(s) => {
            // Apply type coercion
            match type_mapping {
                Some(mapping @ ("@id" | "@vocab")) if safe => {
                    Ok(json!({"@id": expand_id_value(s, mapping, context)?}))
                }
                Some("@id") | Some("@vocab") => {
                    let expanded = context.expand_iri(s).unwrap_or_else(|| s.clone());
                    Ok(json!({"@id": expanded}))
                }
                Some(datatype) if datatype != "@json" => {
                    // Typed literal
                    let resolved_type = context
                        .expand_iri(datatype)
                        .unwrap_or_else(|| datatype.to_string());
                    if safe && (resolved_type.starts_with('@') || !has_iri_scheme(&resolved_type)) {
                        return Err(RdfError::expansion(format!(
                            "safe mode: datatype '{datatype}' does not expand to an absolute IRI"
                        )));
                    }
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
        Value::Bool(b) => match type_mapping {
            // JSON-LD applies a datatype coercion to booleans too.
            Some(dt) if safe && dt != "@id" && dt != "@vocab" => {
                let resolved_type = context.expand_iri(dt).unwrap_or_else(|| dt.to_string());
                Ok(json!({"@value": b, "@type": resolved_type}))
            }
            _ => Ok(json!({"@value": b})),
        },
        Value::Null => Ok(Value::Null),
    }
}

/// Expand a string under `@type: @id` or `@type: @vocab` coercion in safe
/// mode. Blank node identifiers are kept; anything else must expand to an
/// absolute IRI. Under `@id` a value without a scheme is a relative IRI,
/// which has no base to resolve against here, so it is refused rather than
/// resolved as a term or against `@vocab`.
fn expand_id_value(value: &str, mapping: &str, context: &Context) -> Result<String> {
    if value.starts_with("_:") {
        check_node_id(value, context)?;
        return Ok(value.to_string());
    }
    if mapping == "@id" && !has_iri_scheme(value) {
        return Err(RdfError::expansion(format!(
            "safe mode: '{value}' is a relative IRI, which is not supported"
        )));
    }
    match context.expand_iri(value) {
        Some(iri) if !iri.starts_with('@') && has_iri_scheme(&iri) => Ok(iri),
        _ => Err(RdfError::expansion(format!(
            "safe mode: '{value}' does not expand to an absolute IRI"
        ))),
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

    fn safe_error(doc: &Value) -> String {
        expand_document_safe(doc)
            .expect_err("safe mode should refuse this document")
            .to_string()
    }

    /// `@graph` holds named-graph content; lenient expansion skips it with
    /// everything under it, safe mode refuses it.
    #[test]
    fn safe_mode_rejects_graph_keyword() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "@graph": [{ "id": "did:example:1", "name": "inside" }]
        });
        assert!(
            !expand_document(&doc)
                .unwrap()
                .to_string()
                .contains("inside")
        );
        assert!(safe_error(&doc).contains("@graph"));
    }

    #[test]
    fn safe_mode_rejects_term_aliased_to_keyword() {
        let doc = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                { "extras": "@included" }
            ],
            "type": ["VerifiableCredential"],
            "extras": [{ "id": "did:example:2" }]
        });
        assert!(safe_error(&doc).contains("extras"));
    }

    #[test]
    fn safe_mode_rejects_non_string_id() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "credentialSubject": { "id": 42, "name": "x" }
        });
        assert!(safe_error(&doc).contains("not a string"));
    }

    #[test]
    fn safe_mode_rejects_relative_id() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "credentialSubject": { "id": "subject-1", "name": "x" }
        });
        assert!(safe_error(&doc).contains("absolute IRI"));
    }

    #[test]
    fn safe_mode_accepts_blank_node_id() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "credentialSubject": { "id": "_:subject", "name": "x" }
        });
        assert!(expand_document_safe(&doc).is_ok());
    }

    #[test]
    fn safe_mode_rejects_relative_iri_under_id_coercion() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "issuer-1"
        });
        assert!(safe_error(&doc).contains("relative IRI"));
    }

    /// A nested object that expands to nothing would drop the statement that
    /// links it to its parent.
    #[test]
    fn safe_mode_rejects_empty_nested_object() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "credentialSubject": {}
        });
        assert!(expand_document(&doc).is_ok());
        assert!(safe_error(&doc).contains("expands to nothing"));
    }

    #[test]
    fn safe_mode_rejects_value_object_extra_member() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "name": { "@value": "x", "@direction": "rtl" }
        });
        assert!(safe_error(&doc).contains("@direction"));
    }

    #[test]
    fn safe_mode_rejects_value_object_non_string_type() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "name": { "@value": "x", "@type": 7 }
        });
        assert!(safe_error(&doc).contains("@type"));
    }

    #[test]
    fn safe_mode_rejects_value_object_with_object_value() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "name": { "@value": { "nested": true } }
        });
        assert!(safe_error(&doc).contains("@value"));
    }

    #[test]
    fn safe_mode_accepts_language_value_object() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "name": { "@value": "x", "@language": "en" }
        });
        assert!(expand_document_safe(&doc).is_ok());
    }

    /// `verifiableCredential` is a `@graph` container in the VC v2 context.
    /// Expansion here does not build named graphs, so safe mode refuses it.
    #[test]
    fn safe_mode_rejects_graph_container() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential"],
                "credentialSubject": { "id": "did:example:1" }
            }]
        });
        assert!(safe_error(&doc).contains("@graph"));
    }

    #[test]
    fn safe_mode_rejects_list_container() {
        let doc = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                { "steps": { "@id": "https://example.com/steps", "@container": "@list" } }
            ],
            "type": ["VerifiableCredential"],
            "steps": ["one", "two"]
        });
        assert!(safe_error(&doc).contains("@list"));
    }

    #[test]
    fn safe_mode_rejects_unsupported_context_keyword() {
        let doc = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                { "@language": "en" }
            ],
            "type": ["VerifiableCredential"]
        });
        assert!(safe_error(&doc).contains("@language"));
    }

    #[test]
    fn safe_mode_rejects_map_container() {
        let doc = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                { "label": { "@id": "https://example.com/label", "@container": "@language" } }
            ],
            "type": ["VerifiableCredential"]
        });
        assert!(safe_error(&doc).contains("@container"));
    }

    /// The VC v2 context protects `name`; JSON-LD 1.1 forbids a later context
    /// from giving it another meaning.
    #[test]
    fn safe_mode_rejects_protected_term_redefinition() {
        let doc = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                { "name": "https://example.com/name" }
            ],
            "type": ["VerifiableCredential"],
            "name": "x"
        });
        assert!(expand_document(&doc).is_ok());
        assert!(safe_error(&doc).contains("protected term 'name'"));
    }

    #[test]
    fn safe_mode_accepts_identical_protected_redefinition() {
        let doc = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/v2"
            ],
            "type": ["VerifiableCredential"],
            "name": "x"
        });
        assert!(expand_document_safe(&doc).is_ok());
    }

    #[test]
    fn safe_mode_rejects_null_context_over_protected_terms() {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "credentialSubject": {
                "@context": null,
                "@id": "did:example:1"
            }
        });
        assert!(safe_error(&doc).contains("protected"));
    }

    /// Type-scoped contexts apply to the typed node only. A nested node sees
    /// the context from before the type was applied, so `inner` falls back to
    /// `@vocab` there.
    #[test]
    fn safe_mode_does_not_carry_type_scoped_context_into_nested_nodes() {
        let doc = json!({
            "@context": {
                "@vocab": "https://example.com/vocab#",
                "Parent": {
                    "@id": "https://example.com/Parent",
                    "@context": {
                        "child": "https://example.com/scoped#child",
                        "inner": "https://example.com/scoped#inner"
                    }
                }
            },
            "@id": "https://example.com/p",
            "@type": "Parent",
            "child": { "inner": "x" }
        });

        let safe = expand_document_safe(&doc).unwrap().to_string();
        assert!(safe.contains("https://example.com/scoped#child"));
        assert!(safe.contains("https://example.com/vocab#inner"));
        assert!(!safe.contains("https://example.com/scoped#inner"));

        let lenient = expand_document(&doc).unwrap().to_string();
        assert!(lenient.contains("https://example.com/scoped#inner"));
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
