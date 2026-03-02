use serde_json::Value;

use crate::error::{RdfError, Result};
use crate::model::*;

/// Convert expanded JSON-LD to an RDF Dataset.
pub fn to_rdf(expanded: &Value) -> Result<Dataset> {
    let mut dataset = Dataset::new();
    let mut blank_counter: u64 = 0;

    let arr = expanded
        .as_array()
        .ok_or_else(|| RdfError::to_rdf("expanded JSON-LD must be an array"))?;

    for node in arr {
        if let Some(obj) = node.as_object() {
            process_node(obj, &mut dataset, &mut blank_counter, &GraphLabel::Default)?;
        }
    }

    Ok(dataset)
}

fn process_node(
    node: &serde_json::Map<String, Value>,
    dataset: &mut Dataset,
    blank_counter: &mut u64,
    graph: &GraphLabel,
) -> Result<Subject> {
    // Determine subject
    let subject = if let Some(id_val) = node.get("@id") {
        let id = id_val
            .as_str()
            .ok_or_else(|| RdfError::to_rdf("@id must be a string"))?;
        if let Some(stripped) = id.strip_prefix("_:") {
            Subject::Blank(BlankNode::new(stripped))
        } else {
            Subject::Named(NamedNode::new(id))
        }
    } else {
        // Generate a blank node
        let id = format!("b{blank_counter}");
        *blank_counter += 1;
        Subject::Blank(BlankNode::new(id))
    };

    // Process @type
    if let Some(types) = node.get("@type")
        && let Some(type_arr) = types.as_array()
    {
        for type_val in type_arr {
            if let Some(type_iri) = type_val.as_str() {
                dataset.add(Quad::new(
                    subject.clone(),
                    NamedNode::new(rdf::TYPE),
                    Object::Named(NamedNode::new(type_iri)),
                    graph.clone(),
                ));
            }
        }
    }

    // Process properties
    for (key, value) in node {
        if key.starts_with('@') {
            continue; // Skip keywords (@id, @type already handled)
        }

        // key is an expanded IRI (predicate)
        let predicate = NamedNode::new(key.as_str());

        if let Some(arr) = value.as_array() {
            for item in arr {
                let object = value_to_object(item, dataset, blank_counter, graph)?;
                if let Some(obj) = object {
                    dataset.add(Quad::new(
                        subject.clone(),
                        predicate.clone(),
                        obj,
                        graph.clone(),
                    ));
                }
            }
        }
    }

    Ok(subject)
}

/// Convert a JSON-LD expanded value to an RDF object.
fn value_to_object(
    value: &Value,
    dataset: &mut Dataset,
    blank_counter: &mut u64,
    graph: &GraphLabel,
) -> Result<Option<Object>> {
    match value {
        Value::Object(obj) => {
            // Value object: has @value
            if let Some(val) = obj.get("@value") {
                let literal = value_object_to_literal(val, obj)?;
                Ok(Some(Object::Literal(literal)))
            }
            // List object: has @list
            else if let Some(list) = obj.get("@list") {
                let list_obj = list_to_rdf(list, dataset, blank_counter, graph)?;
                Ok(Some(list_obj))
            }
            // Node reference: has @id only
            else if obj.contains_key("@id") && obj.len() == 1 {
                let id = obj
                    .get("@id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| RdfError::to_rdf("@id must be a string"))?;
                if let Some(stripped) = id.strip_prefix("_:") {
                    Ok(Some(Object::Blank(BlankNode::new(stripped))))
                } else {
                    Ok(Some(Object::Named(NamedNode::new(id))))
                }
            }
            // Nested node — recurse
            else {
                let sub = process_node(obj, dataset, blank_counter, graph)?;
                match sub {
                    Subject::Named(n) => Ok(Some(Object::Named(n))),
                    Subject::Blank(b) => Ok(Some(Object::Blank(b))),
                }
            }
        }
        _ => Ok(None), // Shouldn't happen in expanded form
    }
}

/// Convert a @value object to an RDF Literal.
fn value_object_to_literal(val: &Value, obj: &serde_json::Map<String, Value>) -> Result<Literal> {
    let string_value = match val {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => val.to_string(),
    };

    // Check for language tag
    if let Some(lang) = obj.get("@language")
        && let Some(lang_str) = lang.as_str()
    {
        return Ok(Literal::lang(string_value, lang_str));
    }

    // Check for explicit datatype
    if let Some(type_val) = obj.get("@type")
        && let Some(type_str) = type_val.as_str()
    {
        return Ok(Literal::typed(string_value, NamedNode::new(type_str)));
    }

    // Determine default datatype from the value type
    match val {
        Value::Bool(_) => Ok(Literal::typed(string_value, NamedNode::new(xsd::BOOLEAN))),
        Value::Number(n) => {
            if n.is_f64() && n.to_string().contains('.') {
                Ok(Literal::typed(string_value, NamedNode::new(xsd::DOUBLE)))
            } else {
                Ok(Literal::typed(string_value, NamedNode::new(xsd::INTEGER)))
            }
        }
        _ => Ok(Literal::new(string_value)),
    }
}

/// Convert a @list to RDF using rdf:first/rdf:rest/rdf:nil.
fn list_to_rdf(
    list: &Value,
    dataset: &mut Dataset,
    blank_counter: &mut u64,
    graph: &GraphLabel,
) -> Result<Object> {
    let items = list
        .as_array()
        .ok_or_else(|| RdfError::to_rdf("@list must be an array"))?;

    if items.is_empty() {
        return Ok(Object::Named(NamedNode::new(rdf::NIL)));
    }

    // Build the list from end to start
    let mut current = Object::Named(NamedNode::new(rdf::NIL));

    for item in items.iter().rev() {
        let item_obj = value_to_object(item, dataset, blank_counter, graph)?
            .ok_or_else(|| RdfError::to_rdf("invalid list item"))?;

        let node_id = format!("b{blank_counter}");
        *blank_counter += 1;
        let node = BlankNode::new(&node_id);

        dataset.add(Quad::new(
            node.clone(),
            NamedNode::new(rdf::FIRST),
            item_obj,
            graph.clone(),
        ));
        dataset.add(Quad::new(
            node.clone(),
            NamedNode::new(rdf::REST),
            current,
            graph.clone(),
        ));

        current = Object::Blank(node);
    }

    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn simple_node_to_rdf() {
        let expanded = json!([{
            "@id": "http://example.org/s",
            "@type": ["http://example.org/Type"],
            "http://example.org/p": [{"@value": "hello"}]
        }]);

        let ds = to_rdf(&expanded).unwrap();
        assert_eq!(ds.quads().len(), 2); // type + property
    }

    #[test]
    fn blank_node_subject() {
        let expanded = json!([{
            "@type": ["http://example.org/Type"],
            "http://example.org/p": [{"@value": "hello"}]
        }]);

        let ds = to_rdf(&expanded).unwrap();
        // Should have a generated blank node as subject
        let q = &ds.quads()[0];
        assert!(matches!(&q.subject, Subject::Blank(_)));
    }

    #[test]
    fn typed_literal() {
        let expanded = json!([{
            "@id": "http://example.org/s",
            "http://example.org/date": [{
                "@value": "2023-01-01",
                "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
            }]
        }]);

        let ds = to_rdf(&expanded).unwrap();
        assert_eq!(ds.quads().len(), 1);
        match &ds.quads()[0].object {
            Object::Literal(lit) => {
                assert_eq!(lit.value, "2023-01-01");
                assert_eq!(lit.datatype.iri, xsd::DATE_TIME);
            }
            _ => panic!("expected literal"),
        }
    }

    #[test]
    fn node_reference() {
        let expanded = json!([{
            "@id": "http://example.org/s",
            "http://example.org/link": [{"@id": "http://example.org/target"}]
        }]);

        let ds = to_rdf(&expanded).unwrap();
        assert_eq!(ds.quads().len(), 1);
        assert_eq!(
            ds.quads()[0].object,
            Object::Named(NamedNode::new("http://example.org/target"))
        );
    }
}
