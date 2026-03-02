use std::collections::HashMap;

use serde_json::Value;

use super::bundled::get_bundled_context;
use crate::error::{RdfError, Result};

/// A processed JSON-LD context that maps terms to IRIs and type/container info.
#[derive(Clone, Debug, Default)]
pub struct Context {
    pub terms: HashMap<String, TermDefinition>,
    pub vocab: Option<String>,
    pub base: Option<String>,
    pub default_language: Option<String>,
}

/// A single term definition within a JSON-LD context.
#[derive(Clone, Debug)]
pub struct TermDefinition {
    pub iri: String,
    pub type_mapping: Option<String>,
    pub container: Option<ContainerType>,
    pub context: Option<Value>,
    pub protected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContainerType {
    Set,
    List,
    Graph,
}

impl Context {
    /// Process a `@context` value (string URL, object, or array) and merge into this context.
    pub fn process(&mut self, context_value: &Value) -> Result<()> {
        match context_value {
            Value::Array(arr) => {
                for item in arr {
                    self.process(item)?;
                }
            }
            Value::String(url) => {
                self.process_remote(url)?;
            }
            Value::Object(_) => {
                self.process_context_object(context_value)?;
            }
            Value::Null => {
                // Reset context
                self.terms.clear();
                self.vocab = None;
                self.base = None;
                self.default_language = None;
            }
            _ => {
                return Err(RdfError::context(format!(
                    "invalid @context value: {context_value}"
                )));
            }
        }
        Ok(())
    }

    fn process_remote(&mut self, url: &str) -> Result<()> {
        let context_doc = get_bundled_context(url).ok_or_else(|| {
            RdfError::context(format!("unknown context URL (no bundled context): {url}"))
        })?;
        // The bundled doc has {"@context": ...}, extract the inner value
        let inner = context_doc.get("@context").ok_or_else(|| {
            RdfError::context(format!("context document missing @context key: {url}"))
        })?;
        self.process_context_object(inner)
    }

    fn process_context_object(&mut self, ctx: &Value) -> Result<()> {
        let obj = ctx
            .as_object()
            .ok_or_else(|| RdfError::context("@context value is not an object"))?;

        // Process @vocab
        if let Some(vocab) = obj.get("@vocab") {
            self.vocab = vocab.as_str().map(|s| s.to_string());
        }

        // Process @base
        if let Some(base) = obj.get("@base") {
            self.base = base.as_str().map(|s| s.to_string());
        }

        // Process @language
        if let Some(lang) = obj.get("@language") {
            self.default_language = lang.as_str().map(|s| s.to_string());
        }

        let is_protected = obj
            .get("@protected")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Process term definitions
        for (key, value) in obj {
            if key.starts_with('@') {
                continue; // Skip keywords
            }
            let term_def = create_term_definition(key, value, is_protected, self)?;
            self.terms.insert(key.clone(), term_def);
        }

        Ok(())
    }

    /// Expand a term or compact IRI to a full IRI using this context.
    pub fn expand_iri(&self, value: &str) -> Option<String> {
        // Already an absolute IRI
        if is_absolute_iri(value) {
            return Some(value.to_string());
        }

        // JSON-LD keywords
        if value.starts_with('@') {
            return Some(value.to_string());
        }

        // Look up as a term
        if let Some(def) = self.terms.get(value) {
            return Some(def.iri.clone());
        }

        // Try compact IRI (prefix:suffix)
        if let Some(colon_pos) = value.find(':') {
            let prefix = &value[..colon_pos];
            let suffix = &value[colon_pos + 1..];
            if let Some(def) = self.terms.get(prefix) {
                return Some(format!("{}{suffix}", def.iri));
            }
            // If it has a colon but prefix isn't in context, it may be an
            // unknown IRI scheme — return as-is rather than vocab-expanding.
            if !prefix.is_empty()
                && prefix
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
            {
                return Some(value.to_string());
            }
        }

        // Use vocab mapping
        if let Some(ref vocab) = self.vocab {
            return Some(format!("{vocab}{value}"));
        }

        None
    }

    /// Get the term definition for a given term name.
    pub fn get_term(&self, term: &str) -> Option<&TermDefinition> {
        self.terms.get(term)
    }

    /// Create a child context by processing a scoped @context from a term definition,
    /// layered on top of the current context.
    pub fn with_scoped_context(&self, scoped_context: &Value) -> Result<Context> {
        let mut child = self.clone();
        child.process(scoped_context)?;
        Ok(child)
    }
}

fn create_term_definition(
    term: &str,
    value: &Value,
    parent_protected: bool,
    ctx: &Context,
) -> Result<TermDefinition> {
    match value {
        Value::String(iri_or_term) => {
            // Simple mapping: "term": "iri" or "term": "otherTerm"
            let resolved = resolve_iri(iri_or_term, ctx);
            Ok(TermDefinition {
                iri: resolved,
                type_mapping: None,
                container: None,
                context: None,
                protected: parent_protected,
            })
        }
        Value::Object(obj) => {
            // Expanded term definition
            let id = obj.get("@id").and_then(|v| v.as_str()).unwrap_or(term);

            let resolved_iri = resolve_iri(id, ctx);

            let type_mapping = obj.get("@type").and_then(|v| v.as_str()).map(|t| {
                if t.starts_with('@') {
                    t.to_string()
                } else {
                    resolve_iri(t, ctx)
                }
            });

            let container = obj.get("@container").and_then(|v| match v.as_str() {
                Some("@set") => Some(ContainerType::Set),
                Some("@list") => Some(ContainerType::List),
                Some("@graph") => Some(ContainerType::Graph),
                _ => None,
            });

            let scoped_context = obj.get("@context").cloned();

            let protected = obj
                .get("@protected")
                .and_then(|v| v.as_bool())
                .unwrap_or(parent_protected);

            Ok(TermDefinition {
                iri: resolved_iri,
                type_mapping,
                container,
                context: scoped_context,
                protected,
            })
        }
        Value::Null => {
            // Explicitly null definition — term is unmapped
            Ok(TermDefinition {
                iri: String::new(),
                type_mapping: None,
                container: None,
                context: None,
                protected: false,
            })
        }
        _ => Err(RdfError::context(format!(
            "invalid term definition for '{term}': {value}"
        ))),
    }
}

/// Resolve an IRI or term reference against the context.
fn resolve_iri(value: &str, ctx: &Context) -> String {
    // Already absolute
    if is_absolute_iri(value) {
        return value.to_string();
    }

    // JSON-LD keyword
    if value.starts_with('@') {
        return value.to_string();
    }

    // Look up as existing term
    if let Some(def) = ctx.terms.get(value) {
        return def.iri.clone();
    }

    // Try compact IRI
    if let Some(colon_pos) = value.find(':') {
        let prefix = &value[..colon_pos];
        let suffix = &value[colon_pos + 1..];
        if let Some(def) = ctx.terms.get(prefix) {
            return format!("{}{suffix}", def.iri);
        }
        // Unknown scheme — treat as absolute IRI
        if !prefix.is_empty()
            && prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
        {
            return value.to_string();
        }
    }

    // Use vocab
    if let Some(ref vocab) = ctx.vocab {
        return format!("{vocab}{value}");
    }

    value.to_string()
}

/// Check if a string looks like an absolute IRI (has a scheme).
fn is_absolute_iri(value: &str) -> bool {
    if let Some(colon_pos) = value.find(':') {
        let scheme = &value[..colon_pos];
        // A scheme starts with a letter and contains only letters, digits, +, -, .
        if !scheme.is_empty()
            && scheme.chars().next().unwrap().is_ascii_alphabetic()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
        {
            // Check for known IRI schemes or "://"
            if value[colon_pos..].starts_with("://") {
                return true;
            }
            // urn:, did:, etc.
            return matches!(
                scheme,
                "urn" | "did" | "tel" | "mailto" | "data" | "blob" | "cid" | "mid" | "tag"
            );
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_credentials_v2() {
        let mut ctx = Context::default();
        ctx.process(&Value::String(
            "https://www.w3.org/ns/credentials/v2".to_string(),
        ))
        .unwrap();

        // "id" should map to @id
        assert_eq!(ctx.expand_iri("id"), Some("@id".to_string()));
        // "type" should map to @type
        assert_eq!(ctx.expand_iri("type"), Some("@type".to_string()));
        // "name" should expand
        assert_eq!(
            ctx.expand_iri("name"),
            Some("https://schema.org/name".to_string())
        );
    }

    #[test]
    fn process_examples_v2() {
        let mut ctx = Context::default();
        ctx.process(&Value::String(
            "https://www.w3.org/ns/credentials/examples/v2".to_string(),
        ))
        .unwrap();

        // @vocab should be set
        assert_eq!(
            ctx.vocab,
            Some("https://www.w3.org/ns/credentials/examples#".to_string())
        );
        // Unknown terms should use vocab
        assert_eq!(
            ctx.expand_iri("alumniOf"),
            Some("https://www.w3.org/ns/credentials/examples#alumniOf".to_string())
        );
    }

    #[test]
    fn expand_absolute_iri() {
        let ctx = Context::default();
        assert_eq!(
            ctx.expand_iri("http://example.org/foo"),
            Some("http://example.org/foo".to_string())
        );
    }

    #[test]
    fn scoped_context() {
        let mut ctx = Context::default();
        ctx.process(&Value::String(
            "https://www.w3.org/ns/credentials/v2".to_string(),
        ))
        .unwrap();

        // "VerifiableCredential" has a scoped context
        let vc_def = ctx.get_term("VerifiableCredential").unwrap();
        assert!(vc_def.context.is_some());
    }
}
