/*!
 * This module is a simple example of a DID resolver that uses a cache to store DID documents.
 *
 * Should only be used for local testing and development
 *
 * Enable using the did_example feature flag
 */

use ahash::AHashMap as HashMap;
use ssi::dids::document::Document;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DidExampleError {
    #[error("Error parsing DID document: {0}")]
    DocumentParseError(String),
}

#[derive(Clone, Default)]
pub struct DiDExampleCache {
    cache: HashMap<String, Document>,
}

impl DiDExampleCache {
    fn from_string(document: String) -> Result<(String, Document), DidExampleError> {
        let doc = Document::from_json(&document)
            .map_err(|e| {
                DidExampleError::DocumentParseError(format!(
                    "Couldn't parse Document String: {}",
                    e
                ))
            })?
            .into_document();

        Ok((doc.id.to_string(), doc))
    }

    /// Create a new instance of the cache
    pub fn new() -> Self {
        DiDExampleCache {
            cache: HashMap::new(),
        }
    }

    /// Insert a DID document into the cache
    /// `document`: A string representation of a DID document
    pub fn insert_from_string(&mut self, document: &str) -> Result<(), DidExampleError> {
        let (id, doc) = DiDExampleCache::from_string(document.to_string())?;
        self.cache.insert(id, doc);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&Document> {
        self.cache.get(id)
    }
}
