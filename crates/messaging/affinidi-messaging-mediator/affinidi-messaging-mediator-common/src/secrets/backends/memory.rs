//! Process-local, in-memory backend.
//!
//! Used by tests and by the mediator-setup wizard's runner when it needs a
//! short-lived ephemeral store (e.g. the VTA connect sub-flow's temp session).
//! Never used by the mediator binary — bytes would disappear on restart.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::secrets::error::{Result, SecretStoreError};
use crate::secrets::store::SecretStore;

pub struct MemoryStore {
    label: &'static str,
    data: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryStore {
    pub fn new(label: &'static str) -> Self {
        Self {
            label,
            data: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl SecretStore for MemoryStore {
    fn backend(&self) -> &'static str {
        self.label
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let guard = self
            .data
            .lock()
            .map_err(|e| SecretStoreError::Other(format!("in-memory store poisoned: {e}")))?;
        Ok(guard.get(key).cloned())
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut guard = self
            .data
            .lock()
            .map_err(|e| SecretStoreError::Other(format!("in-memory store poisoned: {e}")))?;
        guard.insert(key.to_string(), value.to_vec());
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut guard = self
            .data
            .lock()
            .map_err(|e| SecretStoreError::Other(format!("in-memory store poisoned: {e}")))?;
        guard.remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn roundtrip_is_process_local() {
        let store = Arc::new(MemoryStore::new("memory"));
        assert!(store.get("nothing-here").await.unwrap().is_none());

        store.put("mediator/example", b"payload").await.unwrap();
        let got = store.get("mediator/example").await.unwrap();
        assert_eq!(got.as_deref(), Some(b"payload" as &[u8]));

        store.delete("mediator/example").await.unwrap();
        assert!(store.get("mediator/example").await.unwrap().is_none());
    }
}
