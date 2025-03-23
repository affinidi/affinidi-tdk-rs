/*!
DID Universal Resolver Cache Client SDK

Used to easily connect to the DID Universal Resolver Cache.

# Crate features
As this crate can be used either natively or in a WASM environment, the following features are available:
* **local**
    **default** - Enables the local mode of the SDK. This is the default mode.
* **network**
    * Enables the network mode of the SDK. This mode requires a run-time service address to connect to.
    * This feature is NOT supported in a WASM environment. Will cause a compile error if used in WASM.
*/

#[cfg(all(feature = "network", target_arch = "wasm32"))]
compile_error!("Cannot enable both features at the same time");

use config::DIDCacheConfig;
use errors::DIDCacheError;
use highway::{HighwayHash, HighwayHasher};
use moka::future::Cache;
#[cfg(feature = "network")]
use networking::{
    WSRequest,
    network::{NetworkTask, WSCommands},
};
use ssi::dids::Document;
#[cfg(feature = "network")]
use std::sync::Arc;
use std::{fmt, time::Duration};
#[cfg(feature = "network")]
use tokio::sync::{Mutex, mpsc};
use tracing::debug;
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::*;

pub mod config;
pub mod document;
pub mod errors;
#[cfg(feature = "network")]
pub mod networking;
mod resolver;

/// DID Methods supported by the DID Universal Resolver Cache
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[wasm_bindgen]
pub enum DIDMethod {
    ETHR,
    JWK,
    KEY,
    PEER,
    PKH,
    WEB,
    EXAMPLE,
}

/// Helper function to convert a DIDMethod to a string
impl fmt::Display for DIDMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DIDMethod::ETHR => write!(f, "ethr"),
            DIDMethod::JWK => write!(f, "jwk"),
            DIDMethod::KEY => write!(f, "key"),
            DIDMethod::PEER => write!(f, "peer"),
            DIDMethod::PKH => write!(f, "pkh"),
            DIDMethod::WEB => write!(f, "web"),
            DIDMethod::EXAMPLE => write!(f, "example"),
        }
    }
}

/// Helper function to convert a string to a DIDMethod
impl TryFrom<String> for DIDMethod {
    type Error = DIDCacheError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&str> for DIDMethod {
    type Error = DIDCacheError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "ethr" => Ok(DIDMethod::ETHR),
            "jwk" => Ok(DIDMethod::JWK),
            "key" => Ok(DIDMethod::KEY),
            "peer" => Ok(DIDMethod::PEER),
            "pkh" => Ok(DIDMethod::PKH),
            "web" => Ok(DIDMethod::WEB),
            #[cfg(feature = "did_example")]
            "example" => Ok(DIDMethod::EXAMPLE),
            _ => Err(DIDCacheError::UnsupportedMethod(value.to_string())),
        }
    }
}

pub struct ResolveResponse {
    pub did: String,
    pub method: DIDMethod,
    pub did_hash: [u64; 2],
    pub doc: Document,
    pub cache_hit: bool,
}

// ***************************************************************************

/// [DIDCacheClient] is how you interact with the DID Universal Resolver Cache
/// config: Configuration for the SDK
/// cache: Local cache for resolved DIDs
/// network_task: OPTIONAL: Task to handle network requests
/// network_rx: OPTIONAL: Channel to listen for responses from the network task
#[wasm_bindgen(getter_with_clone)]
#[derive(Clone)]
pub struct DIDCacheClient {
    config: DIDCacheConfig,
    cache: Cache<[u64; 2], Document>,
    #[cfg(feature = "network")]
    network_task_tx: Option<mpsc::Sender<WSCommands>>,
    #[cfg(feature = "network")]
    network_task_rx: Option<Arc<Mutex<mpsc::Receiver<WSCommands>>>>,
    #[cfg(feature = "did_example")]
    did_example_cache: did_example::DiDExampleCache,
}

impl DIDCacheClient {
    /// Front end for resolving a DID
    /// Will check the cache first, and if not found, will resolve the DID
    /// Returns the initial DID, the hashed DID, and the resolved DID Document
    /// NOTE: The DID Document id may be different to the requested DID due to the DID having been updated.
    ///       The original DID should be in the `also_known_as` field of the DID Document.
    pub async fn resolve(&self, did: &str) -> Result<ResolveResponse, DIDCacheError> {
        // If DID's size is greater than 1KB we don't resolve it
        if did.len() > self.config.max_did_size_in_bytes {
            return Err(DIDCacheError::DIDError(format!(
                "The DID size of {}bytes exceeds the limit of {1}. Please ensure the size is less than {1}.",
                did.len(),
                self.config.max_did_size_in_bytes
            )));
        }

        let parts: Vec<&str> = did.split(':').collect();
        if parts.len() < 3 {
            return Err(DIDCacheError::DIDError(format!(
                "did isn't to spec! did ({})",
                did
            )));
        }

        let key_parts: Vec<&str> = parts.last().unwrap().split(".").collect();
        if key_parts.len() > self.config.max_did_parts {
            return Err(DIDCacheError::DIDError(format!(
                "The total number of keys and/or services must be less than or equal to {:?}, but {:?} were found.",
                self.config.max_did_parts,
                parts.len()
            )));
        }

        let hash = DIDCacheClient::hash_did(did);

        #[cfg(feature = "did_example")]
        // Short-circuit for example DIDs
        if parts[1] == "example" {
            if let Some(doc) = self.did_example_cache.get(did) {
                return Ok(ResolveResponse {
                    did: did.to_string(),
                    method: parts[1].try_into()?,
                    did_hash: hash,
                    doc: doc.clone(),
                    cache_hit: true,
                });
            }
        }

        // Check if the DID is in the cache
        if let Some(doc) = self.cache.get(&hash).await {
            debug!("found did ({}) in cache", did);
            Ok(ResolveResponse {
                did: did.to_string(),
                method: parts[1].try_into()?,
                did_hash: hash,
                doc,
                cache_hit: true,
            })
        } else {
            debug!("did ({}) NOT in cache hash ({:#?})", did, hash);
            // If the DID is not in the cache, resolve it (local or via network)
            #[cfg(feature = "network")]
            let doc = {
                if self.config.service_address.is_some() {
                    self.network_resolve(did, hash).await?
                } else {
                    self.local_resolve(did, &parts).await?
                }
            };

            #[cfg(not(feature = "network"))]
            let doc = self.local_resolve(did, &parts).await?;

            debug!("adding did ({}) to cache ({:#?})", did, hash);
            self.cache.insert(hash, doc.clone()).await;
            Ok(ResolveResponse {
                did: did.to_string(),
                method: parts[1].try_into()?,
                did_hash: hash,
                doc,
                cache_hit: false,
            })
        }
    }

    /// If you want to interact directly with the DID Document cache
    /// This will return a clone of the cache (the clone is cheap, and the cache is shared)
    /// For example, accessing cache statistics or manually inserting a DID Document
    pub fn get_cache(&self) -> Cache<[u64; 2], Document> {
        self.cache.clone()
    }

    /// Stops the network task if it is running and removes any resources
    #[cfg(feature = "network")]
    pub fn stop(&self) {
        if let Some(tx) = self.network_task_tx.as_ref() {
            let _ = tx.blocking_send(WSCommands::Exit);
        }
    }

    /// Removes the specified DID from the cache
    /// Returns the removed DID Document if it was in the cache, or None if it was not
    pub async fn remove(&self, did: &str) -> Option<Document> {
        self.cache.remove(&DIDCacheClient::hash_did(did)).await
    }

    /// Add a DID Document to the cache manually
    pub async fn add_did_document(&mut self, did: &str, doc: Document) {
        let hash = DIDCacheClient::hash_did(did);
        debug!("manually adding did ({}) hash({:#?}) to cache", did, hash);
        self.cache.insert(hash, doc).await;
    }

    /// Convenience function to hash a DID
    pub fn hash_did(did: &str) -> [u64; 2] {
        // Use a consistent Seed so it always hashes to the same value
        HighwayHasher::default().hash128(did.as_bytes())
    }
}

/// Following are the WASM bindings for the DIDCacheClient
#[wasm_bindgen]
impl DIDCacheClient {
    /// Create a new DIDCacheClient with configuration generated from [ClientConfigBuilder](config::ClientConfigBuilder)
    ///
    /// Will return an error if the configuration is invalid.
    ///
    /// Establishes websocket connection and sets up the cache.
    // using Self instead of DIDCacheClient leads to E0401 errors in dependent crates
    // this is due to wasm_bindgen generated code (check via `cargo expand`)
    pub async fn new(config: DIDCacheConfig) -> Result<DIDCacheClient, DIDCacheError> {
        // Create the initial cache
        let cache = Cache::builder()
            .max_capacity(config.cache_capacity.into())
            .time_to_live(Duration::from_secs(config.cache_ttl.into()))
            .build();

        #[cfg(feature = "network")]
        let mut client = Self {
            config,
            cache,
            network_task_tx: None,
            network_task_rx: None,
            #[cfg(feature = "did_example")]
            did_example_cache: did_example::DiDExampleCache::new(),
        };
        #[cfg(not(feature = "network"))]
        let client = Self {
            config,
            cache,
            #[cfg(feature = "did_example")]
            did_example_cache: did_example::DiDExampleCache::new(),
        };

        #[cfg(feature = "network")]
        {
            if client.config.service_address.is_some() {
                // Running in network mode

                // Channel to communicate from SDK to network task
                let (sdk_tx, mut task_rx) = mpsc::channel(32);
                // Channel to communicate from network task to SDK
                let (task_tx, sdk_rx) = mpsc::channel(32);

                client.network_task_tx = Some(sdk_tx);
                client.network_task_rx = Some(Arc::new(Mutex::new(sdk_rx)));

                // Start the network task
                let _config = client.config.clone();
                tokio::spawn(async move {
                    let _ = NetworkTask::run(_config, &mut task_rx, &task_tx).await;
                });

                if let Some(arc_rx) = client.network_task_rx.as_ref() {
                    // Wait for the network task to be ready
                    let mut rx = arc_rx.lock().await;
                    rx.recv().await.unwrap();
                }
            }
        }

        Ok(client)
    }

    pub async fn wasm_resolve(&self, did: &str) -> Result<JsValue, DIDCacheError> {
        let response = self.resolve(did).await?;

        match serde_wasm_bindgen::to_value(&response.doc) {
            Ok(values) => Ok(values),
            Err(err) => Err(DIDCacheError::DIDError(format!(
                "Error serializing DID Document: {}",
                err
            ))),
        }
    }

    #[cfg(feature = "did_example")]
    pub fn add_example_did(&mut self, doc: &str) -> Result<(), DIDCacheError> {
        self.did_example_cache
            .insert_from_string(doc)
            .map_err(|e| DIDCacheError::DIDError(format!("Couldn't parse example DID: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID_KEY: &str = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";

    async fn basic_local_client() -> DIDCacheClient {
        let config = config::DIDCacheConfigBuilder::default().build();
        DIDCacheClient::new(config).await.unwrap()
    }

    #[tokio::test]
    async fn remove_existing_cached_did() {
        let client = basic_local_client().await;

        // Resolve a DID which automatically adds it to the cache
        let response = client.resolve(DID_KEY).await.unwrap();
        let removed_doc = client.remove(DID_KEY).await;
        assert_eq!(removed_doc, Some(response.doc));
    }

    #[tokio::test]
    async fn remove_non_existing_cached_did() {
        let client = basic_local_client().await;

        // We haven't resolved the cache, so it shouldn't be in the cache
        let removed_doc = client.remove(DID_KEY).await;
        assert_eq!(removed_doc, None);
    }
}
