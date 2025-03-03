/*!
 * Affinidi Trust Development Kit
 *
 * Instantiate a TDK client with the `new` function
 */

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use reqwest::Client;
use std::sync::Arc;

pub mod did_authentication;

/// TDK instance that can be used to interact with Affinidi services
#[derive(Clone)]
pub struct TDK {
    pub(crate) inner: Arc<SharedState>,
}

/// Private SharedState struct for the TDK to use internally
pub(crate) struct SharedState {
    pub(crate) config: Config,
    pub(crate) did_resolver: DIDCacheClient,
    pub(crate) secrets_resolver: AffinidiSecrets,
    pub(crate) client: Client,
}
