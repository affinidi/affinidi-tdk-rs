use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use reqwest::Client;
use std::{future::Future, pin::Pin, sync::Arc};

use crate::{AuthorizationTokens, errors::Result};

/// Boxed future type for async trait methods
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Trait for custom authentication logic
pub trait CustomAuthHandler: Send + Sync {
    /// Perform custom authentication
    /// 
    /// # Arguments
    /// * `profile_did` - The DID of the profile to authenticate
    /// * `endpoint_did` - The DID of the service endpoint to authenticate against
    /// * `did_resolver` - The DID Resolver Cache Client
    /// * `client` - The HTTP Client to use for requests
    /// 
    /// # Returns
    /// AuthorizationTokens if successful, Error otherwise
    fn authenticate<'a>(
        &'a self,
        profile_did: &'a str,
        endpoint_did: &'a str,
        did_resolver: &'a DIDCacheClient,
        client: &'a Client,
    ) -> BoxFuture<'a, Result<AuthorizationTokens>>;
}

/// Trait for custom token refresh logic
pub trait CustomRefreshHandler: Send + Sync {
    /// Refresh the access tokens
    /// 
    /// # Arguments
    /// * `profile_did` - The DID of the profile
    /// * `endpoint_did` - The DID of the service endpoint
    /// * `current_tokens` - The current tokens to refresh
    /// * `did_resolver` - The DID Resolver Cache Client
    /// * `client` - The HTTP Client to use for requests
    /// 
    /// # Returns
    /// Updated AuthorizationTokens if successful, Error otherwise
    fn refresh<'a>(
        &'a self,
        profile_did: &'a str,
        endpoint_did: &'a str,
        current_tokens: &'a AuthorizationTokens,
        did_resolver: &'a DIDCacheClient,
        client: &'a Client,
    ) -> BoxFuture<'a, Result<AuthorizationTokens>>;
}

/// Container for custom authentication handlers
/// Allows users to provide their own implementations for authentication and token refresh
#[derive(Clone)]
pub struct CustomAuthHandlers {
    pub auth_handler: Option<Arc<dyn CustomAuthHandler>>,
    pub refresh_handler: Option<Arc<dyn CustomRefreshHandler>>,
}

impl CustomAuthHandlers {
    pub fn new() -> Self {
        Self {
            auth_handler: None,
            refresh_handler: None,
        }
    }

    pub fn with_auth_handler(mut self, handler: Arc<dyn CustomAuthHandler>) -> Self {
        self.auth_handler = Some(handler);
        self
    }

    pub fn with_refresh_handler(mut self, handler: Arc<dyn CustomRefreshHandler>) -> Self {
        self.refresh_handler = Some(handler);
        self
    }
}
