//! Resolve agent names through a shared DID cache server.

use std::{future::Future, pin::Pin, time::Duration};

use tracing::debug;
use url::Url;

use crate::{
    error::AgentNameError,
    name::AgentName,
    resolver::{AgentNameResolver, DEFAULT_TIMEOUT, NameResolution},
};

/// Asks an `affinidi-did-resolver-cache-server` to map a name to a DID.
///
/// # Why point at a server at all
///
/// Following an agent name's redirect is the network-facing, cacheable half of
/// resolution. Centralising it on a cache server means the fetch is done once
/// for many clients, and — more usefully — that the SSRF exposure of fetching
/// caller-supplied URLs lives on one hardened host you control rather than on
/// every client.
///
/// # The server is a cache, never a trust anchor
///
/// This backend returns **only a DID**. The mandatory Layer-1 check — that the
/// resolved document's `alsoKnownAs` claims the name — is still performed by the
/// client, against a document the client resolved itself. A server that answered
/// "here is the name, the DID, and the document, and I promise they agree" would
/// be asking to be trusted; nothing here does.
///
/// This mirrors how the SDK re-verifies `did:webvh` logs locally rather than
/// believing the cache server's document.
#[derive(Debug, Clone)]
pub struct CacheServerResolver {
    client: reqwest::Client,
    base_url: Url,
}

impl CacheServerResolver {
    /// Point at a cache server's base URL, e.g. `https://resolver.example`.
    ///
    /// The `/did/v1/resolve-name/` path is appended, so pass the host root, not
    /// the endpoint itself.
    pub fn new(base_url: &str) -> Result<Self, AgentNameError> {
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .map_err(AgentNameError::Http)?;
        Self::with_client(client, base_url)
    }

    /// Use a caller-supplied client.
    pub fn with_client(client: reqwest::Client, base_url: &str) -> Result<Self, AgentNameError> {
        let base_url = Url::parse(base_url).map_err(|e| AgentNameError::InvalidName {
            input: base_url.to_string(),
            reason: format!("not a URL: {e}"),
        })?;
        Ok(Self { client, base_url })
    }

    /// Override the request timeout by supplying a preconfigured client.
    pub fn with_timeout(timeout: Duration, base_url: &str) -> Result<Self, AgentNameError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(AgentNameError::Http)?;
        Self::with_client(client, base_url)
    }

    fn endpoint(&self, name: &AgentName) -> Result<Url, AgentNameError> {
        // The server route is `/did/v1/resolve-name/{*name}`, and the name is
        // sent scheme-less (`example.com/@alice`) because the wildcard captures
        // path segments. `Url::join` would treat a leading `//` as an authority,
        // so build the path by hand and let `Url` percent-encode it.
        let path = format!("did/v1/resolve-name/{}", name.without_scheme());
        self.base_url
            .join(&path)
            .map_err(|e| AgentNameError::InvalidName {
                input: path,
                reason: format!("could not build request URL: {e}"),
            })
    }

    async fn resolve_inner(&self, name: &AgentName) -> Result<String, AgentNameError> {
        let url = self.endpoint(name)?;
        debug!(%url, "resolving agent name via cache server");

        let response = self.client.get(url).send().await?;
        let status = response.status();

        // Read as text and parse deliberately. A server that does not have this
        // endpoint — an older build, or one with `enable_agent_names = false` —
        // answers 404, and an intermediary may answer with HTML rather than
        // JSON. Parsing first would turn all of those into an opaque
        // deserialization error instead of the status the caller needs to see.
        let body = response.text().await?;
        let json: Option<serde_json::Value> = serde_json::from_str(&body).ok();

        if !status.is_success() {
            let message = json
                .as_ref()
                .and_then(|b| b.get("error"))
                .and_then(|e| e.as_str())
                .unwrap_or("cache server returned an error")
                .to_string();
            return Err(AgentNameError::CacheServer {
                name: name.as_str().to_string(),
                status: status.as_u16(),
                message,
            });
        }

        let did = json
            .as_ref()
            .and_then(|b| b.get("did"))
            .and_then(|d| d.as_str())
            .ok_or_else(|| AgentNameError::CacheServer {
                name: name.as_str().to_string(),
                status: status.as_u16(),
                message: "response contained no 'did' field".to_string(),
            })?;

        Ok(did.to_string())
    }
}

impl AgentNameResolver for CacheServerResolver {
    fn name(&self) -> &str {
        "cache-server"
    }

    fn resolve<'a>(
        &'a self,
        name: &'a AgentName,
    ) -> Pin<Box<dyn Future<Output = NameResolution> + Send + 'a>> {
        Box::pin(async move { Some(self.resolve_inner(name).await) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> AgentName {
        AgentName::parse(s).unwrap()
    }

    #[test]
    fn builds_the_endpoint_url() {
        let r = CacheServerResolver::new("https://resolver.example").unwrap();
        assert_eq!(
            r.endpoint(&name("example.com/@alice")).unwrap().as_str(),
            "https://resolver.example/did/v1/resolve-name/example.com/@alice"
        );
    }

    #[test]
    fn builds_the_endpoint_url_for_a_path_qualified_name() {
        let r = CacheServerResolver::new("https://resolver.example").unwrap();
        assert_eq!(
            r.endpoint(&name("firstperson.network/@drummond/h2hsummit"))
                .unwrap()
                .as_str(),
            "https://resolver.example/did/v1/resolve-name/firstperson.network/@drummond/h2hsummit"
        );
    }

    /// A base URL with a trailing path must not silently drop it.
    #[test]
    fn respects_a_base_url_with_a_trailing_slash() {
        let r = CacheServerResolver::new("https://resolver.example/").unwrap();
        assert!(
            r.endpoint(&name("example.com/@alice"))
                .unwrap()
                .as_str()
                .starts_with("https://resolver.example/did/v1/resolve-name/")
        );
    }

    #[test]
    fn rejects_a_malformed_base_url() {
        assert!(CacheServerResolver::new("not a url").is_err());
    }

    #[test]
    fn reports_its_name() {
        assert_eq!(
            CacheServerResolver::new("https://resolver.example")
                .unwrap()
                .name(),
            "cache-server"
        );
    }
}
