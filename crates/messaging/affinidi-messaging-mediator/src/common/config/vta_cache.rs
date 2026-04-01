use aws_config::SdkConfig;
use tracing::debug;
use vta_sdk::did_secrets::DidSecretsBundle;
use vta_sdk::integration::SecretCache;

/// Secret cache for the mediator that stores the encoded [`DidSecretsBundle`]
/// using the same backend scheme as the VTA credential.
///
/// On store: encodes the bundle as a base64url JSON string and persists it.
/// On load: retrieves the string and decodes it back.
#[allow(dead_code)] // aws_config is used behind feature gates
pub(crate) struct MediatorSecretCache {
    /// The scheme://path string for the cache backend, e.g.:
    /// - `string://` — no-op (cannot persist; acts as "no cache")
    /// - `aws_secrets://<name>-cache` — AWS Secrets Manager
    /// - `keyring://<service>/secrets-cache` — OS keyring
    backend: String,
    aws_config: SdkConfig,
}

impl MediatorSecretCache {
    /// Create a cache backend derived from the credential config.
    ///
    /// Appends `-cache` to the credential backend path so that the cached secrets
    /// bundle is stored alongside (but separate from) the credential itself.
    pub fn from_credential_config(credential_config: &str, aws_config: &SdkConfig) -> Self {
        let backend = derive_cache_backend(credential_config);
        debug!("VTA secret cache backend: {backend}");
        Self {
            backend,
            aws_config: aws_config.clone(),
        }
    }
}

/// Derive the cache backend path from the credential config path.
///
/// - `string://...` → `string://` (no persistence possible)
/// - `aws_secrets://mediator/vta-credential` → `aws_secrets://mediator/vta-secrets-cache`
/// - `keyring://service/user` → `keyring://service/secrets-cache`
fn derive_cache_backend(credential_config: &str) -> String {
    if let Some((scheme, path)) = credential_config.split_once("://") {
        match scheme {
            "aws_secrets" => format!("aws_secrets://{path}-secrets-cache"),
            "keyring" => {
                // Use same service, different user
                let service = path.split('/').next().unwrap_or(path);
                format!("keyring://{service}/secrets-cache")
            }
            _ => "string://".to_string(),
        }
    } else {
        "string://".to_string()
    }
}

impl SecretCache for MediatorSecretCache {
    async fn store(
        &self,
        bundle: &DidSecretsBundle,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let encoded = bundle.encode().map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("Failed to encode secrets bundle: {e}").into()
        })?;

        let (scheme, path) = self
            .backend
            .split_once("://")
            .unwrap_or(("string", ""));

        match scheme {
            "aws_secrets" if !path.is_empty() => {
                #[cfg(feature = "vta-aws-secrets")]
                {
                    let asm = aws_sdk_secretsmanager::Client::new(&self.aws_config);
                    // Try update first, create if not found
                    match asm
                        .put_secret_value()
                        .secret_id(path)
                        .secret_string(&encoded)
                        .send()
                        .await
                    {
                        Ok(_) => {}
                        Err(_) => {
                            asm.create_secret()
                                .name(path)
                                .secret_string(&encoded)
                                .send()
                                .await
                                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                                    format!("AWS Secrets Manager cache store failed: {e:?}").into()
                                })?;
                        }
                    }
                    debug!("Cached VTA secrets to AWS Secrets Manager: {path}");
                }
                #[cfg(not(feature = "vta-aws-secrets"))]
                {
                    let _ = (path, &encoded);
                    debug!("Skipping AWS cache (vta-aws-secrets feature not enabled)");
                }
            }
            "keyring" if !path.is_empty() => {
                #[cfg(feature = "vta-keyring")]
                {
                    let parts: Vec<&str> = path.splitn(2, '/').collect();
                    let (service, user) = if parts.len() == 2 {
                        (parts[0], parts[1])
                    } else {
                        (parts[0], "secrets-cache")
                    };
                    let entry = keyring::Entry::new(service, user)
                        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                            format!("Keyring cache access failed: {e}").into()
                        })?;
                    entry
                        .set_password(&encoded)
                        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                            format!("Keyring cache store failed: {e}").into()
                        })?;
                    debug!("Cached VTA secrets to keyring: {service}/{user}");
                }
                #[cfg(not(feature = "vta-keyring"))]
                {
                    let _ = (path, &encoded);
                    debug!("Skipping keyring cache (vta-keyring feature not enabled)");
                }
            }
            _ => {
                debug!("No persistent cache backend available (string:// scheme)");
            }
        }

        Ok(())
    }

    async fn load(
        &self,
    ) -> Result<Option<DidSecretsBundle>, Box<dyn std::error::Error + Send + Sync>> {
        let (scheme, path) = self
            .backend
            .split_once("://")
            .unwrap_or(("string", ""));

        let encoded: Option<String> = match scheme {
            "aws_secrets" if !path.is_empty() => {
                #[cfg(feature = "vta-aws-secrets")]
                {
                    let asm = aws_sdk_secretsmanager::Client::new(&self.aws_config);
                    match asm.get_secret_value().secret_id(path).send().await {
                        Ok(resp) => resp.secret_string,
                        Err(_) => None, // Secret doesn't exist yet
                    }
                }
                #[cfg(not(feature = "vta-aws-secrets"))]
                {
                    let _ = path;
                    None
                }
            }
            "keyring" if !path.is_empty() => {
                #[cfg(feature = "vta-keyring")]
                {
                    let parts: Vec<&str> = path.splitn(2, '/').collect();
                    let (service, user) = if parts.len() == 2 {
                        (parts[0], parts[1])
                    } else {
                        (parts[0], "secrets-cache")
                    };
                    match keyring::Entry::new(service, user) {
                        Ok(entry) => entry.get_password().ok(),
                        Err(_) => None,
                    }
                }
                #[cfg(not(feature = "vta-keyring"))]
                {
                    let _ = path;
                    None
                }
            }
            _ => None,
        };

        match encoded {
            Some(s) if !s.is_empty() => {
                let bundle = DidSecretsBundle::decode(&s)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                        format!("Failed to decode cached secrets bundle: {e}").into()
                    })?;
                debug!("Loaded {} cached secret(s)", bundle.secrets.len());
                Ok(Some(bundle))
            }
            _ => Ok(None),
        }
    }
}
