//! Backend URL parser.
//!
//! Every supported backend is identified by a URL:
//!
//! | Scheme           | Shape                                       | Example                                    |
//! |------------------|---------------------------------------------|--------------------------------------------|
//! | `keyring://`     | `keyring://<service>`                       | `keyring://affinidi-mediator`              |
//! | `file://`        | `file:///<absolute-path>[?encrypt=1]`       | `file:///var/lib/mediator/secrets.json`    |
//! | `aws_secrets://` | `aws_secrets://<region>/<prefix>`           | `aws_secrets://us-east-1/prod/mediator/`   |
//! | `gcp_secrets://` | `gcp_secrets://<project>/<prefix>`          | `gcp_secrets://my-proj/mediator-`          |
//! | `azure_keyvault://` | `azure_keyvault://<vault-name-or-url>`   | `azure_keyvault://my-vault`                |
//! | `vault://`       | `vault://<host[:port]>/<kv-path>`           | `vault://vault.internal/secret/mediator`   |
//!
//! `string://` is intentionally not supported — inline secrets in
//! `mediator.toml` would defeat the whole point. CI scripts that used to
//! rely on it should use env-var overrides (`MEDIATOR_SECRETS_BACKEND=`
//! and per-entry overrides) against a `file://` or cloud backend.

use url::Url;

use crate::secrets::error::{Result, SecretStoreError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendUrl {
    Keyring { service: String },
    File { path: String, encrypted: bool },
    Aws { region: String, prefix: String },
    Gcp { project: String, prefix: String },
    Azure { vault: String },
    Vault { endpoint: String, path: String },
}

/// Parse a backend URL. Returns a structured [`BackendUrl`] or an
/// `InvalidUrl` error with a human-actionable reason.
pub fn parse_url(raw: &str) -> Result<BackendUrl> {
    if raw.starts_with("string://") {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "inline 'string://' secrets are no longer supported — use 'file://' for \
                    local dev (with the --file-backend-encrypt hardening) or a cloud backend \
                    for production. Per-entry env var overrides are still available for CI."
                .into(),
        });
    }

    // `url::Url::parse` rejects some of our schemes because they're not
    // on its "special scheme" list, so we do a cheap prefix split first
    // and parse the body ourselves for keyring/aws/gcp/azure/vault. File
    // uses the real URL parser because the absolute path matters.
    let (scheme, rest) = split_scheme(raw)?;

    match scheme {
        "keyring" => parse_keyring(rest, raw),
        "file" => parse_file(raw),
        "aws_secrets" => parse_aws(rest, raw),
        "gcp_secrets" => parse_gcp(rest, raw),
        "azure_keyvault" => parse_azure(rest, raw),
        "vault" => parse_vault(rest, raw),
        other => Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: format!(
                "unknown scheme '{other}://' — supported schemes: keyring, file, aws_secrets, \
                 gcp_secrets, azure_keyvault, vault"
            ),
        }),
    }
}

fn split_scheme(raw: &str) -> Result<(&str, &str)> {
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "expected '<scheme>://<body>'".into(),
        })?;
    Ok((scheme, rest))
}

fn parse_keyring(rest: &str, raw: &str) -> Result<BackendUrl> {
    let service = rest.trim_end_matches('/');
    if service.is_empty() {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "keyring:// requires a service name, e.g. keyring://affinidi-mediator".into(),
        });
    }
    if service.contains('/') {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "keyring:// service name must not contain '/'".into(),
        });
    }
    Ok(BackendUrl::Keyring {
        service: service.to_string(),
    })
}

fn parse_file(raw: &str) -> Result<BackendUrl> {
    let url = Url::parse(raw).map_err(|e| SecretStoreError::InvalidUrl {
        url: raw.to_string(),
        reason: format!("malformed file:// URL: {e}"),
    })?;
    let path = url.path();
    if path.is_empty() || path == "/" {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "file:// requires an absolute path, e.g. file:///var/lib/mediator/secrets.json"
                .into(),
        });
    }
    let mut encrypted = false;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "encrypt" => {
                encrypted = matches!(v.as_ref(), "1" | "true" | "yes" | "on");
            }
            _ => {
                return Err(SecretStoreError::InvalidUrl {
                    url: raw.to_string(),
                    reason: format!("unknown query parameter '{k}' on file:// URL"),
                });
            }
        }
    }
    Ok(BackendUrl::File {
        path: path.to_string(),
        encrypted,
    })
}

fn parse_aws(rest: &str, raw: &str) -> Result<BackendUrl> {
    let (region, prefix) = rest.split_once('/').ok_or_else(|| SecretStoreError::InvalidUrl {
        url: raw.to_string(),
        reason: "aws_secrets:// requires '<region>/<prefix>', e.g. aws_secrets://us-east-1/mediator/"
            .into(),
    })?;
    if region.is_empty() {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "aws_secrets:// requires a non-empty region".into(),
        });
    }
    Ok(BackendUrl::Aws {
        region: region.to_string(),
        prefix: prefix.to_string(),
    })
}

fn parse_gcp(rest: &str, raw: &str) -> Result<BackendUrl> {
    let (project, prefix) = rest
        .split_once('/')
        .ok_or_else(|| SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "gcp_secrets:// requires '<project>/<prefix>'".into(),
        })?;
    if project.is_empty() {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "gcp_secrets:// requires a non-empty project id".into(),
        });
    }
    Ok(BackendUrl::Gcp {
        project: project.to_string(),
        prefix: prefix.to_string(),
    })
}

fn parse_azure(rest: &str, raw: &str) -> Result<BackendUrl> {
    let trimmed = rest.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "azure_keyvault:// requires a vault name or URL".into(),
        });
    }
    // Accept three input shapes:
    //   - `azure_keyvault://my-vault`
    //     → bare name, expand to `https://my-vault.vault.azure.net`.
    //     Works for Azure Commercial; the DNS is region-agnostic.
    //   - `azure_keyvault://my-vault.vault.usgovcloudapi.net`
    //     → full DNS name (the `.` in the host is the signal); prepend
    //     `https://`. Required for sovereign clouds (Government,
    //     China, Germany).
    //   - `azure_keyvault://https://my-vault.vault.azure.net`
    //     → already a full URL; pass through verbatim.
    let resolved = if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        trimmed.to_string()
    } else if trimmed.contains('.') {
        format!("https://{trimmed}")
    } else {
        format!("https://{trimmed}.vault.azure.net")
    };
    Ok(BackendUrl::Azure { vault: resolved })
}

fn parse_vault(rest: &str, raw: &str) -> Result<BackendUrl> {
    let (endpoint, path) = rest
        .split_once('/')
        .ok_or_else(|| SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "vault:// requires '<host>[:<port>]/<kv-path>'".into(),
        })?;
    if endpoint.is_empty() {
        return Err(SecretStoreError::InvalidUrl {
            url: raw.to_string(),
            reason: "vault:// requires a non-empty endpoint".into(),
        });
    }
    Ok(BackendUrl::Vault {
        endpoint: endpoint.to_string(),
        path: path.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyring_ok() {
        let url = parse_url("keyring://affinidi-mediator").unwrap();
        assert_eq!(
            url,
            BackendUrl::Keyring {
                service: "affinidi-mediator".into()
            }
        );
    }

    #[test]
    fn keyring_missing_service_errors() {
        let err = parse_url("keyring://").unwrap_err();
        assert!(matches!(err, SecretStoreError::InvalidUrl { .. }));
    }

    #[test]
    fn keyring_with_slash_errors() {
        let err = parse_url("keyring://svc/extra").unwrap_err();
        assert!(matches!(err, SecretStoreError::InvalidUrl { .. }));
    }

    #[test]
    fn file_plaintext() {
        let url = parse_url("file:///var/lib/mediator/secrets.json").unwrap();
        assert_eq!(
            url,
            BackendUrl::File {
                path: "/var/lib/mediator/secrets.json".into(),
                encrypted: false,
            }
        );
    }

    #[test]
    fn file_with_encrypt_flag() {
        let url = parse_url("file:///tmp/m.json?encrypt=1").unwrap();
        assert_eq!(
            url,
            BackendUrl::File {
                path: "/tmp/m.json".into(),
                encrypted: true,
            }
        );
    }

    #[test]
    fn file_missing_path_errors() {
        assert!(parse_url("file:///").is_err());
    }

    #[test]
    fn aws_ok() {
        assert_eq!(
            parse_url("aws_secrets://us-east-1/prod/mediator/").unwrap(),
            BackendUrl::Aws {
                region: "us-east-1".into(),
                prefix: "prod/mediator/".into(),
            }
        );
    }

    #[test]
    fn aws_missing_slash_errors() {
        assert!(parse_url("aws_secrets://us-east-1").is_err());
    }

    #[test]
    fn gcp_ok() {
        assert_eq!(
            parse_url("gcp_secrets://my-proj/mediator-").unwrap(),
            BackendUrl::Gcp {
                project: "my-proj".into(),
                prefix: "mediator-".into(),
            }
        );
    }

    #[test]
    fn azure_bare_name_expands_to_commercial_cloud_url() {
        assert_eq!(
            parse_url("azure_keyvault://my-vault").unwrap(),
            BackendUrl::Azure {
                vault: "https://my-vault.vault.azure.net".into()
            }
        );
    }

    #[test]
    fn azure_full_https_url_is_passed_through() {
        assert_eq!(
            parse_url("azure_keyvault://https://my-vault.vault.azure.net").unwrap(),
            BackendUrl::Azure {
                vault: "https://my-vault.vault.azure.net".into()
            }
        );
    }

    #[test]
    fn azure_sovereign_dns_name_gets_https_prefix() {
        // A DNS name with `.` in it signals a sovereign-cloud host;
        // the parser prepends `https://` rather than treating it as a
        // bare name that would expand to the commercial DNS.
        assert_eq!(
            parse_url("azure_keyvault://my-vault.vault.usgovcloudapi.net").unwrap(),
            BackendUrl::Azure {
                vault: "https://my-vault.vault.usgovcloudapi.net".into()
            }
        );
    }

    #[test]
    fn azure_empty_input_errors() {
        assert!(parse_url("azure_keyvault://").is_err());
    }

    #[test]
    fn vault_ok() {
        assert_eq!(
            parse_url("vault://vault.internal/secret/mediator").unwrap(),
            BackendUrl::Vault {
                endpoint: "vault.internal".into(),
                path: "secret/mediator".into(),
            }
        );
    }

    #[test]
    fn string_rejected_with_helpful_pointer() {
        let err = parse_url("string://foo").unwrap_err();
        match err {
            SecretStoreError::InvalidUrl { reason, .. } => {
                assert!(reason.contains("file://"));
                assert!(reason.contains("env var"));
            }
            _ => panic!("wrong error variant"),
        }
    }

    #[test]
    fn unknown_scheme_errors() {
        assert!(parse_url("redis://foo").is_err());
    }
}
