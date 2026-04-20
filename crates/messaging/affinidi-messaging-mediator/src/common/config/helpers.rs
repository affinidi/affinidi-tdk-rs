//! Config-loading helpers for the mediator.
//!
//! After the unified secrets migration, credentials and operating keys
//! are loaded through `MediatorSecrets` rather than per-field URL schemes.
//! The helpers that remain here handle:
//!
//! - Reading the TOML file + applying env overrides.
//! - Resolving `mediator_did` / `admin_did` from either a literal DID or
//!   `aws_parameter_store://<name>`.
//! - Reading the self-hosted DID document from `file://` or
//!   `aws_parameter_store://`.
//! - Hostname resolution and forwarding-loop protection.

use affinidi_did_common::service::Endpoint;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_mediator_common::errors::MediatorError;
#[cfg(feature = "aws")]
use aws_config::SdkConfig;
#[cfg(feature = "aws")]
use aws_sdk_ssm::types::ParameterType;
use std::{
    fs::File,
    io::{self, BufRead},
    path::Path,
};
use tracing::{error, info, warn};

use super::AwsConfig;
use super::processors::ForwardingConfig;

/// Check if any DID-resolution field uses `aws_parameter_store://`,
/// requiring the AWS SDK to be initialised. Secret-store backends are
/// excluded — those are handled via `MediatorSecrets`, which owns its own
/// AWS SDK client when the `secrets-aws` feature is enabled.
pub(crate) fn config_needs_aws(raw: &super::ConfigRaw) -> bool {
    let aws_param = |s: &str| s.starts_with("aws_parameter_store://");
    aws_param(&raw.mediator_did)
        || aws_param(&raw.server.admin_did)
        || raw
            .server
            .did_web_self_hosted
            .as_ref()
            .is_some_and(|s| aws_param(s))
}

/// Extract the AWS `SdkConfig` from an `Option<AwsConfig>`, returning a clear
/// error when AWS is needed but not available.
#[cfg(feature = "aws")]
fn require_aws_config<'a>(
    aws_config: &'a Option<AwsConfig>,
    context: &str,
) -> Result<&'a SdkConfig, MediatorError> {
    aws_config.as_ref().ok_or_else(|| {
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!("{context} requires AWS but AWS SDK was not initialized"),
        )
    })
}

fn parse_scheme<'a>(input: &'a str, field_name: &str) -> Result<(&'a str, &'a str), MediatorError> {
    input.split_once("://").ok_or_else(|| {
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!("Invalid `{field_name}` format: expected scheme://path, got '{input}'"),
        )
    })
}

macro_rules! env_override {
    ($field:expr, $env_var:expr) => {
        if let Ok(val) = std::env::var($env_var) {
            $field = val;
        }
    };
}

macro_rules! env_override_opt {
    ($field:expr, $env_var:expr) => {
        if let Ok(val) = std::env::var($env_var) {
            $field = Some(val);
        }
    };
}

/// Apply environment variable overrides to the raw config. Env vars take
/// priority over values in the TOML file.
pub(crate) fn apply_env_overrides(config: &mut super::ConfigRaw) {
    env_override!(config.log_level, "LOG_LEVEL");
    env_override!(config.log_json, "LOG_JSON");
    env_override!(config.mediator_did, "MEDIATOR_DID");

    env_override!(config.server.listen_address, "LISTEN_ADDRESS");
    env_override!(config.server.api_prefix, "API_PREFIX");
    env_override!(config.server.admin_did, "ADMIN_DID");
    env_override_opt!(config.server.did_web_self_hosted, "DID_WEB_SELF_HOSTED");

    env_override!(config.database.functions_file, "DATABASE_FUNCTIONS_FILE");
    env_override!(config.database.database_url, "DATABASE_URL");
    env_override_opt!(config.database.database_pool_size, "DATABASE_POOL_SIZE");
    env_override!(config.database.database_timeout, "DATABASE_TIMEOUT");

    env_override!(config.security.mediator_acl_mode, "MEDIATOR_ACL_MODE");
    env_override!(config.security.global_acl_default, "GLOBAL_DEFAULT_ACL");
    env_override!(
        config.security.local_direct_delivery_allowed,
        "LOCAL_DIRECT_DELIVERY_ALLOWED"
    );
    env_override!(
        config.security.local_direct_delivery_allow_anon,
        "LOCAL_DIRECT_DELIVERY_ALLOW_ANON"
    );
    env_override!(config.security.use_ssl, "USE_SSL");
    env_override_opt!(config.security.ssl_certificate_file, "SSL_CERTIFICATE_FILE");
    env_override_opt!(config.security.ssl_key_file, "SSL_KEY_FILE");
    env_override!(config.security.jwt_access_expiry, "JWT_ACCESS_EXPIRY");
    env_override!(config.security.jwt_refresh_expiry, "JWT_REFRESH_EXPIRY");
    env_override_opt!(config.security.cors_allow_origin, "CORS_ALLOW_ORIGIN");
    env_override!(
        config.security.block_anonymous_outer_envelope,
        "BLOCK_ANONYMOUS_OUTER_ENVELOPE"
    );
    env_override!(
        config.security.force_session_did_match,
        "FORCE_SESSION_DID_MATCH"
    );
    env_override!(
        config.security.block_remote_admin_msgs,
        "BLOCK_REMOTE_ADMIN_MSGS"
    );
    env_override!(
        config.security.admin_messages_expiry,
        "ADMIN_MESSAGES_EXPIRY"
    );

    env_override!(config.streaming.enabled, "STREAMING_ENABLED");
    env_override!(config.streaming.uuid, "STREAMING_UUID");

    env_override_opt!(config.did_resolver.address, "DID_RESOLVER_ADDRESS");
    env_override!(
        config.did_resolver.cache_capacity,
        "DID_RESOLVER_CACHE_CAPACITY"
    );
    env_override!(config.did_resolver.cache_ttl, "DID_RESOLVER_CACHE_TTL");
    env_override!(
        config.did_resolver.network_timeout,
        "DID_RESOLVER_NETWORK_TIMEOUT"
    );
    env_override!(
        config.did_resolver.network_limit,
        "DID_RESOLVER_NETWORK_LIMIT"
    );

    env_override!(
        config.limits.attachments_max_count,
        "LIMIT_ATTACHMENTS_MAX_COUNT"
    );
    env_override!(
        config.limits.crypto_operations_per_message,
        "LIMIT_CRYPTO_OPERATIONS_PER_MESSAGE"
    );
    env_override!(config.limits.deleted_messages, "LIMIT_DELETED_MESSAGES");
    env_override!(config.limits.forward_task_queue, "LIMIT_FORWARD_TASK_QUEUE");
    env_override!(config.limits.http_size, "LIMIT_HTTP_SIZE");
    env_override!(config.limits.listed_messages, "LIMIT_LISTED_MESSAGES");
    env_override!(config.limits.local_max_acl, "LIMIT_LOCAL_MAX_ACL");
    env_override!(
        config.limits.message_expiry_seconds,
        "LIMIT_MESSAGE_EXPIRY_SECONDS"
    );
    env_override!(config.limits.message_size, "LIMIT_MESSAGE_SIZE");
    env_override!(
        config.limits.queued_send_messages_soft,
        "LIMIT_QUEUED_SEND_MESSAGES_SOFT"
    );
    env_override!(
        config.limits.queued_send_messages_hard,
        "LIMIT_QUEUED_SEND_MESSAGES_HARD"
    );
    env_override!(
        config.limits.queued_receive_messages_soft,
        "LIMIT_QUEUED_RECEIVE_MESSAGES_SOFT"
    );
    env_override!(
        config.limits.queued_receive_messages_hard,
        "LIMIT_QUEUED_RECEIVE_MESSAGES_HARD"
    );
    env_override!(config.limits.to_keys_per_recipient, "LIMIT_TO_KEYS_PER_DID");
    env_override!(config.limits.to_recipients, "LIMIT_TO_RECIPIENTS");
    env_override!(config.limits.ws_size, "LIMIT_WS_SIZE");
    env_override!(config.limits.access_list_limit, "ACCESS_LIST_LIMIT");
    env_override!(config.limits.oob_invite_ttl, "OOB_INVITE_TTL");
    env_override!(config.limits.rate_limit_per_ip, "LIMIT_RATE_LIMIT_PER_IP");
    env_override!(config.limits.rate_limit_burst, "LIMIT_RATE_LIMIT_BURST");
    env_override!(
        config.limits.max_websocket_connections,
        "LIMIT_MAX_WEBSOCKET_CONNECTIONS"
    );
    env_override!(
        config.limits.did_rate_limit_per_second,
        "LIMIT_DID_RATE_LIMIT_PER_SECOND"
    );
    env_override!(
        config.limits.did_rate_limit_burst,
        "LIMIT_DID_RATE_LIMIT_BURST"
    );

    env_override!(
        config.processors.forwarding.enabled,
        "PROCESSOR_FORWARDING_ENABLED"
    );
    env_override!(
        config.processors.forwarding.future_time_limit,
        "PROCESSOR_FORWARDING_FUTURE_TIME_LIMIT"
    );
    env_override!(
        config.processors.forwarding.external_forwarding,
        "PROCESSOR_FORWARDING_EXTERNAL"
    );
    env_override!(
        config.processors.forwarding.report_errors,
        "PROCESSOR_FORWARDING_REPORT_ERRORS"
    );
    env_override!(
        config.processors.forwarding.blocked_forwarding_dids,
        "PROCESSOR_FORWARDING_BLOCKED_DIDS"
    );
    env_override!(
        config.processors.forwarding.rate_window_seconds,
        "PROCESSOR_FORWARDING_RATE_WINDOW"
    );
    env_override!(
        config.processors.forwarding.ws_threshold_msgs_per_10s,
        "PROCESSOR_FORWARDING_WS_THRESHOLD"
    );
    env_override!(
        config.processors.forwarding.ws_idle_timeout_seconds,
        "PROCESSOR_FORWARDING_WS_IDLE_TIMEOUT"
    );
    env_override!(
        config.processors.forwarding.batch_size,
        "PROCESSOR_FORWARDING_BATCH_SIZE"
    );
    env_override!(
        config.processors.forwarding.max_retries,
        "PROCESSOR_FORWARDING_MAX_RETRIES"
    );
    env_override!(
        config.processors.forwarding.initial_backoff_ms,
        "PROCESSOR_FORWARDING_INITIAL_BACKOFF_MS"
    );
    env_override!(
        config.processors.forwarding.max_backoff_ms,
        "PROCESSOR_FORWARDING_MAX_BACKOFF_MS"
    );
    env_override!(
        config.processors.forwarding.consumer_group,
        "PROCESSOR_FORWARDING_CONSUMER_GROUP"
    );

    env_override!(
        config.processors.message_expiry_cleanup.enabled,
        "PROCESSOR_MESSAGE_EXPIRY_CLEANUP_ENABLED"
    );

    env_override!(config.secrets.backend, "MEDIATOR_SECRETS_BACKEND");
    env_override_opt!(config.secrets.cache_ttl, "MEDIATOR_SECRETS_CACHE_TTL");
}

/// Read the primary configuration file for the mediator.
/// Returns a ConfigRaw struct with env var overrides applied.
pub(crate) fn read_config_file(file_name: &str) -> Result<super::ConfigRaw, MediatorError> {
    info!("Config file({file_name})");
    let raw_config = read_file_lines(file_name)?;

    let mut config: super::ConfigRaw = toml::from_str(&raw_config.join("\n")).map_err(|err| {
        error!("Could not parse configuration settings. {err:?}");
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!("Could not parse configuration settings. Reason: {err:?}"),
        )
    })?;

    apply_env_overrides(&mut config);

    Ok(config)
}

/// Reads a file and returns a vector of strings, one for each line in the file.
/// Strips lines starting with `#` (comments).
pub(crate) fn read_file_lines<P>(file_name: P) -> Result<Vec<String>, MediatorError>
where
    P: AsRef<Path>,
{
    let file = File::open(file_name.as_ref()).map_err(|err| {
        error!(
            "Could not open file({}). {}",
            file_name.as_ref().display(),
            err
        );
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!(
                "Could not open file({}). {}",
                file_name.as_ref().display(),
                err
            ),
        )
    })?;

    let mut lines = Vec::new();
    for line in io::BufReader::new(file).lines().map_while(Result::ok) {
        if !line.starts_with('#') {
            lines.push(line);
        }
    }

    Ok(lines)
}

/// Resolve a DID-producing config field.
///
/// Supported schemes:
/// - `did://<did-string>` — literal DID.
/// - `aws_parameter_store://<parameter-name>` — fetched at startup.
///
/// `vta://` is no longer supported here; when VTA integration is enabled
/// the mediator DID is discovered from the admin credential at startup.
pub(crate) async fn read_did_config(
    did_config: &str,
    #[cfg_attr(not(feature = "aws"), allow(unused_variables))] aws_config: &Option<AwsConfig>,
    field_name: &str,
) -> Result<String, MediatorError> {
    let (scheme, path) = parse_scheme(did_config, field_name)?;
    let content: String = match scheme {
        "did" => path.to_string(),
        "aws_parameter_store" => {
            #[cfg(feature = "aws")]
            {
                let cfg = require_aws_config(
                    aws_config,
                    &format!("{field_name} (aws_parameter_store://)"),
                )?;
                aws_parameter_store(path, cfg).await?
            }
            #[cfg(not(feature = "aws"))]
            {
                let _ = path;
                return Err(MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!(
                        "aws_parameter_store:// for {field_name} requires the 'aws' feature. Rebuild with: cargo build --features aws"
                    ),
                ));
            }
        }
        _ => {
            return Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                format!(
                    "Invalid {field_name} format! Expected did:// or aws_parameter_store:// (got '{did_config}')"
                ),
            ));
        }
    };

    Ok(content)
}

pub(crate) fn get_hostname(host_name: &str) -> Result<String, MediatorError> {
    if host_name.starts_with("hostname://") {
        Ok(hostname::get()
            .map_err(|e| {
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!("Couldn't get hostname. Reason: {e}"),
                )
            })?
            .into_string()
            .map_err(|e| {
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!("Couldn't get hostname. Reason: {e:?}"),
                )
            })?)
    } else if host_name.starts_with("string://") {
        Ok(host_name.split_at(9).1.to_string())
    } else {
        Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            "Invalid hostname format!".into(),
        ))
    }
}

#[cfg(feature = "aws")]
pub(crate) async fn aws_parameter_store(
    parameter_name: &str,
    aws_config: &SdkConfig,
) -> Result<String, MediatorError> {
    let ssm = aws_sdk_ssm::Client::new(aws_config);

    let response = ssm
        .get_parameter()
        .set_name(Some(parameter_name.to_string()))
        .send()
        .await
        .map_err(|e| {
            error!("Could not get ({parameter_name:?}) parameter. {e:?}");
            MediatorError::ConfigError(
                12,
                "NA".into(),
                format!("Could not get ({parameter_name:?}) parameter. {e:?}"),
            )
        })?;
    let parameter = response.parameter.ok_or_else(|| {
        error!("No parameter string found in response");
        MediatorError::ConfigError(
            12,
            "NA".into(),
            "No parameter string found in response".into(),
        )
    })?;

    if let Some(_type) = parameter.r#type {
        if _type != ParameterType::String {
            return Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                "Expected String parameter type".into(),
            ));
        }
    } else {
        return Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            "Unknown parameter type".into(),
        ));
    }

    parameter.value.ok_or_else(|| {
        error!(
            "Parameter ({:?}) found, but no parameter value found in response",
            parameter.name
        );
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!(
                "Parameter ({:?}) found, but no parameter value found in response",
                parameter.name
            ),
        )
    })
}

/// Reads document from file or aws_parameter_store
pub(crate) async fn read_document(
    document_path: &str,
    #[cfg_attr(not(feature = "aws"), allow(unused_variables))] aws_config: &Option<AwsConfig>,
) -> Result<String, MediatorError> {
    let (scheme, path) = parse_scheme(document_path, "document_path")?;
    let content: String = match scheme {
        "file" => read_file_lines(path)?.concat(),
        "aws_parameter_store" => {
            #[cfg(feature = "aws")]
            {
                let cfg = require_aws_config(aws_config, "document_path (aws_parameter_store://)")?;
                aws_parameter_store(path, cfg).await?
            }
            #[cfg(not(feature = "aws"))]
            {
                let _ = path;
                return Err(MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    "aws_parameter_store:// requires the 'aws' feature. Rebuild with: cargo build --features aws".into(),
                ));
            }
        }
        _ => {
            return Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                "Invalid document_path format! Expecting file:// or aws_parameter_store:// ..."
                    .into(),
            ));
        }
    };

    Ok(content)
}

/// Creates a set of URI's that can be used to detect if forwarding loopbacks to the mediator could occur
pub(crate) async fn load_forwarding_protection_blocks(
    did_resolver: &DIDCacheClient,
    forwarding_config: &mut ForwardingConfig,
    mediator_did: &str,
    blocked_dids: &str,
) -> Result<(), MediatorError> {
    let mut blocked_dids: Vec<String> = match serde_json::from_str(blocked_dids) {
        Ok(dids) => dids,
        Err(err) => {
            error!("Could not parse blocked_forwarding_dids. Reason: {err}");
            return Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                format!("Could not parse blocked_forwarding_dids. Reason: {err}"),
            ));
        }
    };

    blocked_dids.push(mediator_did.into());

    for did in blocked_dids {
        let doc = did_resolver.resolve(&did).await.map_err(|err| {
            MediatorError::DIDError(
                12,
                "NA".into(),
                did.clone(),
                format!("Couldn't resolve DID. Reason: {err}"),
            )
        })?;

        forwarding_config.blocked_forwarding.insert(did.clone());

        for service in doc.doc.service.iter() {
            match &service.service_endpoint {
                Endpoint::Url(uri) => {
                    forwarding_config.blocked_forwarding.insert(uri.to_string());
                }
                Endpoint::Map(map) => {
                    if let Some(endpoints) = map.as_array() {
                        for endpoint in endpoints {
                            if let Some(uri) = endpoint.get("uri") {
                                if let Some(uri) = uri.as_str() {
                                    forwarding_config.blocked_forwarding.insert(uri.into());
                                } else {
                                    warn!("Couldn't parse URI as a string: {uri:#?}");
                                }
                            } else {
                                warn!(
                                    "Service endpoint map does not contain a URI. DID ({did}), Service ({service:#?}), Endpoint ({endpoint:#?})"
                                );
                            }
                        }
                    } else if let Some(uri) = map.get("uri") {
                        if let Some(uri) = uri.as_str() {
                            forwarding_config.blocked_forwarding.insert(uri.into());
                        } else {
                            warn!("Couldn't parse URI as a string: {uri:#?}");
                        }
                    } else {
                        warn!(
                            "Service endpoint map does not contain a URI. DID ({did}), Service ({service:#?}), Endpoint ({map:#?})"
                        );
                    }
                }
            }
        }
    }

    Ok(())
}
