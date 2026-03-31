use affinidi_did_common::service::Endpoint;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_secrets_resolver::{SecretsResolver, ThreadedSecretsResolver, secrets::Secret};
use vta_sdk::client::VtaClient;
use aws_config::SdkConfig;
use aws_sdk_secretsmanager;
use aws_sdk_ssm::types::ParameterType;
use base64::prelude::*;
use std::{
    env,
    fs::File,
    io::{self, BufRead},
    path::Path,
    sync::Arc,
};
use tracing::info;

use super::VtaConfigRaw;
use super::processors::ForwardingConfig;

/// Override a String config field with an environment variable if set.
macro_rules! env_override {
    ($field:expr, $env_var:expr) => {
        if let Ok(val) = std::env::var($env_var) {
            $field = val;
        }
    };
}

/// Override an Option<String> config field with an environment variable if set.
macro_rules! env_override_opt {
    ($field:expr, $env_var:expr) => {
        if let Ok(val) = std::env::var($env_var) {
            $field = Some(val);
        }
    };
}

/// Apply environment variable overrides to the raw config.
/// Env vars take priority over values in the TOML file.
pub(crate) fn apply_env_overrides(config: &mut super::ConfigRaw) {
    // Top-level
    env_override!(config.log_level, "LOG_LEVEL");
    env_override!(config.log_json, "LOG_JSON");
    env_override!(config.mediator_did, "MEDIATOR_DID");

    // Server
    env_override!(config.server.listen_address, "LISTEN_ADDRESS");
    env_override!(config.server.api_prefix, "API_PREFIX");
    env_override!(config.server.admin_did, "ADMIN_DID");
    env_override_opt!(config.server.did_web_self_hosted, "DID_WEB_SELF_HOSTED");

    // Database
    env_override!(config.database.functions_file, "DATABASE_FUNCTIONS_FILE");
    env_override!(config.database.database_url, "DATABASE_URL");
    env_override!(config.database.database_pool_size, "DATABASE_POOL_SIZE");
    env_override!(config.database.database_timeout, "DATABASE_TIMEOUT");

    // Security
    env_override!(config.security.mediator_acl_mode, "MEDIATOR_ACL_MODE");
    env_override!(config.security.global_acl_default, "GLOBAL_DEFAULT_ACL");
    env_override!(config.security.local_direct_delivery_allowed, "LOCAL_DIRECT_DELIVERY_ALLOWED");
    env_override!(config.security.local_direct_delivery_allow_anon, "LOCAL_DIRECT_DELIVERY_ALLOW_ANON");
    env_override!(config.security.mediator_secrets, "MEDIATOR_SECRETS");
    env_override!(config.security.use_ssl, "USE_SSL");
    env_override_opt!(config.security.ssl_certificate_file, "SSL_CERTIFICATE_FILE");
    env_override_opt!(config.security.ssl_key_file, "SSL_KEY_FILE");
    env_override!(config.security.jwt_authorization_secret, "JWT_AUTHORIZATION_SECRET");
    env_override!(config.security.jwt_access_expiry, "JWT_ACCESS_EXPIRY");
    env_override!(config.security.jwt_refresh_expiry, "JWT_REFRESH_EXPIRY");
    env_override_opt!(config.security.cors_allow_origin, "CORS_ALLOW_ORIGIN");
    env_override!(config.security.block_anonymous_outer_envelope, "BLOCK_ANONYMOUS_OUTER_ENVELOPE");
    env_override!(config.security.force_session_did_match, "FORCE_SESSION_DID_MATCH");
    env_override!(config.security.block_remote_admin_msgs, "BLOCK_REMOTE_ADMIN_MSGS");
    env_override!(config.security.admin_messages_expiry, "ADMIN_MESSAGES_EXPIRY");

    // Streaming
    env_override!(config.streaming.enabled, "STREAMING_ENABLED");
    env_override!(config.streaming.uuid, "STREAMING_UUID");

    // DID Resolver
    env_override_opt!(config.did_resolver.address, "DID_RESOLVER_ADDRESS");
    env_override!(config.did_resolver.cache_capacity, "DID_RESOLVER_CACHE_CAPACITY");
    env_override!(config.did_resolver.cache_ttl, "DID_RESOLVER_CACHE_TTL");
    env_override!(config.did_resolver.network_timeout, "DID_RESOLVER_NETWORK_TIMEOUT");
    env_override!(config.did_resolver.network_limit, "DID_RESOLVER_NETWORK_LIMIT");

    // Limits
    env_override!(config.limits.attachments_max_count, "LIMIT_ATTACHMENTS_MAX_COUNT");
    env_override!(config.limits.crypto_operations_per_message, "LIMIT_CRYPTO_OPERATIONS_PER_MESSAGE");
    env_override!(config.limits.deleted_messages, "LIMIT_DELETED_MESSAGES");
    env_override!(config.limits.forward_task_queue, "LIMIT_FORWARD_TASK_QUEUE");
    env_override!(config.limits.http_size, "LIMIT_HTTP_SIZE");
    env_override!(config.limits.listed_messages, "LIMIT_LISTED_MESSAGES");
    env_override!(config.limits.local_max_acl, "LIMIT_LOCAL_MAX_ACL");
    env_override!(config.limits.message_expiry_seconds, "LIMIT_MESSAGE_EXPIRY_SECONDS");
    env_override!(config.limits.message_size, "LIMIT_MESSAGE_SIZE");
    env_override!(config.limits.queued_send_messages_soft, "LIMIT_QUEUED_SEND_MESSAGES_SOFT");
    env_override!(config.limits.queued_send_messages_hard, "LIMIT_QUEUED_SEND_MESSAGES_HARD");
    env_override!(config.limits.queued_receive_messages_soft, "LIMIT_QUEUED_RECEIVE_MESSAGES_SOFT");
    env_override!(config.limits.queued_receive_messages_hard, "LIMIT_QUEUED_RECEIVE_MESSAGES_HARD");
    env_override!(config.limits.to_keys_per_recipient, "LIMIT_TO_KEYS_PER_DID");
    env_override!(config.limits.to_recipients, "LIMIT_TO_RECIPIENTS");
    env_override!(config.limits.ws_size, "LIMIT_WS_SIZE");
    env_override!(config.limits.access_list_limit, "ACCESS_LIST_LIMIT");
    env_override!(config.limits.oob_invite_ttl, "OOB_INVITE_TTL");
    env_override!(config.limits.rate_limit_per_ip, "LIMIT_RATE_LIMIT_PER_IP");
    env_override!(config.limits.rate_limit_burst, "LIMIT_RATE_LIMIT_BURST");
    env_override!(config.limits.max_websocket_connections, "LIMIT_MAX_WEBSOCKET_CONNECTIONS");
    env_override!(config.limits.did_rate_limit_per_second, "LIMIT_DID_RATE_LIMIT_PER_SECOND");
    env_override!(config.limits.did_rate_limit_burst, "LIMIT_DID_RATE_LIMIT_BURST");

    // Processors - Forwarding
    env_override!(config.processors.forwarding.enabled, "PROCESSOR_FORWARDING_ENABLED");
    env_override!(config.processors.forwarding.future_time_limit, "PROCESSOR_FORWARDING_FUTURE_TIME_LIMIT");
    env_override!(config.processors.forwarding.external_forwarding, "PROCESSOR_FORWARDING_EXTERNAL");
    env_override!(config.processors.forwarding.report_errors, "PROCESSOR_FORWARDING_REPORT_ERRORS");
    env_override!(config.processors.forwarding.blocked_forwarding_dids, "PROCESSOR_FORWARDING_BLOCKED_DIDS");
    env_override!(config.processors.forwarding.rate_window_seconds, "PROCESSOR_FORWARDING_RATE_WINDOW");
    env_override!(config.processors.forwarding.ws_threshold_msgs_per_10s, "PROCESSOR_FORWARDING_WS_THRESHOLD");
    env_override!(config.processors.forwarding.ws_idle_timeout_seconds, "PROCESSOR_FORWARDING_WS_IDLE_TIMEOUT");
    env_override!(config.processors.forwarding.batch_size, "PROCESSOR_FORWARDING_BATCH_SIZE");
    env_override!(config.processors.forwarding.max_retries, "PROCESSOR_FORWARDING_MAX_RETRIES");
    env_override!(config.processors.forwarding.initial_backoff_ms, "PROCESSOR_FORWARDING_INITIAL_BACKOFF_MS");
    env_override!(config.processors.forwarding.max_backoff_ms, "PROCESSOR_FORWARDING_MAX_BACKOFF_MS");
    env_override!(config.processors.forwarding.consumer_group, "PROCESSOR_FORWARDING_CONSUMER_GROUP");

    // Processors - Message Expiry Cleanup
    env_override!(config.processors.message_expiry_cleanup.enabled, "PROCESSOR_MESSAGE_EXPIRY_CLEANUP_ENABLED");

    // VTA - create section from env vars if not present in TOML
    if config.vta.is_none() {
        if let Ok(credential) = env::var("VTA_CREDENTIAL") {
            config.vta = Some(VtaConfigRaw {
                credential,
                context: env::var("VTA_CONTEXT").ok(),
                url: env::var("VTA_URL").ok(),
            });
        }
    } else if let Some(vta) = config.vta.as_mut() {
        env_override!(vta.credential, "VTA_CREDENTIAL");
        env_override_opt!(vta.context, "VTA_CONTEXT");
        env_override_opt!(vta.url, "VTA_URL");
    }
}

/// Loads the secret data into the Config file.
/// Supports file://, aws_secrets://, and vta:// (Verifiable Trust Agent) schemes.
pub(crate) async fn load_secrets(
    secrets_resolver: &Arc<ThreadedSecretsResolver>,
    secrets: &str,
    aws_config: &SdkConfig,
    vta_client: Option<&VtaClient>,
) -> Result<(), MediatorError> {
    let parts: Vec<&str> = secrets.split("://").collect();
    if parts.len() != 2 {
        return Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            "Invalid `mediator_secrets` format".into(),
        ));
    }
    println!("Loading secrets method({}) path({})", parts[0], parts[1]);

    // VTA path: fetch secrets from VTA context.
    // We manually list keys and get each secret because the VTA stores raw key bytes
    // (without multicodec prefix), but Secret::from_multibase requires the prefix to
    // identify the key type. We re-add the prefix using the key_type from the response.
    if parts[0] == "vta" {
        let client = vta_client.ok_or_else(|| {
            MediatorError::ConfigError(
                12,
                "NA".into(),
                "VTA client not initialized but vta:// scheme used for mediator_secrets".into(),
            )
        })?;
        let context_id = parts[1];

        // List all keys in the context
        let keys_resp = client.list_keys(0, 1000, None, Some(context_id)).await.map_err(|e| {
            MediatorError::ConfigError(12, "NA".into(), format!("Could not list keys from VTA: {e}"))
        })?;
        info!("Found {} key(s) in VTA context '{context_id}'", keys_resp.keys.len());

        let mut vta_secrets = Vec::with_capacity(keys_resp.keys.len());
        for key in &keys_resp.keys {
            let secret_resp = client.get_key_secret(&key.key_id).await.map_err(|e| {
                MediatorError::ConfigError(
                    12, "NA".into(),
                    format!("Could not fetch secret for key '{}': {e}", key.key_id),
                )
            })?;

            // Re-encode the private key with the multicodec prefix so that
            // Secret::from_multibase can identify the key type.
            let multibase_with_codec = reencode_with_multicodec(
                &secret_resp.private_key_multibase,
                &key.key_type,
                &key.key_id,
            )?;

            // Use the key's label as the Secret ID if it looks like a verification method ID
            // (e.g., "did:web:example.com#key-0"). The label is set by the setup wizard to
            // match the DID document's verification method IDs. Falls back to VTA key_id.
            let secret_id = key.label.as_deref()
                .filter(|l| l.contains('#') || l.starts_with("did:"))
                .unwrap_or(&key.key_id);

            let secret = Secret::from_multibase(&multibase_with_codec, Some(secret_id))
                .map_err(|e| {
                    MediatorError::ConfigError(
                        12, "NA".into(),
                        format!("Could not create Secret from VTA key '{}': {e}", key.key_id),
                    )
                })?;
            vta_secrets.push(secret);
        }

        info!(
            "Loading {} mediator Secret{} from VTA context '{context_id}'",
            vta_secrets.len(),
            if vta_secrets.len() == 1 { "" } else { "s" }
        );
        secrets_resolver.insert_vec(&vta_secrets).await;
        return Ok(());
    }

    // File / AWS path: fetch JSON content then parse
    let content: String = match parts[0] {
        "file" => read_file_lines(parts[1])?.concat(),
        "aws_secrets" => {
            let asm = aws_sdk_secretsmanager::Client::new(aws_config);

            let response = asm
                .get_secret_value()
                .secret_id(parts[1])
                .send()
                .await
                .map_err(|e| {
                    eprintln!("Could not get secret value. {e:?}");
                    MediatorError::ConfigError(
                        12,
                        "NA".into(),
                        format!("Could not get secret value. {e:?}"),
                    )
                })?;
            response.secret_string.ok_or_else(|| {
                eprintln!("No secret string found in response");
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    "No secret string found in response".into(),
                )
            })?
        }
        _ => {
            return Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                "Invalid `mediator_secrets` format! Expecting file://, aws_secrets://, or vta:// ...".into(),
            ));
        }
    };

    let secrets: Vec<Secret> = serde_json::from_str(&content).map_err(|err| {
        eprintln!("Could not parse `mediator_secrets` JSON content. {err}");
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!("Could not parse `mediator_secrets` JSON content. {err}"),
        )
    })?;

    info!(
        "Loading {} mediator Secret{}",
        secrets.len(),
        if secrets.is_empty() { "" } else { "s" }
    );
    secrets_resolver.insert_vec(&secrets).await;

    Ok(())
}

/// Re-encode a VTA private key (raw bytes in multibase) with the appropriate multicodec
/// prefix so that `Secret::from_multibase` can identify the key type.
///
/// The VTA stores raw key bytes without multicodec prefix, but the secrets resolver
/// needs the prefix to determine if a key is Ed25519, X25519, P256, etc.
fn reencode_with_multicodec(
    private_key_multibase: &str,
    key_type: &vta_sdk::keys::KeyType,
    key_id: &str,
) -> Result<String, MediatorError> {
    use affinidi_encoding::{ED25519_PRIV, X25519_PRIV, P256_PRIV, decode_multikey_with_codec, encode_multikey};

    // First check if the key already has a valid multicodec prefix
    if let Ok((codec, _)) = decode_multikey_with_codec(private_key_multibase) {
        let codec_type = affinidi_encoding::Codec::from_u64(codec);
        if !matches!(codec_type, affinidi_encoding::Codec::Unknown(_)) {
            // Already has a valid multicodec prefix — return as-is
            return Ok(private_key_multibase.to_string());
        }
    }

    // No valid prefix — decode raw bytes and re-encode with the correct codec
    let raw_bytes = affinidi_encoding::decode_base58btc(private_key_multibase).map_err(|e| {
        MediatorError::ConfigError(
            12, "NA".into(),
            format!("Could not decode private key for '{}': {e}", key_id),
        )
    })?;

    let codec = match key_type {
        vta_sdk::keys::KeyType::Ed25519 => ED25519_PRIV,
        vta_sdk::keys::KeyType::X25519 => X25519_PRIV,
        vta_sdk::keys::KeyType::P256 => P256_PRIV,
    };

    Ok(encode_multikey(codec, &raw_bytes))
}

/// Read the primary configuration file for the mediator.
/// Returns a ConfigRaw struct with env var overrides applied.
pub(crate) fn read_config_file(file_name: &str) -> Result<super::ConfigRaw, MediatorError> {
    println!("Config file({file_name})");
    let raw_config = read_file_lines(file_name)?;

    let mut config: super::ConfigRaw = toml::from_str(&raw_config.join("\n")).map_err(|err| {
        eprintln!("Could not parse configuration settings. {err:?}");
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!("Could not parse configuration settings. Reason: {err:?}"),
        )
    })?;

    // Apply environment variable overrides (env vars take priority over TOML values)
    apply_env_overrides(&mut config);

    Ok(config)
}

/// Reads a file and returns a vector of strings, one for each line in the file.
/// It also strips any lines starting with a # (comments)
/// You can join the Vec back into a single string with `.join("\n")`
/// ```ignore
/// let lines = read_file_lines("file.txt")?;
/// let file_contents = lines.join("\n");
/// ```
pub(crate) fn read_file_lines<P>(file_name: P) -> Result<Vec<String>, MediatorError>
where
    P: AsRef<Path>,
{
    let file = File::open(file_name.as_ref()).map_err(|err| {
        eprintln!(
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
        // Strip comments out
        if !line.starts_with('#') {
            lines.push(line);
        }
    }

    Ok(lines)
}

/// Converts the mediator_did config to a valid DID depending on source.
/// Supports did://, aws_parameter_store://, and vta:// (Verifiable Trust Agent) schemes.
pub(crate) async fn read_did_config(
    did_config: &str,
    aws_config: &SdkConfig,
    field_name: &str,
    vta_client: Option<&VtaClient>,
) -> Result<String, MediatorError> {
    let parts: Vec<&str> = did_config.split("://").collect();
    if parts.len() != 2 {
        return Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            format!("Invalid `{field_name}` format"),
        ));
    }
    let content: String = match parts[0] {
        "did" => parts[1].to_string(),
        "aws_parameter_store" => aws_parameter_store(parts[1], aws_config).await?,
        "vta" => {
            let client = vta_client.ok_or_else(|| {
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!("VTA client not initialized but vta:// scheme used for {field_name}"),
                )
            })?;
            let context_id = parts[1];
            info!("Fetching {field_name} from VTA context '{context_id}'");
            let ctx = client.get_context(context_id).await.map_err(|e| {
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!("Could not fetch context '{context_id}' from VTA: {e}"),
                )
            })?;
            ctx.did.ok_or_else(|| {
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    format!("VTA context '{context_id}' has no DID configured"),
                )
            })?
        }
        _ => {
            return Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                format!("Invalid {field_name} format! Expecting did://, aws_parameter_store://, or vta:// ..."),
            ));
        }
    };

    Ok(content)
}

/// Converts the jwt_authorization_secret config to a valid JWT secret
/// Can take a basic string, or fetch from AWS Secrets Manager
pub(crate) async fn config_jwt_secret(
    jwt_secret: &str,
    aws_config: &SdkConfig,
) -> Result<Vec<u8>, MediatorError> {
    let parts: Vec<&str> = jwt_secret.split("://").collect();
    if parts.len() != 2 {
        return Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            "Invalid `jwt_authorization_secret` format".into(),
        ));
    }
    let content: String = match parts[0] {
        "string" => parts[1].to_string(),
        "aws_secrets" => {
            println!("Loading JWT secret from AWS Secrets Manager");
            let asm = aws_sdk_secretsmanager::Client::new(aws_config);

            let response = asm
                .get_secret_value()
                .secret_id(parts[1])
                .send()
                .await
                .map_err(|e| {
                    eprintln!("Could not get secret value. {e:?}");
                    MediatorError::ConfigError(
                        12,
                        "NA".into(),
                        format!("Could not get secret value. {e:?}"),
                    )
                })?;
            response.secret_string.ok_or_else(|| {
                eprintln!("No secret string found in response");
                MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    "No secret string found in response".into(),
                )
            })?
        }
        _ => return Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            "Invalid `jwt_authorization_secret` format! Expecting string:// or aws_secrets:// ..."
                .into(),
        )),
    };

    BASE64_URL_SAFE_NO_PAD.decode(content).map_err(|err| {
        eprintln!("Could not create JWT key pair. {err}");
        MediatorError::ConfigError(
            12,
            "NA".into(),
            format!("Could not create JWT key pair. {err}"),
        )
    })
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

pub(crate) async fn aws_parameter_store(
    parameter_name: &str,
    aws_config: &SdkConfig,
) -> Result<String, MediatorError> {
    let ssm = aws_sdk_ssm::Client::new(aws_config);

    let response = ssm
        .get_parameter()
        // .set_name(Some(parts[1].to_string()))
        .set_name(Some(parameter_name.to_string()))
        .send()
        .await
        .map_err(|e| {
            eprintln!("Could not get ({parameter_name:?}) parameter. {e:?}");
            MediatorError::ConfigError(
                12,
                "NA".into(),
                format!("Could not get ({parameter_name:?}) parameter. {e:?}"),
            )
        })?;
    let parameter = response.parameter.ok_or_else(|| {
        eprintln!("No parameter string found in response");
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
        eprintln!(
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
    aws_config: &SdkConfig,
) -> Result<String, MediatorError> {
    let parts: Vec<&str> = document_path.split("://").collect();
    if parts.len() != 2 {
        return Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            "Invalid `document_path` format".into(),
        ));
    }
    let content: String = match parts[0] {
        "file" => read_file_lines(parts[1])?.concat(),
        "aws_parameter_store" => aws_parameter_store(parts[1], aws_config).await?,
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

/// Loads the VTA credential from the configured source.
/// Supported schemes:
/// - `string://<base64url>` - Direct credential string (for CI/CD via env vars)
/// - `aws_secrets://<secret_name>` - Load from AWS Secrets Manager
/// - `keyring://<service>/<user>` - Load from OS keyring (requires `vta-keyring` feature)
pub(crate) async fn load_vta_credential(
    credential_config: &str,
    #[cfg_attr(not(feature = "vta-aws-secrets"), allow(unused_variables))]
    aws_config: &SdkConfig,
) -> Result<String, MediatorError> {
    let parts: Vec<&str> = credential_config.split("://").collect();
    if parts.len() != 2 {
        return Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            "Invalid VTA credential format. Expected string://, aws_secrets://, or keyring://".into(),
        ));
    }

    match parts[0] {
        "string" => {
            info!("Loading VTA credential from config/environment");
            Ok(parts[1].to_string())
        }
        "aws_secrets" => {
            #[cfg(feature = "vta-aws-secrets")]
            {
                info!("Loading VTA credential from AWS Secrets Manager");
                let asm = aws_sdk_secretsmanager::Client::new(aws_config);
                let response = asm
                    .get_secret_value()
                    .secret_id(parts[1])
                    .send()
                    .await
                    .map_err(|e| {
                        eprintln!("Could not get VTA credential from AWS Secrets Manager. {e:?}");
                        MediatorError::ConfigError(
                            12,
                            "NA".into(),
                            format!("Could not get VTA credential from AWS Secrets Manager. {e:?}"),
                        )
                    })?;
                response.secret_string.ok_or_else(|| {
                    MediatorError::ConfigError(
                        12,
                        "NA".into(),
                        "No secret string found in AWS Secrets Manager response for VTA credential".into(),
                    )
                })
            }
            #[cfg(not(feature = "vta-aws-secrets"))]
            {
                Err(MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    "aws_secrets:// for VTA credentials requires the 'vta-aws-secrets' feature. \
                     Rebuild with: cargo build --features vta-aws-secrets".into(),
                ))
            }
        }
        "keyring" => {
            #[cfg(feature = "vta-keyring")]
            {
                info!("Loading VTA credential from OS keyring");
                let keyring_parts: Vec<&str> = parts[1].splitn(2, '/').collect();
                let (service, user) = match keyring_parts.len() {
                    2 => (keyring_parts[0], keyring_parts[1]),
                    1 => (keyring_parts[0], "credential"),
                    _ => {
                        return Err(MediatorError::ConfigError(
                            12,
                            "NA".into(),
                            "Invalid keyring path. Expected keyring://service or keyring://service/user".into(),
                        ));
                    }
                };
                let entry = keyring::Entry::new(service, user).map_err(|e| {
                    MediatorError::ConfigError(
                        12,
                        "NA".into(),
                        format!("Could not access keyring entry '{service}/{user}': {e}"),
                    )
                })?;
                entry.get_password().map_err(|e| {
                    MediatorError::ConfigError(
                        12,
                        "NA".into(),
                        format!("Could not read VTA credential from keyring '{service}/{user}': {e}"),
                    )
                })
            }
            #[cfg(not(feature = "vta-keyring"))]
            {
                Err(MediatorError::ConfigError(
                    12,
                    "NA".into(),
                    "keyring:// requires the 'vta-keyring' feature. Rebuild with: cargo build --features vta-keyring".into(),
                ))
            }
        }
        _ => Err(MediatorError::ConfigError(
            12,
            "NA".into(),
            format!(
                "Invalid VTA credential scheme '{}'. Expected string://, aws_secrets://, or keyring://",
                parts[0]
            ),
        )),
    }
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
            eprintln!("Could not parse blocked_forwarding_dids. Reason: {err}");
            return Err(MediatorError::ConfigError(
                12,
                "NA".into(),
                format!("Could not parse blocked_forwarding_dids. Reason: {err}"),
            ));
        }
    };

    // Add the mediator DID to the blocked list
    blocked_dids.push(mediator_did.into());

    // Iterate through each DID that we need to block
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

        // Add the service endpoints to the forwarding protection list
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
                                    eprintln!("WARN: Couldn't parse URI as a string: {uri:#?}");
                                }
                            } else {
                                eprintln!(
                                    "WARN: Service endpoint map does not contain a URI. DID ({did}), Service ({service:#?}), Endpoint ({endpoint:#?})"
                                );
                            }
                        }
                    } else if let Some(uri) = map.get("uri") {
                        if let Some(uri) = uri.as_str() {
                            forwarding_config.blocked_forwarding.insert(uri.into());
                        } else {
                            eprintln!("WARN: Couldn't parse URI as a string: {uri:#?}");
                        }
                    } else {
                        eprintln!(
                            "WARN: Service endpoint map does not contain a URI. DID ({did}), Service ({service:#?}), Endpoint ({map:#?})"
                        );
                    }
                }
            }
        }
    }

    Ok(())
}
