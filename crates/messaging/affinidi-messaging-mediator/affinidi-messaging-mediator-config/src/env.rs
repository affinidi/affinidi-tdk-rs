//! Config file reading + environment-variable overrides.
//!
//! `read_config_file` reads `mediator.toml`, deserializes it into
//! [`ConfigRaw`](crate::ConfigRaw), and applies env-var overrides (env wins
//! over the file). Runtime resolution (secrets, DID resolver, VTA) happens
//! later, in the mediator binary.

use std::{
    fs::File,
    io::{self, BufRead},
    path::Path,
};

use tracing::{error, info};

use crate::ConfigRaw;
use crate::error::ConfigError;

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
pub fn apply_env_overrides(config: &mut ConfigRaw) {
    env_override!(config.log_level, "LOG_LEVEL");
    env_override!(config.log_json, "LOG_JSON");
    env_override!(config.mediator_did, "MEDIATOR_DID");

    env_override!(config.server.listen_address, "LISTEN_ADDRESS");
    env_override!(config.server.api_prefix, "API_PREFIX");
    env_override!(config.server.admin_did, "ADMIN_DID");
    env_override_opt!(config.server.did_web_self_hosted, "DID_WEB_SELF_HOSTED");

    env_override!(config.database.functions_file, "DATABASE_FUNCTIONS_FILE");
    env_override!(config.database.database_url, "DATABASE_URL");
    // DATABASE_POOL_SIZE removed — the mediator uses a multiplexed
    // connection, there is no pool to size. Pre-0.14 deployments that
    // set it can drop the env var with no behaviour change.
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
        config.security.enable_inter_mediator_relay,
        "ENABLE_INTER_MEDIATOR_RELAY"
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
        config.limits.max_websocket_connections_per_did,
        "LIMIT_MAX_WEBSOCKET_CONNECTIONS_PER_DID"
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

    env_override!(
        config.processors.session_expiry_cleanup.enabled,
        "PROCESSOR_SESSION_EXPIRY_CLEANUP_ENABLED"
    );

    env_override!(config.secrets.backend, "MEDIATOR_SECRETS_BACKEND");
    env_override_opt!(config.secrets.cache_ttl, "MEDIATOR_SECRETS_CACHE_TTL");
}

/// Read the primary configuration file for the mediator.
/// Returns a [`ConfigRaw`] with env var overrides applied.
pub fn read_config_file(file_name: &str) -> Result<ConfigRaw, ConfigError> {
    info!("Config file({file_name})");
    let raw_config = read_file_lines(file_name)?;

    let mut config: ConfigRaw = toml::from_str(&raw_config.join("\n")).map_err(|err| {
        error!("Could not parse configuration settings. {err:?}");
        ConfigError::Parse(format!("{err:?}"))
    })?;

    apply_env_overrides(&mut config);

    Ok(config)
}

/// Reads a file and returns a vector of strings, one for each line in the file.
/// Strips lines starting with `#` (comments).
fn read_file_lines<P>(file_name: P) -> Result<Vec<String>, ConfigError>
where
    P: AsRef<Path>,
{
    let path = file_name.as_ref();
    let file = File::open(path).map_err(|err| {
        error!("Could not open file({}). {}", path.display(), err);
        ConfigError::FileRead {
            path: path.display().to_string(),
            source: err,
        }
    })?;

    let mut lines = Vec::new();
    for line in io::BufReader::new(file).lines().map_while(Result::ok) {
        if !line.starts_with('#') {
            lines.push(line);
        }
    }

    Ok(lines)
}
