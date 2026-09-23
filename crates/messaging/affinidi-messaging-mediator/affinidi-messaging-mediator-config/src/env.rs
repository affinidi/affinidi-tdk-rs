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

use tracing::{error, info, warn};

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

/// Override a `Vec<String>` field from a comma-separated environment variable.
macro_rules! env_override_list {
    ($field:expr, $env_var:expr) => {
        if let Ok(val) = std::env::var($env_var) {
            $field = split_list(&val);
        }
    };
}

/// Split a comma-separated environment value into list entries.
///
/// Entries are trimmed and empties dropped, so `""` clears the list and
/// `"a, b"` is the same as `"a,b"`. TOML gives these fields a real array, so
/// the comma form exists only for the environment.
fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect()
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
    env_override_list!(config.server.local_endpoints, "LOCAL_ENDPOINTS");

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
    env_override!(
        config.security.trust_task_verification,
        "TRUST_TASK_VERIFICATION"
    );
    env_override!(
        config.security.legacy_admin_protocols,
        "LEGACY_ADMIN_PROTOCOLS"
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
        config.limits.delivered_expiry_seconds,
        "LIMIT_DELIVERED_EXPIRY_SECONDS"
    );
    env_override!(config.limits.pickup_round_robin, "LIMIT_PICKUP_ROUND_ROBIN");
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
    env_override!(config.limits.ws_send_buffer, "LIMIT_WS_SEND_BUFFER");
    env_override!(config.limits.pubsub_buffer, "LIMIT_PUBSUB_BUFFER");

    // `[storage]` is optional, and `[storage.fjall]` is optional within it, so
    // these only override a section that already exists. An env var alone does
    // not conjure a storage backend into being — selecting the backend is a
    // deliberate choice that belongs in the file.
    if let Some(storage) = config.storage.as_mut() {
        env_override!(storage.backend, "STORAGE_BACKEND");
        env_override_opt!(storage.data_dir, "STORAGE_DATA_DIR");
        if storage.fjall.is_none()
            && (std::env::var("STORAGE_FJALL_BLOCK_CACHE").is_ok()
                || std::env::var("STORAGE_FJALL_WRITE_BUFFER").is_ok()
                || std::env::var("STORAGE_FJALL_MAX_JOURNAL").is_ok())
        {
            // Any one of the knobs being set means the operator wants to tune;
            // materialise the section at its defaults so the override lands.
            storage.fjall = Some(crate::FjallConfig::default());
        }
        if let Some(fjall) = storage.fjall.as_mut() {
            env_override!(fjall.block_cache, "STORAGE_FJALL_BLOCK_CACHE");
            env_override!(fjall.write_buffer, "STORAGE_FJALL_WRITE_BUFFER");
            env_override!(fjall.max_journal, "STORAGE_FJALL_MAX_JOURNAL");
        }
    }

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
        config.processors.forwarding.max_hops,
        "PROCESSOR_FORWARDING_MAX_HOPS"
    );
    env_override!(
        config.processors.forwarding.relay_mode,
        "PROCESSOR_FORWARDING_RELAY_MODE"
    );
    env_override!(
        config.processors.forwarding.relay_trusted_mediators,
        "PROCESSOR_FORWARDING_RELAY_TRUSTED_MEDIATORS"
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
///
/// Keys the schema does not recognise are logged as warnings (see
/// [`warn_unknown_keys`]). That only reaches an operator once a tracing
/// subscriber is installed; a caller that reads the file *before* installing
/// one — the mediator's own startup — should use
/// [`read_config_file_with_unknown_keys`] and warn once logging is up.
pub fn read_config_file(file_name: &str) -> Result<ConfigRaw, ConfigError> {
    let (config, unknown_keys) = read_config_file_with_unknown_keys(file_name)?;
    warn_unknown_keys(file_name, &unknown_keys);
    Ok(config)
}

/// [`read_config_file`], also returning the dotted path of every key in the
/// file that the schema does not recognise, instead of logging them.
///
/// Unknown keys are reported, never rejected: a config that boots today must
/// keep booting. The usual cause is not a typo but TOML's table scoping — a
/// key appended at the end of the file lands in whichever `[table]` header
/// precedes it, so `cors_allow_origin` written below
/// `[processors.session_expiry_cleanup]` is
/// `processors.session_expiry_cleanup.cors_allow_origin`, which nothing reads.
pub fn read_config_file_with_unknown_keys(
    file_name: &str,
) -> Result<(ConfigRaw, Vec<String>), ConfigError> {
    info!("Config file({file_name})");
    let raw_config = read_file_lines(file_name)?;

    let (mut config, unknown_keys) = parse_config(&raw_config.join("\n")).map_err(|err| {
        error!("Could not parse configuration settings. {err}");
        err
    })?;

    apply_env_overrides(&mut config);

    Ok((config, unknown_keys))
}

/// Deserialize `mediator.toml` contents into a [`ConfigRaw`] (no env
/// overrides), collecting the dotted path of every key the schema ignored.
pub fn parse_config(contents: &str) -> Result<(ConfigRaw, Vec<String>), ConfigError> {
    // `Display`, not `Debug`: toml's rendering names the line, the key and the
    // expected type — e.g. an array given for the comma-separated
    // `cors_allow_origin` reads "invalid type: sequence, expected a string".
    let parse_err = |err: toml::de::Error| ConfigError::Parse(err.to_string());
    let de = toml::Deserializer::parse(contents).map_err(parse_err)?;
    let mut unknown_keys = Vec::new();
    let config = serde_ignored::deserialize(de, |path| unknown_keys.push(path.to_string()))
        .map_err(parse_err)?;
    Ok((config, unknown_keys))
}

/// The operator-facing warning for one unrecognised key.
pub fn unknown_key_message(file_name: &str, key: &str) -> String {
    match key.rsplit_once('.') {
        Some((table, leaf)) => format!(
            "unknown configuration key `{key}` in {file_name} — ignored. The mediator \
             has no `{leaf}` setting in [{table}]. Check for a typo or a removed \
             setting; if `{leaf}` belongs to another section, note that a key \
             placed after a [table] header belongs to that table, so a key \
             appended at the end of the file lands in its last section. Move it \
             under its own section header."
        ),
        None => format!(
            "unknown configuration key `{key}` in {file_name} — ignored. Check for a \
             typo or a removed/renamed setting."
        ),
    }
}

/// Log one warning per unrecognised key, naming its full dotted path.
pub fn warn_unknown_keys(file_name: &str, unknown_keys: &[String]) {
    for key in unknown_keys {
        warn!("{}", unknown_key_message(file_name, key));
    }
}

/// Reads a file and returns a vector of strings, one for each line in the file.
/// Lines starting with `#` (comments) are blanked rather than dropped, so a
/// parse error's line number still points at the line in the file.
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
        if line.starts_with('#') {
            lines.push(String::new());
        } else {
            lines.push(line);
        }
    }

    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::{parse_config, split_list, unknown_key_message};

    const SHIPPED: &str = include_str!("../../conf/mediator.toml");

    /// A valid config reports nothing — a warning that always fires is one
    /// operators learn to ignore.
    #[test]
    fn the_shipped_config_has_no_unknown_keys() {
        let (_, unknown) = parse_config(SHIPPED).expect("shipped config parses");
        assert!(unknown.is_empty(), "unexpected unknown keys: {unknown:?}");
    }

    /// Keyring VTI-06: a key appended below the last table header is filed
    /// under that table. It used to vanish without a word; now it is reported
    /// with the path it actually landed at.
    #[test]
    fn a_key_appended_after_the_last_table_is_reported_with_its_dotted_path() {
        let toml = format!("{SHIPPED}\ncors_allow_origin = \"*\"\n");
        let (config, unknown) = parse_config(&toml).expect("still parses");
        assert_eq!(
            unknown,
            vec!["processors.session_expiry_cleanup.cors_allow_origin".to_string()]
        );
        // And it did not take effect — which is exactly why it is reported.
        assert!(config.security.cors_allow_origin.is_none());

        let msg = unknown_key_message("mediator.toml", &unknown[0]);
        assert!(msg.contains("`processors.session_expiry_cleanup.cors_allow_origin`"));
        assert!(msg.contains("a key placed after a [table] header belongs to that table"));
    }

    /// The same key appended as an array (the shape the Keyring report used)
    /// is still just an unknown key when misplaced — its type is never checked
    /// because nothing reads it.
    #[test]
    fn a_misplaced_array_is_reported_not_rejected() {
        let toml = format!("{SHIPPED}\ncors_allow_origin = [\"*\"]\n");
        let (_, unknown) = parse_config(&toml).expect("still parses");
        assert_eq!(
            unknown,
            vec!["processors.session_expiry_cleanup.cors_allow_origin".to_string()]
        );
    }

    /// In the right section, an array is the wrong type for the
    /// comma-separated `cors_allow_origin`, and the error says so by name.
    #[test]
    fn an_array_cors_allow_origin_in_security_is_a_clear_error() {
        let toml = SHIPPED.replacen(
            "\n[security]\n",
            "\n[security]\ncors_allow_origin = [\"*\"]\n",
            1,
        );
        assert_ne!(toml, SHIPPED, "fixture must actually inject the key");
        let err = parse_config(&toml)
            .expect_err("an array is not a string")
            .to_string();
        assert!(err.contains("cors_allow_origin"), "{err}");
        assert!(err.contains("expected a string"), "{err}");
    }

    /// A top-level typo has no table to blame; the message does not invent one.
    #[test]
    fn a_top_level_unknown_key_is_reported_plainly() {
        let toml = format!("log_levle = \"debug\"\n{SHIPPED}");
        let (_, unknown) = parse_config(&toml).expect("still parses");
        assert_eq!(unknown, vec!["log_levle".to_string()]);
        assert!(!unknown_key_message("m.toml", "log_levle").contains("[table]"));
    }

    #[test]
    fn split_list_trims_entries_and_drops_empties() {
        assert_eq!(
            split_list("https://a.example.com, https://b.example.com:7037"),
            vec![
                "https://a.example.com".to_string(),
                "https://b.example.com:7037".to_string(),
            ]
        );
        assert_eq!(split_list("did:example:one"), vec!["did:example:one"]);
        // A trailing separator is a typo, not an empty entry.
        assert_eq!(split_list("did:example:one,"), vec!["did:example:one"]);
    }

    /// An empty value clears the list rather than producing one empty entry —
    /// this is how an operator turns off a TOML-configured allowlist from the
    /// environment.
    #[test]
    fn split_list_empty_value_clears_the_list() {
        assert!(split_list("").is_empty());
        assert!(split_list("  ").is_empty());
        assert!(split_list(",,").is_empty());
    }
}
