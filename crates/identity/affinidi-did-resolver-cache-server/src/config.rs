use crate::{errors::CacheError, limits::DEFAULT_MAX_INFLIGHT_PER_CONNECTION};
use affinidi_rate_limit::{ClientIpExtractor, IpNet};
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use std::{
    env, fmt,
    fs::File,
    io::{self, BufRead},
    path::Path,
    time::Duration,
};
use tracing::{Level, event, level_filters::LevelFilter};
use tracing_subscriber::{Registry, reload::Handle};

/// The `[cache]` table. Unknown keys are refused: a setting that belongs at the
/// top level but is written under `[cache]` must fail startup, not be dropped.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheConfig {
    #[serde(default = "default_capacity_count")]
    pub capacity_count: String,
    #[serde(default = "default_expire")]
    pub expire: String,
    /// TTL in seconds for cached raw `did:webvh` logs. `0` disables the cache,
    /// which re-fetches `did.jsonl` on every resolution.
    #[serde(default = "default_webvh_log_expire")]
    pub webvh_log_expire: String,
}

/// Default TTL for the raw `did:webvh` log cache.
///
/// Defaults to `0` (disabled) so behaviour is unchanged unless explicitly
/// enabled: caching these files trades upstream load against how quickly a
/// freshly-published log entry becomes visible, and that is the operator's
/// call to make.
fn default_webvh_log_expire() -> String {
    "0".into()
}

fn default_capacity_count() -> String {
    "1000".into()
}

fn default_expire() -> String {
    "300".into()
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            capacity_count: default_capacity_count(),
            expire: default_expire(),
            webvh_log_expire: default_webvh_log_expire(),
        }
    }
}

/// ConfigRaw Struct is used to deserialize the configuration file
/// We then convert this to the CacheConfig Struct
///
/// Unknown keys are refused, so a misspelt or misplaced setting fails startup
/// instead of silently leaving its default in force.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigRaw {
    pub log_level: String,
    pub listen_address: String,
    pub enable_http_endpoint: String,
    pub enable_websocket_endpoint: String,
    /// Agent name (DID shortcut) lookup endpoint. Defaults to **off**: it makes
    /// the server fetch caller-supplied URLs. See handlers/agent_names.rs.
    #[serde(default = "default_enable_agent_names")]
    pub enable_agent_names: String,
    /// Ceiling on agent name lookups fetching upstream at once. See
    /// `default_agent_name_concurrency`.
    #[serde(default = "default_agent_name_concurrency")]
    pub agent_name_concurrency: String,
    #[serde(default = "default_rate_limit_per_ip")]
    pub rate_limit_per_ip: String,
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: String,
    /// Comma-separated CIDRs of proxies whose `X-Forwarded-For` is read to find
    /// the client address. Empty: the socket peer is the client.
    #[serde(default)]
    pub trusted_proxies: String,
    /// IPv6 clients are charged and counted by this network prefix.
    #[serde(default = "default_client_ipv6_prefix")]
    pub client_ipv6_prefix: String,
    #[serde(default = "default_ws_max_connections")]
    pub ws_max_connections: String,
    #[serde(default = "default_ws_max_connections_per_ip")]
    pub ws_max_connections_per_ip: String,
    #[serde(default = "default_ws_idle_timeout")]
    pub ws_idle_timeout: String,
    #[serde(default = "default_ws_send_timeout")]
    pub ws_send_timeout: String,
    /// `0` (the default) derives the limit from `max_did_size`.
    #[serde(default = "default_ws_max_message_size")]
    pub ws_max_message_size: String,
    #[serde(default = "default_ws_max_inflight_per_connection")]
    pub ws_max_inflight_per_connection: String,
    pub statistics_interval: String,
    #[serde(default = "default_resolve_timeout")]
    pub resolve_timeout: String,
    #[serde(default = "default_max_did_size")]
    pub max_did_size: String,
    pub cache: CacheConfig,
}

/// Default upstream-resolution timeout (seconds), used when the config file
/// predates the `resolve_timeout` key.
fn default_resolve_timeout() -> String {
    "30".into()
}

/// Default maximum accepted DID length in bytes, used when the config file
/// predates the `max_did_size` key.
fn default_max_did_size() -> String {
    "1024".into()
}

/// Agent name lookup defaults to **off**. Enabling it lets callers make this
/// server issue HTTP requests to hosts of their choosing; see
/// `handlers/agent_names.rs` for the SSRF considerations.
fn default_enable_agent_names() -> String {
    "false".into()
}

/// Ceiling on agent name lookups fetching upstream at once.
///
/// Agent name resolution turns one cheap inbound request into one outbound HTTP
/// request to a host the *caller* chose. Without a ceiling that is an
/// amplification primitive: a shared cache server can be driven to fan out
/// arbitrary traffic at third parties, or used to scan them, at a cost to the
/// attacker of one request each.
///
/// The cap bounds that fan-out regardless of how many source addresses the load
/// arrives from, which per-IP rate limiting alone cannot do. Requests beyond it
/// are rejected immediately with 503 rather than queued, so a saturated server
/// sheds load instead of growing an unbounded backlog of pending fetches.
///
/// 16 is deliberately modest: agent name lookups are cache-warming, not a hot
/// path, and a cache server exists precisely so the fetch happens rarely.
fn default_agent_name_concurrency() -> String {
    "16".into()
}

/// Sustained requests per second per client IP; `0` disables limiting.
///
/// Matches the mediator's default. Generous for a resolver cache, whose whole
/// purpose is that most lookups are served from memory.
///
/// **Raise or disable this behind a load balancer or NAT**, where many clients
/// share one source address: `ConnectInfo` reports the *peer* address, so every
/// client behind a proxy is charged to one bucket and legitimate traffic gets
/// throttled.
fn default_rate_limit_per_ip() -> String {
    "100".into()
}

/// Token-bucket depth above the sustained per-IP rate.
fn default_rate_limit_burst() -> String {
    "50".into()
}

/// IPv6 clients are keyed by their /64: a host is normally given a whole /64,
/// so keying by address would give it a fresh bucket per address it picks.
const DEFAULT_CLIENT_IPV6_PREFIX: u8 = 64;
fn default_client_ipv6_prefix() -> String {
    DEFAULT_CLIENT_IPV6_PREFIX.to_string()
}

/// Open WebSocket connections across all clients.
const DEFAULT_WS_MAX_CONNECTIONS: usize = 4096;
fn default_ws_max_connections() -> String {
    DEFAULT_WS_MAX_CONNECTIONS.to_string()
}

/// Open WebSocket connections per client address. The SDK holds one connection
/// per client process, so this leaves room for many processes per host.
const DEFAULT_WS_MAX_CONNECTIONS_PER_IP: usize = 64;
fn default_ws_max_connections_per_ip() -> String {
    DEFAULT_WS_MAX_CONNECTIONS_PER_IP.to_string()
}

/// Seconds a WebSocket may go without receiving any frame before it is closed.
/// The SDK pings every 20 seconds, so its connections are never idle this long.
const DEFAULT_WS_IDLE_TIMEOUT_SECS: u64 = 120;
fn default_ws_idle_timeout() -> String {
    DEFAULT_WS_IDLE_TIMEOUT_SECS.to_string()
}

/// Seconds a single WebSocket send may take before the connection is closed.
const DEFAULT_WS_SEND_TIMEOUT_SECS: u64 = 10;
fn default_ws_send_timeout() -> String {
    DEFAULT_WS_SEND_TIMEOUT_SECS.to_string()
}

fn default_ws_max_message_size() -> String {
    "0".into()
}

/// Requests one WebSocket connection may have in progress at once.
fn default_ws_max_inflight_per_connection() -> String {
    DEFAULT_MAX_INFLIGHT_PER_CONNECTION.to_string()
}

/// The WebSocket message size used when `ws_max_message_size` is `0`: room for
/// a request carrying a name of `max_did_size` bytes twice (`did` and
/// `agent_name`) plus the JSON envelope.
pub fn derived_ws_max_message_size(max_did_size: usize) -> usize {
    max_did_size.saturating_mul(2).saturating_add(1024)
}

/// Parse `trusted_proxies`: comma-separated CIDRs (a bare address is a single
/// host). Empty means no proxy is trusted.
fn parse_trusted_proxies(value: &str) -> Result<Vec<IpNet>, CacheError> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry
                .parse::<IpNet>()
                .or_else(|_| entry.parse::<std::net::IpAddr>().map(IpNet::from))
                .map_err(|_| {
                    CacheError::ConfigError(
                        "NA".into(),
                        format!("trusted_proxies: ({entry}) is not an IP address or CIDR"),
                    )
                })
        })
        .collect()
}

pub struct Config {
    pub log_level: LevelFilter,
    pub listen_address: String,
    pub enable_http_endpoint: bool,
    pub enable_websocket_endpoint: bool,
    pub enable_agent_names: bool,
    pub agent_name_concurrency: usize,
    pub rate_limit_per_ip: u32,
    pub rate_limit_burst: u32,
    /// Proxies whose `X-Forwarded-For` names the client.
    pub trusted_proxies: Vec<IpNet>,
    /// IPv6 clients are rate limited and counted by this network prefix.
    pub client_ipv6_prefix: u8,
    /// Open WebSocket connections across all clients.
    pub ws_max_connections: usize,
    /// Open WebSocket connections per client address.
    pub ws_max_connections_per_ip: usize,
    /// A WebSocket that receives nothing for this long is closed.
    pub ws_idle_timeout: Duration,
    /// A WebSocket send that takes longer than this closes the connection.
    pub ws_send_timeout: Duration,
    /// Largest WebSocket message (and frame) accepted, in bytes.
    pub ws_max_message_size: usize,
    /// Requests one WebSocket connection may have in progress at once.
    pub ws_max_inflight_per_connection: usize,
    pub statistics_interval: Duration,
    /// Maximum time a single upstream DID resolution may take before the
    /// request path gives up and returns an error instead of blocking.
    pub resolve_timeout: Duration,
    /// Maximum accepted DID length in bytes; longer DIDs are rejected before
    /// resolution so a crafted request can't drive unbounded work.
    pub max_did_size: usize,
    pub cache_capacity_count: u32,
    pub cache_expire: u32,
    /// TTL in seconds for cached raw `did:webvh` logs; `0` disables the cache.
    pub webvh_log_expire: u32,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("log_level", &self.log_level)
            .field("listen_address", &self.listen_address)
            .field("enable_http_endpoint", &self.enable_http_endpoint)
            .field("enable_agent_names", &self.enable_agent_names)
            .field("agent_name_concurrency", &self.agent_name_concurrency)
            .field("rate_limit_per_ip", &self.rate_limit_per_ip)
            .field("rate_limit_burst", &self.rate_limit_burst)
            .field("enable_websocket_endpoint", &self.enable_websocket_endpoint)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("client_ipv6_prefix", &self.client_ipv6_prefix)
            .field("ws_max_connections", &self.ws_max_connections)
            .field("ws_max_connections_per_ip", &self.ws_max_connections_per_ip)
            .field(
                "ws_idle_timeout",
                &format!("{} seconds", self.ws_idle_timeout.as_secs()),
            )
            .field(
                "ws_send_timeout",
                &format!("{} seconds", self.ws_send_timeout.as_secs()),
            )
            .field(
                "ws_max_message_size",
                &format!("{} bytes", self.ws_max_message_size),
            )
            .field(
                "ws_max_inflight_per_connection",
                &self.ws_max_inflight_per_connection,
            )
            .field(
                "statistics_interval",
                &format!("{} seconds", self.statistics_interval.as_secs()),
            )
            .field(
                "resolve_timeout",
                &format!("{} seconds", self.resolve_timeout.as_secs()),
            )
            .field("max_did_size", &format!("{} bytes", self.max_did_size))
            .field("cache_capacity_count", &self.cache_capacity_count)
            .field("cache_expire", &format!("{} seconds", self.cache_expire))
            .field(
                "webvh_log_expire",
                &if self.webvh_log_expire == 0 {
                    "disabled".to_string()
                } else {
                    format!("{} seconds", self.webvh_log_expire)
                },
            )
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            log_level: LevelFilter::INFO,
            listen_address: "".into(),
            enable_http_endpoint: true,
            enable_websocket_endpoint: true,
            enable_agent_names: false,
            agent_name_concurrency: 16,
            rate_limit_per_ip: 100,
            rate_limit_burst: 50,
            trusted_proxies: Vec::new(),
            client_ipv6_prefix: DEFAULT_CLIENT_IPV6_PREFIX,
            ws_max_connections: DEFAULT_WS_MAX_CONNECTIONS,
            ws_max_connections_per_ip: DEFAULT_WS_MAX_CONNECTIONS_PER_IP,
            ws_idle_timeout: Duration::from_secs(DEFAULT_WS_IDLE_TIMEOUT_SECS),
            ws_send_timeout: Duration::from_secs(DEFAULT_WS_SEND_TIMEOUT_SECS),
            ws_max_message_size: derived_ws_max_message_size(1024),
            ws_max_inflight_per_connection: DEFAULT_MAX_INFLIGHT_PER_CONNECTION,
            statistics_interval: Duration::from_secs(60),
            resolve_timeout: Duration::from_secs(30),
            max_did_size: 1024,
            cache_capacity_count: 1000,
            cache_expire: 300,
            webvh_log_expire: 0,
        }
    }
}

fn build_client_ip_extractor(
    trusted_proxies: &[IpNet],
    client_ipv6_prefix: u8,
) -> Result<ClientIpExtractor, CacheError> {
    ClientIpExtractor::trusted_proxies(trusted_proxies.to_vec())
        .map_err(|e| CacheError::ConfigError("NA".into(), format!("trusted_proxies: {e}")))?
        .ipv6_prefix(client_ipv6_prefix)
        .map_err(|e| CacheError::ConfigError("NA".into(), format!("client_ipv6_prefix: {e}")))
}

impl Config {
    /// How a request's client address is found: the rate limiter and the
    /// WebSocket connection caps use it, so both charge the same client.
    pub fn client_ip_extractor(&self) -> Result<ClientIpExtractor, CacheError> {
        build_client_ip_extractor(&self.trusted_proxies, self.client_ipv6_prefix)
    }
}

/// A config error naming the key and the value it could not use.
fn invalid(key: &str, value: &str, expected: &str) -> CacheError {
    CacheError::ConfigError("NA".into(), format!("{key}: ({value}) is not {expected}"))
}

/// Parse a number, or fail naming the key and value.
fn number<T: std::str::FromStr>(key: &str, value: &str) -> Result<T, CacheError> {
    value
        .trim()
        .parse()
        .map_err(|_| invalid(key, value, "a number"))
}

/// A ceiling: a positive count, where `0` keeps `default` (neither a typo nor
/// `0` may remove one). An unparseable value is an error.
fn ceiling<T: std::str::FromStr + PartialEq + Default>(
    key: &str,
    value: &str,
    default: T,
) -> Result<T, CacheError> {
    let n: T = number(key, value)?;
    Ok(if n == T::default() { default } else { n })
}

/// Parse a boolean: `true`/`false`, `yes`/`no`, `on`/`off` or `1`/`0`, in any
/// case. Anything else is an error rather than a default: before, `"False"`
/// or `"no"` failed to parse and so *enabled* an endpoint.
fn boolean(key: &str, value: &str) -> Result<bool, CacheError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => Err(invalid(key, value, "true or false")),
    }
}

/// Parse `log_level`: trace, debug, info, warn or error, in any case.
fn log_level(value: &str) -> Result<LevelFilter, CacheError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "trace" => Ok(LevelFilter::TRACE),
        "debug" => Ok(LevelFilter::DEBUG),
        "info" => Ok(LevelFilter::INFO),
        "warn" => Ok(LevelFilter::WARN),
        "error" => Ok(LevelFilter::ERROR),
        _ => Err(invalid(
            "log_level",
            value,
            "one of trace, debug, info, warn, error",
        )),
    }
}

impl TryFrom<ConfigRaw> for Config {
    type Error = CacheError;

    /// Every value must parse: an unreadable value fails with an error naming
    /// the key and the value, rather than silently taking a default.
    fn try_from(raw: ConfigRaw) -> Result<Self, Self::Error> {
        let max_did_size = number("max_did_size", &raw.max_did_size)?;
        let trusted_proxies = parse_trusted_proxies(&raw.trusted_proxies)?;
        let client_ipv6_prefix: u8 = raw.client_ipv6_prefix.trim().parse().map_err(|_| {
            invalid(
                "client_ipv6_prefix",
                &raw.client_ipv6_prefix,
                "a prefix length (1-128)",
            )
        })?;
        // Validate both now, so a bad value fails startup rather than the
        // first request.
        build_client_ip_extractor(&trusted_proxies, client_ipv6_prefix)?;
        let ws_max_message_size = match raw.ws_max_message_size.trim().parse::<usize>() {
            Ok(0) => derived_ws_max_message_size(max_did_size),
            Ok(size) => size,
            Err(_) => {
                return Err(invalid(
                    "ws_max_message_size",
                    &raw.ws_max_message_size,
                    "a byte count",
                ));
            }
        };

        Ok(Config {
            log_level: log_level(&raw.log_level)?,
            listen_address: raw.listen_address,
            enable_http_endpoint: boolean("enable_http_endpoint", &raw.enable_http_endpoint)?,
            enable_websocket_endpoint: boolean(
                "enable_websocket_endpoint",
                &raw.enable_websocket_endpoint,
            )?,
            enable_agent_names: boolean("enable_agent_names", &raw.enable_agent_names)?,
            // A zero cap would mean "no limit", which is the opposite of what
            // this setting is for; it keeps the default.
            agent_name_concurrency: ceiling(
                "agent_name_concurrency",
                &raw.agent_name_concurrency,
                16,
            )?,
            // "0" disables limiting, which is the documented way to.
            rate_limit_per_ip: number("rate_limit_per_ip", &raw.rate_limit_per_ip)?,
            rate_limit_burst: number("rate_limit_burst", &raw.rate_limit_burst)?,
            trusted_proxies,
            client_ipv6_prefix,
            ws_max_connections: ceiling(
                "ws_max_connections",
                &raw.ws_max_connections,
                DEFAULT_WS_MAX_CONNECTIONS,
            )?,
            ws_max_connections_per_ip: ceiling(
                "ws_max_connections_per_ip",
                &raw.ws_max_connections_per_ip,
                DEFAULT_WS_MAX_CONNECTIONS_PER_IP,
            )?,
            ws_idle_timeout: Duration::from_secs(ceiling(
                "ws_idle_timeout",
                &raw.ws_idle_timeout,
                DEFAULT_WS_IDLE_TIMEOUT_SECS,
            )?),
            ws_send_timeout: Duration::from_secs(ceiling(
                "ws_send_timeout",
                &raw.ws_send_timeout,
                DEFAULT_WS_SEND_TIMEOUT_SECS,
            )?),
            ws_max_message_size,
            ws_max_inflight_per_connection: ceiling(
                "ws_max_inflight_per_connection",
                &raw.ws_max_inflight_per_connection,
                DEFAULT_MAX_INFLIGHT_PER_CONNECTION,
            )?,
            statistics_interval: Duration::from_secs(number(
                "statistics_interval",
                &raw.statistics_interval,
            )?),
            resolve_timeout: Duration::from_secs(number("resolve_timeout", &raw.resolve_timeout)?),
            max_did_size,
            cache_capacity_count: number("cache.capacity_count", &raw.cache.capacity_count)?,
            cache_expire: number("cache.expire", &raw.cache.expire)?,
            webvh_log_expire: number("cache.webvh_log_expire", &raw.cache.webvh_log_expire)?,
        })
    }
}

/// Read the primary configuration file for the mediator
/// Returns a ConfigRaw struct, that still needs to be processed for additional information
/// and conversion to Config struct
fn read_config_file(file_name: &str) -> Result<ConfigRaw, CacheError> {
    // Read configuration file parameters
    event!(Level::INFO, "Config file({})", file_name);
    let raw_config = read_file_lines(file_name)?;

    event!(Level::DEBUG, "raw_config = {:?}", raw_config);
    parse_config_lines(&raw_config)
}

/// Expand `${VAR:default}` references in `lines` (comments already stripped)
/// and parse the result.
fn parse_config_lines(lines: &[String]) -> Result<ConfigRaw, CacheError> {
    let config_with_vars = expand_env_vars(lines);
    match toml::from_str(&config_with_vars.join("\n")) {
        Ok(config) => Ok(config),
        Err(err) => {
            event!(
                Level::ERROR,
                "Could not parse configuration settings. {}",
                err
            );
            // A key under `[cache]` that is not a cache setting is the likely
            // cause of an unknown field there: TOML puts every key after a
            // table header into that table.
            let hint = if err.to_string().contains("unknown field") {
                " Keys after the [cache] header belong to [cache]; every other \
                 setting must appear above it."
            } else {
                ""
            };
            Err(CacheError::ConfigError(
                "NA".into(),
                format!("Could not parse configuration settings. Reason: {err}{hint}"),
            ))
        }
    }
}

/// Parse configuration text as the config file loader does (comment lines
/// stripped, `${VAR:default}` expanded), without touching logging.
pub fn parse_config_str(text: &str) -> Result<Config, CacheError> {
    let lines: Vec<String> = text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(str::to_string)
        .collect();
    Config::try_from(parse_config_lines(&lines)?)
}

/// Reads a file and returns a vector of strings, one for each line in the file.
/// It also strips any lines starting with a # (comments)
/// You can join the Vec back into a single string with `.join("\n")`
pub(crate) fn read_file_lines<P>(file_name: P) -> Result<Vec<String>, CacheError>
where
    P: AsRef<Path>,
{
    let file = File::open(file_name.as_ref()).map_err(|err| {
        event!(
            Level::ERROR,
            "Could not open file({}). {}",
            file_name.as_ref().display(),
            err
        );
        CacheError::ConfigError(
            "NA".into(),
            format!(
                "Could not open file({}). {}",
                file_name.as_ref().display(),
                err
            ),
        )
    })?;

    let mut lines = Vec::new();
    for (number, line) in io::BufReader::new(file).lines().enumerate() {
        // A read or UTF-8 error fails the load: stopping at it would silently
        // drop the rest of the file.
        let line = line.map_err(|err| {
            CacheError::ConfigError(
                "NA".into(),
                format!(
                    "Could not read file({}) at line {}: {}",
                    file_name.as_ref().display(),
                    number + 1,
                    err
                ),
            )
        })?;
        // Strip comments out
        if !line.starts_with('#') {
            lines.push(line);
        }
    }

    Ok(lines)
}

/// Replaces all strings ${VAR_NAME:default_value}
/// with the corresponding environment variables (e.g. value of ${VAR_NAME})
/// or with `default_value` if the variable is not defined.
///
/// The default runs to the first `}`, so several references on one line expand
/// separately; a default cannot itself contain `}`.
fn expand_env_vars(raw_config: &[String]) -> Vec<String> {
    let re =
        Regex::new(r"\$\{(?P<env_var>[A-Z_]{1,}[0-9A-Z_]*):(?P<default_value>[^}]*)\}").unwrap();
    let mut result: Vec<String> = Vec::new();
    for line in raw_config {
        result.push(
            re.replace_all(line, |caps: &Captures| match env::var(&caps["env_var"]) {
                Ok(val) => val,
                Err(_) => (caps["default_value"]).into(),
            })
            .into_owned(),
        );
    }
    result
}

/// Default config path used when no `-c` flag is supplied.
pub const DEFAULT_CONFIG_PATH: &str = "conf/cache-conf.toml";

pub fn init(
    config_path: &str,
    reload_handle: Option<Handle<LevelFilter, Registry>>,
) -> Result<Config, CacheError> {
    // Read configuration file parameters, and check every value before
    // acting on any of them.
    let config = Config::try_from(read_config_file(config_path)?)?;

    // Setup logging
    if let Some(reload_handle) = &reload_handle {
        let level = config.log_level;
        reload_handle
            .modify(|filter| *filter = level)
            .map_err(|e| CacheError::InternalError("NA".into(), e.to_string()))?;
        event!(Level::INFO, "Log level set to ({})", level);
    }

    event!(
        Level::INFO,
        "Configuration settings parsed successfully.\n{:#?}",
        config
    );
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHIPPED: &str = include_str!("../conf/cache-conf.toml");

    /// The shipped file with one `${VAR:default}` default replaced, as an
    /// operator editing the file (or exporting the variable) would.
    fn shipped_with(reference: &str, value: &str) -> String {
        let (var, _) = reference.split_once(':').unwrap();
        assert!(
            SHIPPED.contains(reference),
            "shipped config no longer contains {reference}"
        );
        SHIPPED.replace(reference, &format!("{var}:{value}}}"))
    }

    #[test]
    fn the_shipped_config_parses() {
        let config = parse_config_str(SHIPPED).expect("shipped config parses");
        assert_eq!(config.rate_limit_per_ip, 100);
        assert_eq!(config.rate_limit_burst, 50);
        assert!(config.trusted_proxies.is_empty());
        assert_eq!(config.client_ipv6_prefix, 64);
        assert_eq!(config.ws_max_connections, DEFAULT_WS_MAX_CONNECTIONS);
        assert_eq!(
            config.ws_max_connections_per_ip,
            DEFAULT_WS_MAX_CONNECTIONS_PER_IP
        );
        assert_eq!(config.ws_idle_timeout, Duration::from_secs(120));
        assert_eq!(config.ws_send_timeout, Duration::from_secs(10));
        assert_eq!(
            config.ws_max_message_size,
            derived_ws_max_message_size(config.max_did_size)
        );
    }

    /// The rate-limit settings in the shipped file are read: a changed value
    /// reaches `Config`, `0` included.
    #[test]
    fn shipped_rate_limit_settings_take_effect() {
        let config = parse_config_str(&shipped_with("${RATE_LIMIT_PER_IP:100}", "7")).unwrap();
        assert_eq!(config.rate_limit_per_ip, 7);

        let config = parse_config_str(&shipped_with("${RATE_LIMIT_PER_IP:100}", "0")).unwrap();
        assert_eq!(config.rate_limit_per_ip, 0);

        let config = parse_config_str(&shipped_with("${RATE_LIMIT_BURST:50}", "9")).unwrap();
        assert_eq!(config.rate_limit_burst, 9);
    }

    #[test]
    fn shipped_connection_settings_take_effect() {
        let mut text = shipped_with("${WS_MAX_CONNECTIONS:4096}", "11");
        for (reference, value) in [
            ("${WS_MAX_CONNECTIONS_PER_IP:64}", "3"),
            ("${WS_IDLE_TIMEOUT:120}", "5"),
            ("${WS_SEND_TIMEOUT:10}", "4"),
            ("${WS_MAX_MESSAGE_SIZE:0}", "4096"),
            ("${TRUSTED_PROXIES:}", "10.0.0.0/8, 192.0.2.1"),
            ("${CLIENT_IPV6_PREFIX:64}", "56"),
        ] {
            let (var, _) = reference.split_once(':').unwrap();
            assert!(text.contains(reference), "missing {reference}");
            text = text.replace(reference, &format!("{var}:{value}}}"));
        }
        let config = parse_config_str(&text).unwrap();
        assert_eq!(config.ws_max_connections, 11);
        assert_eq!(config.ws_max_connections_per_ip, 3);
        assert_eq!(config.ws_idle_timeout, Duration::from_secs(5));
        assert_eq!(config.ws_send_timeout, Duration::from_secs(4));
        assert_eq!(config.ws_max_message_size, 4096);
        assert_eq!(
            config.trusted_proxies,
            vec![
                "10.0.0.0/8".parse::<IpNet>().unwrap(),
                "192.0.2.1/32".parse::<IpNet>().unwrap()
            ]
        );
        assert_eq!(config.client_ipv6_prefix, 56);
    }

    /// Every key in the shipped file is at the level the loader reads it from.
    #[test]
    fn shipped_keys_are_at_the_right_level() {
        let lines: Vec<String> = SHIPPED.lines().map(str::to_string).collect();
        let table: toml::Table = toml::from_str(&expand_env_vars(&lines).join("\n")).unwrap();
        for key in [
            "rate_limit_per_ip",
            "rate_limit_burst",
            "ws_max_connections",
        ] {
            assert!(table.contains_key(key), "{key} must be a top-level key");
        }
        let cache = table["cache"].as_table().unwrap();
        let mut keys: Vec<&str> = cache.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["capacity_count", "expire", "webvh_log_expire"]);
    }

    /// A top-level setting written under `[cache]` fails to load and the
    /// error says where it belongs.
    #[test]
    fn a_setting_under_the_cache_table_is_refused() {
        let text = format!("{SHIPPED}\nrate_limit_per_ip = \"5\"\n");
        let err = parse_config_str(&text).unwrap_err().to_string();
        assert!(err.contains("rate_limit_per_ip"), "{err}");
        assert!(err.contains("[cache]"), "{err}");
    }

    #[test]
    fn an_unknown_top_level_key_is_refused() {
        let text = format!("rate_limit_per_second = \"5\"\n{SHIPPED}");
        let err = parse_config_str(&text).unwrap_err().to_string();
        assert!(err.contains("rate_limit_per_second"), "{err}");
    }

    #[test]
    fn zero_ceilings_keep_their_defaults() {
        let config = parse_config_str(&shipped_with("${WS_MAX_CONNECTIONS:4096}", "0")).unwrap();
        assert_eq!(config.ws_max_connections, DEFAULT_WS_MAX_CONNECTIONS);
        let config = parse_config_str(&shipped_with("${WS_IDLE_TIMEOUT:120}", "0")).unwrap();
        assert_eq!(config.ws_idle_timeout, Duration::from_secs(120));
        let config =
            parse_config_str(&shipped_with("${WS_MAX_INFLIGHT_PER_CONNECTION:32}", "0")).unwrap();
        assert_eq!(
            config.ws_max_inflight_per_connection,
            DEFAULT_MAX_INFLIGHT_PER_CONNECTION
        );
    }

    /// A value that does not parse fails startup, naming the key and the
    /// value, instead of silently taking a default.
    #[test]
    fn an_unparseable_value_fails_naming_key_and_value() {
        for (reference, value, key) in [
            ("${WS_IDLE_TIMEOUT:120}", "soon", "ws_idle_timeout"),
            ("${WS_MAX_CONNECTIONS:4096}", "lots", "ws_max_connections"),
            ("${RATE_LIMIT_PER_IP:100}", "1OO", "rate_limit_per_ip"),
            ("${RATE_LIMIT_BURST:50}", "-5", "rate_limit_burst"),
            ("${RESOLVE_TIMEOUT:30}", "30s", "resolve_timeout"),
            ("${MAX_DID_SIZE:1024}", "1k", "max_did_size"),
            ("${STATISTICS_INTERVAL:10}", "ten", "statistics_interval"),
            (
                "${AGENT_NAME_CONCURRENCY:16}",
                "x",
                "agent_name_concurrency",
            ),
            (
                "${CACHE_CAPACITY_COUNT:1000}",
                "1e3",
                "cache.capacity_count",
            ),
            ("${EXPIRE:300}", "5m", "cache.expire"),
            ("${WEBVH_LOG_EXPIRE:0}", "off", "cache.webvh_log_expire"),
            (
                "${ENABLE_HTTP_ENDPOINT:true}",
                "Flase",
                "enable_http_endpoint",
            ),
            (
                "${ENABLE_WEBSOCKET_ENDPOINT:true}",
                "disabled",
                "enable_websocket_endpoint",
            ),
            ("${ENABLE_AGENT_NAMES:false}", "nope", "enable_agent_names"),
        ] {
            let err = parse_config_str(&shipped_with(reference, value))
                .err()
                .unwrap_or_else(|| panic!("{key} = {value} must fail"))
                .to_string();
            assert!(err.contains(key) && err.contains(value), "{err}");
        }
        let text = SHIPPED.replace("log_level = \"info\"", "log_level = \"verbose\"");
        let err = parse_config_str(&text).err().unwrap().to_string();
        assert!(
            err.contains("log_level") && err.contains("verbose"),
            "{err}"
        );
    }

    /// The spellings of false all disable an endpoint; before, anything but
    /// `false` failed to parse and enabled it.
    #[test]
    fn booleans_parse_their_usual_spellings() {
        for value in ["false", "False", "FALSE", "no", "off", "0"] {
            let config =
                parse_config_str(&shipped_with("${ENABLE_HTTP_ENDPOINT:true}", value)).unwrap();
            assert!(!config.enable_http_endpoint, "{value}");
        }
        for value in ["true", "True", "yes", "on", "1"] {
            let config =
                parse_config_str(&shipped_with("${ENABLE_WEBSOCKET_ENDPOINT:true}", value))
                    .unwrap();
            assert!(config.enable_websocket_endpoint, "{value}");
        }
    }

    /// Two references on one line expand separately.
    #[test]
    fn env_references_expand_one_at_a_time() {
        let lines = vec!["a = \"${CACHE_TEST_UNSET_ONE:x}-${CACHE_TEST_UNSET_TWO:y}\"".to_string()];
        assert_eq!(expand_env_vars(&lines), vec!["a = \"x-y\"".to_string()]);
    }

    #[test]
    fn a_read_error_fails_the_load() {
        let dir = std::env::temp_dir().join(format!("cache-conf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("invalid-utf8.toml");
        std::fs::write(&path, b"log_level = \"info\"\n\xff\xfe = 1\n").unwrap();
        let err = read_file_lines(&path).unwrap_err().to_string();
        assert!(err.contains("line 2"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_client_address_settings_fail_startup() {
        assert!(parse_config_str(&shipped_with("${TRUSTED_PROXIES:}", "not-a-cidr")).is_err());
        assert!(parse_config_str(&shipped_with("${TRUSTED_PROXIES:}", "0.0.0.0/0")).is_err());
        assert!(parse_config_str(&shipped_with("${CLIENT_IPV6_PREFIX:64}", "0")).is_err());
        assert!(parse_config_str(&shipped_with("${CLIENT_IPV6_PREFIX:64}", "129")).is_err());
        assert!(parse_config_str(&shipped_with("${WS_MAX_MESSAGE_SIZE:0}", "big")).is_err());
    }
}
