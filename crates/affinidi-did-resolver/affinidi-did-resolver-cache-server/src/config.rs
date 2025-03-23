use crate::errors::CacheError;
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

#[derive(Debug, Serialize, Deserialize)]
struct CacheConfig {
    #[serde(default)]
    pub capacity_count: String,
    #[serde(default)]
    pub expire: String,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            capacity_count: "1000".into(),
            expire: "300".into(),
        }
    }
}

/// ConfigRaw Struct is used to deserialize the configuration file
/// We then convert this to the CacheConfig Struct
#[derive(Debug, Serialize, Deserialize)]
struct ConfigRaw {
    pub log_level: String,
    pub listen_address: String,
    pub enable_http_endpoint: String,
    pub enable_websocket_endpoint: String,
    pub statistics_interval: String,
    pub cache: CacheConfig,
}

pub struct Config {
    pub log_level: LevelFilter,
    pub listen_address: String,
    pub enable_http_endpoint: bool,
    pub enable_websocket_endpoint: bool,
    pub statistics_interval: Duration,
    pub cache_capacity_count: u32,
    pub cache_expire: u32,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("log_level", &self.log_level)
            .field("listen_address", &self.listen_address)
            .field("enable_http_endpoint", &self.enable_http_endpoint)
            .field("enable_websocket_endpoint", &self.enable_websocket_endpoint)
            .field(
                "statistics_interval",
                &format!("{} seconds", self.statistics_interval.as_secs()),
            )
            .field("cache_capacity_count", &self.cache_capacity_count)
            .field("cache_expire", &format!("{} seconds", self.cache_expire))
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
            statistics_interval: Duration::from_secs(60),
            cache_capacity_count: CacheConfig::default()
                .capacity_count
                .parse()
                .unwrap_or(1000),
            cache_expire: CacheConfig::default().expire.parse().unwrap_or(300),
        }
    }
}

impl TryFrom<ConfigRaw> for Config {
    type Error = CacheError;

    fn try_from(raw: ConfigRaw) -> Result<Self, Self::Error> {
        Ok(Config {
            log_level: match raw.log_level.as_str() {
                "trace" => LevelFilter::TRACE,
                "debug" => LevelFilter::DEBUG,
                "info" => LevelFilter::INFO,
                "warn" => LevelFilter::WARN,
                "error" => LevelFilter::ERROR,
                _ => LevelFilter::INFO,
            },
            listen_address: raw.listen_address,
            enable_http_endpoint: raw.enable_http_endpoint.parse().unwrap_or(true),
            enable_websocket_endpoint: raw.enable_websocket_endpoint.parse().unwrap_or(true),
            statistics_interval: Duration::from_secs(raw.statistics_interval.parse().unwrap_or(60)),
            cache_capacity_count: raw.cache.capacity_count.parse().unwrap_or(1000),
            cache_expire: raw.cache.expire.parse().unwrap_or(300),
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
    let config_with_vars = expand_env_vars(&raw_config);
    match toml::from_str(&config_with_vars.join("\n")) {
        Ok(config) => Ok(config),
        Err(err) => {
            event!(
                Level::ERROR,
                "Could not parse configuration settings. {:?}",
                err
            );
            Err(CacheError::ConfigError(
                "NA".into(),
                format!("Could not parse configuration settings. Reason: {:?}", err),
            ))
        }
    }
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
    for line in io::BufReader::new(file).lines().map_while(Result::ok) {
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
fn expand_env_vars(raw_config: &Vec<String>) -> Vec<String> {
    let re = Regex::new(r"\$\{(?P<env_var>[A-Z_]{1,}[0-9A-Z_]*):(?P<default_value>.*)\}").unwrap();
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

pub fn init(reload_handle: Option<Handle<LevelFilter, Registry>>) -> Result<Config, CacheError> {
    // Read configuration file parameters
    let config = read_config_file("conf/cache-conf.toml")?;

    // Setup logging
    if reload_handle.is_some() {
        let level: LevelFilter = match config.log_level.as_str() {
            "trace" => LevelFilter::TRACE,
            "debug" => LevelFilter::DEBUG,
            "info" => LevelFilter::INFO,
            "warn" => LevelFilter::WARN,
            "error" => LevelFilter::ERROR,
            _ => {
                event!(
                    Level::WARN,
                    "log_level({}) is unknown in config file. Defaults to INFO",
                    config.log_level
                );
                LevelFilter::INFO
            }
        };
        reload_handle
            .unwrap()
            .modify(|filter| *filter = level)
            .map_err(|e| CacheError::InternalError("NA".into(), e.to_string()))?;
        event!(Level::INFO, "Log level set to ({})", config.log_level);
    }

    match Config::try_from(config) {
        Ok(config) => {
            event!(
                Level::INFO,
                "Configuration settings parsed successfully.\n{:#?}",
                config
            );
            Ok(config)
        }
        Err(err) => Err(err),
    }
}
