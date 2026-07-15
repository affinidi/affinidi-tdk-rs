// `DatabaseConfig` (the serde struct in `config.rs`) is always available
// under the `server` feature — the mediator binary parses it regardless
// of which storage backend the deployment selects. `DatabaseHandler`
// and the redis-using helpers below are gated on `redis-backend`.
pub mod config;

#[cfg(feature = "redis-backend")]
pub mod delete;

#[cfg(feature = "redis-backend")]
use crate::errors::MediatorError;
#[cfg(feature = "redis-backend")]
use crate::types::problem_report::{ProblemReportScope, ProblemReportSorter};
#[cfg(feature = "redis-backend")]
use axum::http::StatusCode;
#[cfg(feature = "redis-backend")]
use config::DatabaseConfig;
#[cfg(feature = "redis-backend")]
use redis::AsyncConnectionConfig;
#[cfg(feature = "redis-backend")]
use redis::aio::{ConnectionManager, ConnectionManagerConfig, MultiplexedConnection, PubSub};

#[cfg(feature = "redis-backend")]
use semver::{Version, VersionReq};
#[cfg(feature = "redis-backend")]
use std::time::Duration;
#[cfg(feature = "redis-backend")]
use tokio::time::sleep;
#[cfg(feature = "redis-backend")]
use tracing::{Level, event, info, warn};

/// Low-level Redis connection handler used by the mediator.
///
/// Uses a single multiplexed connection (via `ConnectionManager` for auto-reconnect)
/// instead of a connection pool. `MultiplexedConnection` handles concurrent commands
/// over one TCP connection, making a pool unnecessary.
#[cfg(feature = "redis-backend")]
#[derive(Clone)]
pub struct DatabaseHandler {
    /// Auto-reconnecting multiplexed connection for normal Redis operations.
    connection: ConnectionManager,
    /// Redis connection URL (kept for creating pub/sub and blocking connections).
    redis_url: String,
}

#[cfg(feature = "redis-backend")]
const REDIS_VERSION_REQ: &str = ">=7.1, <9.0";

/// Major engine lines that [`REDIS_VERSION_REQ`] is known to cover.
///
/// Managed engines — notably **ElastiCache Serverless for Valkey / Redis OSS** —
/// answer `INFO server` with a `redis_version` that carries only the *major*
/// component (e.g. `8`), unlike OSS Valkey/Redis which report a full
/// `MAJOR.MINOR.PATCH` (e.g. `7.2.4`). A bare major cannot be meaningfully
/// range-checked against `>=7.1` (is it `7.0` or `7.9`?), so when only a major is
/// reported we accept it iff it is one of these supported lines. Keep this in sync
/// with `REDIS_VERSION_REQ`.
#[cfg(feature = "redis-backend")]
const SUPPORTED_MAJOR_VERSIONS: &[u64] = &[7, 8];

/// Outcome of checking a reported `redis_version` against [`REDIS_VERSION_REQ`].
#[cfg(feature = "redis-backend")]
#[derive(Debug, PartialEq, Eq)]
enum VersionVerdict {
    Compatible,
    Incompatible,
}

/// Coerce a `redis_version` value from `INFO server` into a full [`Version`],
/// returning the parsed version plus the number of numeric components that were
/// actually present (1, 2 or 3).
///
/// OSS Valkey/Redis report a complete `MAJOR.MINOR.PATCH` (e.g. `7.2.4`). Managed
/// engines can report fewer components — ElastiCache Serverless reports only the
/// major (e.g. `8`). We take the leading numeric dotted core (ignoring an optional
/// `v` prefix and any non-numeric suffix) and zero-fill the missing minor/patch so
/// the value always parses; the returned precision lets the caller decide how
/// strictly it can range-check.
#[cfg(feature = "redis-backend")]
fn normalize_redis_version(raw: &str) -> Result<(Version, usize), semver::Error> {
    let core = raw.trim();
    let core = core.strip_prefix('v').unwrap_or(core);
    let numeric: Vec<&str> = core
        .split('.')
        .take_while(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        .collect();
    if numeric.is_empty() {
        // Nothing numeric to work with — surface a parse error for the raw value.
        return Version::parse(core).map(|version| (version, 3));
    }
    let present = numeric.len().min(3);
    let major = numeric[0];
    let minor = numeric.get(1).copied().unwrap_or("0");
    let patch = numeric.get(2).copied().unwrap_or("0");
    Version::parse(&format!("{major}.{minor}.{patch}")).map(|version| (version, present))
}

/// Decide whether a reported `redis_version` is compatible with `req`.
///
/// - When the minor is known (≥ 2 components), range-check precisely — this is the
///   original strict behaviour for OSS Valkey/Redis.
/// - When only the major is known (ElastiCache Serverless reports e.g. `8`), a
///   `>=7.1` range check would be ambiguous, so accept iff the major is a supported
///   line ([`SUPPORTED_MAJOR_VERSIONS`]).
#[cfg(feature = "redis-backend")]
fn assess_redis_version(raw: &str, req: &VersionReq) -> Result<VersionVerdict, semver::Error> {
    let (version, present) = normalize_redis_version(raw)?;
    let compatible = if present >= 2 {
        req.matches(&version)
    } else {
        SUPPORTED_MAJOR_VERSIONS.contains(&version.major)
    };
    Ok(if compatible {
        VersionVerdict::Compatible
    } else {
        VersionVerdict::Incompatible
    })
}

#[cfg(feature = "redis-backend")]
impl DatabaseHandler {
    /// Creates a new `DatabaseHandler`, establishing a multiplexed connection and verifying
    /// that the Redis server version is compatible. Retries on connection failure.
    pub async fn new(config: &DatabaseConfig) -> Result<Self, MediatorError> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let client = redis::Client::open(config.database_url.as_str()).map_err(|err| {
            MediatorError::problem_with_log(
                1,
                "NA",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.storage.url",
                "Database URL ({1}) is invalid. Reason: {2}",
                vec![config.database_url.clone(), err.to_string()],
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Database URL ({}) is invalid. Reason: {}",
                    config.database_url, err
                ),
            )
        })?;

        let manager_config = ConnectionManagerConfig::new()
            .set_response_timeout(Some(Duration::from_secs(config.database_timeout.into())))
            .set_connection_timeout(Some(Duration::from_secs(config.database_timeout.into())));

        let connection = loop {
            match client
                .get_connection_manager_with_config(manager_config.clone())
                .await
            {
                Ok(conn) => break conn,
                Err(err) => {
                    event!(Level::WARN, "Error connecting to database: {}", err);
                    event!(Level::WARN, "Retrying database connection in 10 seconds");
                    sleep(Duration::from_secs(10)).await;
                }
            }
        };

        let database = Self {
            connection,
            redis_url: config.database_url.clone(),
        };

        // Verify connectivity with PING
        loop {
            let mut conn = database.connection.clone();
            let pong: Result<String, redis::RedisError> =
                redis::cmd("PING").query_async(&mut conn).await;
            match pong {
                Ok(pong) => {
                    event!(
                        Level::INFO,
                        "Database ping ok! Expected (PONG) received ({})",
                        pong
                    );
                    break;
                }
                Err(err) => {
                    event!(
                        Level::WARN,
                        "Can't get connection to database. Reason: {}",
                        err
                    );
                    event!(Level::WARN, "Retrying database connection in 10 seconds");
                    sleep(Duration::from_secs(10)).await;
                }
            }
        }

        // Check the version of Redis Server
        database.check_server_version().await?;

        // Warn if Redis connection has no authentication
        database.check_auth_warning(&config.database_url);

        Ok(database)
    }

    /// Returns a clone of the auto-reconnecting multiplexed connection.
    /// This is cheap (Arc clone internally) and supports concurrent use.
    pub async fn get_async_connection(&self) -> Result<ConnectionManager, MediatorError> {
        Ok(self.connection.clone())
    }

    /// Returns a dedicated Redis connection with no response timeout.
    /// This must be used for blocking commands (e.g. XREADGROUP BLOCK)
    /// because the normal connection's response timeout will kill the
    /// connection before the block period completes.
    pub async fn get_blocking_connection(&self) -> Result<MultiplexedConnection, MediatorError> {
        let client = redis::Client::open(self.redis_url.clone()).map_err(|err| {
            MediatorError::problem_with_log(
                10,
                "NA",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.storage.connection.blocking",
                "Can't open database connection for blocking ops. Reason: {1}",
                vec![err.to_string()],
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Can't open database connection for blocking ops. Reason: {err}"),
            )
        })?;

        let config = AsyncConnectionConfig::new().set_response_timeout(None);
        client
            .get_multiplexed_async_connection_with_config(&config)
            .await
            .map_err(|err| {
                MediatorError::problem_with_log(
                    11,
                    "NA",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.connection.blocking",
                    "Can't establish blocking database connection. Reason: {1}",
                    vec![err.to_string()],
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Can't establish blocking database connection. Reason: {err}"),
                )
            })
    }

    /// Returns a redis database connector or returns an Error
    /// This should only be used for pubsub operations
    pub async fn get_pubsub_connection(&self) -> Result<PubSub, MediatorError> {
        let client = redis::Client::open(self.redis_url.clone()).map_err(|err| {
            MediatorError::problem_with_log(
                4,
                "NA",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.storage.connection.pubsub",
                "Can't open database connection for pubsub. Reason: {1}",
                vec![err.to_string()],
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Can't open database connection for pubsub. Reason: {err}"),
            )
        })?;

        client.get_async_pubsub().await.map_err(|err| {
            MediatorError::problem_with_log(
                5,
                "NA",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.storage.connection.pubsub.receiver",
                "Can't get pubsub receiver. Reason: {1}",
                vec![err.to_string()],
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Can't get pubsub receiver. Reason: {err}"),
            )
        })
    }

    /// Helper function to check the version of the Redis Server
    async fn check_server_version(&self) -> Result<String, MediatorError> {
        let redis_version_req: VersionReq = match VersionReq::parse(REDIS_VERSION_REQ) {
            Ok(result) => result,
            Err(err) => panic!("Couldn't process required Redis version. Reason: {err}"),
        };

        let mut conn = self.connection.clone();
        let server_info: String = match redis::cmd("INFO")
            .arg("SERVER")
            .query_async(&mut conn)
            .await
        {
            Ok(result) => result,
            Err(err) => {
                return Err(MediatorError::problem_with_log(
                    6,
                    "NA",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.info",
                    "Couldn't query database information. Reason: {1}",
                    vec![err.to_string()],
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Couldn't query database information. Reason: {err}"),
                ));
            }
        };

        let server_version = server_info
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split(":").collect();
                if parts.len() == 2 {
                    if parts[0] == "redis_version" {
                        Some(parts[1].to_owned())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .next();

        if let Some(version) = server_version {
            match assess_redis_version(&version, &redis_version_req) {
                Ok(VersionVerdict::Compatible) => {
                    info!("Redis version is compatible: {}", version);
                    Ok(version.to_owned())
                }
                Ok(VersionVerdict::Incompatible) => Err(MediatorError::problem_with_log(
                    8,
                    "NA",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.version.incompatible",
                    "Database version {1} does not match expected {2}",
                    vec![version.clone(), redis_version_req.to_string()],
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "Database version {version} does not match expected {redis_version_req}"
                    ),
                )),
                Err(err) => Err(MediatorError::problem_with_log(
                    7,
                    "NA",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.version",
                    "Cannot parse database version ({1}). Reason: {2}",
                    vec![version.clone(), err.to_string()],
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Cannot parse database version ({version}). Reason: {err}"),
                )),
            }
        } else {
            Err(MediatorError::problem(
                9,
                "NA",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "me.res.storage.version.unknown",
                "Couldn't determine database version",
                vec![],
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }

    /// Log a warning if the Redis connection URL has no authentication configured.
    /// Local connections (127.0.0.1, localhost, unix sockets) get a softer warning.
    fn check_auth_warning(&self, url: &str) {
        let is_tls = url.starts_with("rediss://");
        let is_local = url.contains("127.0.0.1")
            || url.contains("localhost")
            || url.contains("[::1]")
            || url.starts_with("unix://");

        // Check for password in URL: redis://:password@host or redis://user:pass@host
        let has_auth = url.contains('@');

        if !has_auth {
            if is_local {
                warn!(
                    "Redis connection has no authentication (password). \
                     This is acceptable for local development but should be \
                     secured with requirepass or ACLs for any shared environment."
                );
            } else {
                warn!(
                    "SECURITY WARNING: Redis connection has no authentication! \
                     Configure a password: redis://:yourpassword@host:port/ \
                     or use Redis ACLs. Unauthenticated remote Redis is a critical security risk."
                );
            }
        }

        if !is_tls && !is_local {
            warn!(
                "Redis connection is not using TLS (rediss://). \
                 For production deployments, use rediss:// to encrypt data in transit."
            );
        }

        if is_tls {
            info!("Redis TLS connection detected (rediss://)");
        }
    }
}

#[cfg(all(test, feature = "redis-backend"))]
mod version_checks {
    use super::{
        REDIS_VERSION_REQ, SUPPORTED_MAJOR_VERSIONS, VersionVerdict, assess_redis_version,
        normalize_redis_version,
    };
    use semver::{Version, VersionReq};

    fn req() -> VersionReq {
        VersionReq::parse(REDIS_VERSION_REQ).unwrap()
    }

    #[test]
    fn normalizes_full_partial_and_prefixed_versions() {
        // OSS Valkey/Redis: full MAJOR.MINOR.PATCH.
        assert_eq!(
            normalize_redis_version("7.2.4").unwrap(),
            (Version::new(7, 2, 4), 3)
        );
        // Managed proxy reporting MAJOR.MINOR.
        assert_eq!(
            normalize_redis_version("8.1").unwrap(),
            (Version::new(8, 1, 0), 2)
        );
        // ElastiCache Serverless: bare major only.
        assert_eq!(
            normalize_redis_version("8").unwrap(),
            (Version::new(8, 0, 0), 1)
        );
        // Optional `v` prefix and surrounding whitespace are tolerated.
        assert_eq!(
            normalize_redis_version(" v7.4.0 ").unwrap(),
            (Version::new(7, 4, 0), 3)
        );
        // Non-numeric suffix is dropped; only the numeric core is kept.
        assert_eq!(
            normalize_redis_version("7.4.0-serverless").unwrap(),
            (Version::new(7, 4, 0), 2)
        );
    }

    #[test]
    fn rejects_non_numeric_versions() {
        assert!(normalize_redis_version("").is_err());
        assert!(normalize_redis_version("unknown").is_err());
    }

    #[test]
    fn full_and_minor_versions_are_range_checked() {
        assert_eq!(
            assess_redis_version("7.2.4", &req()).unwrap(),
            VersionVerdict::Compatible
        );
        assert_eq!(
            assess_redis_version("8.1", &req()).unwrap(),
            VersionVerdict::Compatible
        );
        // Genuinely below the >=7.1 floor.
        assert_eq!(
            assess_redis_version("7.0", &req()).unwrap(),
            VersionVerdict::Incompatible
        );
        // At/above the <9.0 ceiling.
        assert_eq!(
            assess_redis_version("9.0.0", &req()).unwrap(),
            VersionVerdict::Incompatible
        );
        assert_eq!(
            assess_redis_version("6.2.0", &req()).unwrap(),
            VersionVerdict::Incompatible
        );
    }

    #[test]
    fn bare_major_uses_supported_lines() {
        // ElastiCache Serverless reports only the major (e.g. Valkey 8 -> "8").
        assert_eq!(
            assess_redis_version("8", &req()).unwrap(),
            VersionVerdict::Compatible
        );
        assert_eq!(
            assess_redis_version("7", &req()).unwrap(),
            VersionVerdict::Compatible
        );
        assert_eq!(
            assess_redis_version("6", &req()).unwrap(),
            VersionVerdict::Incompatible
        );
        assert_eq!(
            assess_redis_version("9", &req()).unwrap(),
            VersionVerdict::Incompatible
        );
    }

    #[test]
    fn supported_majors_stay_within_requirement() {
        // Guard against SUPPORTED_MAJOR_VERSIONS drifting out of REDIS_VERSION_REQ:
        // every supported major must satisfy the requirement at some minor.
        let req = req();
        for &major in SUPPORTED_MAJOR_VERSIONS {
            let ok = (0..10).any(|minor| req.matches(&Version::new(major, minor, 0)));
            assert!(
                ok,
                "supported major {major} has no minor within {REDIS_VERSION_REQ}"
            );
        }
    }
}
