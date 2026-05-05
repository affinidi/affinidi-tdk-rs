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
            let semver_version: Version = match Version::parse(&version) {
                Ok(result) => result,
                Err(err) => {
                    return Err(MediatorError::problem_with_log(
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
                    ));
                }
            };
            if redis_version_req.matches(&semver_version) {
                info!("Redis version is compatible: {}", version);
                Ok(version.to_owned())
            } else {
                Err(MediatorError::problem_with_log(
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
                ))
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
