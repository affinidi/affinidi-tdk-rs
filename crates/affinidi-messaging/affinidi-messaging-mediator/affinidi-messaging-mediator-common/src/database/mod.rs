use crate::errors::MediatorError;
use affinidi_messaging_sdk::messages::problem_report::{
    ProblemReport, ProblemReportScope, ProblemReportSorter,
};
use axum::http::StatusCode;
use config::DatabaseConfig;
use deadpool_redis::Connection;
use redis::aio::PubSub;
use semver::{Version, VersionReq};
use std::{thread::sleep, time::Duration};
use tracing::{Level, event, info};

pub mod config;
pub mod delete;

#[derive(Clone)]
pub struct DatabaseHandler {
    pub pool: deadpool_redis::Pool,
    redis_url: String,
}

const REDIS_VERSION_REQ: &str = ">=7.1, <9.0";

impl DatabaseHandler {
    pub async fn new(config: &DatabaseConfig) -> Result<Self, MediatorError> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Creates initial pool Configuration from the redis database URL
        let pool = deadpool_redis::Config::from_url(&config.database_url)
            .builder()
            .map_err(|err| {
                MediatorError::MediatorError(
                    1,
                    "NA".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "me.res.storage.url".into(),
                        "Database URL ({1}) is invalid. Reason: {2}".into(),
                        vec![config.database_url.clone(), err.to_string()],
                        None,
                    )),
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    format!(
                        "Database URL ({}) is invalid. Reason: {}",
                        config.database_url, err
                    ),
                )
            })?;

        // Now that we have a base config, we customise the redis pool config
        // and create the async pool of redis connections
        let pool = pool
            .runtime(deadpool_redis::Runtime::Tokio1)
            .max_size(config.database_pool_size)
            .timeouts(deadpool_redis::Timeouts {
                wait: Some(Duration::from_secs(config.database_timeout.into())),
                create: Some(Duration::from_secs(config.database_timeout.into())),
                recycle: Some(Duration::from_secs(config.database_timeout.into())),
            })
            .build()
            .map_err(|err| {
                MediatorError::MediatorError(
                    2,
                    "NA".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "me.res.storage.config".into(),
                        "Database config is invalid. Reason: {2}".into(),
                        vec![err.to_string()],
                        None,
                    )),
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    format!("Database config is invalid. Reason: {}", err),
                )
            })?;

        let database = Self {
            pool,
            redis_url: config.database_url.clone(),
        };
        loop {
            let mut conn = match database.get_async_connection().await {
                Ok(conn) => conn,
                Err(err) => {
                    event!(Level::WARN, "Error getting connection to database: {}", err);
                    event!(Level::WARN, "Retrying database connection in 10 seconds");
                    sleep(Duration::from_secs(10));
                    continue;
                }
            };

            let pong: Result<String, deadpool_redis::redis::RedisError> =
                deadpool_redis::redis::cmd("PING")
                    .query_async(&mut conn)
                    .await;
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
                    sleep(Duration::from_secs(10));
                }
            }
        }

        // Check the version of Redis Server
        database.check_server_version().await?;

        //database.get_db_metadata().await?;
        Ok(database)
    }

    /// Returns a redis async database connector or returns an Error
    /// This is the main method to get a connection to the database
    pub async fn get_async_connection(&self) -> Result<Connection, MediatorError> {
        self.pool.get().await.map_err(|err| {
            MediatorError::MediatorError(
                3,
                "NA".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.connection".into(),
                    "Can't get database connection. Reason: {1}".into(),
                    vec![err.to_string()],
                    None,
                )),
                StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                format!("Can't get database connection. Reason: {}", err),
            )
        })
    }

    /// Returns a redis database connector or returns an Error
    /// This should only be used for pubsub operations
    pub async fn get_pubsub_connection(&self) -> Result<PubSub, MediatorError> {
        let client = redis::Client::open(self.redis_url.clone()).map_err(|err| {
            MediatorError::MediatorError(
                4,
                "NA".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.connection.pubsub".into(),
                    "Can't open database connection for pubsub. Reason: {1}".into(),
                    vec![err.to_string()],
                    None,
                )),
                StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                format!("Can't open database connection for pubsub. Reason: {}", err),
            )
        })?;

        client.get_async_pubsub().await.map_err(|err| {
            MediatorError::MediatorError(
                5,
                "NA".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.connection.pubsub.receiver".into(),
                    "Can't get pubsub receiver. Reason: {1}".into(),
                    vec![err.to_string()],
                    None,
                )),
                StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                format!("Can't get pubsub receiver. Reason: {}", err),
            )
        })
    }

    /// Helper function to check the version of the Redis Server
    async fn check_server_version(&self) -> Result<String, MediatorError> {
        let redis_version_req: VersionReq = match VersionReq::parse(REDIS_VERSION_REQ) {
            Ok(result) => result,
            Err(err) => panic!("Couldn't process required Redis version. Reason: {}", err),
        };

        let mut conn = self.get_async_connection().await?;
        let server_info: String = match deadpool_redis::redis::cmd("INFO")
            .arg("SERVER")
            .query_async(&mut conn)
            .await
        {
            Ok(result) => result,
            Err(err) => {
                return Err(MediatorError::MediatorError(
                    6,
                    "NA".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "me.res.storage.info".into(),
                        "Couldn't query database information. Reason: {1}".into(),
                        vec![err.to_string()],
                        None,
                    )),
                    StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    format!("Couldn't query database information. Reason: {}", err),
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
                    return Err(MediatorError::MediatorError(
                        7,
                        "NA".to_string(),
                        None,
                        Box::new(ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "me.res.storage.version".into(),
                            "Cannot parse database version ({1}). Reason: {2}".into(),
                            vec![version.clone(), err.to_string()],
                            None,
                        )),
                        StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                        format!(
                            "Cannot parse database version ({}). Reason: {}",
                            version, err
                        ),
                    ));
                }
            };
            if redis_version_req.matches(&semver_version) {
                info!("Redis version is compatible: {}", version);
                Ok(version.to_owned())
            } else {
                Err(MediatorError::MediatorError(
                    8,
                    "NA".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "me.res.storage.version.incompatible".into(),
                        "Database version {1} does not match expected {2}".into(),
                        vec![version.clone(), redis_version_req.to_string()],
                        None,
                    )),
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    format!(
                        "Database version {} does not match expected {}",
                        version, redis_version_req
                    ),
                ))
            }
        } else {
            Err(MediatorError::MediatorError(
                9,
                "NA".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.version.unknown".into(),
                    "Couldn't determine database version".into(),
                    vec![],
                    None,
                )),
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                "Couldn't determine database version".to_string(),
            ))
        }
    }
}
