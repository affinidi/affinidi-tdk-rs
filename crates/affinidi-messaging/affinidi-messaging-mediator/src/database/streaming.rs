use crate::tasks::websocket_streaming::PubSubRecord;
use affinidi_messaging_mediator_common::errors::MediatorError;
use redis::{Value, from_redis_value};
use tracing::{Level, debug, error, event};

use super::Database;

impl Database {
    pub async fn streaming_clean_start(&self, uuid: &str) -> Result<(), MediatorError> {
        let mut conn = self.0.get_async_connection().await?;

        let response: Vec<Value> = deadpool_redis::redis::pipe()
            .atomic()
            .cmd("FCALL")
            .arg("clean_start_streaming")
            .arg(1)
            .arg(uuid)
            .query_async(&mut conn)
            .await
            .map_err(|err| {
                event!(
                    Level::ERROR,
                    "redis function clean_start_streaming() failed. Reason: {}",
                    err
                );
                MediatorError::DatabaseError(
                    "NA".into(),
                    format!(
                        "redis function clean_start_streaming() failed. Reason: {}",
                        err
                    ),
                )
            })?;

        if let Ok(count) = from_redis_value::<i64>(&response[0]) {
            event!(
                Level::INFO,
                "clean_start_streaming() cleaned {} sessions",
                count
            );
            Ok(())
        } else {
            event!(
                Level::ERROR,
                "clean_start_streaming() failed to parse response: {:?}",
                response
            );
            Err(MediatorError::DatabaseError(
                "NA".into(),
                format!(
                    "redis fn clean_start_streaming() failed. Response ({:?})",
                    response
                ),
            ))
        }
    }

    /// Checks if the given DID hash is live streaming
    /// did_hash: The DID hash to check
    /// force_delivery: If true, the message will be delivered even if the client is not live streaming
    /// Returns the streaming service ID that the client is connecting to if the DID hash is live streaming
    pub async fn streaming_is_client_live(
        &self,
        did_hash: &str,
        force_delivery: bool,
    ) -> Option<String> {
        let mut conn = match self.0.get_async_connection().await {
            Ok(conn) => conn,
            _ => {
                error!("is_live_streaming(): Failed to get connection to Redis");
                return None;
            }
        };

        match deadpool_redis::redis::cmd("HGET")
            .arg("GLOBAL_STREAMING")
            .arg(did_hash)
            .query_async::<Option<String>>(&mut conn)
            .await
        {
            Ok(response) => {
                if let Some(row) = response {
                    let parts: Vec<&str> = row.split(':').collect();

                    if parts.len() == 2 {
                        if parts[1] == "TRUE" {
                            // Client is live streaming
                            Some(parts[0].to_string())
                        } else if force_delivery {
                            // Client is not live streaming, but we are forcing delivery
                            Some(parts[0].to_string())
                        } else {
                            // Client is not live streaming
                            None
                        }
                    } else {
                        // Invalid Redis data
                        None
                    }
                } else {
                    // No Redis data found.
                    None
                }
            }
            Err(err) => {
                event!(
                    Level::ERROR,
                    "check if live_streaming for did_hash({}) failed. Reason: {}",
                    did_hash,
                    err
                );
                None
            }
        }
    }

    /// Publishes a live message to the streaming service
    /// This follows a call to is_live_streaming() to get the streaming service ID if valid
    /// NOTE: There is a chance that a client could close live-streaming between the check and publishing
    ///        Not an issue, as the streaming component will handle this gracefully
    /// NOTE: Why not combine is_live_streaming() and this function into an atomic action?
    ///       While it would be more efficient in some ways, it would also mean pushing the full message to Redis
    ///       on every delivery, as messages get larger this would become less efficient.
    ///       So best compromise is to have the client check if live-streaming is active, then send the message
    pub async fn streaming_publish_message(
        &self,
        did_hash: &str,
        stream_uuid: &str,
        message: &str,
        force_delivery: bool,
    ) -> Result<(), MediatorError> {
        let record = match serde_json::to_string(&PubSubRecord {
            did_hash: did_hash.to_string(),
            message: message.to_string(),
            force_delivery,
        }) {
            Ok(record) => record,
            Err(err) => {
                event!(
                    Level::ERROR,
                    "publish_live_message() for did_hash({}) failed to serialize message. Reason: {}",
                    did_hash,
                    err
                );
                return Err(MediatorError::DatabaseError(
                    "NA".into(),
                    format!(
                        "publish_live_message() for did_hash({}) failed to serialize message. Reason: {}",
                        did_hash, err
                    ),
                ));
            }
        };

        let mut conn = self.0.get_async_connection().await?;

        match deadpool_redis::redis::cmd("PUBLISH")
            .arg(["CHANNEL:", stream_uuid].concat())
            .arg(record)
            .exec_async(&mut conn)
            .await
        {
            Ok(_) => {
                debug!(
                    "published message to channel(CHANNEL:{}) for did_hash({})",
                    stream_uuid, did_hash
                );
                Ok(())
            }
            Err(err) => {
                event!(
                    Level::ERROR,
                    "publish_live_message() for did_hash({}) channel(CHANNEL:{}) failed. Reason: {}",
                    did_hash,
                    stream_uuid,
                    err
                );
                Err(MediatorError::DatabaseError(
                    "NA".into(),
                    format!(
                        "publish_live_message() for did_hash({}) channel(CHANNEL:{}) failed. Reason: {}",
                        did_hash, stream_uuid, err
                    ),
                ))
            }
        }
    }

    /// Registers a client to the live streaming service
    pub async fn streaming_register_client(
        &self,
        did_hash: &str,
        stream_uuid: &str,
    ) -> Result<(), MediatorError> {
        let mut conn = self.0.get_async_connection().await?;

        match deadpool_redis::redis::pipe()
            .atomic()
            .cmd("SADD")
            .arg(["STREAMING_SESSIONS:", stream_uuid].concat())
            .arg(did_hash)
            .cmd("HSET")
            .arg("GLOBAL_STREAMING")
            .arg(did_hash)
            .arg([stream_uuid, ":FALSE"].concat())
            .exec_async(&mut conn)
            .await
        {
            Ok(_) => {
                debug!("did_hash({}) registered to ({})", did_hash, stream_uuid);

                Ok(())
            }
            Err(err) => {
                event!(
                    Level::ERROR,
                    "streaming_register_client() for did_hash({}) stream_uuid(STREAMING_SESSIONS:{}) failed. Reason: {}",
                    did_hash,
                    stream_uuid,
                    err
                );
                Err(MediatorError::DatabaseError(
                    "NA".into(),
                    format!(
                        "streaming_register_client() for did_hash({}) stream_uuid(STREAMING_SESSIONS:{}) failed. Reason: {}",
                        did_hash, stream_uuid, err
                    ),
                ))
            }
        }
    }

    /// Enables live streaming for the client
    pub async fn streaming_start_live(
        &self,
        did_hash: &str,
        stream_uuid: &str,
    ) -> Result<(), MediatorError> {
        let mut conn = self.0.get_async_connection().await?;

        match deadpool_redis::redis::cmd("HSET")
            .arg("GLOBAL_STREAMING")
            .arg(did_hash)
            .arg([stream_uuid, ":", "TRUE"].concat())
            .exec_async(&mut conn)
            .await
        {
            Ok(_) => {
                debug!(
                    "did_hash({}) started live streaming from ({})",
                    did_hash, stream_uuid
                );

                Ok(())
            }
            Err(err) => {
                event!(
                    Level::ERROR,
                    "streaming_start_live() for did_hash({}) stream_uuid(STREAMING_SESSIONS:{}) failed. Reason: {}",
                    did_hash,
                    stream_uuid,
                    err
                );
                Err(MediatorError::DatabaseError(
                    "NA".into(),
                    format!(
                        "streaming_start_live() for did_hash({}) stream_uuid(STREAMING_SESSIONS:{}) failed. Reason: {}",
                        did_hash, stream_uuid, err
                    ),
                ))
            }
        }
    }

    /// Disables live streaming for a client
    pub async fn streaming_stop_live(
        &self,
        did_hash: &str,
        stream_uuid: &str,
    ) -> Result<(), MediatorError> {
        let mut conn = self.0.get_async_connection().await?;

        match deadpool_redis::redis::cmd("HSET")
            .arg("GLOBAL_STREAMING")
            .arg(did_hash)
            .arg([stream_uuid, ":", "FALSE"].concat())
            .exec_async(&mut conn)
            .await
        {
            Ok(_) => {
                debug!(
                    "did_hash({}) stopped live streaming from ({})",
                    did_hash, stream_uuid
                );

                Ok(())
            }
            Err(err) => {
                event!(
                    Level::ERROR,
                    "streaming_stop_live() for did_hash({}) stream_uuid(STREAMING_SESSIONS:{}) failed. Reason: {}",
                    did_hash,
                    stream_uuid,
                    err
                );
                Err(MediatorError::DatabaseError(
                    "NA".into(),
                    format!(
                        "streaming_stop_live() for did_hash({}) stream_uuid(STREAMING_SESSIONS:{}) failed. Reason: {}",
                        did_hash, stream_uuid, err
                    ),
                ))
            }
        }
    }

    /// Removes client from live streaming service
    pub async fn streaming_deregister_client(
        &self,
        did_hash: &str,
        stream_uuid: &str,
    ) -> Result<(), MediatorError> {
        let mut conn = self.0.get_async_connection().await?;

        match deadpool_redis::redis::pipe()
            .atomic()
            .cmd("SREM")
            .arg(["STREAMING_SESSIONS:", stream_uuid].concat())
            .arg(did_hash)
            .cmd("HDEL")
            .arg("GLOBAL_STREAMING")
            .arg(did_hash)
            .exec_async(&mut conn)
            .await
        {
            Ok(_) => {
                debug!("did_hash({}) deregistered from ({})", did_hash, stream_uuid);

                Ok(())
            }
            Err(err) => {
                event!(
                    Level::ERROR,
                    "streaming_deregister_client() for did_hash({}) stream_uuid(STREAMING_SESSIONS:{}) failed. Reason: {}",
                    did_hash,
                    stream_uuid,
                    err
                );
                Err(MediatorError::DatabaseError(
                    "NA".into(),
                    format!(
                        "streaming_deregister_client() for did_hash({}) stream_uuid(STREAMING_SESSIONS:{}) failed. Reason: {}",
                        did_hash, stream_uuid, err
                    ),
                ))
            }
        }
    }
}
