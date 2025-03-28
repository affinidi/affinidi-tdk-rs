use super::Database;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::MessageListElement;
use itertools::Itertools;
use redis::{Value, from_redis_value};
use subtle::ConstantTimeEq;
use tracing::{Instrument, Level, debug, event, span};

impl Database {
    /// Get a message from the database
    /// - msg_id: The unique identifier of the message
    pub async fn get_message(
        &self,
        did_hash: &str,
        msg_id: &str,
    ) -> Result<MessageListElement, MediatorError> {
        let _span = span!(Level::DEBUG, "get_message", msg_id = msg_id,);
        async move {
            let mut conn = self.0.get_async_connection().await?;

            let (didcomm_message, meta_data): (Value, Vec<String>) = deadpool_redis::redis::pipe()
                .atomic()
                .cmd("GET")
                .arg(["MSG:", msg_id].concat())
                .cmd("HGETALL")
                .arg(["MSG:META:", msg_id].concat())
                .query_async(&mut conn)
                .await
                .map_err(|err| {
                    event!(
                        Level::ERROR,
                        "Couldn't get message_id({}) from database: {}",
                        msg_id,
                        err
                    );
                    MediatorError::DatabaseError(
                        "NA".into(),
                        format!("Couldn't get message_id({}) from database: {}", msg_id, err),
                    )
                })?;

            let didcomm_message: String = match didcomm_message {
                Value::Nil => {
                    return Err(MediatorError::DatabaseError(
                        did_hash.into(),
                        format!("Message not found for ID: {}", msg_id),
                    ));
                }
                v => from_redis_value(&v).map_err(|e| {
                    MediatorError::InternalError(
                        did_hash.into(),
                        format!("Couldn't convert didcomm_message to string: {}", e),
                    )
                })?,
            };

            debug!("didcomm_message: {:?}", didcomm_message);
            debug!("metadata: {:?}", meta_data);

            let mut message = MessageListElement {
                msg_id: msg_id.to_string(),
                msg: Some(didcomm_message),
                ..Default::default()
            };

            for (k, v) in meta_data.iter().tuples() {
                match k.as_str() {
                    "MSG_ID" => message.msg_id.clone_from(v),
                    "BYTES" => message.size = v.parse().unwrap_or(0),
                    "FROM" => message.from_address = Some(v.clone()),
                    "TO" => message.to_address = Some(v.clone()),
                    "TIMESTAMP" => message.timestamp = v.parse().unwrap_or(0),
                    "SEND_ID" => message.send_id = Some(v.clone()),
                    "RECEIVE_ID" => message.receive_id = Some(v.clone()),
                    _ => {}
                }
            }

            // Update SEND metrics

            if did_hash
                .as_bytes()
                .ct_eq(
                    message
                        .from_address
                        .as_ref()
                        .unwrap_or(&"".to_string())
                        .as_bytes(),
                )
                .unwrap_u8()
                == 1
                || did_hash
                    .as_bytes()
                    .ct_eq(
                        message
                            .to_address
                            .as_ref()
                            .unwrap_or(&"".to_string())
                            .as_bytes(),
                    )
                    .unwrap_u8()
                    == 1
            {
                let _ = self.update_send_stats(message.size as i64).await;
                Ok(message)
            } else {
                Err(MediatorError::DatabaseError(
                    did_hash.into(),
                    format!("Message not found for DID: {}", did_hash),
                ))
            }
        }
        .instrument(_span)
        .await
    }
}
