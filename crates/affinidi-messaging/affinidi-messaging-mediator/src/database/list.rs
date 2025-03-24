use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::{Folder, MessageList, MessageListElement};
use itertools::Itertools;
use redis::{Value, from_redis_value};
use tracing::{Instrument, Level, event, span};

use super::Database;

impl Database {
    /// Retrieves list of messages for the specified DID and folder
    /// The folder can be either Inbox or Outbox
    /// - did_hash: The DID sha256 hash to retrieve messages for
    /// - range: stream ID range to retrieve (defaults to '-' and '+' which gets all messages)
    pub async fn list_messages(
        &self,
        did_hash: &str,
        folder: Folder,
        range: Option<(&str, &str)>,
        limit: u32,
    ) -> Result<MessageList, MediatorError> {
        let _span = span!(
            Level::DEBUG,
            "list_messages",
            did_hash = did_hash,
            folder = format!("{:?}", folder),
            range = format!("{:?}", range)
        );
        async move {
            let mut conn = self.0.get_async_connection().await?;

            let key = match folder {
                Folder::Inbox => format!("RECEIVE_Q:{}", did_hash),
                Folder::Outbox => format!("SEND_Q:{}", did_hash),
            };

            let (start, end) = if let Some((start, end)) = range {
                (start, end)
            } else {
                ("-", "+")
            };

            let db_response: Value = deadpool_redis::redis::cmd("XRANGE")
                .arg(&key)
                .arg(start)
                .arg(end)
                .arg("COUNT")
                .arg(limit)
                .query_async(&mut conn)
                .await
                .map_err(|err| {
                    event!(
                        Level::ERROR,
                        "Couldn't get message_list({}) from database for DID_hash {}: {}",
                        key,
                        did_hash,
                        err
                    );
                    MediatorError::DatabaseError(
                        did_hash.into(),
                        format!(
                            "Couldn't get message_list({}) from database for DID_hash {}: {}",
                            key, did_hash, err
                        ),
                    )
                })?;

            // The following should really be a Impl FromRedisValue for MessageList
            // But I don't want to poison the affinidi-messaging-sdk crate with Redis and internal details
            // So I'm going to manually parse the response here
            // We could have an internal/external SDK - but that's a lot of work
            let mut messages: MessageList = Vec::new();

            // Redis response is
            // Bulk([bulk(string(id), bulk(string(field), string(field))])

            fn _error<T>(e: T, did: &str, key: &str) -> MediatorError
            where
                T: std::fmt::Display,
            {
                event!(
                    Level::ERROR,
                    "Couldn't parse message_list did({}) folder({}): {}",
                    did,
                    key,
                    e
                );
                MediatorError::DatabaseError(
                    "NA".into(),
                    format!(
                        "Couldn't parse message_list did({}) folder({}): {}",
                        did, key, e
                    ),
                )
            }

            let items: Vec<Value> =
                from_redis_value(&db_response).map_err(|e| _error(e, did_hash, &key))?;

            for item in items {
                // item = Bulk(string(id), Bulk(fields...))
                let item: Vec<Value> = from_redis_value(&item).unwrap();
                let mut msg_element = MessageListElement::default();

                let stream_id: String =
                    from_redis_value(&item[0]).map_err(|e| _error(e, did_hash, &key))?;
                match folder {
                    Folder::Inbox => {
                        msg_element.receive_id = Some(stream_id.clone());
                    }
                    Folder::Outbox => {
                        msg_element.send_id = Some(stream_id.clone());
                    }
                }

                msg_element.timestamp = stream_id
                    .split('-')
                    .next()
                    .unwrap_or("")
                    .parse()
                    .unwrap_or(0);

                let fields: Vec<String> =
                    from_redis_value(&item[1]).map_err(|e| _error(e, did_hash, &key))?;

                for (k, v) in fields.iter().tuples() {
                    match k.as_str() {
                        "MSG_ID" => msg_element.msg_id.clone_from(v),
                        "BYTES" => msg_element.size = v.parse().unwrap_or(0),
                        "FROM" => msg_element.from_address = Some(v.clone()),
                        "TO" => msg_element.to_address = Some(v.clone()),
                        _ => {}
                    }
                }
                messages.push(msg_element);
            }

            Ok(messages)
        }
        .instrument(_span)
        .await
    }
}
