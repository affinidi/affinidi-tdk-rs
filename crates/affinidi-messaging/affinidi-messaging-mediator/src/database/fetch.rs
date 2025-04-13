use super::Database;
use affinidi_messaging_mediator_common::errors::MediatorError;
use affinidi_messaging_sdk::messages::{
    FetchDeletePolicy, GetMessagesResponse, MessageListElement, fetch::FetchOptions,
};
use itertools::Itertools;
use redis::{Value, from_redis_value};
use tracing::{Instrument, Level, debug, event, span, warn};

impl Database {
    /// Fetch as many messages as possible from the database
    /// - did_hash: DID we are checking
    pub async fn fetch_messages(
        &self,
        session_id: &str,
        did_hash: &str,
        options: &FetchOptions,
    ) -> Result<GetMessagesResponse, MediatorError> {
        let _span = span!(Level::DEBUG, "fetch_messages");
        async move {
            let mut conn = self.0.get_async_connection().await?;

            let start_id = options.start_id.as_deref().unwrap_or("-");

            let results: Vec<Value> = deadpool_redis::redis::cmd("FCALL")
                .arg("fetch_messages")
                .arg(1)
                .arg(did_hash)
                .arg(start_id)
                .arg(options.limit)
                .query_async(&mut conn)
                .await
                .map_err(|err| {
                    event!(
                        Level::ERROR,
                        "Couldn't fetch_messages() from database: {}",
                        err
                    );
                    MediatorError::DatabaseError(
                        14,
                        "NA".into(),
                        format!("Couldn't fetch_messages() from database: {}", err),
                    )
                })?;

            let mut messages = GetMessagesResponse::default();
            for item in &results {
                let sub_item: Vec<String> = match from_redis_value(item) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Error parsing redis value: ({:?}). Reason: {:?}", item, e);
                        messages
                            .get_errors
                            .push((format!("{:?}", item), e.to_string()));
                        continue;
                    }
                };
                let mut message = MessageListElement::default();
                for (k, v) in sub_item.iter().tuples() {
                    match k.as_str() {
                        "MSG_ID" => message.msg_id.clone_from(v),
                        "META_SEND_ID" => message.send_id = Some(v.clone()),
                        "META_RECEIVE_ID" => message.receive_id = Some(v.clone()),
                        "META_BYTES" => message.size = v.parse().unwrap_or(0),
                        "META_TIMESTAMP" => message.timestamp = v.parse().unwrap_or(0),
                        "META_TO" => message.to_address = Some(v.clone()),
                        "FROM_DID" => message.from_address = Some(v.clone()),
                        "MSG" => message.msg = Some(v.clone()),
                        _ => {}
                    }
                }
                debug!("Message id({}) fetched", &message.msg_id);

                // Delete message if requested
                if let FetchDeletePolicy::Optimistic = options.delete_policy {
                    match self
                        .0
                        .delete_message(Some(session_id), did_hash, &message.msg_id, None)
                        .await
                    {
                        Ok(_) => {
                            debug!("Message deleted: ({})", message.msg_id);
                        }
                        Err(e) => {
                            warn!("Error deleting message: ({})", e);
                            messages
                                .delete_errors
                                .push((message.msg_id.clone(), e.to_string()));
                        }
                    }
                }
                messages.success.push(message);
            }

            Ok(messages)
        }
        .instrument(_span)
        .await
    }
}
