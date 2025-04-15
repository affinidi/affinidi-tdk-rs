/*!
 * Scans the database every second for any messages that need to be deleted
 *
 * Message expiry is stored in two different database fields:
 * 1. A Sorted Set `MSG_EXPIRY` that stores at a per second resolution any messages expiring at that time
 *    These are called `expiry timeslots`
 * 2. A Set `MSG_EXPIRY:<SECONDS>` that stores the message IDs that are expiring at that time
 *
 * Where SECONDS is the number of seconds since the Unix epoch
 */

use std::time::SystemTime;

use affinidi_messaging_mediator_common::errors::ProcessorError;

use crate::message_expiry_cleanup::processor::MessageExpiryCleanupProcessor;

impl MessageExpiryCleanupProcessor {
    pub(crate) async fn timeslot_scan(&self) -> Result<Vec<String>, ProcessorError> {
        // Get the current EPOCH time in seconds
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut conn = self.database.get_async_connection().await?;

        deadpool_redis::redis::cmd("ZRANGE")
            .arg("MSG_EXPIRY")
            .arg("-inf")
            .arg(now)
            .arg("BYSCORE")
            .query_async(&mut conn)
            .await
            .map_err(|err| {
                ProcessorError::MessageExpiryCleanupError(format!(
                    "timeslot_scan failed. Reason: {}",
                    err
                ))
            })
    }

    /// Expires a message from the specified timeslot
    /// - key: The timeslot to expire the message from
    ///
    /// Returns
    /// - (expired, total)
    /// - expired: The number of messages that were expired
    /// - total: The total number of messages in the timeslot
    ///
    /// NOTE: The delta between total and expired is caused by messages that were already deleted in normal operation
    pub(crate) async fn expire_messages_from_timeslot(
        &self,
        key: &str,
    ) -> Result<(u32, u32), ProcessorError> {
        let mut conn = self.database.get_async_connection().await?;

        let mut expired: u32 = 0;
        let mut total: u32 = 0;

        loop {
            let msg_id: Option<String> = deadpool_redis::redis::cmd("SPOP")
                .arg(key)
                .query_async(&mut conn)
                .await
                .map_err(|err| {
                    ProcessorError::MessageExpiryCleanupError(format!(
                        "SPOP {} failed. Reason: {}",
                        key, err
                    ))
                })?;

            if let Some(msg_id) = msg_id {
                if self
                    .database
                    .delete_message(None, &msg_id, "ADMIN", None)
                    .await
                    .is_ok()
                {
                    expired += 1;
                }
                total += 1;
            } else {
                deadpool_redis::redis::cmd("ZREM")
                    .arg("MSG_EXPIRY")
                    .arg(key)
                    .exec_async(&mut conn)
                    .await
                    .map_err(|err| {
                        ProcessorError::MessageExpiryCleanupError(format!(
                            "ZREM MSG_EXPIRY {} failed. Reason: {}",
                            key, err
                        ))
                    })?;
                break;
            }
        }

        Ok((expired, total))
    }
}
