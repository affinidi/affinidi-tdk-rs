/*!
 * Main task that runs in a loop checking for expired messages and removing them
 */

use affinidi_messaging_mediator_common::{database::DatabaseHandler, errors::ProcessorError};
use std::time::Duration;
use tracing::{debug, info, warn};

use super::config::MessageExpiryCleanupConfig;

/// MessageExpiryCleanupProcessor deletes expired messages from the Mediator database
pub struct MessageExpiryCleanupProcessor {
    /// Configuration for the MessageExpiryCleanupProcessor
    _config: MessageExpiryCleanupConfig,
    /// Database handler for the Mediator
    pub(crate) database: DatabaseHandler,
}

impl MessageExpiryCleanupProcessor {
    pub fn new(config: MessageExpiryCleanupConfig, database: DatabaseHandler) -> Self {
        MessageExpiryCleanupProcessor {
            _config: config,
            database,
        }
    }

    pub async fn start(&self) -> Result<(), ProcessorError> {
        info!("Expired message cleanup processor started");

        loop {
            let sleep: tokio::time::Sleep = tokio::time::sleep(Duration::from_secs(1));
            sleep.await;

            let timeslots = match self.timeslot_scan().await {
                Ok(timeslots) => timeslots,
                Err(err) => {
                    info!("Error getting timeslots: {}", err);
                    continue;
                }
            };
            debug!("# of prior Timeslots: {}", timeslots.len());
            if timeslots.is_empty() {
                continue;
            } else if timeslots.len() > 5 {
                warn!(
                    "Timeslots are backed up. Current timeslot queue: {}",
                    timeslots.len()
                );
            }
            for timeslot in &timeslots {
                let (expired, total) = match self.expire_messages_from_timeslot(timeslot).await {
                    Ok((expired, total)) => (expired, total),
                    Err(err) => {
                        info!("Error expiring messages from timeslot: {}", err);
                        continue;
                    }
                };
                info!(
                    "timeslot ({}): expired {} messages out of {}",
                    timeslot, expired, total
                );
            }
        }

        // Ok(())
    }
}
