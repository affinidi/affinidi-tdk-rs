/*!
 * This module contains the implementation of the delete handler.
 *
 * A task that runs deleting messages in the background.
 * This provides a performant way to delete messages without blocking the main thread.
 *
 * Messages can still be deleted from the main thread where you may want direct control.
 *
 * A deletion message is sent to the deletionthread, containing the profile and the message ID.
 * The deletion thread then deletes the message from the profile, using whatever transport method is required.
 *
 */

use crate::{
    ATM, SharedState, errors::ATMError, messages::DeleteMessageRequest, profiles::ATMProfile,
};
use std::sync::Arc;
use tokio::{
    select,
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
};
use tracing::{Instrument, Level, debug, span};

pub enum DeletionHandlerCommands {
    DeleteMessage(Arc<ATMProfile>, String),
    Exit,
}

impl ATM {
    /// Starts the Deletion Handler
    pub async fn start_deletion_handler(
        &self,
        mut from_sdk: Receiver<DeletionHandlerCommands>,
        to_sdk: Sender<DeletionHandlerCommands>,
    ) -> Result<JoinHandle<()>, ATMError> {
        let shared_state = self.inner.clone();

        let handle = tokio::spawn(async move {
            let _ = ATM::deletion_handler(shared_state, &mut from_sdk, to_sdk).await;
        });

        debug!("Deletion handler started");

        Ok(handle)
    }

    /// Close the Deletion task gracefully
    pub async fn abort_deletion_handler(&self) -> Result<(), ATMError> {
        let _ = self
            .inner
            .deletion_handler_send_stream
            .send(DeletionHandlerCommands::Exit)
            .await;

        Ok(())
    }

    pub(crate) async fn deletion_handler(
        shared_state: Arc<SharedState>,
        from_sdk: &mut Receiver<DeletionHandlerCommands>,
        to_sdk: Sender<DeletionHandlerCommands>,
    ) -> Result<(), ATMError> {
        let _span = span!(Level::INFO, "deletion_handler");
        async move {
            let atm = ATM {
                inner: shared_state,
            };
            loop {
                select! {
                    value = from_sdk.recv() => {
                        match value {
                            Some(DeletionHandlerCommands::DeleteMessage(profile, message_id)) => {
                                let _ = atm.delete_messages_direct(&profile, &DeleteMessageRequest { message_ids: vec![message_id.clone()] }).await;
                            }
                            Some(DeletionHandlerCommands::Exit) => {
                                break;
                            }
                            None => {
                                break;
                            }
                        }
                    }
                }
            }

            debug!("Deletion handler stopped");
            let _ = to_sdk.send(DeletionHandlerCommands::Exit).await;
            Ok(())
        }
        .instrument(_span)
        .await
    }
}
