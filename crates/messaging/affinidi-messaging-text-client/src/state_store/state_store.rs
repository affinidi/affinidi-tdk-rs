use super::{State, actions::Action};
use crate::{
    state_store::{
        actions::{
            invitation::{create_invitation, send_invitation_accept},
            manual_connect::manual_connect_setup,
        },
        inbound_messages::handle_message,
        outbound_messages::send_message,
    },
    termination::{Interrupted, Terminator},
};
use affinidi_messaging_sdk::{
    ATM, config::ATMConfigBuilder, profiles::ATMProfile, transports::websockets::WebSocketResponses,
};
use affinidi_tdk::{common::TDKSharedState, secrets_resolver::SecretsResolver};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::{
    broadcast,
    mpsc::{self, UnboundedReceiver, UnboundedSender},
};
use tracing::{debug, error, info, warn};

pub struct StateStore {
    state_tx: UnboundedSender<Arc<State>>,
}

impl StateStore {
    pub fn new() -> (Self, UnboundedReceiver<Arc<State>>) {
        let (state_tx, state_rx) = mpsc::unbounded_channel::<Arc<State>>();

        (StateStore { state_tx }, state_rx)
    }
}

impl StateStore {
    pub async fn main_loop(
        self,
        mut terminator: Terminator,
        mut action_rx: UnboundedReceiver<Action>,
        mut interrupt_rx: broadcast::Receiver<Interrupted>,
        tdk: Arc<TDKSharedState>,
        state_file: PathBuf,
    ) -> anyhow::Result<Interrupted> {
        // Every early return goes through here: the UI loop only stops on an
        // interrupt (or the end of the key stream), so without this a failed
        // start leaves a live UI that cannot quit. The reason is printed by
        // `main` once the terminal has been restored.
        let mut fail = |reason: String| -> anyhow::Result<Interrupted> {
            error!("{}", reason);
            let interrupted = Interrupted::SystemError(reason);
            let _ = terminator.terminate(interrupted.clone());
            Ok(interrupted)
        };

        // Setup the initial state
        let atm_config = match ATMConfigBuilder::default()
            .with_inbound_message_channel(100)
            .build()
        {
            Ok(config) => config,
            Err(e) => return fail(format!("Failed to build the ATM config: {e}")),
        };
        let atm = match ATM::new(atm_config, tdk.clone()).await {
            Ok(atm) => atm,
            Err(e) => return fail(format!("Failed to initialize ATM: {e}")),
        };

        // Load any profiles from existing chats.
        let mut state = match State::load(&state_file) {
            Ok(state) => state,
            Err(e) => {
                return fail(format!(
                    "Cannot read {}: {e}. Fix or move the file aside; it is not overwritten",
                    state_file.display()
                ));
            }
        };
        info!("State file: {}", state_file.display());
        state.initialization = true;

        tdk.secrets_resolver().insert_vec(&state.secrets).await;

        if !state.chat_list.chats.is_empty() {
            // Set the first chat as the active chat
            state.chat_list.active_chat = state.chat_list.chats.keys().next().cloned();
        }

        // Send the initial state once
        self.state_tx.send(Arc::new(state.clone()))?;

        info!("Activating ({}) profiles", state.chat_list.chats.len());
        for chat in state.chat_list.chats.values() {
            let profile = match ATMProfile::from_tdk_profile(&atm, &chat.our_profile).await {
                Ok(profile) => profile,
                Err(e) => {
                    return fail(format!(
                        "Failed to load profile for chat {}: {e}",
                        chat.name
                    ));
                }
            };
            match atm.profile_add(&profile, true).await {
                Ok(_) => info!(
                    "Profile ({}) added for chat {}",
                    profile.inner.alias, chat.name
                ),
                Err(e) => {
                    return fail(format!(
                        "Failed to add profile for chat {} (is the mediator reachable?): {e}",
                        chat.name
                    ));
                }
            }
        }

        state.initialization = false;

        let mut inbound_message_channel = match atm.get_inbound_channel() {
            Some(channel) => channel,
            _ => return fail("Failed to get the inbound message channel".to_string()),
        };

        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        let mut last_saved = None;
        let mut save_failed = false;

        let result = loop {
            tokio::select! {
                // The inbound channel is a bounded mpsc: it never drops a
                // message, it holds the socket back while this loop is busy.
                // `None` (every sender gone) disables this arm.
                Some(message_received) = inbound_message_channel.recv() => {
                    match message_received {
                        WebSocketResponses::MessageReceived(message, meta) => {
                            handle_message(&atm, &mut state, &message, &meta).await;
                        },
                        WebSocketResponses::PackedMessageReceived(_) => {
                            // Ignore packed messages
                            warn!("Packed message received but not handled");
                        },
                        WebSocketResponses::Disconnected => {
                            // In-flight request waiters are notified of a dropped
                            // connection via dedicated channels; nothing to do on
                            // the inbound stream.
                            debug!("WebSocket disconnected notification");
                        },
                    }
                },
                Some(action) = action_rx.recv() => match action {
                    Action::SendMessage { chat_msg } => {
                       send_message(&mut state, &atm, &chat_msg).await;
                    },
                    Action::DeleteChat { chat } => {
                        match state.chat_list.chats.remove(&chat) {
                            Some(_) => {
                                info!("Chat {} removed", chat);
                            },
                            None => {
                                warn!("Chat {} not found", chat);
                            }
                        }
                        let _ = atm.profile_remove(&chat).await;
                        state.chat_list.active_chat = state.chat_list.chats.keys().next().cloned();
                    },
                    Action::ShowChatDetails { chat} => {
                        state.chat_details_popup.show = true;
                        state.chat_details_popup.chat_name = Some(chat.clone());
                    },
                    Action::CloseChatDetails => {
                        state.chat_details_popup.show = false;
                        state.chat_details_popup.chat_name = None;
                    },
                    Action::SetCurrentChat { chat } => {
                        state.chat_list.active_chat = Some(chat.clone());
                        if let Some(chat) = state.chat_list.chats.get_mut(&chat) {
                            chat.has_unread = false;
                        }
                    },
                    Action::Exit => {
                        let _ = terminator.terminate(Interrupted::UserInt);

                        break Interrupted::UserInt;
                    },
                    Action::SettingsPopupToggle => {
                        state.settings.show_settings_popup = !state.settings.show_settings_popup;
                    },
                    Action::SettingsCheck { settings } => {
                        settings.check(&mut state, tdk.did_resolver()).await;
                    }
                    Action::SettingsUpdate { settings } => {
                        if settings.update(&mut state, tdk.did_resolver()).await {
                            state.settings.show_settings_popup = false;
                        }
                    }
                    Action::InvitePopupStart => {
                        match create_invitation(&mut state, &self.state_tx, &atm).await {
                            Ok(_) => {
                                info!("OOB Invitation created and added to Chats");
                            },
                            Err(e) => {
                                warn!("Failed to create invitation: {}", e);
                            }
                        }
                    },
                    Action::InvitePopupStop => {
                        state.invite_popup.show_invite_popup = false;
                        state.invite_popup.invite = None;
                    },
                    Action::AcceptInvitePopupStart => {
                        state.accept_invite_popup.show = true;
                    }
                    Action::AcceptInvite { invite_link } => {
                        state.accept_invite_popup.invite_link = invite_link;
                        let _ = send_invitation_accept(&mut state, &self.state_tx, &atm).await;
                    }
                    Action::AcceptInvitePopupStop => {
                        state.accept_invite_popup.show = false;
                        state.accept_invite_popup.invite_link = String::new();
                    }
                    Action::ManualConnectPopupStart => {
                        state.manual_connect_popup.show = true;
                        state.manual_connect_popup.remote_did = String::new();
                        state.manual_connect_popup.alias = String::new();
                        state.manual_connect_popup.error_msg = None;
                    },
                    Action::ManualConnectPopupStop => {
                        state.manual_connect_popup.show = false;
                        state.manual_connect_popup.remote_did = String::new();
                        state.manual_connect_popup.alias = String::new();
                        state.manual_connect_popup.error_msg = None;
                    },
                    Action::ManualConnect { alias, remote_did } => {
                        match manual_connect_setup(&mut state, &atm, &alias, &remote_did).await {
                            Ok(_) => {
                                // Everything worked - close popup
                                state.manual_connect_popup.show = false;
                                state.manual_connect_popup.remote_did = String::new();
                        state.manual_connect_popup.alias = String::new();
                        state.manual_connect_popup.error_msg = None;
                            },
                            Err(e) => {
                                state.manual_connect_popup.error_msg = Some(e.to_string());
                            }
                        }
                    }
                },
                // Tick to terminate the select every N milliseconds
                // Nothing changed: no save, no state sent to the UI.
                _ = ticker.tick() => continue,
                // Catch and handle interrupt signal to gracefully shutdown
                Ok(interrupted) = interrupt_rx.recv() => {
                    break interrupted;
                }
                // The UI loop ended on its own (end of the key stream, or a
                // render error). State is no longer sent every tick, so a
                // failed send cannot be relied on to notice; stop here.
                _ = self.state_tx.closed() => {
                    break Interrupted::UserInt;
                }
            }
            match state.save_if_changed(&state_file, &mut last_saved) {
                Ok(()) => save_failed = false,
                Err(e) => {
                    // Shown in the UI's log pane; reported once per run of
                    // failures rather than on every change.
                    if !save_failed {
                        error!(
                            "Failed to save state to {}: {e}. Changes are not on disk",
                            state_file.display()
                        );
                    }
                    save_failed = true;
                }
            }
            self.state_tx.send(Arc::new(state.clone()))?;
        };

        if let Err(e) = state.save_to_file(&state_file) {
            error!("Failed to save state to {}: {e}", state_file.display());
            if !matches!(result, Interrupted::SystemError(_)) {
                return Ok(Interrupted::SystemError(format!(
                    "Failed to save state to {} on exit: {e}",
                    state_file.display()
                )));
            }
        }

        Ok(result)
    }
}
