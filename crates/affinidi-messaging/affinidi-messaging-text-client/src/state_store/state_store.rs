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
use std::time::Duration;
use tokio::sync::{
    broadcast,
    mpsc::{self, UnboundedReceiver, UnboundedSender},
};
use tracing::{info, warn};

pub struct StateStore {
    state_tx: UnboundedSender<State>,
}

impl StateStore {
    pub fn new() -> (Self, UnboundedReceiver<State>) {
        let (state_tx, state_rx) = mpsc::unbounded_channel::<State>();

        (StateStore { state_tx }, state_rx)
    }
}

impl StateStore {
    pub async fn main_loop(
        self,
        mut terminator: Terminator,
        mut action_rx: UnboundedReceiver<Action>,
        mut interrupt_rx: broadcast::Receiver<Interrupted>,
        tdk: TDKSharedState,
    ) -> anyhow::Result<Interrupted> {
        // Setup the initial state
        let atm = match ATM::new(
            ATMConfigBuilder::default()
                .with_inbound_message_channel(100)
                .build()?,
            tdk.clone(),
        )
        .await
        {
            Ok(atm) => atm,
            Err(e) => {
                warn!("Failed to initialize ATM: {}", e);
                return Ok(Interrupted::SystemError);
            }
        };

        // Load any profiles from existing chats.
        let mut state = State::read_from_file("config.json").unwrap_or_default();
        state.initialization = true;

        tdk.secrets_resolver.insert_vec(&state.secrets).await;

        if !state.chat_list.chats.is_empty() {
            // Set the first chat as the active chat
            state.chat_list.active_chat = state.chat_list.chats.keys().next().cloned();
        }

        // Send the initial state once
        self.state_tx.send(state.clone())?;

        info!("Activating ({}) profiles", state.chat_list.chats.len());
        for chat in state.chat_list.chats.values() {
            let profile = match ATMProfile::from_tdk_profile(&atm, &chat.our_profile).await {
                Ok(profile) => profile,
                Err(e) => {
                    warn!("Failed to load profile for chat {}: {}", chat.name, e);
                    return Ok(Interrupted::SystemError);
                }
            };
            match atm.profile_add(&profile, true).await {
                Ok(_) => info!(
                    "Profile ({}) added for chat {}",
                    profile.inner.alias, chat.name
                ),
                Err(e) => {
                    warn!("Failed to add profile for chat {}: {}", chat.name, e);
                    return Ok(Interrupted::SystemError);
                }
            }
        }

        state.initialization = false;

        let mut inbound_message_channel = match atm.get_inbound_channel() {
            Some(channel) => channel,
            _ => {
                warn!("Failed to get inbound channel");
                return Ok(Interrupted::SystemError);
            }
        };

        let mut ticker = tokio::time::interval(Duration::from_secs(1));

        let result = loop {
            tokio::select! {
                message_received = inbound_message_channel.recv() => {
                    match message_received {
                        Ok(WebSocketResponses::MessageReceived(message, meta)) => {
                            handle_message(&atm, &mut state, &message, &meta).await;
                        },
                        Err(e) => {
                            warn!("Failed to receive message: {}", e);
                        }
                    }
                    //handle_message(&atm, &mut state, message, meta);
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
                        settings.check(&mut state, &tdk.did_resolver).await;
                    }
                    Action::SettingsUpdate { settings } => {
                        if settings.update(&mut state, &tdk.did_resolver).await {
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
                _ = ticker.tick() => {
                    // Do nothing
                },
                // Catch and handle interrupt signal to gracefully shutdown
                Ok(interrupted) = interrupt_rx.recv() => {
                    break interrupted;
                }
            }
            self.state_tx.send(state.clone())?;
        };

        let _ = state.save_to_file("config.json");

        Ok(result)
    }
}
