//! Handles processing of inbound messages
use super::State;
use crate::state_store::actions::chat_list::{Chat, ChatStatus};
use crate::state_store::actions::invitation::create_new_profile;
use crate::state_store::chat_message::{ChatEffect, ChatMessage, ChatMessageType};
use affinidi_messaging_didcomm::message::{Attachment, Message};
use affinidi_messaging_sdk::ATM;
use affinidi_messaging_sdk::messages::compat::UnpackMetadata;
use affinidi_messaging_sdk::messages::problem_report::ProblemReport;
use affinidi_messaging_sdk::protocols::message_pickup::{MessagePickup, MessagePickupStatusReply};
use affinidi_messaging_sdk::tasks::messaging::account::get::v0_2::MediatorAclAccessListMode;
use base64::prelude::*;
use rand::RngExt;
use rand::distr::Alphanumeric;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha256::digest;
use tracing::error;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Name {
    pub given: Option<String>,
    pub surname: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VcardType {
    pub r#type: VcardTypes,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum VcardTypes {
    #[serde(rename = "work")]
    Work(String),
    #[serde(rename = "cell")]
    Cell(String),
}
#[derive(Debug, Serialize, Deserialize)]
pub struct VCard {
    pub n: Name,
    pub email: Option<VcardType>,
    pub tel: Option<VcardType>,
}

#[derive(Serialize, Deserialize, Debug)]
struct _ChatMessage {
    pub text: Option<String>,
    pub effect: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct InviteChannel {
    pub channel_did: String,
}

fn random_suffix() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(4)
        .map(char::from)
        .collect()
}

/// Chat name from the vCard in the first attachment, or `UNKNOWN` and a
/// random suffix when there is none or it cannot be read.
fn chat_name_from_attachments(attachments: Option<&[Attachment]>) -> String {
    let Some(b64) = attachments
        .and_then(|attachments| attachments.first())
        .and_then(|attachment| attachment.data.base64.as_ref())
    else {
        return format!("UNKNOWN {}", random_suffix());
    };
    let vcard = match BASE64_URL_SAFE_NO_PAD.decode(b64) {
        Ok(decoded) => match serde_json::from_slice::<VCard>(&decoded) {
            Ok(vcard) => vcard,
            Err(e) => {
                warn!("Failed to parse vCard: {}", e);
                return format!("UNKNOWN {}", random_suffix());
            }
        },
        Err(e) => {
            warn!("Failed to decode vCard: {}", e);
            return format!("UNKNOWN {}", random_suffix());
        }
    };
    let first = vcard.n.given.as_deref().unwrap_or("UNKNOWN");
    let surname = vcard.n.surname.unwrap_or_else(random_suffix);
    format!("{first} {surname}")
}

/// The last five characters of a DID, or all of it if it is shorter.
fn did_suffix(did: &str) -> &str {
    did.char_indices()
        .nth_back(4)
        .map_or(did, |(position, _)| &did[position..])
}

/// The DID that authenticated a message: its authcrypt sender, else its
/// signer.
fn authenticated_sender_did(meta: &UnpackMetadata) -> Option<&str> {
    let kid = if meta.authenticated {
        meta.encrypted_from_kid.as_deref()
    } else {
        meta.sign_from.as_deref()
    }?;
    kid.split_once('#')
        .map(|(did, _)| did)
        .filter(|did| !did.is_empty())
}

/// Whether a message was authenticated as coming from the chat's peer.
fn sent_by_chat_peer(chat: &Chat, meta: &UnpackMetadata) -> bool {
    chat.remote_did.is_some() && authenticated_sender_did(meta) == chat.remote_did.as_deref()
}

/// Responsible for completing an incoming OOB Invitation flow.
/// This occurs after this client has shared a QR Code with another client.
async fn _handle_connection_setup(
    atm: &ATM,
    state: &mut State,
    message: &Message,
    meta: &UnpackMetadata,
) {
    info!("Received connection setup message");
    info!("Invite Message: {:#?}", message);

    let mut new_chat_name = chat_name_from_attachments(message.attachments.as_deref());

    let Some(from) = message.to.as_ref().and_then(|to| to.first()).cloned() else {
        warn!("Connection setup message has no recipient");
        return;
    };
    let Some(to) = message.from.clone() else {
        warn!("Connection setup message has no sender");
        return;
    };
    let (Some(pthid), Some(thid)) = (message.pthid.clone(), message.thid.clone()) else {
        warn!("Connection setup message is missing its thread ids");
        return;
    };
    let Some(mediator_did) = state.settings.mediator_did.clone() else {
        warn!("No mediator DID configured; cannot complete the connection setup");
        return;
    };
    let Some(our_name) = state.settings.our_name.clone() else {
        warn!("No name configured; cannot complete the connection setup");
        return;
    };

    // Create the new DID for this chat
    let our_new_did = match create_new_profile(
        atm,
        &mediator_did,
        Some(new_chat_name.clone()),
        true,
        state,
    )
    .await
    {
        Ok(profile) => profile,
        Err(e) => {
            warn!("Failed to create a profile for the new chat: {}", e);
            return;
        }
    };

    // Modify the new_chat_name so it is unique if it already exists
    if state.chat_list.chats.contains_key(&new_chat_name) {
        new_chat_name = format!("{new_chat_name} {}", did_suffix(&our_new_did.inner.did));
    }

    // Get the current profile
    let profiles = atm.get_profiles();

    let remote_secure_did =
        if let Ok(channel_did) = serde_json::from_value::<InviteChannel>(message.body.clone()) {
            channel_did.channel_did
        } else {
            warn!("Failed to parse connection accepted message");
            return;
        };
    info!("New remote secure DID: {}", remote_secure_did);

    let current_profile = {
        let Some(profile) = profiles
            .read()
            .await
            .0
            .values()
            .find(|p| p.inner.did == from)
            .cloned()
        else {
            warn!("No profile for DID({})", from);
            return;
        };
        profile
    };

    // Add this new profile to ATM
    let our_new_profile = match atm.profile_add(&our_new_did, true).await {
        Ok(profile) => profile,
        Err(e) => {
            warn!("Failed to add the new profile: {}", e);
            return;
        }
    };
    info!("Added new profile to ATM");

    // Add the remote secure DID to the our new secure profile
    let our_new_profile_info = match atm.trust_tasks().account_get(&our_new_profile, None).await {
        Ok(info) => info,
        Err(e) => {
            warn!(
                "Failed to get temp invite response profile info from mediator: {}",
                e
            );
            return;
        }
    };

    if our_new_profile_info.acl.access_list_mode == Some(MediatorAclAccessListMode::ExplicitAllow) {
        // Add the new remote secure DID to our new secure DID
        match atm
            .trust_tasks()
            .access_list_update(
                &our_new_profile,
                None,
                false,
                vec![digest(&remote_secure_did)],
                vec![],
            )
            .await
        {
            Ok(_) => {}
            Err(e) => {
                warn!(
                    "Failed to add {} to ACL of new secure profile: {}",
                    remote_secure_did, e
                );
                return;
            }
        }
    }

    let vcard = VCard {
        n: Name {
            given: Some(our_name.clone()),
            surname: Some(String::new()),
        },
        email: Some(VcardType {
            r#type: VcardTypes::Work(String::new()),
        }),
        tel: Some(VcardType {
            r#type: VcardTypes::Cell(String::new()),
        }),
    };
    let vcard = match serde_json::to_string(&vcard) {
        Ok(vcard) => vcard,
        Err(e) => {
            warn!("Failed to serialize our vCard: {}", e);
            return;
        }
    };
    let attachment = Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode(vcard))
        .id(Uuid::new_v4().to_string())
        .description(format!("{our_name}'s vCard Info"))
        .media_type("text/x-vcard".into())
        .format("https://affinidi.com/atm/client-attachment/contact-card".into())
        .finalize();

    // Create the response message
    let new_message = Message::build(
        uuid::Uuid::new_v4().to_string(),
        "https://affinidi.com/atm/client-actions/connection-accepted".to_string(),
        json!({"channel_did": our_new_did.inner.did}),
    )
    .from(from.clone())
    .pthid(pthid)
    .thid(thid)
    .to(to.clone())
    .attachment(attachment)
    .finalize();

    let packed = match atm
        .pack_encrypted(&new_message, &to, Some(&from), Some(&from))
        .await
    {
        Ok((packed, _)) => packed,
        Err(e) => {
            warn!("Failed to pack the connection setup response: {}", e);
            return;
        }
    };

    let (forward_id, forwarded) = match atm
        .routing()
        .forward_message(
            &current_profile,
            false,
            &packed,
            &mediator_did,
            &to,
            None,
            None,
        )
        .await
    {
        Ok(forwarded) => forwarded,
        Err(e) => {
            warn!("Failed to wrap the connection setup response: {}", e);
            return;
        }
    };

    let _ = atm
        .send_message(&current_profile, &forwarded, &forward_id, false, true)
        .await;

    info!("Sent connection setup response message");

    // Start cleaning up the old chat and profiles
    let Some(chat) = state.chat_list.find_chat_by_did(&current_profile.inner.did) else {
        error!("Chat not found for DID({})", &current_profile.inner.did);
        return;
    };

    // Invitation is complete
    let _ = MessagePickup::default()
        .send_messages_received(
            atm,
            &current_profile,
            &vec![meta.sha256_hash.clone()],
            false,
        )
        .await;

    // Remove the old invite chat
    state.remove_chat(&chat, atm).await;

    // Create the new chat with the new DID
    state
        .chat_list
        .create_chat(
            &new_chat_name,
            &format!("Chatting with {new_chat_name}"),
            &our_new_profile,
            Some(remote_secure_did.to_string()),
            None,
            ChatStatus::EstablishedChannel,
        )
        .await;

    // Insert a new message into the chat
    if let Some(new_chat) = state.chat_list.chats.get_mut(&new_chat_name) {
        new_chat.messages.push(ChatMessage::new(
            ChatMessageType::Effect {
                effect: ChatEffect::System,
            },
            format!("Start of conversation with {new_chat_name}"),
        ));
    }

    if state.chat_list.active_chat.is_none() {
        state.chat_list.active_chat = Some(new_chat_name.clone());
    }
}

pub async fn handle_message(
    atm: &ATM,
    state: &mut State,
    message: &Message,
    meta: &UnpackMetadata,
) {
    let to_did = if let Some(to) = &message.to {
        if let Some(to) = to.first() {
            to.to_string()
        } else {
            warn!("No to DID found in message");
            return;
        }
    } else {
        warn!("No to DID found in message");
        return;
    };

    let profile = {
        match atm.get_profiles().read().await.find_by_did(&to_did) {
            Some(profile) => profile,
            _ => {
                warn!("Profile not found for DID({})", &to_did);
                return;
            }
        }
    };

    let Some(chat) = state.chat_list.find_chat_by_did(&to_did) else {
        warn!("Chat not found for DID({})", &to_did);
        return;
    };

    match message.typ.as_str() {
        "https://affinidi.com/atm/client-actions/connection-setup" => {
            // Completes an inbound OOB Invitation flow (after sharing a QR Code)
            _handle_connection_setup(atm, state, message, meta).await;
            return; // message was deleted in the function
        }
        "https://affinidi.com/atm/client-actions/chat-activity" => {
            // Notice that someone else is typing
            /*
                Message {
                   id: "a141cca2-87ec-49b1-8f4b-5309281cb16b",
                   typ: "application/didcomm-plain+json",
                   type_: "https://affinidi.com/atm/client-actions/chat-activity",
                   body: Object {
                       "seqNo": Number(0),
                   },
                   from: Some(
                       "did:key:zDnaejpsRCMGt1HbTptCh9toKYsDrUukRshMVGBNkZYDb4Sv8",
                   ),
                   to: Some(
                       [
                           "did:key:zDnaeh4gZ787EKUUgt4Jwyq9EbVh7F4qrF3UUkQK8dTSiX43y",
                       ],
                   ),
                   thid: Some(
                       "a141cca2-87ec-49b1-8f4b-5309281cb16b",
                   ),
                   pthid: None,
                   extra_headers: {},
                   created_time: Some(
                       1733764621,
                   ),
                   expires_time: None,
                   from_prior: None,
                   attachments: None,
               }
            */
        }
        "https://affinidi.com/atm/client-actions/chat-message" => 'label_break: {
            // Received a chat message - need to add this to our chats
            let chat_msg: _ChatMessage =
                match serde_json::from_value::<_ChatMessage>(message.body.clone()) {
                    Ok(msg) => msg,
                    Err(e) => {
                        warn!("Failed to parse chat message: {}", e);
                        break 'label_break;
                    }
                };

            let Some(text) = chat_msg.text else {
                warn!("Chat message has no text");
                break 'label_break;
            };

            if !sent_by_chat_peer(&chat, meta) {
                warn!("Chat message for ({}) not sent by its peer", &chat.name);
                break 'label_break;
            }

            let Some(mut_chat) = state.chat_list.chats.get_mut(&chat.name) else {
                error!("Chats = {:#?}", state.chat_list.chats);
                warn!("Couldn't get mutable chat({})", &chat.name);
                break 'label_break;
            };

            if let Some(active_chat) = &state.chat_list.active_chat
                && active_chat != &chat.name
            {
                mut_chat.has_unread = true;
            }
            mut_chat
                .messages
                .push(ChatMessage::new(ChatMessageType::Inbound, text));
        }
        "https://didcomm.org/messagepickup/3.0/status" => 'label_break: {
            if chat.initialization {
                // Check if we have any messages waiting to be picked up
                let Ok(status) =
                    serde_json::from_value::<MessagePickupStatusReply>(message.body.clone())
                else {
                    warn!("Failed to parse message pickup status message");
                    break 'label_break;
                };
                info!(
                    "Profile ({}) has ({}) messages waiting",
                    &profile.inner.alias, status.message_count
                );

                let msg_pickup = MessagePickup::default();
                if status.message_count > 0 {
                    let _ = msg_pickup
                        .send_delivery_request(
                            atm,
                            &profile,
                            Some(status.message_count as usize),
                            false,
                        )
                        .await;
                }

                if let Some(mut_chat) = state.chat_list.chats.get_mut(&chat.name) {
                    mut_chat.initialization = false;
                } else {
                    warn!("Couldn't get mutable chat({})", &chat.name);
                }
            }
            return; // Ephemeral status message - no need to delete it
        }
        "https://affinidi.com/atm/client-actions/chat-delivered" => {
            /*
                Message {
                    id: "62f8bffb-fde5-4e04-841e-de7fc98e248e",
                    typ: "application/didcomm-plain+json",
                    type_: "https://affinidi.com/atm/client-actions/chat-delivered",
                    body: Object {
                        "messages": Array [
                            String("1c7b9964-92f0-430c-8ec9-6bbe852d0e4d"),
                        ],
                    },
                    from: Some(
                        "did:key:zDnaetp9QPxuWUBtfTfjsKPEfCo8p9BiWg1buNaS5LTEsEz75",
                    ),
                    to: Some(
                        [
                            "did:key:zDnaef5UtAgL3Nayo7aWLkWh86EuMfkW5Vio6DvNN86U5QxcZ",
                        ],
                    ),
                    thid: Some(
                        "62f8bffb-fde5-4e04-841e-de7fc98e248e",
                    ),
                    pthid: None,
                    extra_headers: {},
                    created_time: Some(
                        1733846313,
                    ),
                    expires_time: None,
                    from_prior: None,
                    attachments: None,
                }
            */
        }
        "https://affinidi.com/atm/client-actions/chat-effect" => 'label_break: {
            let chat_msg: _ChatMessage =
                match serde_json::from_value::<_ChatMessage>(message.body.clone()) {
                    Ok(msg) => msg,
                    Err(e) => {
                        warn!("Failed to parse chat message: {}", e);
                        break 'label_break;
                    }
                };

            let Some(effect) = chat_msg.effect else {
                warn!("Chat effect message has no effect");
                break 'label_break;
            };

            if !sent_by_chat_peer(&chat, meta) {
                warn!("Chat effect for ({}) not sent by its peer", &chat.name);
                break 'label_break;
            }

            let Some(mut_chat) = state.chat_list.chats.get_mut(&chat.name) else {
                warn!("Couldn't get mutable chat({})", &chat.name);
                break 'label_break;
            };

            if let Some(active_chat) = &state.chat_list.active_chat
                && active_chat != &chat.name
            {
                mut_chat.has_unread = true;
            }

            let effect = match effect.as_str() {
                "balloons" => ChatEffect::Ballons,
                "confetti" => ChatEffect::Confetti,
                _ => ChatEffect::System,
            };
            mut_chat.messages.push(ChatMessage::new(
                ChatMessageType::Effect { effect },
                String::new(),
            ));
        }
        "https://didcomm.org/messagepickup/3.0/delivery" => {
            // Received a message pickup delivery message
            if let Some(attachments) = &message.attachments {
                for attachment in attachments {
                    if let Some(b64) = &attachment.data.base64 {
                        let decoded = match BASE64_URL_SAFE_NO_PAD.decode(b64.clone()) {
                            Ok(decoded) => match String::from_utf8(decoded) {
                                Ok(decoded) => decoded,
                                Err(e) => {
                                    warn!(
                                        "Error encoding vec[u8] to string: ({:?}). Attachment ID ({:?})",
                                        e, attachment.id
                                    );
                                    continue;
                                }
                            },
                            Err(e) => {
                                warn!(
                                    "Error decoding base64: ({:?}). Attachment ID ({:?})",
                                    e, attachment.id
                                );
                                continue;
                            }
                        };

                        match atm.unpack(&decoded).await {
                            Ok((mut m, meta)) => {
                                info!("Delivered message: id({:?})\n {:#?}", attachment.id, m);
                                if let Some(attachment_id) = &attachment.id {
                                    m.id = attachment_id.to_string();
                                }
                                Box::pin(handle_message(atm, state, &m, &meta)).await;
                            }
                            Err(e) => {
                                warn!("Error unpacking message: ({:?})", e);
                                continue;
                            }
                        };
                    } else {
                        warn!("Attachment type not supported: {:?}", attachment.data);
                        continue;
                    }
                }
            }
            return; // ephemeral status message - no need to delete it
        }
        "https://affinidi.com/atm/client-actions/connection-accepted" => 'label_break: {
            // OOB Invitation acceptance has been received

            let remote_secure_did = if let Ok(channel_did) =
                serde_json::from_value::<InviteChannel>(message.body.clone())
            {
                channel_did.channel_did
            } else {
                warn!("Failed to parse connection accepted message");
                break 'label_break;
            };

            let mut new_chat_name = chat_name_from_attachments(message.attachments.as_deref());
            new_chat_name = new_chat_name.trim().to_string();

            let Some(secure_channel_did) = &chat.hidden else {
                warn!("Expecting to see hidden chat details");
                break 'label_break;
            };

            let profiles = atm.get_profiles();
            let our_secure_profile = {
                let Some(profile) = profiles
                    .read()
                    .await
                    .0
                    .values()
                    .find(|p| &p.inner.did == secure_channel_did)
                    .cloned()
                else {
                    warn!("No profile for secure DID({})", secure_channel_did);
                    break 'label_break;
                };
                profile
            };

            // Set up the ACL for the remote secure DID.
            let local_secure_profile_info = match atm
                .trust_tasks()
                .account_get(&our_secure_profile, None)
                .await
            {
                Ok(info) => info,
                Err(e) => {
                    warn!(
                        "Failed to get local secure profile info from mediator: {}",
                        e
                    );
                    return;
                }
            };

            if local_secure_profile_info.acl.access_list_mode
                == Some(MediatorAclAccessListMode::ExplicitAllow)
            {
                // Add the remote secure DID to this profile's ACL
                match atm
                    .trust_tasks()
                    .access_list_update(
                        &our_secure_profile,
                        None,
                        false,
                        vec![digest(&remote_secure_did)],
                        vec![],
                    )
                    .await
                {
                    Ok(_) => {
                        info!(
                            "Added {} to ACL of local secure profile {}",
                            remote_secure_did, our_secure_profile.inner.did
                        );
                    }
                    Err(e) => {
                        warn!(
                            "Failed to add {} to ACL of new secure profile: {}",
                            remote_secure_did, e
                        );
                        return;
                    }
                }
            }

            // We don't need the ephemeral chat anymore - delete it
            state.remove_chat(&chat, atm).await;

            // Update the secure chat with new details
            let Some(secure_chat) = state.chat_list.find_chat_by_did(secure_channel_did) else {
                warn!("Couldn't find secure chat by DID({})", &secure_channel_did);
                break 'label_break;
            };

            // Modify the new_chat_name so it is unique if it already exists
            if state.chat_list.chats.contains_key(&new_chat_name) {
                new_chat_name = format!("{new_chat_name} {}", did_suffix(secure_channel_did));
            }

            let mut new_secure_chat =
                if let Some(chat) = state.chat_list.chats.get(&secure_chat.name) {
                    chat.clone()
                } else {
                    warn!("Couldn't get mutable secure chat({})", &secure_chat.name);
                    break 'label_break;
                };

            new_secure_chat.remote_did = Some(remote_secure_did.clone());
            new_secure_chat.status = ChatStatus::EstablishedChannel;
            let old_chat_name = new_secure_chat.name.clone();
            new_secure_chat.name = new_chat_name.clone();

            // Remove the old chat from the list and add the new one
            state.chat_list.chats.remove(&old_chat_name);
            state
                .chat_list
                .chats
                .insert(new_chat_name.clone(), new_secure_chat);
        }
        "https://didcomm.org/report-problem/2.0/problem-report" => 'label_break: {
            // Received a problem report message
            // Show the message in the chat
            let problem_report: ProblemReport =
                match serde_json::from_value::<ProblemReport>(message.body.clone()) {
                    Ok(msg) => msg,
                    Err(e) => {
                        warn!("Failed to parse problem report: {}", e);
                        break 'label_break;
                    }
                };

            let Some(mut_chat) = state.chat_list.chats.get_mut(&chat.name) else {
                warn!("Couldn't get mutable chat({})", &chat.name);
                break 'label_break;
            };

            if let Some(active_chat) = &state.chat_list.active_chat
                && active_chat != &chat.name
            {
                mut_chat.has_unread = true;
            }

            mut_chat.messages.push(ChatMessage::new(
                ChatMessageType::Error,
                problem_report.to_string(),
            ));
        }
        _ => {
            warn!("Unknown message type: {}", message.typ);
        }
    }
    // Do we need to delete the message after processing?
    match MessagePickup::default()
        .send_messages_received(atm, &profile, &vec![meta.sha256_hash.clone()], false)
        .await
    {
        Ok(_) => info!("Deleted message ({})", message.id),
        Err(err) => error!("Failed to delete message ({}) - {:?}", message.id, err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_messaging_sdk::config::ATMConfig;
    use affinidi_messaging_sdk::profiles::ATMProfile;
    use affinidi_tdk::common::TDKSharedState;
    use affinidi_tdk::common::config::TDKConfig;
    use std::sync::Arc;

    const OUR_DID: &str = "did:example:us";
    const PEER_DID: &str = "did:example:peer";
    const CHAT: &str = "peer chat";

    async fn atm_with_chat() -> (ATM, State) {
        let tdk = TDKSharedState::new(TDKConfig::headless().unwrap())
            .await
            .unwrap();
        let atm = ATM::new(ATMConfig::builder().build().unwrap(), Arc::new(tdk))
            .await
            .unwrap();
        let profile = ATMProfile::new(&atm, Some(CHAT.into()), OUR_DID.into(), None)
            .await
            .unwrap();
        atm.profile_add(&profile, false).await.unwrap();

        let mut state = State::default();
        state
            .chat_list
            .create_chat(
                CHAT,
                "",
                &profile,
                Some(PEER_DID.into()),
                None,
                ChatStatus::EstablishedChannel,
            )
            .await;
        (atm, state)
    }

    fn message(message_type: &str, body: serde_json::Value) -> Message {
        Message::build(Uuid::new_v4().to_string(), message_type.to_string(), body)
            .from(PEER_DID.to_string())
            .to(OUR_DID.to_string())
            .finalize()
    }

    fn sent_by(did: &str) -> UnpackMetadata {
        let mut meta = UnpackMetadata::default();
        meta.authenticated = true;
        meta.encrypted_from_kid = Some(format!("{did}#key-1"));
        meta
    }

    fn messages_in(state: &State) -> usize {
        state.chat_list.chats[CHAT].messages.len()
    }

    const CHAT_MESSAGE: &str = "https://affinidi.com/atm/client-actions/chat-message";
    const CHAT_EFFECT: &str = "https://affinidi.com/atm/client-actions/chat-effect";

    #[tokio::test]
    async fn a_chat_message_without_text_is_dropped() {
        let (atm, mut state) = atm_with_chat().await;
        handle_message(
            &atm,
            &mut state,
            &message(CHAT_MESSAGE, json!({})),
            &sent_by(PEER_DID),
        )
        .await;
        assert_eq!(messages_in(&state), 0);
    }

    #[tokio::test]
    async fn a_chat_effect_without_an_effect_is_dropped() {
        let (atm, mut state) = atm_with_chat().await;
        handle_message(
            &atm,
            &mut state,
            &message(CHAT_EFFECT, json!({})),
            &sent_by(PEER_DID),
        )
        .await;
        assert_eq!(messages_in(&state), 0);
    }

    #[tokio::test]
    async fn a_chat_message_from_the_peer_is_shown() {
        let (atm, mut state) = atm_with_chat().await;
        let chat_message = message(CHAT_MESSAGE, json!({"text": "hello"}));
        handle_message(&atm, &mut state, &chat_message, &sent_by(PEER_DID)).await;
        assert_eq!(messages_in(&state), 1);
        let shown = state.chat_list.chats[CHAT].messages.iter().next().unwrap();
        assert_eq!(shown.message, "hello");
    }

    #[tokio::test]
    async fn a_chat_message_not_authenticated_as_the_peer_is_dropped() {
        let (atm, mut state) = atm_with_chat().await;
        let chat_message = message(CHAT_MESSAGE, json!({"text": "hello"}));
        handle_message(
            &atm,
            &mut state,
            &chat_message,
            &sent_by("did:example:other"),
        )
        .await;
        handle_message(&atm, &mut state, &chat_message, &UnpackMetadata::default()).await;
        assert_eq!(messages_in(&state), 0);
    }

    #[tokio::test]
    async fn a_connection_accepted_with_an_unreadable_vcard_does_not_panic() {
        let (atm, mut state) = atm_with_chat().await;
        let mut accepted = message(
            "https://affinidi.com/atm/client-actions/connection-accepted",
            json!({"channel_did": "did:example:secure"}),
        );
        accepted.attachments = Some(vec![Attachment::base64("not base64!".into()).finalize()]);
        handle_message(&atm, &mut state, &accepted, &sent_by(PEER_DID)).await;
    }

    #[tokio::test]
    async fn a_connection_setup_without_a_sender_does_not_panic() {
        let (atm, mut state) = atm_with_chat().await;
        let mut setup = message(
            "https://affinidi.com/atm/client-actions/connection-setup",
            json!({"channel_did": "did:example:secure"}),
        );
        setup.from = None;
        handle_message(&atm, &mut state, &setup, &sent_by(PEER_DID)).await;
        assert!(state.chat_list.chats.contains_key(CHAT));
    }

    #[test]
    fn chat_names_fall_back_when_the_vcard_cannot_be_read() {
        assert!(chat_name_from_attachments(None).starts_with("UNKNOWN "));

        let bad_base64 = [Attachment::base64("not base64!".into()).finalize()];
        assert!(chat_name_from_attachments(Some(&bad_base64)).starts_with("UNKNOWN "));

        let bad_json = [Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode("{")).finalize()];
        assert!(chat_name_from_attachments(Some(&bad_json)).starts_with("UNKNOWN "));

        let vcard = json!({"n": {"given": "Alice", "surname": "Smith"}}).to_string();
        let good = [Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode(vcard)).finalize()];
        assert_eq!(chat_name_from_attachments(Some(&good)), "Alice Smith");
    }

    #[test]
    fn did_suffix_handles_short_dids() {
        assert_eq!(did_suffix("did:example:abcdef"), "bcdef");
        assert_eq!(did_suffix("abc"), "abc");
        assert_eq!(did_suffix(""), "");
    }
}
