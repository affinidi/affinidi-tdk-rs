//! Handles processing of inbound messages
use super::State;
use crate::state_store::actions::chat_list::ChatStatus;
use crate::state_store::actions::invitation::create_new_profile;
use crate::state_store::chat_message::{ChatEffect, ChatMessage, ChatMessageType};
use affinidi_messaging_didcomm::{Attachment, AttachmentData, Message, UnpackMetadata};
use affinidi_messaging_sdk::ATM;
use affinidi_messaging_sdk::messages::problem_report::ProblemReport;
use affinidi_messaging_sdk::protocols::mediator::acls::{AccessListModeType, MediatorACLSet};
use affinidi_messaging_sdk::protocols::message_pickup::{MessagePickup, MessagePickupStatusReply};
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

    // Unpack the attachment vcard if it exists
    let mut new_chat_name = if let Some(attachment) = message.attachments.as_ref() {
        if let Some(vcard) = attachment.first() {
            if let AttachmentData::Base64 { value } = &vcard.data {
                let vcard_decoded = BASE64_URL_SAFE_NO_PAD.decode(value.base64.clone()).unwrap();
                let vcard: VCard = match serde_json::from_slice(&vcard_decoded) {
                    Ok(vcard) => vcard,
                    Err(e) => {
                        warn!("Failed to parse vCard: {}", e);
                        warn!("vCard: {:?}", vcard_decoded);
                        VCard {
                            n: Name {
                                given: Some("UNKNOWN".to_string()),
                                surname: Some(
                                    rand::rng()
                                        .sample_iter(&Alphanumeric)
                                        .take(4)
                                        .map(char::from)
                                        .collect::<String>(),
                                ),
                            },
                            email: Some(VcardType {
                                r#type: VcardTypes::Work(String::new()),
                            }),
                            tel: Some(VcardType {
                                r#type: VcardTypes::Cell(String::new()),
                            }),
                        }
                    }
                };

                let first = if let Some(first) = vcard.n.given.as_ref() {
                    first
                } else {
                    "UNKNOWN"
                };
                let surname = if let Some(surname) = vcard.n.surname.as_ref() {
                    surname.to_string()
                } else {
                    rand::rng()
                        .sample_iter(&Alphanumeric)
                        .take(4)
                        .map(char::from)
                        .collect::<String>()
                        .to_string()
                };

                format!("{first} {surname}")
            } else {
                format!(
                    "UNKNOWN {}",
                    rand::rng()
                        .sample_iter(&Alphanumeric)
                        .take(4)
                        .map(char::from)
                        .collect::<String>()
                )
            }
        } else {
            format!(
                "UNKNOWN {}",
                rand::rng()
                    .sample_iter(&Alphanumeric)
                    .take(4)
                    .map(char::from)
                    .collect::<String>()
            )
        }
    } else {
        format!(
            "UNKNOWN {}",
            rand::rng()
                .sample_iter(&Alphanumeric)
                .take(4)
                .map(char::from)
                .collect::<String>()
        )
    };

    // Create the new DID for this chat
    let our_new_did = create_new_profile(
        atm,
        &state.settings.mediator_did.clone().unwrap(),
        Some(new_chat_name.clone()),
        true,
        state,
    )
    .await
    .unwrap();

    // Modify the new_chat_name so it is unique if it already exists
    if state.chat_list.chats.contains_key(&new_chat_name) {
        let split_pos = our_new_did.inner.did.char_indices().nth_back(4).unwrap().0;
        let a = &our_new_did.inner.did[split_pos..];
        new_chat_name = format!("{new_chat_name} {a}");
    }

    // Get the current profile
    let profiles = atm.get_profiles();

    let from: String = message.to.clone().unwrap().first().unwrap().to_string();
    let to: String = message.from.clone().unwrap();

    let remote_secure_did =
        if let Ok(channel_did) = serde_json::from_value::<InviteChannel>(message.body.clone()) {
            channel_did.channel_did
        } else {
            warn!("Failed to parse connection accepted message");
            return;
        };
    info!("New remote secure DID: {}", remote_secure_did);

    let current_profile = {
        profiles
            .read()
            .await
            .0
            .values()
            .find(|p| p.inner.did == from)
            .unwrap()
            .clone()
    };

    // Add this new profile to ATM
    let our_new_profile = atm.profile_add(&our_new_did, true).await.unwrap();
    info!("Added new profile to ATM");

    // Add the remote secure DID to the our new secure profile
    let our_new_profile_info = match atm.mediator().account_get(&our_new_profile, None).await {
        Ok(Some(info)) => info,
        Ok(None) => {
            warn!(
                "No profile info found for local secure DID ({})",
                &our_new_profile.inner.did
            );
            return;
        }
        Err(e) => {
            warn!(
                "Failed to get temp invite response profile info from mediator: {}",
                e
            );
            return;
        }
    };

    let our_new_profile_acl_flags = MediatorACLSet::from_u64(our_new_profile_info.acls);
    if let AccessListModeType::ExplicitAllow = our_new_profile_acl_flags.get_access_list_mode().0 {
        // Add the new remote secure DID to our new secure DID
        match atm
            .mediator()
            .access_list_add(&our_new_profile, None, &[&digest(&remote_secure_did)])
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
            given: Some(state.settings.our_name.clone().unwrap()),
            surname: Some(String::new()),
        },
        email: Some(VcardType {
            r#type: VcardTypes::Work(String::new()),
        }),
        tel: Some(VcardType {
            r#type: VcardTypes::Cell(String::new()),
        }),
    };
    let vcard = serde_json::to_string(&vcard).unwrap();
    let attachment = Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode(vcard))
        .id(Uuid::new_v4().into())
        .description(format!(
            "{}'s vCard Info",
            state.settings.our_name.clone().unwrap()
        ))
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
    .pthid(message.pthid.clone().unwrap())
    .thid(message.thid.clone().unwrap())
    .to(to.clone())
    .attachment(attachment)
    .finalize();

    let packed = atm
        .pack_encrypted(
            &new_message,
            message.from.as_ref().unwrap(),
            Some(&from),
            Some(&from),
            None,
        )
        .await;

    let forwarded = atm
        .routing()
        .forward_message(
            &current_profile,
            false,
            packed.unwrap().0.as_str(),
            state.settings.mediator_did.as_ref().unwrap(),
            &to,
            None,
            None,
        )
        .await;

    let _ = atm
        .send_message(
            &current_profile,
            &forwarded.as_ref().unwrap().1,
            &forwarded.as_ref().unwrap().0,
            false,
            true,
        )
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
    state
        .chat_list
        .chats
        .get_mut(&new_chat_name)
        .unwrap()
        .messages
        .push(ChatMessage::new(
            ChatMessageType::Effect {
                effect: ChatEffect::System,
            },
            format!("Start of conversation with {new_chat_name}"),
        ));

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

    match message.type_.as_str() {
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
            mut_chat.messages.push(ChatMessage::new(
                ChatMessageType::Inbound,
                chat_msg.text.unwrap(),
            ));
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

            let Some(mut_chat) = state.chat_list.chats.get_mut(&chat.name) else {
                warn!("Couldn't get mutable chat({})", &chat.name);
                break 'label_break;
            };

            if let Some(active_chat) = &state.chat_list.active_chat
                && active_chat != &chat.name
            {
                mut_chat.has_unread = true;
            }

            let effect = match chat_msg.effect.unwrap().as_str() {
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
                    match &attachment.data {
                        AttachmentData::Base64 { value } => {
                            let decoded = match BASE64_URL_SAFE_NO_PAD.decode(value.base64.clone())
                            {
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
                        }
                        _ => {
                            warn!("Attachment type not supported: {:?}", attachment.data);
                            continue;
                        }
                    };
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

            let mut new_chat_name = if let Some(attachment) = message.attachments.as_ref() {
                if let Some(vcard) = attachment.first() {
                    if let AttachmentData::Base64 { value } = &vcard.data {
                        let vcard_decoded =
                            BASE64_URL_SAFE_NO_PAD.decode(value.base64.clone()).unwrap();
                        let vcard: VCard = serde_json::from_slice(&vcard_decoded).unwrap();
                        let first = if let Some(first) = vcard.n.given.as_ref() {
                            first
                        } else {
                            "UNKNOWN"
                        };
                        let surname = if let Some(surname) = vcard.n.surname.as_ref() {
                            surname.to_string()
                        } else {
                            rand::rng()
                                .sample_iter(&Alphanumeric)
                                .take(4)
                                .map(char::from)
                                .collect::<String>()
                                .to_string()
                        };

                        format!("{first} {surname}")
                    } else {
                        format!(
                            "UNKNOWN {}",
                            rand::rng()
                                .sample_iter(&Alphanumeric)
                                .take(4)
                                .map(char::from)
                                .collect::<String>()
                        )
                    }
                } else {
                    format!(
                        "UNKNOWN {}",
                        rand::rng()
                            .sample_iter(&Alphanumeric)
                            .take(4)
                            .map(char::from)
                            .collect::<String>()
                    )
                }
            } else {
                format!(
                    "UNKNOWN {}",
                    rand::rng()
                        .sample_iter(&Alphanumeric)
                        .take(4)
                        .map(char::from)
                        .collect::<String>()
                )
            };
            new_chat_name = new_chat_name.trim().to_string();

            let Some(secure_channel_did) = &chat.hidden else {
                warn!("Expecting to see hidden chat details");
                break 'label_break;
            };

            let profiles = atm.get_profiles();
            let our_secure_profile = {
                profiles
                    .read()
                    .await
                    .0
                    .values()
                    .find(|p| &p.inner.did == secure_channel_did)
                    .unwrap()
                    .clone()
            };

            // Set up the ACL for the remote secure DID.
            let local_secure_profile_info =
                match atm.mediator().account_get(&our_secure_profile, None).await {
                    Ok(Some(info)) => info,
                    Ok(None) => {
                        warn!(
                            "No profile info found for local secure DID ({})",
                            &profile.inner.did
                        );
                        return;
                    }
                    Err(e) => {
                        warn!(
                            "Failed to get local secure profile info from mediator: {}",
                            e
                        );
                        return;
                    }
                };

            let local_secure_profile_acl_flags =
                MediatorACLSet::from_u64(local_secure_profile_info.acls);
            if let AccessListModeType::ExplicitAllow =
                local_secure_profile_acl_flags.get_access_list_mode().0
            {
                // Add the remote secure DID to this profile's ACL
                match atm
                    .mediator()
                    .access_list_add(&our_secure_profile, None, &[&digest(&remote_secure_did)])
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
                let split_pos = secure_channel_did.char_indices().nth_back(4).unwrap().0;
                let a = &secure_channel_did[split_pos..];
                new_chat_name = format!("{new_chat_name} {a}");
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
            warn!("Unknown message type: {}", message.type_);
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
