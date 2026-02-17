use affinidi_messaging_didcomm::{Attachment, Message, MessageBuilder};
use affinidi_messaging_sdk::{
    ATM,
    messages::SuccessResponse,
    profiles::ATMProfile,
    protocols::mediator::acls::{AccessListModeType, MediatorACLSet},
};
use affinidi_tdk::dids::{DID as DIDKey, KeyType};
use affinidi_tdk::secrets_resolver::SecretsResolver;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use image::Luma;
use log::info;
use qrcode::QrCode;
use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
};
use serde_json::json;
use sha256::digest;
use std::{
    fmt::{self, Debug, Formatter},
    sync::Arc,
};
use tokio::sync::mpsc::UnboundedSender;
use tracing::warn;
use uuid::Uuid;

use crate::state_store::{
    State,
    inbound_messages::{Name, VCard},
};

use super::chat_list::ChatStatus;

#[derive(Clone, Default)]
pub struct Invite {
    pub invite_url: String,
    pub invite_profile: Option<Arc<ATMProfile>>,
    pub qr_code: Option<image::ImageBuffer<Luma<u8>, Vec<u8>>>,
}

impl Debug for Invite {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite")
            .field("invite_url", &self.invite_url)
            .field("invite_profile", &self.invite_profile)
            .finish()
    }
}

#[derive(Clone, Debug, Default)]
pub struct InvitePopupState {
    pub show_invite_popup: bool,
    pub invite: Option<Invite>,
    pub invite_error: Option<String>,
    pub messages: Vec<Line<'static>>,
}

/// Helper function to create a new profile with a random DID and add it to the mediator
/// atm: Affinidi Text Messenger instance
/// mediator_did: Mediator DID to connect to
/// alias: Optional alias for the profile
/// alias_suffix: Whether to add a suffix to the alias (last 4 character of the DID)
pub async fn create_new_profile(
    atm: &ATM,
    mediator_did: &str,
    alias: Option<String>,
    alias_suffix: bool,
    state: &mut State,
) -> anyhow::Result<ATMProfile> {
    let (did_key, p256_secret) = DIDKey::generate_did_key(KeyType::P256)?;

    let mut alias = if let Some(alias) = alias {
        alias
    } else {
        format!(
            "Invite {}",
            &did_key[did_key.char_indices().nth_back(3).unwrap().0..]
        )
    };

    if alias_suffix {
        alias.push_str(&format!(
            " {}",
            &did_key[did_key.char_indices().nth_back(3).unwrap().0..]
        ));
    }

    atm.get_tdk()
        .secrets_resolver
        .insert(p256_secret.clone())
        .await;
    state.add_secret(p256_secret);
    match ATMProfile::new(
        atm,
        Some(alias),
        did_key.clone(),
        Some(mediator_did.to_string()),
    )
    .await
    {
        Ok(profile) => Ok(profile),
        Err(e) => {
            warn!("Failed to create new profile: {}", e);
            Err(e.into())
        }
    }
}

/// Given an OOB Invitation link, this will send an accept message to the inviter
pub async fn send_invitation_accept(
    state: &mut State,
    state_tx: &UnboundedSender<State>,
    atm: &ATM,
) -> anyhow::Result<()> {
    // Fetch the Invite message
    let body = reqwest::get(&state.accept_invite_popup.invite_link)
        .await?
        .text()
        .await?;

    state
        .accept_invite_popup
        .messages
        .push(Line::from(Span::styled(
            format!(
                "Fetched OOB Invite from remote link: {}",
                &state.accept_invite_popup.invite_link
            ),
            Style::default().fg(Color::LightBlue),
        )));
    state_tx.send(state.clone())?;

    // Parse the message
    let parsed_body: SuccessResponse<String> = match serde_json::from_str(&body) {
        Ok(parsed_body) => parsed_body,
        Err(e) => {
            warn!("Failed to parse OOB Invite: {}", e);
            return Ok(());
        }
    };

    let Some(base64_invite) = parsed_body.data else {
        warn!("Failed to parse OOB Invite: No data found");
        return Ok(());
    };

    let invite = if let Ok(invite) = BASE64_URL_SAFE_NO_PAD.decode(base64_invite) {
        String::from_utf8(invite).unwrap()
    } else {
        warn!("Bas64 decoding failed on invite!");
        return Ok(());
    };

    let invite_message = match serde_json::from_str::<Message>(&invite) {
        Ok(invite_message) => invite_message,
        Err(e) => {
            warn!("Failed to parse OOB Invite message: {}", e);
            return Ok(());
        }
    };

    let Some(mediator_did) = state.settings.mediator_did.clone() else {
        warn!("Mediator DID is not set");
        return Ok(());
    };

    let Some(invite_did) = invite_message.from else {
        warn!("Invite message is missing 'from' field");
        return Ok(());
    };
    let invite_did_suffix = invite_did.split_at(invite_did.len() - 4).1;

    state
        .accept_invite_popup
        .messages
        .push(Line::from(Span::styled(
            format!("Invitation originated from Remote DID ({invite_did})."),
            Style::default().fg(Color::LightBlue),
        )));
    state_tx.send(state.clone())?;

    // Create a new temporary profile for the invitation
    let accept_temp_profile = create_new_profile(
        atm,
        &mediator_did,
        Some(format!("Ephemeral Accept {invite_did_suffix}")),
        true,
        state,
    )
    .await?;
    let accept_temp_profile = atm.profile_add(&accept_temp_profile, true).await?;

    // Set up the ACL for the temporary profile. Allow the invite DID to send messages to this DID
    let Some(accept_temp_profile_info) = atm
        .mediator()
        .account_get(&accept_temp_profile, None)
        .await?
    else {
        state.invite_popup.messages.push(Line::from(Span::styled(
            "Failed to get temp invite response profile info from mediator",
            Style::default().fg(Color::Red),
        )));
        state_tx.send(state.clone())?;

        warn!("Failed to get temp invite response profile info from mediator");
        return Err(anyhow::anyhow!(
            "Failed to get temp invite response profile info from mediator"
        ));
    };

    info!("temp invite response profile info: {accept_temp_profile_info:?}");
    let accept_temp_profile_acl_flags = MediatorACLSet::from_u64(accept_temp_profile_info.acls);
    if let AccessListModeType::ExplicitAllow =
        accept_temp_profile_acl_flags.get_access_list_mode().0
    {
        // Add the invite DID to this profile's ACL
        match atm
            .mediator()
            .access_list_add(&accept_temp_profile, None, &[&digest(&invite_did)])
            .await
        {
            Ok(_) => {}
            Err(e) => {
                state
                    .accept_invite_popup
                    .messages
                    .push(Line::from(Span::styled(
                        format!("Failed to add {invite_did} to ACL of temporary profile: {e}"),
                        Style::default().fg(Color::Red),
                    )));
                state_tx.send(state.clone())?;

                warn!(
                    "Failed to add {} to ACL of temporary profile: {}",
                    invite_did, e
                );
                return Err(anyhow::anyhow!(
                    "Failed to add {invite_did} to ACL of temporary profile: {e}"
                ));
            }
        }
    }

    state
        .chat_list
        .create_chat(
            &format!(
                "Ephemeral OOB Accept {} {}",
                invite_did_suffix,
                accept_temp_profile
                    .inner
                    .did
                    .split_at(accept_temp_profile.inner.did.len() - 4)
                    .1
            ),
            &format!(
                "Ephemeral DID used to setup Secure Chat: {}",
                accept_temp_profile.inner.did
            ),
            &accept_temp_profile,
            Some(invite_did.clone()),
            Some(state.accept_invite_popup.invite_link.clone()),
            ChatStatus::EphemeralAcceptInvite,
        )
        .await;

    /*let our_ephemeral_chat = state
        .chat_list
        .find_chat_by_did(&accept_temp_profile.inner.did)
        .unwrap();
    let mut_our_ephemeral_chat = state
        .chat_list
        .chats
        .get_mut(&our_ephemeral_chat.name)
        .unwrap();
    //mut_our_ephemeral_chat.messages.push(Line::from())
    */

    state
        .accept_invite_popup
        .messages
        .push(Line::from(Span::styled(
            format!(
                "Our Ephemeral invite DID ({}) to accept invite.",
                &accept_temp_profile.inner.did
            ),
            Style::default().fg(Color::LightBlue),
        )));
    state_tx.send(state.clone())?;

    // Create a new secure profile for the established chat channel
    let accept_secure_profile = create_new_profile(
        atm,
        &mediator_did,
        Some(format!("Secure Accept {invite_did_suffix}")),
        true,
        state,
    )
    .await?;
    let accept_secure_profile = atm.profile_add(&accept_secure_profile, true).await?;

    state
        .chat_list
        .create_chat(
            &format!(
                "Secure Channel OOB Accept {} {}",
                invite_did_suffix,
                accept_secure_profile
                    .inner
                    .did
                    .split_at(accept_secure_profile.inner.did.len() - 4)
                    .1
            ),
            &format!(
                "Secure Channel DID used for Secure Chat: {}",
                accept_secure_profile.inner.did
            ),
            &accept_secure_profile,
            None,
            Some(state.accept_invite_popup.invite_link.clone()),
            ChatStatus::AwaitingInvitationAcceptance,
        )
        .await;
    state
        .accept_invite_popup
        .messages
        .push(Line::from(Span::styled(
            format!(
                "Our Secure future Chat DID ({}) to use when invite process is completed.",
                &accept_secure_profile.inner.did
            ),
            Style::default().fg(Color::LightBlue),
        )));
    state_tx.send(state.clone())?;

    let Some(c) = state
        .chat_list
        .find_chat_by_did(&accept_temp_profile.inner.did)
    else {
        warn!(
            "Failed to find chat by DID: {}",
            &accept_temp_profile.inner.did
        );
        return Ok(());
    };

    if let Some(mut_chat) = state.chat_list.chats.get_mut(&c.name) {
        mut_chat.hidden = Some(accept_secure_profile.inner.did.clone());
    }

    // Create the vcard
    let vcard = VCard {
        n: Name {
            given: state.settings.our_name.clone(),
            surname: None,
        },
        email: None,
        tel: None,
    };

    let attachment =
        Attachment::base64(BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_string(&vcard).unwrap()))
            .id(Uuid::new_v4().to_string())
            .description("vCard Info".into())
            .media_type("text/x-vcard".into())
            .format("https://affinidi.com/atm/client-attachment/contact-card".into())
            .finalize();

    // Create response message
    let accept_message_id = Uuid::new_v4();
    let accept_message = MessageBuilder::new(
        accept_message_id.to_string(),
        "https://affinidi.com/atm/client-actions/connection-setup".to_string(),
        json!({"channel_did": accept_secure_profile.inner.did.clone()}),
    )
    .from(accept_temp_profile.inner.did.clone())
    .to(invite_did.clone())
    .attachment(attachment)
    .thid(accept_message_id.to_string())
    .pthid(invite_message.id)
    .finalize();

    let packed = atm
        .pack_encrypted(
            &accept_message,
            &invite_did,
            Some(&accept_temp_profile.inner.did.clone()),
            Some(&accept_temp_profile.inner.did.clone()),
            None,
        )
        .await?;

    // Send the response message
    atm.forward_and_send_message(
        &accept_temp_profile,
        false,
        &packed.0,
        None,
        &mediator_did,
        &invite_did,
        None,
        None,
        false,
    )
    .await?;

    state
        .accept_invite_popup
        .messages
        .push(Line::from(Span::styled(
            format!(
                "Successfully sent connection-setup message to remote DID: {}",
                &invite_did
            ),
            Style::default().fg(Color::LightBlue),
        )));
    state_tx.send(state.clone())?;

    Ok(())
}

pub async fn create_invitation(
    state: &mut State,
    state_tx: &UnboundedSender<State>,
    atm: &ATM,
) -> anyhow::Result<()> {
    state.invite_popup.show_invite_popup = true;
    state.invite_popup.invite_error = None;
    state.invite_popup.messages.clear();
    // Send the state immediately so we render the popup while waiting for the rest to complete
    state_tx.send(state.clone())?;
    if let Some(mediator_did) = state.settings.mediator_did.clone() {
        match create_new_profile(atm, &mediator_did, None, false, state).await {
            Ok(profile) => {
                state.invite_popup.messages.push(Line::from(vec![
                    Span::styled(
                        "Temporary invite DID created: ",
                        Style::default().fg(Color::Green),
                    ),
                    Span::styled(
                        profile.inner.did.clone(),
                        Style::default()
                            .add_modifier(Modifier::BOLD)
                            .fg(Color::Blue),
                    ),
                ]));
                state.invite_popup.messages.push(Line::from(Span::styled(
                    "Attempting initial authentication to mediator...",
                    Style::default().fg(Color::LightBlue),
                )));
                state_tx.send(state.clone())?;

                // Add profile to the mediator
                match atm.profile_add(&profile, true).await {
                    Ok(profile) => {
                        state.invite_popup.messages.push(Line::from(vec![
                            Span::styled(
                                "Successfully connected to mediator: ",
                                Style::default().fg(Color::Green),
                            ),
                            Span::styled(
                                mediator_did,
                                Style::default()
                                    .add_modifier(Modifier::BOLD)
                                    .fg(Color::Blue),
                            ),
                        ]));
                        state_tx.send(state.clone())?;

                        // Ensure Mediator ACL set up is correctly setup
                        let Some(profile_info) = atm.mediator().account_get(&profile, None).await?
                        else {
                            state.invite_popup.messages.push(Line::from(Span::styled(
                                "Failed to get profile info from mediator",
                                Style::default().fg(Color::Red),
                            )));
                            state_tx.send(state.clone())?;

                            warn!("Failed to get profile info from mediator");
                            return Err(anyhow::anyhow!(
                                "Failed to get profile info from mediator"
                            ));
                        };
                        info!("Profile info: {profile_info:?}");

                        let profile_acl_flags = MediatorACLSet::from_u64(profile_info.acls);
                        if let AccessListModeType::ExplicitAllow =
                            profile_acl_flags.get_access_list_mode().0
                        {
                            // Need to set invitation DID to explicit_deny
                            if profile_acl_flags.get_access_list_mode_admin_change() {
                                let mut new_acl = profile_acl_flags;
                                new_acl.set_access_list_mode(
                                    AccessListModeType::ExplicitDeny,
                                    true,
                                    false,
                                )?;
                                atm.mediator()
                                    .acls_set(&profile, &digest(&profile.inner.did), &new_acl)
                                    .await?;
                            } else {
                                state.invite_popup.messages.push(Line::from(Span::styled(
                                    "Mediator is not allowing DID owners to change their Access List Mode! Contact support.",
                                    Style::default().fg(Color::Red),
                                )));
                                state_tx.send(state.clone())?;
                                return Err(anyhow::anyhow!(
                                    "Mediator is not allowing DID owners to change their Access List Mode! Contact support."
                                ));
                            }
                        }

                        state.invite_popup.messages.push(Line::from(Span::styled(
                            "Asking Mediator for OOB Invitation link...",
                            Style::default().fg(Color::LightBlue),
                        )));
                        state_tx.send(state.clone())?;

                        // Get the OOB Invite itself
                        match atm.oob_discovery().create_invite(&profile, None).await {
                            Ok(invite) => {
                                state.invite_popup.messages.push(Line::from(Span::styled(
                                    "OOB Invite Link successfully created",
                                    Style::default().fg(Color::Green),
                                )));

                                let url = format!(
                                    "{}/oob?_oobid={}",
                                    profile.get_mediator_rest_endpoint().unwrap(),
                                    invite
                                );

                                let code = QrCode::new(url.as_bytes())?;

                                // Render the bits into an image.
                                let qr_code: image::ImageBuffer<Luma<u8>, Vec<u8>> =
                                    code.render::<Luma<u8>>().build();
                                // DynamicImage::ImageLuma8(code.render::<Luma<u8>>().build());

                                state.invite_popup.invite = Some(Invite {
                                    invite_url: url.clone(),
                                    invite_profile: Some(profile.clone()),
                                    qr_code: Some(qr_code),
                                });

                                state
                                    .chat_list
                                    .create_chat(
                                        &profile.inner.alias,
                                        &format!(
                                            "OOB Invite stage 1. Ephemeral DID: {}",
                                            profile.inner.did
                                        ),
                                        &profile,
                                        None,
                                        Some(url.clone()),
                                        ChatStatus::AwaitingInvitationAcceptance,
                                    )
                                    .await;
                            }
                            Err(e) => {
                                state.invite_popup.invite_error =
                                    Some(format!("Failed to create OOB Invite: {e}"));
                            }
                        }
                    }
                    Err(e) => {
                        state.invite_popup.invite_error =
                            Some(format!("Failed to add profile to mediator: {e}"));
                    }
                };
            }
            Err(e) => {
                state.invite_popup.invite_error = Some(e.to_string());
            }
        }
    } else {
        state.invite_popup.invite_error = Some("Mediator DID is not set".to_string());
    }

    Ok(())
}
