use super::chat_list::ChatStatus;
use crate::state_store::State;
use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};
use trust_tasks_rs::specs::messaging::account::get::v0_1::MediatorAclAccessListMode;
use affinidi_tdk::{
    dids::{DID, KeyType, PeerKeyRole},
    secrets_resolver::SecretsResolver,
};
use anyhow::anyhow;
use sha256::digest;
use tracing::warn;

pub async fn manual_connect_setup(
    state: &mut State,
    atm: &ATM,
    alias: &str,
    remote_did: &str,
) -> anyhow::Result<()> {
    // Are the settings ok?
    let Some(mediator_did) = &state.settings.mediator_did else {
        return Err(anyhow!("Mediator DID not set"));
    };

    // Create a local DID for this connection
    let (did_peer, mut secrets) = DID::generate_did_peer(
        vec![
            (PeerKeyRole::Verification, KeyType::P256),
            (PeerKeyRole::Encryption, KeyType::P256),
            (PeerKeyRole::Encryption, KeyType::Ed25519),
        ],
        Some(mediator_did.clone()),
    )?;

    let profile = ATMProfile::new(
        atm,
        Some(alias.to_string()),
        did_peer.clone(),
        Some(mediator_did.to_string()),
    )
    .await?;
    atm.get_tdk().secrets_resolver().insert_vec(&secrets).await;
    state.add_secrets(&mut secrets);

    let profile = atm.profile_add(&profile, true).await?;

    // Setup Access List Setup
    // Add the remote secure DID to the our new secure profile
    let profile_info = match atm.trust_tasks().account_get(&profile, None).await {
        Ok(info) => info,
        Err(e) => {
            warn!("Failed to get profile info from mediator: {}", e);
            return Err(anyhow!("Failed to get profile info from mediator: {e}"));
        }
    };

    if profile_info.acl.access_list_mode == Some(MediatorAclAccessListMode::ExplicitAllow) {
        // Add the remote secure DID to our secure DID
        if let Err(e) = atm
            .trust_tasks()
            .access_list_add(&profile, None, vec![digest(remote_did)])
            .await
        {
            warn!(
                "Failed to add {} to ACL of our secure profile: {}",
                remote_did, e
            );
            return Err(anyhow!(
                "Failed to add {remote_did} to ACL of our secure profile: {e}"
            ));
        }
    }

    state
        .chat_list
        .create_chat(
            alias,
            "Manually Added Channel - No Discovery",
            &profile,
            Some(remote_did.to_string()),
            None,
            ChatStatus::EstablishedChannel,
        )
        .await;

    Ok(())
}
