use super::chat_list::ChatStatus;
use crate::state_store::State;
use affinidi_messaging_sdk::{
    ATM,
    profiles::ATMProfile,
    protocols::mediator::acls::{AccessListModeType, MediatorACLSet},
};
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
    atm.get_tdk().secrets_resolver.insert_vec(&secrets).await;
    state.add_secrets(&mut secrets);

    let profile = atm.profile_add(&profile, true).await?;

    // Setup Access List Setup
    // Add the remote secure DID to the our new secure profile
    let profile_info = match atm.mediator().account_get(&profile, None).await {
        Ok(Some(info)) => info,
        Ok(None) => {
            warn!("No profile info found ({})", &profile.inner.did);
            return Err(anyhow!("No profile info found"));
        }
        Err(e) => {
            warn!("Failed to get profile info from mediator: {}", e);
            return Err(anyhow!("Failed to get profile info from mediator: {e}"));
        }
    };

    let profile_acl_flags = MediatorACLSet::from_u64(profile_info.acls);
    if let AccessListModeType::ExplicitAllow = profile_acl_flags.get_access_list_mode().0 {
        // Add the remote secure DID to our secure DID
        match atm
            .mediator()
            .access_list_add(&profile, None, &[&digest(remote_did)])
            .await
        {
            Ok(_) => {}
            Err(e) => {
                warn!(
                    "Failed to add {} to ACL of our secure profile: {}",
                    remote_did, e
                );
                return Err(anyhow!(
                    "Failed to add {remote_did} to ACL of our secure profile: {e}"
                ));
            }
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
