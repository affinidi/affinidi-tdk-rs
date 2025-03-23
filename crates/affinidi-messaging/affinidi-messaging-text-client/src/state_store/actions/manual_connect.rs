use super::chat_list::ChatStatus;
use crate::state_store::State;
use affinidi_messaging_sdk::{ATM, profiles::ATMProfile};
use affinidi_tdk::secrets_resolver::{
    SecretsResolver,
    secrets::{Secret, SecretMaterial, SecretType},
};
use anyhow::{Context, Result, anyhow};
use did_peer::{
    DIDPeer, DIDPeerCreateKeys, DIDPeerKeys, DIDPeerService, PeerServiceEndPoint,
    PeerServiceEndPointLong,
};
use ssi::{JWK, jwk::Params};

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
    let (did_peer, mut secrets) = create_did_peer(mediator_did)?;

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

/// Creates a DID Peer to use as the DIDComm agent for a Ollama Model
pub fn create_did_peer(mediator_did: &str) -> Result<(String, Vec<Secret>)> {
    let e_p256_key = JWK::generate_p256();
    let v_ed25519_key = JWK::generate_ed25519().unwrap();

    let e_did_key = ssi::dids::DIDKey::generate(&e_p256_key).unwrap();
    let v_did_key = ssi::dids::DIDKey::generate(&v_ed25519_key).unwrap();

    let keys = vec![
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Verification,
            type_: None,
            public_key_multibase: Some(v_did_key[8..].to_string()),
        },
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Encryption,
            type_: None,
            public_key_multibase: Some(e_did_key[8..].to_string()),
        },
    ];

    // Create a service definition
    let services = vec![DIDPeerService {
        _type: "dm".into(),
        service_end_point: PeerServiceEndPoint::Long(PeerServiceEndPointLong {
            uri: mediator_did.into(),
            accept: vec!["didcomm/v2".into()],
            routing_keys: vec![],
        }),
        id: None,
    }];

    // Create the did:peer DID
    let (did_peer, _) =
        DIDPeer::create_peer_did(&keys, Some(&services)).context("Failed to create did:peer")?;

    // Save the private keys to secure storage
    let mut secrets = Vec::new();
    if let Params::OKP(map) = v_ed25519_key.params {
        secrets.push(Secret {
            id: [&did_peer, "#key-1"].concat(),
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK {
                private_key_jwk: serde_json::json!({
                     "crv": map.curve, "kty": "OKP", "x": String::from(map.public_key.clone()), "d": String::from(map.private_key.clone().unwrap())}
                ),
            },
        });
    }

    if let Params::EC(map) = e_p256_key.params {
        secrets.push(Secret {
            id: [&did_peer, "#key-2"].concat(),
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK {
                private_key_jwk: serde_json::json!({
                     "crv": map.curve, "kty": "EC", "x": String::from(map.x_coordinate.clone().unwrap()), "y": String::from(map.y_coordinate.clone().unwrap()), "d": String::from(map.ecc_private_key.clone().unwrap())
                }),
            },
        });
    }

    Ok((did_peer, secrets))
}
