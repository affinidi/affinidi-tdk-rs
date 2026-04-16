use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};

/// Generate a did:peer for the mediator with Ed25519 (signing) + X25519 (encryption) keys,
/// plus an optional DIDComm service endpoint.
pub fn generate_did_peer(service_uri: Option<String>) -> anyhow::Result<(String, Vec<Secret>)> {
    let keys = vec![
        (PeerKeyRole::Verification, KeyType::Ed25519),
        (PeerKeyRole::Encryption, KeyType::X25519),
    ];

    let (did, secrets) = DID::generate_did_peer(keys, service_uri)
        .map_err(|e| anyhow::anyhow!("Failed to generate did:peer: {e}"))?;

    Ok((did, secrets))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_did_peer() {
        let (did, secrets) = generate_did_peer(None).unwrap();
        assert!(did.starts_with("did:peer:2.V"));
        assert_eq!(secrets.len(), 2);
        assert!(secrets[0].id.contains("#key-1"));
        assert!(secrets[1].id.contains("#key-2"));
    }

    #[test]
    fn test_generate_did_peer_with_service() {
        let (did, secrets) =
            generate_did_peer(Some("https://mediator.example.com/mediator/v1".into())).unwrap();
        assert!(did.starts_with("did:peer:2.V"));
        assert!(did.contains(".S")); // service section
        assert_eq!(secrets.len(), 2);
    }
}
