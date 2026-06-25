use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk::dids::{
    DID, KeyType, OneOrMany, PeerKeyRole, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
};

use crate::cli::KeySuite;

/// Generate a did:peer for the mediator with Ed25519 (signing) + X25519 (encryption) keys,
/// plus an optional DIDComm service endpoint. Any opt-in `key_suites` append
/// extra key pairs after the mandatory Curve25519 pair — e.g. `p256` adds a
/// P-256 verification key and a P-256 encryption key.
pub fn generate_did_peer(
    service_uri: Option<String>,
    key_suites: &[KeySuite],
) -> anyhow::Result<(String, Vec<Secret>)> {
    let mut keys = vec![
        (PeerKeyRole::Verification, KeyType::Ed25519),
        (PeerKeyRole::Encryption, KeyType::X25519),
    ];
    if key_suites.contains(&KeySuite::P256) {
        keys.push((PeerKeyRole::Verification, KeyType::P256));
        keys.push((PeerKeyRole::Encryption, KeyType::P256));
    }

    let services = service_uri.as_deref().map(mediator_services).transpose()?;

    let (did, secrets) = DID::generate_did_peer_with_services(keys, services)
        .map_err(|e| anyhow::anyhow!("Failed to generate did:peer: {e}"))?;

    Ok((did, secrets))
}

fn mediator_services(service_uri: &str) -> anyhow::Result<Vec<PeerService>> {
    let service_uri = service_uri.trim_end_matches('/').to_string();
    let ws_uri = websocket_service_uri(&service_uri)?;
    let auth_uri = format!("{service_uri}/authenticate");

    Ok(vec![
        PeerService {
            type_: "dm".into(),
            endpoint: PeerServiceEndpoint::Long(OneOrMany::Many(vec![
                PeerServiceEndpointLong {
                    uri: service_uri,
                    accept: vec!["didcomm/v2".into()],
                    routing_keys: vec![],
                },
                PeerServiceEndpointLong {
                    uri: ws_uri,
                    accept: vec!["didcomm/v2".into()],
                    routing_keys: vec![],
                },
            ])),
            id: None,
        },
        PeerService {
            type_: "Authentication".into(),
            endpoint: PeerServiceEndpoint::Uri(auth_uri),
            id: Some("#auth".into()),
        },
    ])
}

fn websocket_service_uri(service_uri: &str) -> anyhow::Result<String> {
    let mut url = url::Url::parse(service_uri)
        .map_err(|e| anyhow::anyhow!("Invalid mediator service URL '{service_uri}': {e}"))?;

    match url.scheme() {
        "http" => url
            .set_scheme("ws")
            .map_err(|_| anyhow::anyhow!("Failed to convert '{service_uri}' to ws://"))?,
        "https" => url
            .set_scheme("wss")
            .map_err(|_| anyhow::anyhow!("Failed to convert '{service_uri}' to wss://"))?,
        other => {
            return Err(anyhow::anyhow!(
                "Mediator service URL must use http:// or https:// (got {other}://)"
            ));
        }
    }

    let path = url.path().trim_end_matches('/');
    url.set_path(&format!("{path}/ws"));

    Ok(url.to_string().trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::Value;

    fn decode_service_segments(did: &str) -> Vec<Value> {
        did.split('.')
            .filter_map(|segment| segment.strip_prefix('S'))
            .map(|segment| {
                let bytes = URL_SAFE_NO_PAD.decode(segment).unwrap();
                serde_json::from_slice(&bytes).unwrap()
            })
            .collect()
    }

    #[test]
    fn test_generate_did_peer() {
        let (did, secrets) = generate_did_peer(None, &[]).unwrap();
        assert!(did.starts_with("did:peer:2.V"));
        assert_eq!(secrets.len(), 2);
        assert!(secrets[0].id.contains("#key-1"));
        assert!(secrets[1].id.contains("#key-2"));
    }

    #[test]
    fn test_generate_did_peer_with_p256_suite() {
        // P-256 appends a verification key (`#key-3`) and an encryption key
        // (`#key-4`) after the mandatory Ed25519 + X25519 pair.
        let (did, secrets) = generate_did_peer(None, &[KeySuite::P256]).unwrap();
        // Two verification segments (Ed25519, P-256) and two encryption.
        assert_eq!(did.matches(".V").count(), 2);
        assert_eq!(did.matches(".E").count(), 2);
        assert_eq!(secrets.len(), 4);
        assert!(secrets[2].id.contains("#key-3"));
        assert!(secrets[3].id.contains("#key-4"));
        use affinidi_secrets_resolver::secrets::KeyType;
        assert!(matches!(secrets[2].get_key_type(), KeyType::P256));
        assert!(matches!(secrets[3].get_key_type(), KeyType::P256));
    }

    #[test]
    fn test_generate_did_peer_with_service() {
        let (did, secrets) =
            generate_did_peer(Some("http://localhost:7037/mediator/v1/".into()), &[]).unwrap();
        assert!(did.starts_with("did:peer:2.V"));
        assert_eq!(did.matches(".S").count(), 2);
        assert_eq!(secrets.len(), 2);

        let services = decode_service_segments(&did);
        assert_eq!(services.len(), 2);

        let endpoints = services[0]["s"].as_array().unwrap();
        assert_eq!(services[0]["t"], "dm");
        assert_eq!(endpoints[0]["uri"], "http://localhost:7037/mediator/v1");
        assert_eq!(endpoints[1]["uri"], "ws://localhost:7037/mediator/v1/ws");
        assert_eq!(endpoints[0]["accept"][0], "didcomm/v2");

        assert_eq!(services[1]["t"], "Authentication");
        assert!(services[1]["id"].as_str().unwrap().ends_with("#auth"));
        assert_eq!(
            services[1]["s"],
            "http://localhost:7037/mediator/v1/authenticate"
        );
    }
}
