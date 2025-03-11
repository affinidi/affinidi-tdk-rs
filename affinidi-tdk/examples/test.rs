use affinidi_tdk::dids::{DID, KeyType};
use did_peer::DIDPeerKeys;

fn main() {
    let result = DID::generate_did_peer(
        vec![
            (DIDPeerKeys::Verification, KeyType::P256),
            (DIDPeerKeys::Encryption, KeyType::Ed25519),
        ],
        Some("did:web:affinidi.com".into()),
    );

    println!("Result = {:#?}", result);
}
