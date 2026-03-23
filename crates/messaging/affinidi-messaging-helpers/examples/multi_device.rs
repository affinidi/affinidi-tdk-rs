//! Tests a message being sent from Alice to Bob, which can be read by any of Bob's devices.
//!
//! This example demonstrates using the affinidi-didcomm crate's low-level pack/unpack API
//! with multiple recipient keys (simulating multi-device scenarios).
//!
//! NOTE: The mediator is NOT used in this example.

use affinidi_messaging_didcomm::crypto::key_agreement::{Curve, PrivateKeyAgreement};
use affinidi_messaging_didcomm::message::pack::{pack_encrypted_authcrypt, unpack_encrypted};
use affinidi_messaging_didcomm::message::unpack;
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_sdk::errors::ATMError;
use serde_json::json;
use std::time::SystemTime;
use tracing::{info, error};
use tracing_subscriber::filter;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    // Generate Alice's key agreement key
    let alice_private = PrivateKeyAgreement::generate(Curve::X25519);
    let alice_kid = "did:example:alice#key-x25519-1";
    info!("Alice key agreement key created");

    // Generate Bob's multiple device keys (simulating multi-device)
    let bob_device1_private = PrivateKeyAgreement::generate(Curve::X25519);
    let bob_device1_kid = "did:example:bob#key-x25519-1";

    let bob_device2_private = PrivateKeyAgreement::generate(Curve::X25519);
    let bob_device2_kid = "did:example:bob#key-x25519-2";

    let bob_device3_private = PrivateKeyAgreement::generate(Curve::X25519);
    let bob_device3_kid = "did:example:bob#key-x25519-3";

    info!("Bob's 3 device keys created");

    // Create message from Alice to Bob
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let msg = Message::build(
        Uuid::new_v4().to_string(),
        "Chatty Alice".to_string(),
        json!("Hello Bob!"),
    )
    .to("did:example:bob".to_string())
    .from("did:example:alice".to_string())
    .created_time(now)
    .expires_time(now + 10)
    .finalize();

    let msg_id = msg.id.clone();

    info!(
        "Plaintext Message from Alice to Bob msg_id({}):\n {:#?}",
        msg_id, msg
    );

    // Pack message for all of Bob's devices
    let bob_device1_pub = bob_device1_private.public_key();
    let bob_device2_pub = bob_device2_private.public_key();
    let bob_device3_pub = bob_device3_private.public_key();

    let recipients_ref: Vec<(&str, &affinidi_messaging_didcomm::crypto::key_agreement::PublicKeyAgreement)> = vec![
        (bob_device1_kid, &bob_device1_pub),
        (bob_device2_kid, &bob_device2_pub),
        (bob_device3_kid, &bob_device3_pub),
    ];

    let packed_msg = pack_encrypted_authcrypt(
        &msg,
        alice_kid,
        &alice_private,
        &recipients_ref,
    )
    .map_err(|e| ATMError::DidcommError("pack".to_string(), format!("{}", e)))?;

    info!(
        "Packed encrypted+signed message from Alice to Bob:\n{}",
        packed_msg
    );

    // Unpack message using all keys/secrets from Bob (device 1)
    info!("Unpack message using Bob's device 1 key");
    let decrypted1 = unpack_encrypted(
        &packed_msg,
        bob_device1_kid,
        &bob_device1_private,
        Some(&alice_private.public_key()),
    )
    .map_err(|e| ATMError::DidcommError("unpack".to_string(), format!("{}", e)))?;

    let unpacked1 = Message::from_json(&decrypted1.plaintext)
        .map_err(|e| ATMError::DidcommError("parse".to_string(), format!("{}", e)))?;
    info!("Message unpacked successfully with device 1: {}", unpacked1.body);

    // Test using 2nd key only
    info!("Unpack message using Bob's device 2 key");
    let decrypted2 = unpack_encrypted(
        &packed_msg,
        bob_device2_kid,
        &bob_device2_private,
        Some(&alice_private.public_key()),
    )
    .map_err(|e| ATMError::DidcommError("unpack".to_string(), format!("{}", e)))?;

    let unpacked2 = Message::from_json(&decrypted2.plaintext)
        .map_err(|e| ATMError::DidcommError("parse".to_string(), format!("{}", e)))?;
    info!("Message unpacked successfully with device 2: {}", unpacked2.body);

    // Test using 3rd key only
    info!("Unpack message using Bob's device 3 key");
    let decrypted3 = unpack_encrypted(
        &packed_msg,
        bob_device3_kid,
        &bob_device3_private,
        Some(&alice_private.public_key()),
    )
    .map_err(|e| ATMError::DidcommError("unpack".to_string(), format!("{}", e)))?;

    let unpacked3 = Message::from_json(&decrypted3.plaintext)
        .map_err(|e| ATMError::DidcommError("parse".to_string(), format!("{}", e)))?;
    info!("Message unpacked successfully with device 3: {}", unpacked3.body);

    // Also test the generic unpack function
    info!("Test generic unpack with device 1");
    let result = unpack::unpack(
        &packed_msg,
        Some(bob_device1_kid),
        Some(&bob_device1_private),
        Some(&alice_private.public_key()),
        None,
    )
    .map_err(|e| ATMError::DidcommError("unpack".to_string(), format!("{}", e)))?;

    match result {
        unpack::UnpackResult::Encrypted { message, authenticated, .. } => {
            info!(
                "Generic unpack successful. Authenticated: {}. Body: {}",
                authenticated, message.body
            );
        }
        _ => {
            error!("Expected encrypted message result");
        }
    }

    Ok(())
}
