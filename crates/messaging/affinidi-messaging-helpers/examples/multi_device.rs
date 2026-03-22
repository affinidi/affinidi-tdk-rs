//! Tests a message being sent from Alice to Bob, which can be read by any of Bob's devices.
//!
//! NOTE: This example requires that the resolver is running with `did_example` feature flag enabled!
//! NOTE: The mediator is NOT used in this example.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
use affinidi_messaging_didcomm::UnpackOptions;
use affinidi_messaging_didcomm::envelope::MetaEnvelope;
use affinidi_messaging_didcomm::{Message, PackEncryptedOptions};
use affinidi_messaging_sdk::errors::ATMError;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use affinidi_tdk::secrets_resolver::{SecretsResolver, SimpleSecretsResolver};
use clap::Parser;
use serde_json::json;
use std::time::SystemTime;
use tracing::{error, info};
use tracing_subscriber::filter;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Environment to use
    #[arg(short, long)]
    environment: Option<String>,

    /// Path to the environments file (defaults to environments.json)
    #[arg(short, long)]
    path_environments: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), ATMError> {
    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let mut did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("Couldn't create DID Resolver");
    info!("Local DID Resolver created");

    // These example DID's come from the DIDComm V2.1 Specification references
    let alice_raw_doc = r#"
    {
   "@context":[
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1"
   ],
   "id":"did:example:alice",
   "authentication":[
      {
         "id":"did:example:alice#key-1",
         "type":"JsonWebKey2020",
         "controller":"did:example:alice",
         "publicKeyJwk":{
            "kty":"OKP",
            "crv":"Ed25519",
            "x":"G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
         }
      },
      {
         "id":"did:example:alice#key-2",
         "type":"JsonWebKey2020",
         "controller":"did:example:alice",
         "publicKeyJwk":{
            "kty":"EC",
            "crv":"P-256",
            "x":"2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
            "y":"BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w"
         }
      },
      {
         "id":"did:example:alice#key-3",
         "type":"JsonWebKey2020",
         "controller":"did:example:alice",
         "publicKeyJwk":{
            "kty":"EC",
            "crv":"secp256k1",
            "x":"aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
            "y":"JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk"
         }
      }
   ],
   "keyAgreement":[
      {
         "id":"did:example:alice#key-x25519-1",
         "type":"JsonWebKey2020",
         "controller":"did:example:alice",
         "publicKeyJwk":{
            "kty":"OKP",
            "crv":"X25519",
            "x":"avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
         }
      },
      {
         "id":"did:example:alice#key-p256-1",
         "type":"JsonWebKey2020",
         "controller":"did:example:alice",
         "publicKeyJwk":{
            "kty":"EC",
            "crv":"P-256",
            "x":"L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
            "y":"SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo"
         }
      },
      {
         "id":"did:example:alice#key-p521-1",
         "type":"JsonWebKey2020",
         "controller":"did:example:alice",
         "publicKeyJwk":{
            "kty":"EC",
            "crv":"P-521",
            "x":"AHBEVPRhAv-WHDEvxVM9S0px9WxxwHL641Pemgk9sDdxvli9VpKCBdra5gg_4kupBDhz__AlaBgKOC_15J2Byptz",
            "y":"AciGcHJCD_yMikQvlmqpkBbVqqbg93mMVcgvXBYAQPP-u9AF7adybwZrNfHWCKAQwGF9ugd0Zhg7mLMEszIONFRk"
         }
      }
   ]
}
    "#;

    did_resolver
        .add_example_did(alice_raw_doc)
        .expect("Couldn't add Alice's DID");
    let (alice_did, _) = match did_resolver.resolve("did:example:alice").await {
        Ok(response) => (response.did, response.doc),
        _ => {
            error!("Couldn't resolve Alice's DID");
            return Ok(());
        }
    };
    info!("Alice DID Created");

    // Create Alice Secrets
    let alice_secrets: Vec<Secret> = serde_json::from_str(
        r#"[
    {
        "id": "did:example:alice#key-1",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "kid": "did:example:alice#key-1",
            "kty": "OKP",
            "d": "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
            "crv": "Ed25519",
            "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
        }
    },
    {
        "id": "did:example:alice#key-2",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "kid": "did:example:alice#key-2",
            "kty": "EC",
            "d": "7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A",
            "crv": "P-256",
            "x": "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
            "y": "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w"
        }
    },
    {
        "id": "did:example:alice#key-3",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "kid": "did:example:alice#key-3",
            "kty": "EC",
            "d": "N3Hm1LXA210YVGGsXw_GklMwcLu_bMgnzDese6YQIyA",
            "crv": "secp256k1",
            "x": "aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
            "y": "JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk"
        }
    },
    {
        "id": "did:example:alice#key-x25519-1",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "kid": "did:example:alice#key-x25519-1",
            "kty": "OKP",
            "d": "r-jK2cO3taR8LQnJB1_ikLBTAnOtShJOsHXRUWT-aZA",
            "crv": "X25519",
            "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
        }
    },
    {
        "id": "did:example:alice#key-p256-1",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "kid": "did:example:alice#key-p256-1",
            "kty": "EC",
            "d": "sB0bYtpaXyp-h17dDpMx91N3Du1AdN4z1FUq02GbmLw",
            "crv": "P-256",
            "x": "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
            "y": "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo"
        }
    },
    {
        "id": "did:example:alice#key-p521-1",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "kid": "did:example:alice#key-p521-1",
            "kty": "EC",
            "d": "AQCQKE7rZpxPnX9RgjXxeywrAMp1fJsyFe4cir1gWj-8t8xWaM_E2qBkTTzyjbRBu-JPXHe_auT850iYmE34SkWi",
            "crv": "P-521",
            "x": "AHBEVPRhAv-WHDEvxVM9S0px9WxxwHL641Pemgk9sDdxvli9VpKCBdra5gg_4kupBDhz__AlaBgKOC_15J2Byptz",
            "y": "AciGcHJCD_yMikQvlmqpkBbVqqbg93mMVcgvXBYAQPP-u9AF7adybwZrNfHWCKAQwGF9ugd0Zhg7mLMEszIONFRk"
        }
    }
]"#,
    )
    .expect("Couldn't create Alice Secrets");
    info!("Alice Secrets Created");

    let bob_raw_doc = r#"
    {
   "@context":[
      "https://www.w3.org/ns/did/v2"
   ],
   "id":"did:example:bob",
   "keyAgreement":[
      {
         "id":"did:example:bob#key-x25519-1",
         "type":"JsonWebKey2020",
         "controller":"did:example:bob",
         "publicKeyJwk":{
            "kty":"OKP",
            "crv":"X25519",
            "x":"fYuIS0FyxRGLA2RETNxA9G1ibVYXcFmAAbZC1U85IGg"
         }
      },
      {
         "id":"did:example:bob#key-x25519-2",
         "type":"JsonWebKey2020",
         "controller":"did:example:bob",
         "publicKeyJwk":{
            "kty":"OKP",
            "crv":"X25519",
            "x":"UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM"
         }
      },
      {
         "id":"did:example:bob#key-x25519-3",
         "type":"JsonWebKey2020",
         "controller":"did:example:bob",
         "publicKeyJwk":{
            "kty":"OKP",
            "crv":"X25519",
            "x":"82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY"
         }
      },
      {
         "id":"did:example:bob#key-p256-1",
         "type":"JsonWebKey2020",
         "controller":"did:example:bob",
         "publicKeyJwk":{
            "kty":"EC",
            "crv":"P-256",
            "x":"FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
            "y":"6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY"
         }
      },
      {
         "id":"did:example:bob#key-p256-2",
         "type":"JsonWebKey2020",
         "controller":"did:example:bob",
         "publicKeyJwk":{
            "kty":"EC",
            "crv":"P-256",
            "x":"n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
            "y":"ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw"
         }
      },
      {
         "id":"did:example:bob#key-p384-1",
         "type":"JsonWebKey2020",
         "controller":"did:example:bob",
         "publicKeyJwk":{
            "kty":"EC",
            "crv":"P-384",
            "x":"MvnE_OwKoTcJVfHyTX-DLSRhhNwlu5LNoQ5UWD9Jmgtdxp_kpjsMuTTBnxg5RF_Y",
            "y":"X_3HJBcKFQEG35PZbEOBn8u9_z8V1F9V1Kv-Vh0aSzmH-y9aOuDJUE3D4Hvmi5l7"
         }
      },
      {
         "id":"did:example:bob#key-p384-2",
         "type":"JsonWebKey2020",
         "controller":"did:example:bob",
         "publicKeyJwk":{
            "kty":"EC",
            "crv":"P-384",
            "x":"2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
            "y":"W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd"
         }
      },
      {
         "id":"did:example:bob#key-p521-1",
         "type":"JsonWebKey2020",
         "controller":"did:example:bob",
         "publicKeyJwk":{
            "kty":"EC",
            "crv":"P-521",
            "x":"Af9O5THFENlqQbh2Ehipt1Yf4gAd9RCa3QzPktfcgUIFADMc4kAaYVViTaDOuvVS2vMS1KZe0D5kXedSXPQ3QbHi",
            "y":"ATZVigRQ7UdGsQ9j-omyff6JIeeUv3CBWYsZ0l6x3C_SYqhqVV7dEG-TafCCNiIxs8qeUiXQ8cHWVclqkH4Lo1qH"
         }
      },
      {
         "id":"did:example:bob#key-p521-2",
         "type":"JsonWebKey2020",
         "controller":"did:example:bob",
         "publicKeyJwk":{
            "kty":"EC",
            "crv":"P-521",
            "x":"ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
            "y":"AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH"
         }
      }
   ]
}"#;

    did_resolver
        .add_example_did(bob_raw_doc)
        .expect("Couldn't add Bob's DID");
    let (bob_did, _) = match did_resolver.resolve("did:example:bob").await {
        Ok(response) => (response.did, response.doc),
        _ => {
            error!("Couldn't resolve Bob's DID");
            return Ok(());
        }
    };
    info!("Bob DID Created");

    // Create Bob Secrets
    let bob_secrets: Vec<Secret> = serde_json::from_str(
        r#"
[
    {
        "id": "did:example:bob#key-x25519-1",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "kid": "did:example:bob#key-x25519-1",
            "kty": "OKP",
            "d": "I3jbRndnKKJCTCtOffbSoLHT9-vinFQXLaOTrWSvaZ8",
            "crv": "X25519",
            "x": "fYuIS0FyxRGLA2RETNxA9G1ibVYXcFmAAbZC1U85IGg"
        }
    },
    {
        "id": "did:example:bob#key-x25519-2",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "kid": "did:example:bob#key-x25519-2",
            "kty": "OKP",
            "d": "p-vteoF1gopny1HXywt76xz_uC83UUmrgszsI-ThBKk",
            "crv": "X25519",
            "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM"
        }
    },
    {
        "id": "did:example:bob#key-x25519-3",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "kid": "did:example:bob#key-x25519-3",
            "kty": "OKP",
            "d": "f9WJeuQXEItkGM8shN4dqFr5fLQLBasHnWZ-8dPaSo0",
            "crv": "X25519",
            "x": "82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY"
        }
    },
    {
        "id": "did:example:bob#key-p256-1",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "kid": "did:example:bob#key-p256-1",
            "kty": "EC",
            "d": "PgwHnlXxt8pwR6OCTUwwWx-P51BiLkFZyqHzquKddXQ",
            "crv": "P-256",
            "x": "FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
            "y": "6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY"
        }
    },
    {
        "id": "did:example:bob#key-p256-2",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "kid": "did:example:bob#key-p256-2",
            "kty": "EC",
            "d": "agKz7HS8mIwqO40Q2dwm_Zi70IdYFtonN5sZecQoxYU",
            "crv": "P-256",
            "x": "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
            "y": "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw"
        }
    },
    {
        "id": "did:example:bob#key-p384-1",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "kid": "did:example:bob#key-p384-1",
            "kty": "EC",
            "d": "ajqcWbYA0UDBKfAhkSkeiVjMMt8l-5rcknvEv9t_Os6M8s-HisdywvNCX4CGd_xY",
            "crv": "P-384",
            "x": "MvnE_OwKoTcJVfHyTX-DLSRhhNwlu5LNoQ5UWD9Jmgtdxp_kpjsMuTTBnxg5RF_Y",
            "y": "X_3HJBcKFQEG35PZbEOBn8u9_z8V1F9V1Kv-Vh0aSzmH-y9aOuDJUE3D4Hvmi5l7"
        }
    },
    {
        "id": "did:example:bob#key-p384-2",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "kid": "did:example:bob#key-p384-2",
            "kty": "EC",
            "d": "OiwhRotK188BtbQy0XBO8PljSKYI6CCD-nE_ZUzK7o81tk3imDOuQ-jrSWaIkI-T",
            "crv": "P-384",
            "x": "2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
            "y": "W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd"
        }
    },
    {
        "id": "did:example:bob#key-p521-1",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "kid": "did:example:bob#key-p521-1",
            "kty": "EC",
            "d": "AV5ocjvy7PkPgNrSuvCxtG70NMj6iTabvvjSLbsdd8OdI9HlXYlFR7RdBbgLUTruvaIRhjEAE9gNTH6rWUIdfuj6",
            "crv": "P-521",
            "x": "Af9O5THFENlqQbh2Ehipt1Yf4gAd9RCa3QzPktfcgUIFADMc4kAaYVViTaDOuvVS2vMS1KZe0D5kXedSXPQ3QbHi",
            "y": "ATZVigRQ7UdGsQ9j-omyff6JIeeUv3CBWYsZ0l6x3C_SYqhqVV7dEG-TafCCNiIxs8qeUiXQ8cHWVclqkH4Lo1qH"
        }
    },
    {
        "id": "did:example:bob#key-p512-2",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "kid": "did:example:bob#key-p521-2",
            "kty": "EC",
            "d": "ABixMEZHsyT7SRw-lY5HxdNOofTZLlwBHwPEJ3spEMC2sWN1RZQylZuvoyOBGJnPxg4-H_iVhNWf_OtgYODrYhCk",
            "crv": "P-521",
            "x": "ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
            "y": "AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH"
        }
    }
]"#,
    )
    .expect("Couldn't create Bob Secrets");
    info!("Bob Secrets Created");

    let secrets = SimpleSecretsResolver::new(&[alice_secrets, bob_secrets].concat()).await;

    let r = secrets.get_secret("did:example:alice#key-x25519-1").await;

    info!("Secret found: {:#?}", r);

    // Create message from Alice to Bob
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let msg = Message::build(
        Uuid::new_v4().into(),
        "Chatty Alice".into(),
        json!("Hello Bob!"),
    )
    .to(bob_did.clone())
    .from(alice_did.clone())
    .created_time(now)
    .expires_time(now + 10)
    .finalize();

    let msg_id = msg.id.clone();

    info!(
        "Plaintext Message from Alice to Bob msg_id({}):\n {:#?}",
        msg_id, msg
    );

    let packed_msg = msg
        .pack_encrypted(
            &bob_did,
            Some(&alice_did),
            Some(&alice_did),
            &did_resolver,
            &secrets,
            &PackEncryptedOptions::default(),
        )
        .await
        .expect("Couldn't pack encrypted message");

    info!(
        "Packed encrypted+signed message from Alice to Bob:\n{}",
        packed_msg.0
    );

    info!("Unpack message using all keys/secrets from Bob");
    let mut envelope = MetaEnvelope::new(&packed_msg.0, &did_resolver)
        .await
        .expect("Couldn't create MetaEnvelope");

    let unpack = Message::unpack(
        &mut envelope,
        &did_resolver,
        &secrets,
        &UnpackOptions::default(),
    )
    .await
    .expect("Couldn't unpack message");
    info!("Message unpacked successfully: {}", unpack.0.body);

    // Test using 2nd key only
    let bob_secrets2: Secret = serde_json::from_str(
        r#"{
        "id": "did:example:bob#key-x25519-2",
        "type": "JsonWebKey2020",
        "privateKeyJwk": {
            "kid": "did:example:bob#key-x25519-2",
            "kty": "OKP",
            "d": "p-vteoF1gopny1HXywt76xz_uC83UUmrgszsI-ThBKk",
            "crv": "X25519",
            "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM"
        }
    }"#,
    )
    .expect("Couldn't create Bob Secrets 2");

    let secrets2 = SimpleSecretsResolver::new(&[bob_secrets2]).await;

    let unpack2 = Message::unpack(
        &mut envelope,
        &did_resolver,
        &secrets2,
        &UnpackOptions::default(),
    )
    .await
    .expect("Couldn't unpack message");
    info!("Message unpacked successfully: {}", unpack2.0.body);
    Ok(())
}
