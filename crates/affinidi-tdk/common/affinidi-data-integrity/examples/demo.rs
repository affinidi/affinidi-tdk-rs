use affinidi_data_integrity::sign_data_jcs;
use affinidi_tdk::{
    TDK,
    common::{config::TDKConfig, profiles::TDKProfile},
    dids::{DID, KeyType},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, ed25519::signature::SignerMut};
use multibase::Base;

#[tokio::main]
async fn main() {
    let (did, secret) = DID::generate_did_key(KeyType::Ed25519).unwrap();
    println!("DID: {}\n  secret: {:#?}", did, secret);

    let (_, mb_d) = multibase::decode(&did.strip_prefix("did:key:").unwrap()).unwrap();
    let (_, me) = unsigned_varint::decode::u64(&mb_d).unwrap();
    println!(
        "multibase decoded did: {}",
        BASE64_URL_SAFE_NO_PAD.encode(me)
    );
    println!(
        "private   decoded did: {}",
        BASE64_URL_SAFE_NO_PAD.encode(secret.get_public_bytes())
    );

    let profile = TDKProfile::new("demo profile", &did, None, vec![secret.clone()]);

    let tdk = TDK::new(
        TDKConfig::builder()
            .with_load_environment(false)
            .build()
            .unwrap(),
        None,
    )
    .await
    .unwrap();

    tdk.add_profile(&profile).await;
    let resolved = tdk.did_resolver().resolve(&did).await.unwrap();

    println!("Resolved DID: {:#?}", resolved.doc);

    let a = sign_data_jcs(&resolved.doc).unwrap();
    println!(" *************** ");
    println!("{:?}", a);

    let mut signing_key = SigningKey::from_bytes(secret.get_private_bytes().try_into().unwrap());
    let signed = BASE64_URL_SAFE_NO_PAD.encode(signing_key.sign(a.as_bytes()).to_bytes());

    println!("signed: {}", signed);
}
