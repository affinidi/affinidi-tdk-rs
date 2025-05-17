use affinidi_data_integrity::sign_data;
use affinidi_tdk::{
    TDK,
    common::{config::TDKConfig, profiles::TDKProfile},
    dids::{DID, KeyType},
};

#[tokio::main]
async fn main() {
    let (did, secret) = DID::generate_did_key(KeyType::Ed25519).unwrap();
    println!("DID: {}\n  secret: {:#?}", did, secret);

    let profile = TDKProfile::new("demo profile", &did, None, vec![secret]);

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

    let a = sign_data(&resolved.doc);
    println!(" *************** ");
    println!("{}", a);
}
