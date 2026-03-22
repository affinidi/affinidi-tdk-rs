use affinidi_secrets_resolver::secrets::Secret;
use lazy_static::lazy_static;
use serde_json::json;

lazy_static! {
    pub static ref CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519: Secret = Secret::from_str (
        "did:example:charlie#key-x25519-1",
            &json!({
                "kty": "OKP",
                "crv": "X25519",
                "x": "nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw",
                "d": "Z-BsgFe-eCvhuZlCBX5BV2XiDE2M92gkaORCe68YdZI",
            })
    ).expect("Failed to create secret from string");
    pub static ref CHARLIE_SECRET_AUTH_KEY_ED25519: Secret = Secret::from_str (
        "did:key:z6MkhKzjHrZKpxHqmW9x1BVxgKZ9n7N1WXE3jTtJC26PYASp#z6MkhKzjHrZKpxHqmW9x1BVxgKZ9n7N1WXE3jTtJC26PYASp",
            &json!({
                "kty": "OKP",
                "use": "sig",
                "alg": "EdDSA",
                "kid": "9deaf520-700d-4806-a559-3212cf92567d",
                "crv": "Ed25519",
                "x": "KrathNH2Ijma8XsC_jstmWPL7RCaGYOCSCn00WdKozU",
                "d": "QxH6U2ZvAe4G2zqbBjKSfGOYdyGAvIpZiPSq7Z9a9ZM"
              })
    ).expect("Failed to create secret from string");
    pub static ref CHARLIE_SECRETS: Vec<Secret> = vec![
        CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519.clone(),
        CHARLIE_SECRET_AUTH_KEY_ED25519.clone(),
    ];
}
