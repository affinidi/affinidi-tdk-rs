use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_messaging_didcomm::{Message, PackEncryptedOptions};
use affinidi_messaging_mediator::server::start;
use affinidi_messaging_sdk::{
    config::ATMConfig,
    errors::ATMError,
    messages::{
        AuthenticationChallenge, AuthorizationResponse, DeleteMessageRequest,
        DeleteMessageResponse, Folder, GetMessagesRequest, GetMessagesResponse, MessageList,
        MessageListElement, SuccessResponse, fetch::FetchOptions,
    },
    transports::SendMessageResponse,
};
use affinidi_secrets_resolver::{SecretsResolver, SimpleSecretsResolver, secrets::Secret};
use common::{
    ALICE_DID, ALICE_E1, ALICE_V1, BOB_DID, BOB_E1, BOB_V1, CONFIG_PATH, MEDIATOR_API, SECRETS_PATH,
};
use core::panic;
use message_builders::{
    build_delivery_request_message, build_forward_request_message, build_message_received_message,
    build_ping_message, build_status_request_message, create_auth_challenge_response,
};
use reqwest::{Certificate, Client, ClientBuilder};
use response_validations::{
    validate_forward_request_response, validate_list_messages, validate_message_delivery,
    validate_message_received_status_reply, validate_status_reply,
};
use serde_json::json;
use sha256::digest;
use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader},
    path::Path,
    process::Command,
    str,
    time::Duration,
};
use tokio::time::sleep;

mod common;
mod message_builders;
mod response_validations;

//#[tokio::test]
#[allow(dead_code)]
async fn test_mediator_server() {
    // Generate secrets and did for mediator if not existing
    if fs::metadata(SECRETS_PATH).is_err() {
        println!("Generating secrets");
        _generate_keys();
        _generate_secrets();
        let mediator_did = _get_did_from_secrets(SECRETS_PATH.into());
        _inject_did_into_config(CONFIG_PATH, &mediator_did);
        println!("Secrets generated and did injected to mediator.toml");
    }

    _start_mediator_server().await;

    // Allow some time for the server to start
    sleep(Duration::from_millis(2000)).await;

    let config = ATMConfig::builder()
        .with_ssl_certificates(&mut vec![
            "../affinidi-messaging-mediator/conf/keys/client.chain".into(),
        ])
        .build()
        .unwrap();

    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .unwrap();
    let alice_secrets_resolver = SimpleSecretsResolver::new(&[
        Secret::from_str(&format!("{}#key-1", ALICE_DID), &ALICE_V1),
        Secret::from_str(&format!("{}#key-2", ALICE_DID), &ALICE_E1),
    ])
    .await;
    let bob_secrets_resolver = SimpleSecretsResolver::new(&[
        Secret::from_str(&format!("{}#key-1", BOB_DID), &BOB_V1),
        Secret::from_str(&format!("{}#key-2", BOB_DID), &BOB_E1),
    ])
    .await;

    let client = init_client(config.clone());

    let mediator_did = _well_known(client.clone()).await;

    // Start Authentication
    let alice_authentication_challenge = _authenticate_challenge(client.clone(), ALICE_DID).await;
    let bob_authentication_challenge = _authenticate_challenge(client.clone(), BOB_DID).await;

    // /authenticate/challenge
    let alice_auth_response_msg =
        create_auth_challenge_response(&alice_authentication_challenge, ALICE_DID, &mediator_did);

    let bob_auth_response_msg =
        create_auth_challenge_response(&bob_authentication_challenge, BOB_DID, &mediator_did);

    // /authenticate
    let alice_authentication_response = _authenticate(
        client.clone(),
        alice_auth_response_msg,
        ALICE_DID,
        &mediator_did,
        &did_resolver,
        &alice_secrets_resolver,
    )
    .await;
    let bob_authentication_response = _authenticate(
        client.clone(),
        bob_auth_response_msg,
        BOB_DID,
        &mediator_did,
        &did_resolver,
        &bob_secrets_resolver,
    )
    .await;

    assert!(!alice_authentication_response.access_token.is_empty());
    assert!(!alice_authentication_response.refresh_token.is_empty());
    assert!(!bob_authentication_response.access_token.is_empty());
    assert!(!bob_authentication_response.refresh_token.is_empty());

    // POST /inbound
    // MessageType=TrustPing
    // Send signed ping and expecting response
    let (_, signed_ping_msg_info) = build_ping_message(
        &mediator_did,
        ALICE_DID.into(),
        true,
        true,
        &did_resolver,
        &alice_secrets_resolver,
    )
    .await;

    /*
        let signed_ping_res: SendMessageResponse = _send_inbound_message(
            client.clone(),
            alice_authentication_response.clone(),
            &signed_ping_msg,
            200,
        )
        .await;
    */

    let pong_msg_id = signed_ping_msg_info.message_id.clone();
    assert!(!pong_msg_id.is_empty());

    // Send anonymous ping
    let (anon_ping_msg, _) = build_ping_message(
        &mediator_did,
        ALICE_DID.into(),
        false,
        false,
        &did_resolver,
        &alice_secrets_resolver,
    )
    .await;
    let _anon_ping_res: SendMessageResponse = _send_inbound_message(
        client.clone(),
        alice_authentication_response.clone(),
        &anon_ping_msg,
        500,
    )
    .await;

    // MessageType=MessagePickupStatusRequest
    let status_request_msg = build_status_request_message(
        &mediator_did,
        ALICE_DID.into(),
        &did_resolver,
        &alice_secrets_resolver,
    )
    .await;
    let status_reply: SendMessageResponse = _send_inbound_message(
        client.clone(),
        alice_authentication_response.clone(),
        &status_request_msg,
        200,
    )
    .await;
    validate_status_reply(
        status_reply,
        ALICE_DID.into(),
        &did_resolver,
        &alice_secrets_resolver,
    )
    .await;

    // MessageType=MessagePickupDeliveryRequest
    let delivery_request_msg = build_delivery_request_message(
        &mediator_did,
        ALICE_DID.into(),
        &did_resolver,
        &alice_secrets_resolver,
    )
    .await;
    let message_delivery: SendMessageResponse = _send_inbound_message(
        client.clone(),
        alice_authentication_response.clone(),
        &delivery_request_msg,
        200,
    )
    .await;
    let message_received_ids = validate_message_delivery(
        message_delivery,
        &did_resolver,
        &alice_secrets_resolver,
        &pong_msg_id,
    )
    .await;

    // MessageType=MessagePickupMessagesReceived
    let message_received_msg = build_message_received_message(
        &mediator_did,
        ALICE_DID.into(),
        &did_resolver,
        &alice_secrets_resolver,
        message_received_ids.clone(),
    )
    .await;
    let message_received_status_reply: SendMessageResponse = _send_inbound_message(
        client.clone(),
        alice_authentication_response.clone(),
        &message_received_msg,
        200,
    )
    .await;

    validate_message_received_status_reply(
        message_received_status_reply,
        ALICE_DID.into(),
        &did_resolver,
        &alice_secrets_resolver,
    )
    .await;

    // MessageType=ForwardRequest
    let forward_request_msg = build_forward_request_message(
        &mediator_did,
        ALICE_DID.into(),
        BOB_DID.into(),
        &did_resolver,
        &bob_secrets_resolver,
    )
    .await;

    let forward_request_response: SendMessageResponse = _send_inbound_message(
        client.clone(),
        alice_authentication_response.clone(),
        &forward_request_msg,
        200,
    )
    .await;

    //let forwarded_msg_id = validate_forward_request_response(forward_request_response).await;
    validate_forward_request_response(forward_request_response).await;

    // /outbound
    // delete messages: FALSE
    /*let get_message_no_delete_request = GetMessagesRequest {
                message_ids: vec![forwarded_msg_id.clone()],
                delete: false,
            };
            let msg_list = _outbound_message(
                client.clone(),
                &get_message_no_delete_request,
                alice_authentication_response.clone(),
                200,
                false,
            )
            .await;

            validate_get_message_response(msg_list, ALICE_DID, &did_resolver, &alice_secrets_resolver)
                .await;

            // delete messages: TRUE
            let get_message_delete_request = GetMessagesRequest {
                message_ids: vec![forwarded_msg_id.clone()],
                delete: true,
            };
            let msg_list = _outbound_message(
                client.clone(),
                &get_message_delete_request,
                alice_authentication_response.clone(),
                200,
                false,
            )
            .await;


        validate_get_message_response(msg_list, ALICE_DID, &did_resolver, &alice_secrets_resolver)
            .await;


        // get message should return not found
        let _msg_list = _outbound_message(
            client.clone(),
            &get_message_delete_request,
            alice_authentication_response.clone(),
            200,
            true,
        )
        .await;
    */

    // Sending messages to list/fetch
    for _ in 0..3 {
        let (signed_ping_msg, _) = build_ping_message(
            &mediator_did,
            ALICE_DID.into(),
            true,
            true,
            &did_resolver,
            &alice_secrets_resolver,
        )
        .await;

        let _: SendMessageResponse = _send_inbound_message(
            client.clone(),
            alice_authentication_response.clone(),
            &signed_ping_msg,
            200,
        )
        .await;
    }

    // /list/:did_hash/:folder
    // /list/:did_hash/Inbox
    let msgs_list = list_messages(
        client.clone(),
        alice_authentication_response.clone(),
        200,
        ALICE_DID,
        Folder::Inbox,
    )
    .await;
    validate_list_messages(msgs_list, &mediator_did);

    // /list/:did_hash/Outbox
    let msgs_list = list_messages(
        client.clone(),
        alice_authentication_response.clone(),
        200,
        ALICE_DID,
        Folder::Outbox,
    )
    .await;
    assert_eq!(msgs_list.len(), 0);

    // /fetch
    let messages = _fetch_messages(
        client.clone(),
        alice_authentication_response.clone(),
        200,
        &FetchOptions {
            limit: 10,
            start_id: None,
            delete_policy: affinidi_messaging_sdk::messages::FetchDeletePolicy::DoNotDelete,
        },
    )
    .await;
    assert_eq!(messages.success.len(), 4);

    let msg_ids: Vec<String> = messages
        .success
        .iter()
        .map(|msg| msg.msg_id.clone())
        .collect();

    let deleted_msgs = _delete_messages(
        client.clone(),
        alice_authentication_response.clone(),
        200,
        &DeleteMessageRequest {
            message_ids: msg_ids,
        },
    )
    .await;
    assert_eq!(deleted_msgs.success.len(), 4);
}

async fn _start_mediator_server() {
    tokio::spawn(async move { start().await });
    println!("Server running");
}

#[allow(dead_code)]
fn init_client(config: ATMConfig) -> Client {
    // Set up the HTTPS client
    let mut client = ClientBuilder::new()
        .use_rustls_tls()
        .https_only(false)
        .user_agent("Affinidi Trusted Messaging");

    for cert in config.get_ssl_certificates() {
        client =
            client.add_root_certificate(Certificate::from_der(cert.to_vec().as_slice()).unwrap());
    }

    match client.build() {
        Ok(client) => client,
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

async fn _well_known(client: Client) -> String {
    let well_known_did_atm_api = format!("{}/.well-known/did", MEDIATOR_API);

    let res = client
        .get(well_known_did_atm_api)
        .header("Content-Type", "application/json")
        .send()
        .await
        .unwrap();

    let status = res.status();
    assert_eq!(status, 200);
    println!("API response: status({})", status);
    let body = res.text().await.unwrap();

    let body = serde_json::from_str::<SuccessResponse<String>>(&body)
        .ok()
        .unwrap();
    let did = if let Some(did) = body.data {
        did
    } else {
        panic!("Not able to fetch mediator did");
    };
    assert!(!did.is_empty());

    did
}

async fn _authenticate_challenge(client: Client, did: &str) -> AuthenticationChallenge {
    let res = client
        .post(format!("{}/authenticate/challenge", MEDIATOR_API))
        .header("Content-Type", "application/json")
        .body(format!("{{\"did\": \"{}\"}}", did).to_string())
        .send()
        .await
        .unwrap();

    let status = res.status();
    assert_eq!(status, 200);

    let body = res.text().await.unwrap();

    if !status.is_success() {
        panic!("Failed to get authentication challenge. Body: {:?}", body);
    }
    let body = serde_json::from_str::<SuccessResponse<AuthenticationChallenge>>(&body)
        .ok()
        .unwrap();

    let challenge = if let Some(challenge) = body.data {
        challenge
    } else {
        panic!("No challenge received from ATM");
    };
    assert!(!challenge.challenge.is_empty());
    assert!(!challenge.session_id.is_empty());

    challenge
}

async fn _authenticate<S>(
    client: Client,
    auth_response: Message,
    actor_did: &str,
    atm_did: &str,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &S,
) -> AuthorizationResponse
where
    S: SecretsResolver,
{
    let (auth_msg, _) = auth_response
        .pack_encrypted(
            atm_did,
            Some(actor_did),
            Some(actor_did),
            did_resolver,
            secrets_resolver,
            &PackEncryptedOptions::default(),
        )
        .await
        .map_err(|e| {
            ATMError::MsgSendError(format!(
                "Couldn't pack authentication response message: {:?}",
                e
            ))
        })
        .unwrap();

    let res = client
        .post(format!("{}/authenticate", MEDIATOR_API))
        .header("Content-Type", "application/json")
        .body(auth_msg)
        .send()
        .await
        .map_err(|e| {
            ATMError::TransportError(format!("Could not post authentication response: {:?}", e))
        })
        .unwrap();

    let status = res.status();
    println!("Authentication response: status({})", status);

    let body = res.text().await.unwrap();

    assert!(status.is_success(), "Received status code: {}", status);

    if !status.is_success() {
        println!("Failed to get authentication response. Body: {:?}", body);
        panic!("Failed to get authentication response");
    }
    let body = serde_json::from_str::<SuccessResponse<AuthorizationResponse>>(&body).unwrap();

    if let Some(tokens) = body.data {
        tokens
    } else {
        panic!("No tokens received from ATM");
    }
}

async fn _send_inbound_message(
    client: Client,
    tokens: AuthorizationResponse,
    message: &str,
    expected_status_code: u16,
) -> SendMessageResponse {
    let msg = message.to_owned();

    let res = client
        .post(format!("{}/inbound", MEDIATOR_API))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", tokens.access_token))
        .body(msg)
        .send()
        .await
        .unwrap();

    let status = res.status();
    println!("API response: status({})", status);
    assert_eq!(status, expected_status_code);

    let body = res.text().await.unwrap();

    SendMessageResponse::RestAPI(json!(body))
}

async fn _outbound_message(
    client: Client,
    messages: &GetMessagesRequest,
    tokens: AuthorizationResponse,
    expected_status_code: u16,
    expecting_get_errors: bool,
) -> GetMessagesResponse {
    let body = serde_json::to_string(messages)
        .map_err(|e| {
            ATMError::TransportError(format!("Could not serialize get message request: {:?}", e))
        })
        .unwrap();

    let res = client
        .post(format!("{}/outbound", MEDIATOR_API))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", tokens.access_token))
        .body(body)
        .send()
        .await
        .map_err(|e| {
            ATMError::TransportError(format!("Could not send get_messages request: {:?}", e))
        })
        .unwrap();

    let status = res.status();
    println!("API response: status({})", status);
    assert_eq!(status, expected_status_code);
    let body = res
        .text()
        .await
        .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))
        .unwrap();

    let body = serde_json::from_str::<SuccessResponse<GetMessagesResponse>>(&body)
        .ok()
        .unwrap();

    let list = if let Some(list) = body.data {
        list
    } else {
        panic!("No messages found")
    };

    if expecting_get_errors {
        assert!(!list.get_errors.is_empty())
    } else {
        assert!(list.get_errors.is_empty())
    }

    if !list.get_errors.is_empty() {
        for (msg, err) in &list.get_errors {
            println!("failed get: msg({}) error({})", msg, err);
        }
    }
    if !list.delete_errors.is_empty() {
        for (msg, err) in &list.delete_errors {
            println!("failed delete: msg({}) error({})", msg, err);
        }
    }
    list
}

#[allow(dead_code)]
async fn list_messages(
    client: Client,
    tokens: AuthorizationResponse,
    expected_status_code: u16,
    actor_did: &str,
    folder: Folder,
) -> Vec<MessageListElement> {
    let res = client
        .get(format!(
            "{}/list/{}/{}",
            MEDIATOR_API,
            digest(actor_did),
            folder,
        ))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", tokens.access_token))
        .send()
        .await
        .map_err(|e| {
            ATMError::TransportError(format!("Could not send list_messages request: {:?}", e))
        })
        .unwrap();

    let status = res.status();
    println!("API response: status({})", status);
    assert_eq!(status, expected_status_code);

    let body = res
        .text()
        .await
        .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))
        .unwrap();

    let body = serde_json::from_str::<SuccessResponse<MessageList>>(&body)
        .ok()
        .unwrap();

    if let Some(list) = body.data {
        list
    } else {
        panic!("No messages found");
    }
}

async fn _fetch_messages(
    client: Client,
    tokens: AuthorizationResponse,
    expected_status_code: u16,
    options: &FetchOptions,
) -> GetMessagesResponse {
    let body = serde_json::to_string(options)
        .map_err(|e| {
            ATMError::TransportError(format!(
                "Could not serialize fetch_message() options: {:?}",
                e
            ))
        })
        .unwrap();

    let res = client
        .post(format!("{}/fetch", MEDIATOR_API))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", tokens.access_token))
        .body(body)
        .send()
        .await
        .map_err(|e| {
            ATMError::TransportError(format!("Could not send list_messages request: {:?}", e))
        })
        .unwrap();

    let status = res.status();
    println!("API response: status({})", status);
    assert_eq!(status, expected_status_code);

    let body = res
        .text()
        .await
        .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))
        .unwrap();

    let body = serde_json::from_str::<SuccessResponse<GetMessagesResponse>>(&body)
        .ok()
        .unwrap();

    if let Some(list) = body.data {
        list
    } else {
        panic!("No messages found");
    }
}

async fn _delete_messages(
    client: Client,
    tokens: AuthorizationResponse,
    expected_status_code: u16,
    messages: &DeleteMessageRequest,
) -> DeleteMessageResponse {
    let msg = serde_json::to_string(messages)
        .map_err(|e| {
            ATMError::TransportError(format!(
                "Could not serialize delete message request: {:?}",
                e
            ))
        })
        .unwrap();

    let res = client
        .delete(format!("{}/delete", MEDIATOR_API))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", tokens.access_token))
        .body(msg)
        .send()
        .await
        .map_err(|e| {
            ATMError::TransportError(format!("Could not send delete_messages request: {:?}", e))
        })
        .unwrap();

    let status = res.status();
    println!("API response: status({})", status);
    assert_eq!(status, expected_status_code);

    let body = res
        .text()
        .await
        .map_err(|e| ATMError::TransportError(format!("Couldn't get body: {:?}", e)))
        .unwrap();

    let body = serde_json::from_str::<SuccessResponse<DeleteMessageResponse>>(&body)
        .ok()
        .unwrap();

    let list = if let Some(list) = body.data {
        list
    } else {
        panic!("No messages found");
    };

    if !list.errors.is_empty() {
        for (msg, err) in &list.errors {
            println!("failed: msg({}) error({})", msg, err);
        }
        panic!("Failed to delete above messages")
    }

    list
}

fn _generate_secrets() {
    let output = Command::new("cargo")
        .args(["run", "--example", "generate_secrets"])
        .output()
        .expect("Failed to generate secrets");
    assert!(output.status.success());
    let source_path = "../affinidi-messaging-mediator/conf/secrets.json-generated";

    match fs::copy(source_path, SECRETS_PATH) {
        Ok(_) => println!("Copied {} to {}", source_path, SECRETS_PATH),
        Err(e) => panic!("Failed with error: {e:?}"),
    };
}

fn _generate_keys() {
    let output = Command::new("cargo")
        .args(["run", "--example", "create_local_certs"])
        .output()
        .expect("Failed to create local certs");
    assert!(output.status.success());
}

fn _get_did_from_secrets(path: String) -> String {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);

    // Parse the JSON file
    let config: Vec<Secret> = serde_json::from_reader(reader).unwrap();
    let id_split: Vec<&str> = config.first().unwrap().id.split("#").collect();
    let did = *id_split.first().unwrap();
    did.into()
}

fn _inject_did_into_config<P>(file_name: P, did: &str)
where
    P: AsRef<Path>,
{
    let file = File::open(file_name.as_ref())
        .map_err(|err| {
            panic!(
                "{}",
                format!(
                    "Could not open file({}). {}",
                    file_name.as_ref().display(),
                    err
                )
            );
        })
        .unwrap();

    let mut lines: Vec<String> = Vec::new();
    for mut line in io::BufReader::new(file).lines().map_while(Result::ok) {
        // Strip comments out
        if line.starts_with("mediator_did =") {
            let line_split: Vec<&str> = line.split("//").collect();
            let line_beginning = *line_split.first().unwrap();
            line = format!("{}{}{}{}", line_beginning, "//", did, "}\"");
        }
        lines.push(line);
    }
    let config_file = lines.join("\n");
    fs::write(file_name, config_file).expect("Failed to write to file");
}
