use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_messaging_didcomm::message::Message;
use affinidi_messaging_mediator::didcomm_compat;
use affinidi_messaging_sdk::{
    messages::{
        GetMessagesResponse, MessageListElement, SuccessResponse,
        compat::UnpackMetadata,
        sending::InboundMessageResponse,
    },
    protocols::message_pickup::MessagePickupStatusReply,
    transports::SendMessageResponse,
};
use affinidi_secrets_resolver::SecretsResolver;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use sha256::digest;

#[allow(dead_code)]
pub async fn validate_status_reply<S>(
    status_reply: SendMessageResponse,
    recipient_did: String,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &S,
) where
    S: SecretsResolver,
{
    if let SendMessageResponse::RestAPI(value) = status_reply {
        let j: SuccessResponse<InboundMessageResponse> =
            serde_json::from_str(value.as_str().unwrap()).unwrap();
        let message = if let Some(InboundMessageResponse::Ephemeral(message)) = j.data {
            message
        } else {
            panic!();
        };

        let (message, _) = didcomm_compat::unpack(
            &message,
            did_resolver,
            secrets_resolver,
        )
        .await
        .unwrap();
        let status: MessagePickupStatusReply =
            serde_json::from_value(message.body.clone()).unwrap();

        assert!(!status.live_delivery);
        // Removing as can sometimes be 0
        // assert!(status.longest_waited_seconds.unwrap() > 0);
        assert!(status.message_count == 1);
        assert!(status.recipient_did == recipient_did);
        assert!(status.total_bytes > 0);
    }
}

#[allow(dead_code)]
pub async fn validate_message_delivery<S>(
    message_delivery: SendMessageResponse,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &S,
    pong_msg_id: &str,
) -> Vec<String>
where
    S: SecretsResolver,
{
    if let SendMessageResponse::RestAPI(value) = message_delivery {
        let j: SuccessResponse<InboundMessageResponse> =
            serde_json::from_str(value.as_str().unwrap()).unwrap();
        let message = if let Some(InboundMessageResponse::Ephemeral(message)) = j.data {
            message
        } else {
            panic!();
        };

        let (message, _) = didcomm_compat::unpack(
            &message,
            did_resolver,
            secrets_resolver,
        )
        .await
        .unwrap();

        let messages = _handle_delivery(&message, did_resolver, secrets_resolver).await;
        let mut to_delete_ids: Vec<String> = Vec::new();

        assert_eq!(
            messages.first().unwrap().0.thid,
            Some(pong_msg_id.to_string())
        );

        for (message, _) in messages {
            to_delete_ids.push(message.id.clone());
        }
        to_delete_ids
    } else {
        vec![]
    }
}

async fn _handle_delivery<S>(
    message: &Message,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &S,
) -> Vec<(Message, UnpackMetadata)>
where
    S: SecretsResolver,
{
    let mut response: Vec<(Message, UnpackMetadata)> = Vec::new();

    if let Some(attachments) = &message.attachments {
        for attachment in attachments {
            if let Some(ref b64) = attachment.data.base64 {
                let decoded = match BASE64_URL_SAFE_NO_PAD.decode(b64.clone()) {
                    Ok(decoded) => match String::from_utf8(decoded) {
                        Ok(decoded) => decoded,
                        Err(e) => {
                            panic!("{:?}", e);
                        }
                    },
                    Err(e) => {
                        panic!("{:?}", e);
                    }
                };

                match didcomm_compat::unpack(
                    &decoded,
                    did_resolver,
                    secrets_resolver,
                )
                .await
                {
                    Ok((mut m, u)) => {
                        if let Some(attachment_id) = &attachment.id {
                            m.id = attachment_id.to_string();
                        }
                        response.push((m, u))
                    }
                    Err(e) => {
                        panic!("{:?}", e);
                    }
                };
            } else {
                panic!("Expected base64 attachment data");
            }
        }
    }

    response
}

#[allow(dead_code)]
pub async fn validate_message_received_status_reply<S>(
    status_reply: SendMessageResponse,
    recipient_did: String,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &S,
) where
    S: SecretsResolver,
{
    if let SendMessageResponse::RestAPI(value) = status_reply {
        let j: SuccessResponse<InboundMessageResponse> =
            serde_json::from_str(value.as_str().unwrap()).unwrap();
        let message = if let Some(InboundMessageResponse::Ephemeral(message)) = j.data {
            message
        } else {
            panic!();
        };

        let (message, _) = didcomm_compat::unpack(
            &message,
            did_resolver,
            secrets_resolver,
        )
        .await
        .unwrap();
        let status: MessagePickupStatusReply =
            serde_json::from_value(message.body.clone()).unwrap();

        assert!(!status.live_delivery);
        assert!(status.longest_waited_seconds.is_none());
        assert!(status.message_count == 0);
        assert!(status.recipient_did == recipient_did);
        assert!(status.total_bytes == 0);
    }
}

#[allow(dead_code)]
pub async fn validate_forward_request_response(
    forward_request_response: SendMessageResponse,
) -> bool {
    let forwarded = if let SendMessageResponse::RestAPI(value) = forward_request_response {
        let j: SuccessResponse<InboundMessageResponse> =
            serde_json::from_str(value.as_str().unwrap()).unwrap();
        matches!(j.data, Some(InboundMessageResponse::Forwarded))
    } else {
        false
    };

    assert!(forwarded);

    forwarded
}

#[allow(dead_code)]
pub async fn validate_get_message_response<S>(
    list: GetMessagesResponse,
    actor_did: &str,
    did_resolver: &DIDCacheClient,
    secrets_resolver: &S,
) where
    S: SecretsResolver,
{
    for msg in list.success {
        assert_eq!(msg.to_address.unwrap(), digest(actor_did));
        let _ = didcomm_compat::unpack(
            &msg.msg.unwrap(),
            did_resolver,
            secrets_resolver,
        )
        .await
        .unwrap();
        println!("Msg id: {}", msg.msg_id);
    }
}

#[allow(dead_code)]
pub fn validate_list_messages(list: Vec<MessageListElement>, mediator_did: &str) {
    assert_eq!(list.len(), 4);

    for msg in &list[1..3] {
        assert_eq!(msg.from_address.as_ref().unwrap(), mediator_did);
    }
}
