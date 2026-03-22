mod jwe;
mod jwk;
mod jws;
mod message;
mod utils;

// Allows share test vectors between unit and integration tests
#[cfg(test)]
pub(crate) use crate as affinidi_messaging_didcomm;
#[cfg(test)]
mod test_vectors;

pub mod algorithms;
pub(crate) mod document;
pub mod envelope;
pub mod error;
pub mod protocols;

pub use message::{
    Attachment, AttachmentBuilder, AttachmentData, Base64AttachmentData, FromPrior,
    JsonAttachmentData, LinksAttachmentData, Message, MessageBuilder, MessagingServiceMetadata,
    PackEncryptedMetadata, PackEncryptedOptions, PackSignedMetadata, UnpackMetadata, UnpackOptions,
};

#[cfg(test)]
mod tests {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use affinidi_secrets_resolver::SimpleSecretsResolver;
    use serde_json::json;

    use crate::{Message, PackEncryptedOptions, UnpackOptions};

    #[tokio::test]
    #[ignore = "will be fixed after https://github.com/sicpa-dlab/didcomm-gemini/issues/71"]
    async fn demo_works() {
        // --- Build message ---

        let sender = "did:example:1";
        let recipient = "did:example:2";

        let msg = Message::build(
            "example-1".into(),
            "example/v1".into(),
            json!("example-body"),
        )
        .to(recipient.into())
        .from(sender.into())
        .finalize();

        // --- Packing message ---

        let sender_did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let sender_secrets_resolver = SimpleSecretsResolver::new(&[]).await;

        let (packed_msg, metadata) = msg
            .pack_encrypted(
                recipient,
                Some(sender),
                None,
                &sender_did_resolver,
                &sender_secrets_resolver,
                &PackEncryptedOptions::default(),
            )
            .await
            .expect("pack is ok.");

        // --- Send message using service endpoint ---

        let service_endpoint = metadata
            .messaging_service
            .expect("messagin service present.")
            .service_endpoint;

        println!("Sending message {packed_msg} through {service_endpoint}");

        // --- Unpacking message ---

        let recipient_did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let recipient_secrets_resolver = SimpleSecretsResolver::new(&[]).await;

        let (msg, metadata) = Message::unpack_string(
            &packed_msg,
            &recipient_did_resolver,
            &recipient_secrets_resolver,
            &UnpackOptions::default(),
        )
        .await
        .expect("unpack is ok.");

        assert!(metadata.encrypted);
        assert!(metadata.authenticated);
        assert!(metadata.encrypted_from_kid.is_some());
        assert!(metadata.encrypted_from_kid.unwrap().starts_with(recipient));

        assert_eq!(msg.from, Some(sender.into()));
        assert_eq!(msg.to, Some(vec![recipient.into()]));
        assert_eq!(msg.body, json!("example-body"));
    }
}
