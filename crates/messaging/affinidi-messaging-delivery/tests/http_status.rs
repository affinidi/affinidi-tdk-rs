//! A transport's typed HTTP status (a mediator `429`, say) reaches the caller of
//! `MessagingService` intact — not flattened into `MessagingError::Transport`.

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_core::{
    ConnState, HttpStatusError, Inbound, InboundAck, MessageTransport, MessagingError, SendReceipt,
    TransportKind,
};
use affinidi_messaging_delivery::{Delivery, InMemoryOutboxStore, MessagingService};
use futures_util::stream::{self, BoxStream};
use tokio::sync::watch;

/// A wire whose every send is refused by the mediator's rate limiter.
struct RateLimitedWire {
    conn: watch::Receiver<ConnState>,
}

#[async_trait::async_trait]
impl MessageTransport for RateLimitedWire {
    fn kind(&self) -> TransportKind {
        TransportKind::Didcomm
    }

    async fn send(&self, _dest: &str, _packed: Vec<u8>) -> Result<SendReceipt, MessagingError> {
        Err(HttpStatusError::from_parts(
            "didcomm forward+send failed: send DIDComm message",
            429,
            Some("mediator"),
            Some("7"),
            "",
        )
        .into())
    }

    fn connection_state(&self) -> watch::Receiver<ConnState> {
        self.conn.clone()
    }

    fn inbound(&self) -> BoxStream<'static, Inbound> {
        Box::pin(stream::empty())
    }

    async fn ack(&self, _ack: InboundAck) -> Result<(), MessagingError> {
        Ok(())
    }

    async fn outbox_message_ids(&self) -> Result<Option<Vec<String>>, MessagingError> {
        Ok(None)
    }
}

fn service() -> MessagingService {
    let (_tx, conn) = watch::channel(ConnState::Connected);
    MessagingService::new(
        Arc::new(RateLimitedWire { conn }),
        Arc::new(InMemoryOutboxStore::new()),
    )
}

fn assert_mediator_429(err: &MessagingError) {
    assert!(err.is_rate_limited(), "{err:?}");
    let status = err.http_status().expect("typed HTTP status");
    assert_eq!(status.rate_limit_source.as_deref(), Some("mediator"));
    assert_eq!(status.retry_after_secs, Some(7));
}

#[tokio::test]
async fn a_best_effort_send_keeps_the_http_status() {
    let err = service()
        .send("did:example:bob", b"m".to_vec(), Delivery::BestEffort)
        .await
        .unwrap_err();
    assert_mediator_429(&err);
}

#[tokio::test]
async fn a_request_keeps_the_http_status() {
    let err = service()
        .request(
            "did:example:bob",
            b"m".to_vec(),
            "thid-1",
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
    assert_mediator_429(&err);
}
