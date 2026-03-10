use std::env;

use affinidi_did_common::{DID as DIDCommon, PeerCreateKey, PeerKeyPurpose};
use affinidi_didcomm_service::{
    DIDCommResponse, DIDCommService, DIDCommServiceConfig, DIDCommServiceError, HandlerContext,
    ListenerConfig, MessagePolicy, Next, ProblemReport, RestartPolicy, RetryConfig, Router,
    ServiceProblemReport, handler_fn, middleware_fn,
};
use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk_common::profiles::TDKProfile;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

const ECHO_RESPONSE_TYPE: &str = "https://example.com/protocols/echo/1.0/response";

async fn logging_middleware(
    ctx: HandlerContext,
    message: Message,
    meta: UnpackMetadata,
    next: Next,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    info!(
        ">> Incoming: type={} from={}",
        message.type_, ctx.sender_did
    );
    let result = next.run(ctx, message, meta).await;
    info!(
        "<< Result: has_response={}",
        result.as_ref().map_or(false, |r| r.is_some())
    );
    result
}

async fn echo_handler(
    ctx: HandlerContext,
    message: Message,
    _meta: UnpackMetadata,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    info!(
        "Echo: from={} type={} body={:?}",
        ctx.sender_did, message.type_, message.body
    );

    let response_body = json!({
        "echo": message.body,
        "original_type": message.type_,
    });

    Ok(Some(DIDCommResponse::new(
        ECHO_RESPONSE_TYPE,
        response_body,
    )))
}

async fn problem_report_handler(
    ctx: HandlerContext,
    message: Message,
    _meta: UnpackMetadata,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    warn!("Problem report from {}: {:?}", ctx.sender_did, message.body);
    Ok(None)
}

async fn fallback_handler(
    ctx: HandlerContext,
    message: Message,
    _meta: UnpackMetadata,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    warn!(
        "Unhandled message type '{}' from {}",
        message.type_, ctx.sender_did
    );
    Ok(Some(DIDCommResponse::problem_report(
        ProblemReport::bad_request(format!("Unsupported message type: {}", message.type_)),
    )))
}

fn generate_did_peer() -> Result<(String, Vec<Secret>), Box<dyn std::error::Error>> {
    let mut v_key = Secret::generate_ed25519(None, None);
    let mut e_secp256k1 = Secret::generate_secp256k1(None, None)?;
    let mut e_p256 = Secret::generate_p256(None, None)?;

    let v_multibase = v_key.get_public_keymultibase()?;
    let e_secp256k1_multibase = e_secp256k1.get_public_keymultibase()?;
    let e_p256_multibase = e_p256.get_public_keymultibase()?;

    let keys = vec![
        PeerCreateKey::from_multibase(PeerKeyPurpose::Verification, v_multibase),
        PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, e_secp256k1_multibase),
        PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, e_p256_multibase),
    ];

    let (did_peer, _) = DIDCommon::generate_peer(&keys, None)?;
    let did_str = did_peer.to_string();

    v_key.id = format!("{}#key-1", did_str);
    e_secp256k1.id = format!("{}#key-2", did_str);
    e_p256.id = format!("{}#key-3", did_str);

    Ok((did_str, vec![v_key, e_secp256k1, e_p256]))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("echo_server=info".parse().unwrap()),
        )
        .init();

    let mediator_did = env::var("MEDIATOR_DID").expect("MEDIATOR_DID env var required");

    let (did, secrets) = generate_did_peer()?;
    info!("Generated did:peer: {}", did);

    let profile = TDKProfile::new("echo-server", &did, Some(&mediator_did), secrets);

    let config = DIDCommServiceConfig {
        listeners: vec![ListenerConfig {
            id: "echo-listener".into(),
            profile,
            restart_policy: RestartPolicy::Always {
                backoff: RetryConfig::default(),
            },
            ..Default::default()
        }],
        retry: RetryConfig::default(),
    };

    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutting down...");
        shutdown_clone.cancel();
    });

    info!(
        "Starting echo server (DID: {}, mediator: {})",
        did, mediator_did
    );

    let router = Router::new()
        .route_regex(
            r"https://example\.com/protocols/echo/.+",
            handler_fn(echo_handler),
        )
        .route(
            "https://didcomm.org/report-problem/2.0/problem-report",
            handler_fn(problem_report_handler),
        )
        .fallback(handler_fn(fallback_handler))
        .layer(
            MessagePolicy::new()
                .require_encrypted(true)
                .require_authenticated(true)
                .allow_anonymous_sender(false),
        )
        .layer(middleware_fn(logging_middleware));

    let _service = DIDCommService::start(config, router, shutdown).await?;

    tokio::signal::ctrl_c().await.ok();

    Ok(())
}
