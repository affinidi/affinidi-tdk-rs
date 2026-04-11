use std::collections::HashMap;
use std::env;
use std::sync::Arc;

use affinidi_did_common::{DID as DIDCommon, PeerCreateKey, PeerKeyPurpose};
use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommService, DIDCommServiceConfig, DIDCommServiceError, ErrorHandler,
    Extension, HandlerContext, ListenerConfig, MESSAGE_PICKUP_STATUS_TYPE, MessagePolicy, Next,
    ProblemReport, RequestLogging, RestartPolicy, RetryConfig, Router, ServiceProblemReport,
    TRUST_PING_TYPE, handler_fn, ignore_handler, middleware_fn, trust_ping_handler,
};
use affinidi_messaging_sdk::protocols::mediator::acls::AccessListModeType;
use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk_common::profiles::TDKProfile;
use serde_json::json;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

const ECHO_RESPONSE_TYPE: &str = "https://example.com/protocols/echo/1.0/response";

#[derive(Clone)]
struct AppConfig {
    server_name: String,
}

type Db = Arc<RwLock<HashMap<String, u64>>>;

async fn custom_middleware(
    ctx: HandlerContext,
    message: Message,
    meta: UnpackMetadata,
    next: Next,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    // custom action
    next.run(ctx, message, meta).await
}

async fn echo_handler(
    ctx: HandlerContext,
    message: Message,
    Extension(config): Extension<AppConfig>,
    Extension(db): Extension<Db>,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    let sender_key = ctx
        .sender_did
        .clone()
        .unwrap_or_else(|| "<anon>".to_string());
    let count = {
        let mut store = db.write().await;
        let entry = store.entry(sender_key).or_insert(0);
        *entry += 1;
        *entry
    };

    info!(
        "[{}] Echo #{} from={} type={}",
        config.server_name,
        count,
        ctx.sender_did.as_deref().unwrap_or("<anon>"),
        message.typ
    );

    let response_body = json!({
        "echo": message.body,
        "original_type": message.typ,
        "server": config.server_name,
        "message_count": count,
    });

    Ok(Some(DIDCommResponse::new(
        ECHO_RESPONSE_TYPE,
        response_body,
    )))
}

async fn problem_report_handler(
    ctx: HandlerContext,
    message: Message,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    warn!(
        "Problem report from {}: {:?}",
        ctx.sender_did.as_deref().unwrap_or("<anon>"),
        message.body
    );
    Ok(None)
}

async fn fallback_handler(
    ctx: HandlerContext,
    message: Message,
) -> Result<Option<DIDCommResponse>, DIDCommServiceError> {
    warn!(
        "Unhandled message type '{}' from {}",
        message.typ,
        ctx.sender_did.as_deref().unwrap_or("<anon>")
    );
    Ok(Some(DIDCommResponse::problem_report(
        ProblemReport::bad_request(format!("Unsupported message type: {}", message.typ)),
    )))
}

struct EchoErrorHandler;

impl ErrorHandler for EchoErrorHandler {
    fn on_error(&self, ctx: &HandlerContext, error: &DIDCommServiceError) {
        warn!(
            profile = %ctx.profile.inner.alias,
            message_id = %ctx.message_id,
            error = %error,
            "Echo server handler error"
        );
    }
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
                .add_directive("echo_server=info".parse().unwrap())
                .add_directive("didcomm_server::request=info".parse().unwrap()),
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
            acl_mode: Some(AccessListModeType::ExplicitDeny),
            ..Default::default()
        }],
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

    let app_config = AppConfig {
        server_name: "echo-server".into(),
    };
    let db: Db = Arc::new(RwLock::new(HashMap::new()));

    let router = Router::new()
        .extension(app_config)
        .extension(db)
        .route(TRUST_PING_TYPE, handler_fn(trust_ping_handler))?
        .route(MESSAGE_PICKUP_STATUS_TYPE, handler_fn(ignore_handler))?
        .route_regex(
            r"https://example\.com/protocols/echo/.+",
            handler_fn(echo_handler),
        )?
        .route(
            "https://didcomm.org/report-problem/2.0/problem-report",
            handler_fn(problem_report_handler),
        )?
        .fallback(handler_fn(fallback_handler))
        .on_error(EchoErrorHandler)
        .layer(
            MessagePolicy::new()
                .require_encrypted(true)
                .require_authenticated(true)
                .allow_anonymous_sender(false),
        )
        .layer(middleware_fn(custom_middleware))
        .layer(RequestLogging);

    let _service = DIDCommService::start(config, router, shutdown).await?;

    tokio::signal::ctrl_c().await.ok();

    Ok(())
}
