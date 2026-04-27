//! Thin adapters over the SDK's online provisioning runner.
//!
//! The SDK's [`vta_sdk::provision_client::run_connection_test`] and
//! [`vta_sdk::provision_client::run_provision_flight`] take a
//! [`ProvisionAsk`] + an `Arc<dyn OperatorMessages>` directly. The
//! wizard's `app.rs` call sites work in terms of `context_id` /
//! `mediator_url` / `label`, so these wrappers stitch those into the
//! SDK shape and inject [`MediatorMessages`] (the operator-string set
//! that produces the wizard's PNM-command output verbatim).
//!
//! Keeps the SDK-shape concerns confined to one file rather than
//! sprinkled across `app.rs`.

use std::sync::Arc;

use tokio::sync::mpsc::UnboundedSender;
use vta_sdk::provision_client::{self, MediatorMessages, OperatorMessages, ProvisionAsk, VtaEvent};

use super::Protocol;
use super::intent::VtaIntent;

/// Drive the resolve → enumerate → dispatch sequence end-to-end. Mirrors
/// the SDK's [`provision_client::run_connection_test`] but takes the
/// wizard's existing `(context_id, mediator_url)` shape and converts to
/// a [`ProvisionAsk::didcomm_mediator`] internally.
///
/// `intent` must not be [`VtaIntent::OfflineExport`] — that variant is
/// for the offline sealed-handoff sub-flow and never reaches the online
/// runner.
#[allow(clippy::too_many_arguments)]
pub async fn run_connection_test(
    intent: VtaIntent,
    vta_did: String,
    setup_did: String,
    setup_privkey_mb: String,
    context_id: String,
    mediator_url: String,
    force_transport: Option<Protocol>,
    tx: UnboundedSender<VtaEvent>,
) {
    let sdk_intent = intent
        .to_sdk()
        .expect("OfflineExport must not reach the online runner");
    let ask = ProvisionAsk::didcomm_mediator(context_id, mediator_url);
    provision_client::run_connection_test(
        sdk_intent,
        vta_did,
        setup_did,
        setup_privkey_mb,
        ask,
        force_transport,
        tx,
    )
    .await;
}

/// Run the FullSetup provision flight after the operator has resolved a
/// webvh-server choice. Mirrors the SDK's
/// [`provision_client::run_provision_flight`] but keeps the wizard's
/// (context, mediator_url, label) shape and injects
/// [`MediatorMessages`] so the SDK's PNM-command output matches what
/// the wizard rendered before the migration.
#[allow(clippy::too_many_arguments)]
pub async fn run_provision_flight(
    vta_did: String,
    setup_did: String,
    setup_privkey_mb: String,
    mediator_did: String,
    rest_url: Option<String>,
    context: String,
    mediator_url: String,
    label: Option<String>,
    webvh_server_id: Option<String>,
    webvh_path: Option<String>,
    tx: UnboundedSender<VtaEvent>,
) {
    let mut ask = ProvisionAsk::didcomm_mediator(context, mediator_url);
    if let Some(label) = label {
        ask = ask.with_label(label);
    }
    let messages: Arc<dyn OperatorMessages> = Arc::new(MediatorMessages);
    provision_client::run_provision_flight(
        vta_did,
        setup_did,
        setup_privkey_mb,
        mediator_did,
        rest_url,
        ask,
        webvh_server_id,
        webvh_path,
        messages,
        tx,
    )
    .await;
}
