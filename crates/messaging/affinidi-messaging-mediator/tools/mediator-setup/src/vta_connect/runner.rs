//! Background provisioning driver.
//!
//! Runs the diagnostic checklist against a running VTA and drives the
//! `provision-integration` round-trip — resolve, enumerate, open
//! DIDComm session as the setup DID, send a VP asking for a
//! `didcomm-mediator` template render + `vta-admin` admin rollover,
//! receive the sealed bundle, open locally.
//!
//! Per-check updates stream back to the main event loop via an
//! unbounded channel; the wizard event loop drains events on its
//! regular tick. The runner is spawned as a detached tokio task.
//!
//! Provision-integration is DIDComm-only on the wizard side (the
//! file-path escape hatch lives on the VTA host). If the VTA DID
//! document doesn't advertise a DIDComm endpoint, the runner hard-
//! fails with a hint to use the offline sealed-handoff flow instead.

use tokio::sync::mpsc::UnboundedSender;

use crate::vta_connect::diagnostics::{DiagCheck, DiagStatus, Protocol};
use crate::vta_connect::provision::{ProvisionAsk, ProvisionError, provision_mediator_integration};
use crate::vta_connect::resolve::resolve_vta;
use crate::vta_connect::{AdminCredentialReply, VtaIntent, VtaReply};

/// Single event emitted by the runner. The consumer applies it to the
/// diagnostics list and/or transitions the sub-flow phase.
#[derive(Debug)]
pub enum VtaEvent {
    CheckStart(DiagCheck),
    CheckDone(DiagCheck, DiagStatus),
    Connected {
        protocol: Protocol,
        /// REST URL advertised in the VTA DID doc, retained for the
        /// mediator's runtime credential so it has a URL fallback at
        /// startup. Always `None` when the VTA is DIDComm-only.
        rest_url: Option<String>,
        /// DIDComm mediator DID from the VTA DID doc. Always `Some`
        /// when `protocol == DidComm`.
        mediator_did: Option<String>,
        /// Unified reply — carries either the full template-bootstrap
        /// result (FullSetup) or the enrolled admin credential the
        /// wizard just verified (AdminOnly). See [`VtaReply`].
        reply: VtaReply,
    },
    Failed(String),
}

/// Run the resolve → enumerate → provision sequence end-to-end.
///
/// Best-effort: every channel `send` is ignored on failure (receiver
/// dropped if the operator cancelled). Short-circuits on the first
/// non-recoverable failure; diagnostic events carry enough detail
/// for the UI to surface an actionable error without the operator
/// having to dig into logs.
///
/// `context`, `mediator_url`, `label` are captured up-front from the
/// wizard's earlier phases and fed into the VP's `TemplateBootstrapAsk`.
pub async fn run_connection_test(
    intent: VtaIntent,
    vta_did: String,
    setup_did: String,
    setup_privkey_mb: String,
    context: String,
    mediator_url: String,
    label: Option<String>,
    tx: UnboundedSender<VtaEvent>,
) {
    // ── 1. Resolve ────────────────────────────────────────────────────
    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::ResolveDid));
    let resolved = match resolve_vta(&vta_did).await {
        Ok(r) => {
            let detail = match (&r.mediator_did, &r.rest_url) {
                (Some(m), _) => format!("mediator DID: {m}"),
                (None, Some(u)) => format!("REST: {u}"),
                (None, None) => "resolved (no endpoints)".into(),
            };
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ResolveDid,
                DiagStatus::Ok(detail),
            ));
            r
        }
        Err(e) => {
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ResolveDid,
                DiagStatus::Failed(e.to_string()),
            ));
            let _ = tx.send(VtaEvent::Failed(format!(
                "Could not resolve {vta_did}. Verify the DID is correct and its \
                 publication endpoint is reachable."
            )));
            return;
        }
    };

    // ── 2. Enumerate ──────────────────────────────────────────────────
    //
    // Provision-integration is DIDComm-only. A VTA that doesn't
    // advertise a `#DIDCommMessaging` service cannot be provisioned via
    // this wizard path — the operator needs to use the offline
    // sealed-handoff flow instead.
    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::EnumerateServices));
    let rest_url = resolved.rest_url.clone();
    let mediator_did_opt = resolved.mediator_did.clone();
    let enum_detail = format!(
        "REST: {}, DIDCommMessaging: {}",
        if rest_url.is_some() { "yes" } else { "no" },
        if mediator_did_opt.is_some() {
            "yes"
        } else {
            "no"
        },
    );
    let Some(mediator_did) = mediator_did_opt.clone() else {
        let _ = tx.send(VtaEvent::CheckDone(
            DiagCheck::EnumerateServices,
            DiagStatus::Failed(enum_detail),
        ));
        let _ = tx.send(VtaEvent::CheckDone(
            DiagCheck::Authenticate,
            DiagStatus::Skipped("no DIDComm endpoint".into()),
        ));
        let _ = tx.send(VtaEvent::CheckDone(
            DiagCheck::ProvisionIntegration,
            DiagStatus::Skipped("no DIDComm endpoint".into()),
        ));
        let _ = tx.send(VtaEvent::Failed(
            "VTA DID document does not advertise a DIDComm mediator endpoint. \
             Provision-integration requires DIDComm — use the offline \
             sealed-handoff flow for VTAs that are DIDComm-less or unreachable."
                .into(),
        ));
        return;
    };
    let _ = tx.send(VtaEvent::CheckDone(
        DiagCheck::EnumerateServices,
        DiagStatus::Ok(enum_detail),
    ));

    // ── 3. Authenticate (+ provision, for FullSetup) ─────────────────
    //
    // Both intents open a DIDComm session as the setup DID. For
    // `FullSetup` the session then carries the VP round-trip;
    // `AdminOnly` stops after the session opens — the fact that the
    // authcrypt handshake completes is sufficient proof that the
    // operator's out-of-band `pnm acl create` worked.
    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::Authenticate));

    match intent {
        VtaIntent::FullSetup => {
            let ask = ProvisionAsk::mediator(context.clone(), mediator_url.clone())
                .with_label(label.unwrap_or_else(|| format!("mediator setup — {context}")));

            let provision = match provision_mediator_integration(
                &setup_did,
                &setup_privkey_mb,
                &vta_did,
                &mediator_did,
                &ask,
            )
            .await
            {
                Ok(result) => {
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::Authenticate,
                        DiagStatus::Ok(format!("DIDComm session as {setup_did}")),
                    ));
                    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::ProvisionIntegration));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ProvisionIntegration,
                        DiagStatus::Ok(format!(
                            "admin DID: {} (rolled: {}), integration DID: {}",
                            result.admin_did(),
                            result.summary.admin_rolled_over,
                            result.integration_did(),
                        )),
                    ));
                    result
                }
                Err(ProvisionError::SessionOpen(msg)) => {
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::Authenticate,
                        DiagStatus::Failed(msg.clone()),
                    ));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ProvisionIntegration,
                        DiagStatus::Skipped("session did not open".into()),
                    ));
                    let _ = tx.send(VtaEvent::Failed(format!(
                        "Could not open an authenticated DIDComm session to the VTA. \
                         Confirm the `pnm acl create` command ran successfully for \
                         this setup DID and that the VTA's mediator service is \
                         reachable. ({msg})"
                    )));
                    return;
                }
                Err(err) => {
                    // Authentication opened (DIDComm session is up) but the
                    // provision call failed downstream.
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::Authenticate,
                        DiagStatus::Ok(format!("DIDComm session as {setup_did}")),
                    ));
                    let msg = err.to_string();
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ProvisionIntegration,
                        DiagStatus::Failed(msg.clone()),
                    ));
                    let hint = if msg.to_lowercase().contains("forbidden")
                        || msg.contains("401")
                        || msg.contains("403")
                    {
                        format!(
                            "The VTA rejected the provisioning request. Confirm the \
                             `pnm acl create` command ran successfully for setup DID \
                             {setup_did} in context `{context}`, then retry."
                        )
                    } else if msg.to_lowercase().contains("template") {
                        format!(
                            "VTA rejected the template render — the `didcomm-mediator` \
                             or `vta-admin` template may be missing or have a \
                             different required-vars contract. Details: {msg}"
                        )
                    } else {
                        format!("Provisioning failed. Details: {msg}")
                    };
                    let _ = tx.send(VtaEvent::Failed(hint));
                    return;
                }
            };

            let _ = tx.send(VtaEvent::Connected {
                protocol: Protocol::DidComm,
                rest_url,
                mediator_did: Some(mediator_did),
                reply: VtaReply::Full(provision),
            });
        }
        VtaIntent::AdminOnly => {
            // AdminOnly: open a DIDComm session as the setup DID and
            // stop there. The setup DID *is* the long-term admin DID
            // (no rotation) — the session open is the authenticated
            // proof that the operator's `pnm acl create` landed. We
            // skip the ProvisionIntegration diagnostic row so the
            // checklist stays honest about what ran.
            use vta_sdk::didcomm_session::DIDCommSession;

            match DIDCommSession::connect(&setup_did, &setup_privkey_mb, &vta_did, &mediator_did)
                .await
            {
                Ok(_session) => {
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::Authenticate,
                        DiagStatus::Ok(format!("DIDComm session as {setup_did}")),
                    ));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ProvisionIntegration,
                        DiagStatus::Skipped(
                            "AdminOnly — wizard verified session only, no template provision"
                                .into(),
                        ),
                    ));
                    let _ = tx.send(VtaEvent::Connected {
                        protocol: Protocol::DidComm,
                        rest_url,
                        mediator_did: Some(mediator_did),
                        reply: VtaReply::AdminOnly(AdminCredentialReply {
                            admin_did: setup_did.clone(),
                            admin_private_key_mb: setup_privkey_mb.clone(),
                        }),
                    });
                }
                Err(e) => {
                    let msg = e.to_string();
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::Authenticate,
                        DiagStatus::Failed(msg.clone()),
                    ));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ProvisionIntegration,
                        DiagStatus::Skipped("session did not open".into()),
                    ));
                    let _ = tx.send(VtaEvent::Failed(format!(
                        "Could not open an authenticated DIDComm session to the VTA. \
                         Confirm the `pnm acl create` command ran successfully for \
                         this DID and that the VTA's mediator service is reachable. \
                         ({msg})"
                    )));
                }
            }
        }
    }
}
