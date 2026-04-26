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
use vta_sdk::webvh::WebvhServerRecord;

use crate::vta_connect::diagnostics::{DiagCheck, DiagStatus, Protocol};
use crate::vta_connect::provision::{ProvisionAsk, provision_mediator_integration};
use crate::vta_connect::resolve::resolve_vta;
use crate::vta_connect::{AdminCredentialReply, VtaIntent, VtaReply};

/// Outcome of a single transport's auth attempt.
///
/// Returned by [`run_didcomm_attempt`] (and, in Slice 1, the REST
/// equivalent). The orchestrator translates this into the
/// transport-agnostic [`VtaEvent::Connected`] /
/// [`VtaEvent::PreflightDone`] / [`VtaEvent::Failed`] event that the
/// wizard's main loop already understands.
///
/// The pre-auth / post-auth distinction matters for fallback. Slice 3
/// uses it to decide whether to try a different transport — a pre-auth
/// failure (transport / handshake / ACL miss) is worth retrying over
/// REST, while a post-auth failure (template error, etc.) means the
/// VTA accepted us and a different wire will reproduce the rejection.
#[derive(Debug)]
pub(super) enum AttemptOutcome {
    /// Attempt produced a final reply with no further preflight
    /// needed. Carries either a [`VtaReply::AdminOnly`] (for the
    /// AdminOnly intent on either transport) or a [`VtaReply::Full`]
    /// (for FullSetup over REST, which doesn't preflight a webvh
    /// catalogue). The orchestrator emits this directly as a
    /// [`VtaEvent::Connected`].
    Connected(VtaReply),
    /// FullSetup preflight success. The orchestrator emits a
    /// [`VtaEvent::PreflightDone`]; the main loop then either
    /// auto-picks a webvh server (0/1 catalogue entries) or shows
    /// the picker (2+) before spawning the provision flight.
    PreflightOk {
        rest_url: Option<String>,
        mediator_did: String,
        servers: Vec<WebvhServerRecord>,
    },
    /// Failure before auth completed (transport / handshake / ACL
    /// miss). The string is the operator-facing failure message —
    /// the orchestrator emits it verbatim as [`VtaEvent::Failed`].
    PreAuthFailure(String),
    /// Failure after auth completed but before the protocol's
    /// natural endpoint. Reserved for Slice 1's REST FullSetup
    /// path; the DIDComm attempt has no post-auth failure mode in
    /// this scope (`list_webvh_servers` errors are non-fatal and
    /// downstream `provision_integration` lives in
    /// `run_provision_flight`).
    #[allow(dead_code)]
    PostAuthFailure(String),
}

/// Single event emitted by the runner. The consumer applies it to the
/// diagnostics list and/or transitions the sub-flow phase.
#[derive(Debug)]
pub enum VtaEvent {
    CheckStart(DiagCheck),
    CheckDone(DiagCheck, DiagStatus),
    /// Emitted by the preflight flight on FullSetup when the auth
    /// check has succeeded and the webvh-server catalogue has been
    /// fetched. The main loop inspects `servers` to decide whether
    /// to auto-pick (0 or 1 entry) or prompt the operator (2+).
    /// After the choice is settled, a provision flight is spawned
    /// with the chosen `webvh_server_id` (or `None` for serverless).
    PreflightDone {
        rest_url: Option<String>,
        mediator_did: String,
        servers: Vec<WebvhServerRecord>,
    },
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
            DiagCheck::AuthenticateDIDComm,
            DiagStatus::Skipped("no DIDComm endpoint".into()),
        ));
        let _ = tx.send(VtaEvent::CheckDone(
            DiagCheck::AuthenticateREST,
            DiagStatus::Skipped("REST runner not yet implemented".into()),
        ));
        let _ = tx.send(VtaEvent::CheckDone(
            DiagCheck::ListWebvhServers,
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
    // DIDComm path is taken on this run. The REST row stays
    // `Skipped` to keep the checklist honest about which transports
    // were exercised; Slice 1 replaces this with a live REST attempt
    // when the operator falls back or REST is the only advertised
    // transport.
    let _ = tx.send(VtaEvent::CheckDone(
        DiagCheck::AuthenticateREST,
        DiagStatus::Skipped("DIDComm-only VTA".into()),
    ));

    // ── 3. DIDComm attempt ───────────────────────────────────────────
    //
    // The attempt fn handles its own diagnostic rows; we translate
    // the outcome into the final transport-agnostic event the
    // wizard's main loop expects.
    let outcome = run_didcomm_attempt(
        intent,
        vta_did,
        mediator_did.clone(),
        rest_url.clone(),
        setup_did,
        setup_privkey_mb,
        &tx,
    )
    .await;

    match outcome {
        AttemptOutcome::Connected(reply) => {
            let _ = tx.send(VtaEvent::Connected {
                protocol: Protocol::DidComm,
                rest_url,
                mediator_did: Some(mediator_did),
                reply,
            });
        }
        AttemptOutcome::PreflightOk {
            rest_url,
            mediator_did,
            servers,
        } => {
            let _ = tx.send(VtaEvent::PreflightDone {
                rest_url,
                mediator_did,
                servers,
            });
        }
        AttemptOutcome::PreAuthFailure(reason) | AttemptOutcome::PostAuthFailure(reason) => {
            let _ = tx.send(VtaEvent::Failed(reason));
        }
    }
}

/// Run the DIDComm leg of the auth check.
///
/// Emits diagnostic rows ([`DiagCheck::AuthenticateDIDComm`],
/// [`DiagCheck::ListWebvhServers`], [`DiagCheck::ProvisionIntegration`])
/// through `tx` as the attempt progresses. Returns an
/// [`AttemptOutcome`] capturing whether the attempt reached its
/// natural endpoint, failed pre-auth, or failed post-auth — the
/// orchestrator translates the outcome into the final
/// transport-agnostic [`VtaEvent`].
///
/// Pre-auth boundary: any failure before [`DIDCommSession::connect`]
/// resolves `Ok` is pre-auth. The DIDComm attempt today has no
/// post-auth failure mode in this scope — `list_webvh_servers`
/// errors are non-fatal (we continue serverless) and downstream
/// `provision_integration` runs in [`run_provision_flight`]. Slice 1
/// extends the boundary for the REST attempt.
async fn run_didcomm_attempt(
    intent: VtaIntent,
    vta_did: String,
    mediator_did: String,
    rest_url: Option<String>,
    setup_did: String,
    setup_privkey_mb: String,
    tx: &UnboundedSender<VtaEvent>,
) -> AttemptOutcome {
    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::AuthenticateDIDComm));

    match intent {
        VtaIntent::FullSetup => {
            // FullSetup preflight: open the session (auth check), then
            // list the VTA's registered webvh servers. Keeping list +
            // provision in separate flights lets the operator change
            // their mind on the webvh pick without wasting a VP nonce.
            use vta_sdk::didcomm_session::DIDCommSession;
            use vta_sdk::protocols::did_management::servers::ListWebvhServersResultBody;
            use vta_sdk::protocols::did_management::{
                LIST_WEBVH_SERVERS, LIST_WEBVH_SERVERS_RESULT,
            };

            let session = match DIDCommSession::connect(
                &setup_did,
                &setup_privkey_mb,
                &vta_did,
                &mediator_did,
            )
            .await
            {
                Ok(s) => {
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::AuthenticateDIDComm,
                        DiagStatus::Ok(format!("DIDComm session as {setup_did}")),
                    ));
                    s
                }
                Err(e) => {
                    let msg = e.to_string();
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::AuthenticateDIDComm,
                        DiagStatus::Failed(msg.clone()),
                    ));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ListWebvhServers,
                        DiagStatus::Skipped("session did not open".into()),
                    ));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ProvisionIntegration,
                        DiagStatus::Skipped("session did not open".into()),
                    ));
                    return AttemptOutcome::PreAuthFailure(format!(
                        "Could not open an authenticated DIDComm session to the VTA. \
                         Confirm the `pnm acl create` command ran successfully for \
                         this setup DID and that the VTA's mediator service is \
                         reachable. ({msg})"
                    ));
                }
            };

            // Webvh-server catalogue lookup. Failure here is
            // non-fatal — the serverless path still works — but we
            // surface the attempt in the checklist so the operator
            // can see whether the picker is about to show up.
            let _ = tx.send(VtaEvent::CheckStart(DiagCheck::ListWebvhServers));
            let servers = match session
                .send_and_wait::<ListWebvhServersResultBody>(
                    LIST_WEBVH_SERVERS,
                    serde_json::json!({}),
                    LIST_WEBVH_SERVERS_RESULT,
                    30,
                )
                .await
            {
                Ok(body) => {
                    let detail = match body.servers.len() {
                        0 => "no registered servers — serverless path".into(),
                        1 => format!("1 registered server ({})", body.servers[0].id),
                        n => format!("{n} registered servers"),
                    };
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ListWebvhServers,
                        DiagStatus::Ok(detail),
                    ));
                    body.servers
                }
                Err(e) => {
                    let msg = e.to_string();
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ListWebvhServers,
                        DiagStatus::Failed(format!(
                            "could not list — continuing serverless ({msg})"
                        )),
                    ));
                    Vec::new()
                }
            };

            AttemptOutcome::PreflightOk {
                rest_url,
                mediator_did,
                servers,
            }
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
                        DiagCheck::AuthenticateDIDComm,
                        DiagStatus::Ok(format!("DIDComm session as {setup_did}")),
                    ));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ListWebvhServers,
                        DiagStatus::Skipped(
                            "AdminOnly — no VTA-minted DID so no webvh host needed".into(),
                        ),
                    ));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ProvisionIntegration,
                        DiagStatus::Skipped(
                            "AdminOnly — setup did:key is the long-term admin credential; \
                             no template render, no rollover"
                                .into(),
                        ),
                    ));
                    AttemptOutcome::Connected(VtaReply::AdminOnly(AdminCredentialReply {
                        admin_did: setup_did,
                        admin_private_key_mb: setup_privkey_mb,
                    }))
                }
                Err(e) => {
                    let msg = e.to_string();
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::AuthenticateDIDComm,
                        DiagStatus::Failed(msg.clone()),
                    ));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ListWebvhServers,
                        DiagStatus::Skipped("session did not open".into()),
                    ));
                    let _ = tx.send(VtaEvent::CheckDone(
                        DiagCheck::ProvisionIntegration,
                        DiagStatus::Skipped("session did not open".into()),
                    ));
                    AttemptOutcome::PreAuthFailure(format!(
                        "Could not open an authenticated DIDComm session to the VTA. \
                         Confirm the `pnm acl create` command ran successfully for \
                         this DID and that the VTA's mediator service is reachable. \
                         ({msg})"
                    ))
                }
            }
        }
        VtaIntent::OfflineExport => {
            // OfflineExport has no online transport — the entry path
            // in `app.rs` routes straight to the sealed-handoff
            // sub-flow without ever spawning the runner. Reaching
            // here would mean a wiring bug (e.g. someone added an
            // online entry for OfflineExport without the matching
            // request shape). Surface the misconfiguration rather
            // than hanging silently.
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::AuthenticateDIDComm,
                DiagStatus::Skipped("OfflineExport has no online transport".into()),
            ));
            AttemptOutcome::PreAuthFailure(
                "OfflineExport intent has no online runner — \
                 use the sealed-handoff sub-flow instead. This is a wizard \
                 wiring bug; please report."
                    .into(),
            )
        }
    }
}

/// FullSetup provision flight — runs after the preflight
/// [`VtaEvent::PreflightDone`] has been handled and the operator's
/// webvh-server choice is settled (either auto-picked by the main
/// loop or selected interactively on the `PickWebvhServer` phase).
///
/// Opens a fresh DIDComm session (cheap; ~100ms authcrypt handshake)
/// rather than keeping preflight's session alive across the picker
/// dialog — the picker may stay on screen for many seconds, and
/// tying a live session to a UI wait is fragile. Re-handshaking is
/// simpler and well inside the VP's freshness window.
///
/// `webvh_server_id`: `Some(id)` → injects `WEBVH_SERVER` into the
/// VP's `mediator_template_vars` so the VTA pins the minted DID's
/// did.jsonl log to that server; `None` → serverless path (DID
/// self-hosts at `URL`).
///
/// `webvh_path`: `Some(p)` → injects `WEBVH_PATH` into
/// `mediator_template_vars` so the VTA forwards the operator's path
/// suggestion to the webvh server's `request_uri` call; `None` →
/// server auto-assigns. Only meaningful when `webvh_server_id` is
/// `Some` (the serverless branch has no server to ask).
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
    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::ProvisionIntegration));

    let mut ask = ProvisionAsk::mediator(context.clone(), mediator_url.clone())
        .with_label(label.unwrap_or_else(|| format!("mediator setup — {context}")));
    if let Some(ref id) = webvh_server_id {
        ask.mediator_template_vars.insert(
            "WEBVH_SERVER".to_string(),
            serde_json::Value::String(id.clone()),
        );
    }
    if let Some(ref p) = webvh_path {
        ask.mediator_template_vars.insert(
            "WEBVH_PATH".to_string(),
            serde_json::Value::String(p.clone()),
        );
    }

    match provision_mediator_integration(
        &setup_did,
        &setup_privkey_mb,
        &vta_did,
        &mediator_did,
        &ask,
    )
    .await
    {
        Ok(result) => {
            let webvh_note = webvh_server_id
                .as_ref()
                .map(|id| format!(", webvh server: {id}"))
                .unwrap_or_else(|| ", webvh: serverless".into());
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::ProvisionIntegration,
                DiagStatus::Ok(format!(
                    "admin DID: {} (rolled: {}), integration DID: {}{webvh_note}",
                    result.admin_did(),
                    result.summary.admin_rolled_over,
                    result.integration_did(),
                )),
            ));
            let _ = tx.send(VtaEvent::Connected {
                protocol: Protocol::DidComm,
                rest_url,
                mediator_did: Some(mediator_did),
                reply: VtaReply::Full(result),
            });
        }
        Err(err) => {
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
                    "VTA rejected the template render — check the `didcomm-mediator` \
                     template is present and your `WEBVH_SERVER` (if any) matches \
                     a registered server. Details: {msg}"
                )
            } else {
                format!("Provisioning failed. Details: {msg}")
            };
            let _ = tx.send(VtaEvent::Failed(hint));
        }
    }
}
