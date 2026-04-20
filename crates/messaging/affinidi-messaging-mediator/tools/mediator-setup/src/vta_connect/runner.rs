//! Background connection test.
//!
//! Runs the diagnostic checklist against a running VTA and streams per-check
//! updates back to the main event loop via an unbounded channel. The runner
//! is spawned as a detached tokio task; the wizard event loop drains events
//! on its regular tick.
//!
//! Authentication goes through `vta_sdk::session::SessionStore::ensure_authenticated`
//! with a `needs_rotation: true` session. On the first successful challenge-
//! response the SDK atomically mints a fresh did:key, mirrors the ACL entry
//! onto it, and drops the temp DID. The setup DID the operator briefly
//! exposed via copy-paste is therefore short-lived; the wizard surfaces the
//! rotated DID to the operator as the mediator's long-term admin identity.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::mpsc::UnboundedSender;
use vta_sdk::session::{SessionBackend, SessionStore};

use crate::vta_connect::diagnostics::{DiagCheck, DiagStatus, Protocol};
use crate::vta_connect::resolve::resolve_vta;

const WIZARD_SESSION_KEY: &str = "mediator-setup-wizard";

/// Single event emitted by the runner. The consumer applies it to the
/// diagnostics list and/or transitions the sub-flow phase.
#[derive(Debug)]
pub enum VtaEvent {
    CheckStart(DiagCheck),
    CheckDone(DiagCheck, DiagStatus),
    Connected {
        protocol: Protocol,
        access_token: String,
        rest_url: String,
        /// Rotated admin DID returned by the SDK after auto-rotation. The
        /// setup DID the operator registered is already gone from the ACL.
        admin_did: String,
        admin_private_key_mb: String,
    },
    Failed(String),
}

/// In-memory session backend — the wizard's sessions never touch disk or
/// the OS keyring. The process-local map is enough because the runner lives
/// for the duration of the test and hands its result back through
/// `VtaEvent::Connected`.
#[derive(Default)]
struct InMemorySessionBackend {
    map: Mutex<HashMap<String, String>>,
}

impl SessionBackend for InMemorySessionBackend {
    fn load(&self, key: &str) -> Option<String> {
        self.map.lock().ok()?.get(key).cloned()
    }

    fn save(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.map
            .lock()
            .map_err(|e| format!("session map poisoned: {e}"))?
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn clear(&self, key: &str) {
        if let Ok(mut m) = self.map.lock() {
            m.remove(key);
        }
    }
}

/// Run the full diagnostic + auth sequence.
///
/// Best-effort: every channel `send` is ignored on failure (receiver dropped
/// if the operator cancelled). Short-circuits on the first non-recoverable
/// failure (resolve / no REST endpoint). Authentication is REST-only: the
/// rotation flow requires `ensure_authenticated`, which is REST-backed.
pub async fn run_connection_test(
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
    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::EnumerateServices));
    let rest_url = resolved.rest_url.clone();
    let has_didcomm = resolved.has_didcomm();
    let enum_detail = format!(
        "REST: {}, DIDCommMessaging: {}",
        if rest_url.is_some() { "yes" } else { "no" },
        if has_didcomm { "yes" } else { "no" },
    );
    let Some(rest_url) = rest_url else {
        let _ = tx.send(VtaEvent::CheckDone(
            DiagCheck::EnumerateServices,
            DiagStatus::Failed(enum_detail),
        ));
        let _ = tx.send(VtaEvent::Failed(
            "VTA DID document has no #vta-rest service endpoint — cannot \
             authenticate. Ask the VTA operator to publish a REST endpoint."
                .into(),
        ));
        return;
    };
    let _ = tx.send(VtaEvent::CheckDone(
        DiagCheck::EnumerateServices,
        DiagStatus::Ok(enum_detail),
    ));

    // ── 3. Authenticate via SessionStore with rotation ────────────────
    let store = SessionStore::with_backend(Box::new(InMemorySessionBackend::default()));
    if let Err(e) = store.store_pending_rotation(
        WIZARD_SESSION_KEY,
        &setup_did,
        &setup_privkey_mb,
        &vta_did,
        Some(&rest_url),
    ) {
        let _ = tx.send(VtaEvent::Failed(format!(
            "Could not prepare wizard session: {e}"
        )));
        return;
    }

    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::Authenticate));
    let token = match store
        .ensure_authenticated(&rest_url, WIZARD_SESSION_KEY)
        .await
    {
        Ok(token) => {
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::Authenticate,
                DiagStatus::Ok(format!("setup DID authenticated: {setup_did}")),
            ));
            token
        }
        Err(e) => {
            let msg = e.to_string();
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::Authenticate,
                DiagStatus::Failed(msg.clone()),
            ));
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::RotateAdminDid,
                DiagStatus::Skipped("auth failed — rotation did not run".into()),
            ));
            let hint = if msg.contains("401") || msg.contains("403") {
                "Authentication rejected — confirm the `pnm contexts create` \
                 command ran successfully on the VTA host for this setup DID."
            } else if msg.contains("could not connect") {
                "VTA REST endpoint is unreachable — check network connectivity \
                 and that the VTA service is running."
            } else {
                "Authentication failed. See the diagnostic entry above for \
                 details."
            };
            let _ = tx.send(VtaEvent::Failed(hint.into()));
            return;
        }
    };

    // ── 4. Rotation outcome ───────────────────────────────────────────
    // `ensure_authenticated` has already rotated (or not); we load the
    // session to find out.
    let _ = tx.send(VtaEvent::CheckStart(DiagCheck::RotateAdminDid));
    let rotated = match store.loaded_session(WIZARD_SESSION_KEY) {
        Some(info) => info,
        None => {
            let _ = tx.send(VtaEvent::CheckDone(
                DiagCheck::RotateAdminDid,
                DiagStatus::Failed("session vanished after auth".into()),
            ));
            let _ = tx.send(VtaEvent::Failed(
                "Internal error: session disappeared after authentication.".into(),
            ));
            return;
        }
    };

    if rotated.client_did == setup_did {
        // The SDK skipped rotation — this shouldn't happen for a session
        // stored with `store_pending_rotation`, but if it did we surface
        // it as a soft failure so the operator can tell.
        let _ = tx.send(VtaEvent::CheckDone(
            DiagCheck::RotateAdminDid,
            DiagStatus::Failed("setup DID was not rotated".into()),
        ));
        let _ = tx.send(VtaEvent::Failed(
            "Admin DID rotation did not complete. The setup DID is still \
             live on the VTA — consider rotating manually or re-running the \
             wizard."
                .into(),
        ));
        return;
    }

    let _ = tx.send(VtaEvent::CheckDone(
        DiagCheck::RotateAdminDid,
        DiagStatus::Ok(format!("admin DID: {}", rotated.client_did)),
    ));
    let _ = tx.send(VtaEvent::Connected {
        protocol: Protocol::Rest,
        access_token: token,
        rest_url,
        admin_did: rotated.client_did,
        admin_private_key_mb: rotated.private_key_multibase,
    });
}
