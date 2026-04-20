//! Live checklist of diagnostic steps run against the VTA during the Testing
//! phase. Each entry's status is updated as events arrive from the background
//! runner; the UI renders the whole list with per-step icons and detail text.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagCheck {
    ResolveDid,
    EnumerateServices,
    Authenticate,
    RotateAdminDid,
}

impl DiagCheck {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ResolveDid => "Resolve VTA DID",
            Self::EnumerateServices => "Enumerate service endpoints",
            Self::Authenticate => "Authenticate with setup DID",
            Self::RotateAdminDid => "Rotate admin DID",
        }
    }

    /// Ordered list of every check the runner performs, in execution order.
    /// The UI uses this to render pending rows before any events arrive.
    pub fn all() -> &'static [DiagCheck] {
        &[
            Self::ResolveDid,
            Self::EnumerateServices,
            Self::Authenticate,
            Self::RotateAdminDid,
        ]
    }
}

#[derive(Clone, Debug)]
pub enum DiagStatus {
    Pending,
    Running,
    Ok(String),
    Skipped(String),
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct DiagEntry {
    pub check: DiagCheck,
    pub status: DiagStatus,
}

/// Which authentication path the runner actually completed with. Surfaced to
/// the operator so they know which transport is active.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    DidComm,
    Rest,
}

impl Protocol {
    pub fn label(&self) -> &'static str {
        match self {
            Self::DidComm => "DIDComm",
            Self::Rest => "REST",
        }
    }
}

/// Info about a successful connection. Retained on `VtaConnectState` for
/// downstream phases — the Did step consumes `rest_url` + `access_token` to
/// provision a VTA-managed mediator DID, and write-config consumes the
/// rotated admin identity to seed the mediator's secret storage.
#[derive(Clone, Debug)]
pub struct ConnectedInfo {
    pub protocol: Protocol,
    pub access_token: String,
    /// REST URL resolved from the VTA's DID document.
    pub rest_url: String,
    /// Rotated admin did:key. The setup DID the operator briefly exposed
    /// via ACL registration is gone; this fresh DID is what the mediator
    /// uses long-term to authenticate to the VTA.
    pub admin_did: String,
    /// Private key (multibase) matching `admin_did`. Stored locally and
    /// eventually persisted to the chosen secret backend.
    pub admin_private_key_mb: String,
    /// webvh hosting services registered on the VTA. Retained so the
    /// Did step can offer them as DID-publish targets without a second
    /// round-trip.
    pub webvh_servers: Vec<vta_sdk::webvh::WebvhServerRecord>,
}

/// Seed a fresh diagnostics list with every check in `Pending`.
pub fn pending_list() -> Vec<DiagEntry> {
    DiagCheck::all()
        .iter()
        .map(|c| DiagEntry {
            check: *c,
            status: DiagStatus::Pending,
        })
        .collect()
}

/// Apply a single (check, status) update to an existing diagnostics list.
/// If the check is not present, the update is silently ignored (the runner
/// and the list come from the same source so this should not happen in
/// practice — we avoid the panic for robustness).
pub fn apply_update(list: &mut [DiagEntry], check: DiagCheck, status: DiagStatus) {
    for entry in list.iter_mut() {
        if entry.check == check {
            entry.status = status;
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_list_has_all_checks() {
        let list = pending_list();
        assert_eq!(list.len(), DiagCheck::all().len());
        assert!(list.iter().all(|e| matches!(e.status, DiagStatus::Pending)));
    }

    #[test]
    fn apply_update_sets_status_on_matching_check() {
        let mut list = pending_list();
        apply_update(
            &mut list,
            DiagCheck::ResolveDid,
            DiagStatus::Ok("did:webvh:...".into()),
        );
        let resolved = &list[0];
        assert_eq!(resolved.check, DiagCheck::ResolveDid);
        assert!(matches!(resolved.status, DiagStatus::Ok(_)));
    }
}
