//! Live checklist of diagnostic steps run against the VTA during the Testing
//! phase. Each entry's status is updated as events arrive from the background
//! runner; the UI renders the whole list with per-step icons and detail text.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagCheck {
    ResolveDid,
    EnumerateServices,
    /// DIDComm-leg of the auth check. The runner emits `Running` /
    /// `Ok` / `Failed` on this row when the configured transport is
    /// DIDComm. When DIDComm isn't advertised by the VTA, this row
    /// stays `Skipped`.
    AuthenticateDIDComm,
    /// REST-leg of the auth check. Emitted when the runner falls
    /// back to REST after a DIDComm failure, when the VTA advertises
    /// only REST, or as a `Skipped` placeholder when the DIDComm
    /// path completed without needing a fallback. Slice 0 only emits
    /// `Skipped`; live REST emissions land in Slice 1.
    AuthenticateREST,
    /// FullSetup-only: fetches the VTA's registered webvh-hosting-server
    /// catalogue so the wizard can either auto-pick (0/1 entries) or
    /// prompt the operator (2+). Skipped on AdminOnly.
    ListWebvhServers,
    ProvisionIntegration,
}

impl DiagCheck {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ResolveDid => "Resolve VTA DID",
            Self::EnumerateServices => "Enumerate service endpoints",
            Self::AuthenticateDIDComm => "Authenticate via DIDComm",
            Self::AuthenticateREST => "Authenticate via REST",
            Self::ListWebvhServers => "List webvh hosting servers",
            Self::ProvisionIntegration => "Provision mediator DID + admin credential",
        }
    }

    /// Ordered list of every check the runner performs, in execution order.
    /// The UI uses this to render pending rows before any events arrive.
    pub fn all() -> &'static [DiagCheck] {
        &[
            Self::ResolveDid,
            Self::EnumerateServices,
            Self::AuthenticateDIDComm,
            Self::AuthenticateREST,
            Self::ListWebvhServers,
            Self::ProvisionIntegration,
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
/// the operator so they know which transport is active. The runner only
/// emits `DidComm` today — `Rest` is preserved so the `label()` switch and
/// downstream UI handle the transport gracefully when REST-only auth lands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
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

/// Info about a successful VTA round-trip. Retained on
/// `VtaConnectState` so downstream wizard steps can read the result
/// without re-contacting the VTA.
///
/// The variant carried by `reply` matches the intent the runner was
/// invoked with:
///
/// - [`crate::vta_connect::VtaReply::Full`] — FullSetup path,
///   provision-integration completed, carries a
///   [`crate::vta_connect::provision::ProvisionResult`] with the
///   VTA-minted integration DID, admin key, VC, template outputs.
/// - [`crate::vta_connect::VtaReply::AdminOnly`] — AdminOnly path,
///   carries the admin DID + private key the operator enrolled via
///   `pnm acl create` (wizard verified by opening an authenticated
///   DIDComm session but did not mint or rotate anything).
#[derive(Clone, Debug)]
pub struct ConnectedInfo {
    /// Which transport actually carried the round-trip. Always
    /// `Protocol::DidComm` today — the auth check and (for FullSetup)
    /// the provision-integration call both use DIDComm.
    pub protocol: Protocol,
    /// REST URL advertised by the VTA DID document, for runtime-side
    /// fallback. The wizard itself does not use it.
    pub rest_url: Option<String>,
    /// DIDComm mediator DID advertised by the VTA. Always `Some` when
    /// `protocol == DidComm`.
    pub mediator_did: Option<String>,
    /// Unified reply — see [`VtaReply`] for the two variants.
    pub reply: crate::vta_connect::VtaReply,
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

    #[test]
    fn all_lists_split_authenticate_rows_in_order() {
        let all = DiagCheck::all();
        assert_eq!(
            all,
            &[
                DiagCheck::ResolveDid,
                DiagCheck::EnumerateServices,
                DiagCheck::AuthenticateDIDComm,
                DiagCheck::AuthenticateREST,
                DiagCheck::ListWebvhServers,
                DiagCheck::ProvisionIntegration,
            ]
        );
    }

    #[test]
    fn authenticate_rows_have_distinct_labels() {
        assert_eq!(
            DiagCheck::AuthenticateDIDComm.label(),
            "Authenticate via DIDComm"
        );
        assert_eq!(DiagCheck::AuthenticateREST.label(), "Authenticate via REST");
    }
}
