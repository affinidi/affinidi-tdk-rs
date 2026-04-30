//! Cross-flow VTA session — what the wizard hangs onto after either
//! sub-flow (online or sealed-handoff) completes.
//!
//! [`VtaSession`] is the durable handle downstream wizard steps (Did,
//! Summary, secret-writing, exit recap) read from. It abstracts over the
//! three reply variants so consumers don't need to know which adapter
//! produced the result.

use vta_sdk::context_provision::ContextProvisionBundle;
use vta_sdk::provision_client::{AdminCredentialReply, ProvisionResult};

use super::intent::VtaReply;

/// A completed VTA interaction — retained on `WizardApp` after the
/// sub-flow exits so downstream steps (Did, Summary, secret-writing) can
/// use the resulting credential material.
///
/// The [`reply`](Self::reply) field carries the transport-agnostic payload.
/// Accessors below flatten the three variants into the shape downstream code
/// actually consumes (admin DID, admin private key, optional integration
/// DID).
#[derive(Clone, Debug)]
pub struct VtaSession {
    pub context_id: String,
    pub vta_did: String,
    /// REST URL advertised by the VTA DID doc. `None` for a
    /// DIDComm-only VTA or a sealed-handoff session. Persisted onto
    /// the mediator's admin credential so its runtime code has a URL
    /// fallback for VTA operations.
    pub rest_url: Option<String>,
    /// DIDComm mediator DID advertised by the VTA. Captured so a
    /// DIDComm-backed `VtaClient` can be reopened without
    /// re-resolving the VTA DID document. No current consumer reads
    /// this — preserved as plumbing for the future reopen path.
    #[allow(dead_code)]
    pub mediator_did: Option<String>,
    /// Unified reply — either a full template-bootstrap result, an
    /// admin-credential-only reply, or a sealed context-export bundle.
    /// See [`VtaReply`].
    pub reply: VtaReply,
}

impl VtaSession {
    /// Construct a session from a full template-bootstrap reply (both
    /// online and offline `FullSetup` adapters call this).
    pub fn full(
        context_id: String,
        vta_did: String,
        rest_url: Option<String>,
        mediator_did: Option<String>,
        provision: ProvisionResult,
    ) -> Self {
        Self {
            context_id,
            vta_did,
            rest_url,
            mediator_did,
            reply: VtaReply::Full(Box::new(provision)),
        }
    }

    /// Construct a session from an admin-credential-only reply (both
    /// online and offline `AdminOnly` adapters call this).
    pub fn admin_only(
        context_id: String,
        vta_did: String,
        rest_url: Option<String>,
        mediator_did: Option<String>,
        admin_did: String,
        admin_private_key_mb: String,
    ) -> Self {
        Self {
            context_id,
            vta_did,
            rest_url,
            mediator_did,
            reply: VtaReply::AdminOnly(AdminCredentialReply {
                admin_did,
                admin_private_key_mb,
            }),
        }
    }

    /// Construct a session from a `ContextProvision` sealed bundle —
    /// the OfflineExport adapter's reply shape. The bundle's `vta_did`
    /// / `vta_url` may be absent (older VTA-side flows) so we
    /// substitute empty strings to keep the session shape uniform;
    /// downstream code that needs them treats empty as "unknown".
    pub fn context_export(context_id: String, bundle: ContextProvisionBundle) -> Self {
        let vta_did = bundle.vta_did.clone().unwrap_or_default();
        let rest_url = bundle.vta_url.clone();
        Self {
            context_id,
            vta_did,
            rest_url,
            mediator_did: None,
            reply: VtaReply::ContextExport(Box::new(bundle)),
        }
    }

    /// Long-term admin DID the mediator authenticates as. For a
    /// [`VtaReply::Full`] reply this is the rolled-over DID from the
    /// `ProvisionResult`; for `AdminOnly` it's the DID the VTA supplied
    /// directly; for `ContextExport` it's the (auto-minted) admin DID
    /// the VTA shipped inside the [`ContextProvisionBundle`].
    pub fn admin_did(&self) -> &str {
        match &self.reply {
            VtaReply::Full(p) => p.admin_did(),
            VtaReply::AdminOnly(a) => &a.admin_did,
            VtaReply::ContextExport(b) => &b.admin_did,
        }
    }

    /// Private key (multibase) matching [`Self::admin_did`]. Returns an
    /// empty slice when a `Full` reply has no admin-key entry (the
    /// legacy no-rollover path); callers should treat empty as "reuse
    /// the setup key" exactly as before.
    pub fn admin_private_key_mb(&self) -> &str {
        match &self.reply {
            VtaReply::Full(p) => p
                .admin_key()
                .map(|k| k.signing_key.private_key_multibase.as_str())
                .unwrap_or(""),
            VtaReply::AdminOnly(a) => &a.admin_private_key_mb,
            VtaReply::ContextExport(b) => b.credential.private_key_multibase.as_str(),
        }
    }

    /// Integration (mediator-service) DID the VTA rendered or
    /// re-exported. `None` for `AdminOnly` (mediator brought its own
    /// DID) and for any `ContextExport` whose bundle didn't include a
    /// `did` slot (admin-only context — degenerate but possible).
    pub fn integration_did(&self) -> Option<&str> {
        match &self.reply {
            VtaReply::Full(p) => p.integration_did(),
            VtaReply::AdminOnly(_) => None,
            VtaReply::ContextExport(b) => b.did.as_ref().map(|d| d.id.as_str()),
        }
    }

    /// Borrow the full [`ProvisionResult`] when the reply is
    /// [`VtaReply::Full`]. Returns `None` for `AdminOnly` and
    /// `ContextExport` — those carry their own shapes; see
    /// [`Self::as_context_export`] for the ContextExport accessor.
    pub fn as_full_provision(&self) -> Option<&ProvisionResult> {
        match &self.reply {
            VtaReply::Full(p) => Some(p),
            VtaReply::AdminOnly(_) | VtaReply::ContextExport(_) => None,
        }
    }

    /// Borrow the [`ContextProvisionBundle`] when the reply is
    /// [`VtaReply::ContextExport`]. Sibling to [`Self::as_full_provision`]
    /// — `main.rs::generate_and_write` walks both accessors when the
    /// `did_method` is `DID_VTA` and picks whichever is present.
    pub fn as_context_export(&self) -> Option<&ContextProvisionBundle> {
        match &self.reply {
            VtaReply::ContextExport(b) => Some(b),
            VtaReply::Full(_) | VtaReply::AdminOnly(_) => None,
        }
    }
}
