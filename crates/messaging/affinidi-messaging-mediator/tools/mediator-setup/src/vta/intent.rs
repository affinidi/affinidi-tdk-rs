//! Local VTA request / reply types spanning online and offline transports.
//!
//! The wizard's VTA integration has two orthogonal axes:
//!
//! - **Intent** — what the operator wants from the VTA ([`VtaIntent`]).
//!   `FullSetup` has the VTA mint the mediator's integration DID via a
//!   template; `AdminOnly` has the operator bring their own DID and only
//!   asks the VTA for an admin credential; `OfflineExport` picks up
//!   already-provisioned state via a sealed bundle.
//! - **Transport** — how the request reaches the VTA ([`VtaTransport`]).
//!   `Online` is a live network call; `Offline` is an armored sealed-bundle
//!   handoff via a VTA administrator.
//!
//! The SDK ([`vta_sdk::provision_client`]) owns the online surface and so
//! only knows `FullSetup` / `AdminOnly`. The wizard's `OfflineExport`
//! variant + the [`VtaReply::ContextExport`] reply variant are local
//! TUI-state extensions for the offline sealed-handoff flow.

use vta_sdk::context_provision::ContextProvisionBundle;
use vta_sdk::provision_client::{
    AdminCredentialReply, ProvisionResult, VtaIntent as SdkVtaIntent, VtaReply as SdkVtaReply,
};

/// What the operator wants the VTA to do during setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VtaIntent {
    /// VTA mints the mediator's integration DID via a template render,
    /// rolls over an admin DID, and returns a [`ProvisionResult`] with
    /// keys, `did.jsonl`, authorization VC, and VTA trust bundle.
    FullSetup,
    /// Mediator brings its own integration DID (from the Did step); the
    /// VTA only issues an admin credential and an ACL row. The reply
    /// carries an admin DID + matching private key.
    AdminOnly,
    /// Pick up state the VTA admin already provisioned out-of-band.
    /// The VTA's own bootstrap (or an earlier admin run) created the
    /// context + mediator DID + keys; the wizard's job is to retrieve
    /// them sealed to its ephemeral keypair via the v1
    /// `sealed_transfer::BootstrapRequest` flow. No template render
    /// happens on the VTA — the bundle carries existing material as
    /// `SealedPayloadV1::ContextProvision`. Always offline (the v1
    /// request shape has no online transport equivalent).
    OfflineExport,
}

impl VtaIntent {
    /// Project this intent onto the SDK's intent enum. Returns `None`
    /// for [`VtaIntent::OfflineExport`] — that variant never reaches an
    /// SDK call (the offline sealed-handoff flow lives entirely in
    /// `crate::sealed_handoff`).
    pub fn to_sdk(self) -> Option<SdkVtaIntent> {
        match self {
            Self::FullSetup => Some(SdkVtaIntent::FullSetup),
            Self::AdminOnly => Some(SdkVtaIntent::AdminOnly),
            Self::OfflineExport => None,
        }
    }
}

/// How the request reaches the VTA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VtaTransport {
    /// Direct network interaction — DIDComm for `FullSetup`, or a
    /// verification check against the VTA for `AdminOnly` (the ACL row
    /// itself is created out-of-band via `pnm acl create`).
    Online,
    /// Sealed-bundle handoff. Wizard writes a request JSON to disk; the
    /// operator ships it to the VTA admin out-of-band, who responds with
    /// an armored bundle the wizard opens locally.
    Offline,
}

/// Unified reply from any of the transport-adapter combinations.
///
/// Downstream consumers switch on the variant instead of branching on
/// intent + transport separately. `Full` and `AdminOnly` mirror the
/// SDK's [`SdkVtaReply`] shape so a successful online run can be lifted
/// without re-shaping; `ContextExport` is the offline-only variant the
/// SDK does not represent.
#[derive(Clone, Debug)]
pub enum VtaReply {
    /// Full template-bootstrap reply. The VTA minted the mediator's
    /// integration DID, (optionally) rolled over an admin DID, and
    /// returned the complete trust bundle. Produced by FullSetup
    /// (online or offline-mint).
    Full(Box<ProvisionResult>),
    /// Admin-credential-only reply. The mediator keeps its own
    /// integration DID; the VTA supplied an admin identity the mediator
    /// authenticates as against the VTA's admin APIs.
    AdminOnly(AdminCredentialReply),
    /// Context-export reply. The VTA admin ran `vta contexts reprovision`
    /// against an existing context; the bundle carries the
    /// already-provisioned mediator DID + operational keys + admin
    /// credential. Produced exclusively by the OfflineExport intent.
    /// Boxed because [`ContextProvisionBundle`] is the largest variant.
    ContextExport(Box<ContextProvisionBundle>),
}

impl From<SdkVtaReply> for VtaReply {
    fn from(reply: SdkVtaReply) -> Self {
        match reply {
            SdkVtaReply::Full(p) => Self::Full(p),
            SdkVtaReply::AdminOnly(a) => Self::AdminOnly(a),
        }
    }
}
