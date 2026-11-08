/*! Implementation of the `did:webs` DID method.
 *
 * `did:webs` is `did:web` discovery with KERI-verified key state: the DID's
 * last label is a KERI **AID**, and the DID document is *derived* from a key
 * event log fetched alongside it rather than trusted as published.
 *
 * ```text
 * https://<host>/<path>/<AID>/did.json     the document, as a cache
 * https://<host>/<path>/<AID>/keri.cesr    the key event log it must match
 * ```
 *
 * All of the method's security lives in verifying that KEL. A published
 * `did.json` carries no authority on its own — it is checked against the
 * document derived from the verified key state, and a disagreement is an
 * error rather than a preference for one or the other.
 *
 * What the key state cannot express — key agreement keys, and services of
 * types KERI's endpoint data cannot carry — the AID adds by designation: an
 * ACDC it issues to itself and anchors in its KEL ([`key_agreement`],
 * [`designated_services`](mod@designated_services)).
 */

#[cfg(feature = "create")]
pub mod artifacts;
#[cfg(feature = "create")]
pub(crate) mod attestation;
#[cfg(feature = "create")]
pub mod create;
#[cfg(feature = "create")]
pub mod custody;
#[cfg(feature = "create")]
pub mod endpoints;
#[cfg(feature = "create")]
pub mod update;

pub mod aliases;
pub mod designated_services;
pub(crate) mod designation;
pub mod document;
pub mod errors;
pub mod fetch;
pub mod identifier;
pub mod kel;
pub mod key_agreement;
pub mod resolver;
pub mod services;

pub use aliases::{DesignatedAliases, designated_aliases};
#[cfg(feature = "create")]
pub use artifacts::Artifacts;
#[cfg(feature = "create")]
pub use create::{CreateConfig, CreateResult, SelfEndpoint, create};
#[cfg(feature = "create")]
pub use custody::KeyCustody;
pub use designated_services::{DesignatedService, DesignatedServices, designated_services};
pub use errors::DidWebsError;
pub use fetch::{HostPolicy, WebsResolver, resolve};
pub use identifier::{DID_JSON, DidWebs, KERI_CESR};
pub use kel::Kels;
pub use key_agreement::{DesignatedKeys, KeyAgreementKey, designated_key_agreement};
pub use resolver::{DocumentMetadata, Resolution, resolve_from_artifacts, resolve_with_metadata};
pub use services::{ServiceEndpoint, delegator_service, service_endpoints};
#[cfg(feature = "create")]
pub use update::{Change, UpdateConfig, UpdateResult, update};
