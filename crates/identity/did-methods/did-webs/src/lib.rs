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
 */

pub mod document;
pub mod errors;
pub mod fetch;
pub mod identifier;
pub mod kel;
pub mod resolver;

pub use errors::DidWebsError;
pub use fetch::{WebsResolver, resolve};
pub use identifier::{DID_JSON, DidWebs, KERI_CESR};
pub use kel::Kels;
pub use resolver::resolve_from_artifacts;
