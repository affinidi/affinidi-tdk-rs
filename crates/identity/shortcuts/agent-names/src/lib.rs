/*!
 * Agent Names — human-memorable shortcuts that resolve to DIDs.
 *
 * A DID is unmemorable. An **agent name** is a URL whose path begins with `/@`
 * and which resolves to one:
 *
 * ```text
 * example.com/@alice
 * connect.me/@bob
 * names.somewhere.info/@john-smith
 * firstperson.network/@drummond/h2hsummit   # trailing path adds context
 * ```
 *
 * An agent name is **not** a DID method. It is a shortcut layer in front of DID
 * resolution, and the specification anticipates other shortcut kinds later.
 *
 * # Resolution is two-stage, and the second stage is the important one
 *
 * 1. The agent name URL redirects to a DID.
 * 2. The DID resolves to a DID Document as usual.
 * 3. **The document must claim the name back via `alsoKnownAs`.**
 *
 * Step 3 is mandatory, not advisory. Step 1 is served by the name's own web
 * server, so on its own it proves nothing — anyone can publish a redirect
 * pointing at somebody else's DID. Only the DID's controller can add an
 * `alsoKnownAs` entry, so requiring both directions is what makes the binding
 * real. See [`verify_also_known_as`].
 *
 * What that check does **not** buy you: it does not survive DNS poisoning or a
 * breach of the name's web server. Defending against those is Layer 2 (the
 * agent name credential), which this crate does not implement — the
 * [`AgentNameResolver`] trait is the seam where it would go.
 *
 * # Status: the redirect contract is not pinned down
 *
 * The agent name FAQ says resolution "typically works through a simple web
 * redirect" without specifying the status code, the form the DID arrives in, or
 * any content negotiation, and there is no reference implementation to check
 * against (`firstperson.network` is live, but its example names return 404).
 *
 * [`HttpRedirectResolver`] is therefore deliberately permissive, and all of that
 * guesswork is confined to it. The parsing, canonicalisation and verification
 * layers do not depend on how the DID was obtained, so pinning the contract down
 * later should not disturb them.
 *
 * # Usage
 *
 * ```no_run
 * # async fn run() -> Result<(), agent_names::AgentNameError> {
 * use agent_names::{AgentName, AgentNameResolver, HttpRedirectResolver};
 *
 * let name: AgentName = "example.com/@alice".parse()?;
 * let resolver = HttpRedirectResolver::new();
 *
 * // Stage 1: name -> DID
 * let did = resolver.resolve(&name).await
 *     .ok_or_else(|| agent_names::AgentNameError::Unresolvable(name.to_string()))??;
 *
 * // Stage 2: resolve `did` with your DID resolver, then:
 * // agent_names::verify_also_known_as(&document, &name)?;
 * # Ok(()) }
 * ```
 *
 * Callers generally should not drive those stages by hand — the unified
 * `resolve_any()` entry point on `DIDCacheClient` wires them together with the
 * resolution cache. This crate is the standalone, dependency-light half.
 */

pub mod error;
pub mod name;
pub mod resolver;
pub mod verify;

pub use error::AgentNameError;
pub use name::{AGENT_NAME_MARKER, AgentName};
pub use resolver::{
    AgentNameResolver, DEFAULT_MAX_HOPS, DEFAULT_TIMEOUT, HttpRedirectResolver, NameResolution,
};
pub use verify::{also_known_as_contains, extract_agent_names, verify_also_known_as};
