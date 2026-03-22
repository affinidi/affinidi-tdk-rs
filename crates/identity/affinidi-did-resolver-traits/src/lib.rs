/*!
 * Pluggable DID resolution traits.
 *
 * Provides [`Resolver`] (sync) and [`AsyncResolver`] (async) traits for
 * decoupling DID resolution from concrete types. External consumers implement
 * these traits for custom DID methods; the SDK composes them with built-in
 * resolvers.
 *
 * Every [`Resolver`] is automatically an [`AsyncResolver`] via blanket impl,
 * so the SDK only needs `Box<dyn AsyncResolver>` for composition.
 *
 * # Return Convention
 *
 * Resolvers return `Option<Result<Document, ResolverError>>`:
 * - `None` — "not my DID, pass to next resolver"
 * - `Some(Ok(doc))` — resolved successfully
 * - `Some(Err(e))` — recognized the DID but resolution failed
 */

use std::future::Future;
use std::pin::Pin;

mod error;
mod resolvers;

pub use error::ResolverError;
pub use resolvers::{KeyResolver, PeerResolver};

use affinidi_did_common::{DID, DIDMethod, Document};

/// Result type alias for resolver return values.
///
/// - `None`: this resolver does not handle the given DID method
/// - `Some(Ok(doc))`: resolved successfully
/// - `Some(Err(e))`: this resolver handles the method but resolution failed
pub type Resolution = Option<Result<Document, ResolverError>>;

/// Discriminant for DID method types — used as HashMap key for resolver dispatch.
///
/// Unlike `DIDMethod` (which carries parsed data), this is a pure tag type
/// suitable for `Hash + Eq` keying. Derived from `DIDMethod` via `From` impl
/// in the SDK crate.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum MethodName {
    Key,
    Peer,
    Web,
    Jwk,
    Ethr,
    Pkh,
    Webvh,
    Cheqd,
    Scid,
    /// Catch-all for methods not explicitly modeled.
    Other(String),
}

impl std::fmt::Display for MethodName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MethodName::Key => write!(f, "key"),
            MethodName::Peer => write!(f, "peer"),
            MethodName::Web => write!(f, "web"),
            MethodName::Jwk => write!(f, "jwk"),
            MethodName::Ethr => write!(f, "ethr"),
            MethodName::Pkh => write!(f, "pkh"),
            MethodName::Webvh => write!(f, "webvh"),
            MethodName::Cheqd => write!(f, "cheqd"),
            MethodName::Scid => write!(f, "scid"),
            MethodName::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Convert `DIDMethod` (with data) to `MethodName` (pure discriminant).
impl From<&DIDMethod> for MethodName {
    fn from(method: &DIDMethod) -> Self {
        match method {
            DIDMethod::Key { .. } => MethodName::Key,
            DIDMethod::Peer { .. } => MethodName::Peer,
            DIDMethod::Web { .. } => MethodName::Web,
            DIDMethod::Jwk { .. } => MethodName::Jwk,
            DIDMethod::Ethr { .. } => MethodName::Ethr,
            DIDMethod::Pkh { .. } => MethodName::Pkh,
            DIDMethod::Webvh { .. } => MethodName::Webvh,
            DIDMethod::Cheqd { .. } => MethodName::Cheqd,
            DIDMethod::Scid { .. } => MethodName::Scid,
            DIDMethod::Other { method, .. } => MethodName::Other(method.clone()),
            _ => MethodName::Other(format!("{method}")),
        }
    }
}

/// Synchronous DID resolver for methods that require no IO.
///
/// Implement this for methods where resolution is pure computation
/// (e.g., `did:key`, `did:peer`). Every `Resolver` is automatically
/// an [`AsyncResolver`] via blanket impl.
pub trait Resolver: Send + Sync {
    /// Human-readable name for this resolver (e.g., `"KeyResolver"`).
    ///
    /// Must be unique within a method's resolver chain. Used by
    /// `find_resolver()` to locate resolvers by name.
    fn name(&self) -> &str;

    /// Attempt to resolve the given DID to a Document.
    fn resolve(&self, did: &DID) -> Resolution;
}

/// Asynchronous DID resolver for methods that require IO.
///
/// Implement this directly for methods that need network access,
/// database lookups, or other async operations (e.g., `did:web`, `did:ethr`).
///
/// Sync resolvers get this for free via the blanket impl.
///
/// This trait is dyn-compatible: the SDK stores resolvers as
/// `Box<dyn AsyncResolver>` for composition.
pub trait AsyncResolver: Send + Sync {
    /// Human-readable name for this resolver (e.g., `"EthrResolver"`).
    ///
    /// Must be unique within a method's resolver chain. Used by
    /// `find_resolver()` to locate resolvers by name.
    fn name(&self) -> &str;

    /// Attempt to resolve the given DID to a Document.
    fn resolve<'a>(&'a self, did: &'a DID)
    -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>>;
}

/// Every sync [`Resolver`] is automatically an [`AsyncResolver`].
impl<T: Resolver> AsyncResolver for T {
    fn name(&self) -> &str {
        Resolver::name(self)
    }

    fn resolve<'a>(
        &'a self,
        did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(std::future::ready(Resolver::resolve(self, did)))
    }
}
