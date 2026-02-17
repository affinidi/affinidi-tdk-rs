/*!
 * Pluggable DID resolution traits.
 *
 * Provides [`Resolver`] (sync) and [`AsyncResolver`] (async) traits for
 * decoupling DID resolution from concrete types. External consumers implement
 * these traits for custom DID methods; the SDK composes them with built-in
 * resolvers.
 *
 * Every [`Resolver`] is automatically an [`AsyncResolver`] via blanket impl,
 * so the SDK only needs `Vec<Box<dyn AsyncResolver>>` for composition.
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

use affinidi_did_common::{DID, Document};

/// Result type alias for resolver return values.
///
/// - `None`: this resolver does not handle the given DID method
/// - `Some(Ok(doc))`: resolved successfully
/// - `Some(Err(e))`: this resolver handles the method but resolution failed
pub type Resolution = Option<Result<Document, ResolverError>>;

/// Synchronous DID resolver for methods that require no IO.
///
/// Implement this for methods where resolution is pure computation
/// (e.g., `did:key`, `did:peer`). Every `Resolver` is automatically
/// an [`AsyncResolver`] via blanket impl.
pub trait Resolver: Send + Sync {
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
/// `Vec<Box<dyn AsyncResolver>>` for composition.
pub trait AsyncResolver: Send + Sync {
    /// Attempt to resolve the given DID to a Document.
    fn resolve(&self, did: &DID) -> Pin<Box<dyn Future<Output = Resolution> + Send + '_>>;
}

/// Every sync [`Resolver`] is automatically an [`AsyncResolver`].
impl<T: Resolver> AsyncResolver for T {
    fn resolve(&self, did: &DID) -> Pin<Box<dyn Future<Output = Resolution> + Send + '_>> {
        Box::pin(std::future::ready(Resolver::resolve(self, did)))
    }
}
