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

pub use error::{NetworkFetchError, ResolverError};
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
/// suitable for `Hash + Eq` keying. Derived from `DIDMethod` via `From`.
///
/// `#[non_exhaustive]` since 0.2.0, so a method can gain a typed variant
/// without another breaking release: a `match` needs a wildcard arm. A method
/// name with a typed variant always maps to it, never to
/// [`MethodName::Other`] (see [`MethodName::from_name`]).
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
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
    Ebsi,
    /// `did:webs` (KERI-backed did:web). Before 0.2.0 it was
    /// `Other("webs")`.
    Webs,
    /// Catch-all for methods not explicitly modeled.
    Other(String),
}

impl MethodName {
    /// The `MethodName` for a DID method name (`"key"`, `"webs"`, …): its
    /// typed variant when it has one, [`MethodName::Other`] otherwise.
    pub fn from_name(name: &str) -> Self {
        match name {
            "key" => MethodName::Key,
            "peer" => MethodName::Peer,
            "web" => MethodName::Web,
            "jwk" => MethodName::Jwk,
            "ethr" => MethodName::Ethr,
            "pkh" => MethodName::Pkh,
            "webvh" => MethodName::Webvh,
            "cheqd" => MethodName::Cheqd,
            "scid" => MethodName::Scid,
            "ebsi" => MethodName::Ebsi,
            "webs" => MethodName::Webs,
            method => MethodName::Other(method.to_string()),
        }
    }

    /// The same method with an [`MethodName::Other`] that names a typed
    /// method replaced by that typed variant, so `Other("webs")` is
    /// [`MethodName::Webs`]. Any other value is returned unchanged.
    ///
    /// A registry keyed by `MethodName` normalises its keys with this, so a
    /// caller that still names a method by its catch-all spelling reaches the
    /// same entry as the DIDs it resolves.
    pub fn canonical(self) -> Self {
        match self {
            MethodName::Other(name) => MethodName::from_name(&name),
            typed => typed,
        }
    }
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
            MethodName::Ebsi => write!(f, "ebsi"),
            MethodName::Webs => write!(f, "webs"),
            MethodName::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Convert `DIDMethod` (with data) to `MethodName` (pure discriminant).
impl From<&DIDMethod> for MethodName {
    fn from(method: &DIDMethod) -> Self {
        MethodName::from_name(method.name())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_webs_has_its_own_method_name() {
        let did: DID = "did:webs:example.com:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe"
            .parse()
            .expect("valid did:webs");
        assert_eq!(MethodName::from(&did.method()), MethodName::Webs);
        assert_eq!(MethodName::Webs.to_string(), "webs");
    }

    #[test]
    fn canonical_maps_a_catch_all_spelling_to_its_typed_variant() {
        assert_eq!(
            MethodName::Other("webs".to_string()).canonical(),
            MethodName::Webs
        );
        assert_eq!(
            MethodName::Other("key".to_string()).canonical(),
            MethodName::Key
        );
        assert_eq!(
            MethodName::Other("example".to_string()).canonical(),
            MethodName::Other("example".to_string())
        );
        assert_eq!(MethodName::Web.canonical(), MethodName::Web);
    }

    #[test]
    fn from_name_round_trips_through_display() {
        for name in [
            "key", "peer", "web", "jwk", "ethr", "pkh", "webvh", "cheqd", "scid", "ebsi", "webs",
            "example",
        ] {
            assert_eq!(MethodName::from_name(name).to_string(), name);
        }
    }
}
