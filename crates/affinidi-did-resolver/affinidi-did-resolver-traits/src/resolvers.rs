//! Built-in resolver implementations for locally-resolvable DID methods.

use affinidi_did_common::{DID, DIDMethod, DocumentExt};

use crate::{Resolution, Resolver, ResolverError};

/// Resolver for `did:key` — derives DID Documents from public key material.
///
/// Resolution is pure computation (no IO). Supports Ed25519, P-256, P-384,
/// secp256k1, and X25519 key types.
pub struct KeyResolver;

impl Resolver for KeyResolver {
    fn name(&self) -> &str {
        "KeyResolver"
    }

    fn resolve(&self, did: &DID) -> Resolution {
        match did.method() {
            DIDMethod::Key { .. } => Some(did.resolve().map_err(ResolverError::from)),
            _ => None,
        }
    }
}

/// Resolver for `did:peer` — derives DID Documents from peer DID encoding.
///
/// Resolution is pure computation (no IO). Supports numalgo 0 (inception key)
/// and numalgo 2 (multiple keys + services).
pub struct PeerResolver;

impl Resolver for PeerResolver {
    fn name(&self) -> &str {
        "PeerResolver"
    }

    fn resolve(&self, did: &DID) -> Resolution {
        match did.method() {
            DIDMethod::Peer { .. } => Some(
                did.resolve()
                    .map_err(ResolverError::from)
                    .and_then(|doc| doc.expand_peer_keys().map_err(ResolverError::from)),
            ),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AsyncResolver;

    // --- KeyResolver (sync) ---

    #[test]
    fn key_resolver_resolves_ed25519() {
        let did: DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();
        let result = Resolver::resolve(&KeyResolver, &did);
        assert!(result.is_some());
        let doc = result.unwrap().unwrap();
        assert_eq!(
            doc.id.as_str(),
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
        // Ed25519 derives both Ed25519 + X25519 verification methods
        assert_eq!(doc.verification_method.len(), 2);
        assert_eq!(doc.key_agreement.len(), 1);
    }

    #[test]
    fn key_resolver_resolves_p256() {
        let did: DID = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"
            .parse()
            .unwrap();
        let result = Resolver::resolve(&KeyResolver, &did);
        assert!(result.is_some());
        let doc = result.unwrap().unwrap();
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.key_agreement.len(), 1);
    }

    #[test]
    fn key_resolver_returns_none_for_peer() {
        let did: DID = "did:peer:0z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();
        assert!(Resolver::resolve(&KeyResolver, &did).is_none());
    }

    #[test]
    fn key_resolver_returns_none_for_web() {
        let did: DID = "did:web:example.com".parse().unwrap();
        assert!(Resolver::resolve(&KeyResolver, &did).is_none());
    }

    // --- PeerResolver (sync) ---

    #[test]
    fn peer_resolver_resolves_numalgo_0() {
        let did: DID = "did:peer:0z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();
        let result = Resolver::resolve(&PeerResolver, &did);
        assert!(result.is_some());
        let doc = result.unwrap().unwrap();
        // Numalgo 0 wraps did:key — Ed25519 has 2 VMs
        assert_eq!(doc.verification_method.len(), 2);
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.key_agreement.len(), 1);
    }

    #[test]
    fn peer_resolver_resolves_numalgo_2() {
        let did: DID = "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"
            .parse()
            .unwrap();
        let result = Resolver::resolve(&PeerResolver, &did);
        assert!(result.is_some());
        let doc = result.unwrap().unwrap();
        assert_eq!(doc.verification_method.len(), 2);
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.assertion_method.len(), 1);
        assert_eq!(doc.key_agreement.len(), 1);
    }

    #[test]
    fn peer_resolver_resolves_numalgo_2_with_service() {
        let did: DID = "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9kaWRjb21tIn0"
            .parse()
            .unwrap();
        let result = Resolver::resolve(&PeerResolver, &did);
        assert!(result.is_some());
        let doc = result.unwrap().unwrap();
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.service.len(), 1);
    }

    #[test]
    fn peer_resolver_returns_none_for_key() {
        let did: DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();
        assert!(Resolver::resolve(&PeerResolver, &did).is_none());
    }

    // --- Blanket AsyncResolver impl ---

    #[tokio::test]
    async fn key_resolver_works_as_async() {
        let did: DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();
        // Use KeyResolver through AsyncResolver trait (dyn-compatible)
        let resolver: Box<dyn AsyncResolver> = Box::new(KeyResolver);
        let result = resolver.resolve(&did).await;
        assert!(result.is_some());
        let doc = result.unwrap().unwrap();
        assert_eq!(
            doc.id.as_str(),
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
    }

    #[tokio::test]
    async fn peer_resolver_works_as_async() {
        let did: DID = "did:peer:0z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();
        let resolver: Box<dyn AsyncResolver> = Box::new(PeerResolver);
        let result = resolver.resolve(&did).await;
        assert!(result.is_some());
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn resolver_composition_finds_first_match() {
        let resolvers: Vec<Box<dyn AsyncResolver>> =
            vec![Box::new(KeyResolver), Box::new(PeerResolver)];

        let did: DID = "did:peer:0z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();

        let mut resolved: Resolution = None;
        for resolver in &resolvers {
            if let Some(result) = resolver.resolve(&did).await {
                resolved = Some(result);
                break;
            }
        }
        assert!(resolved.is_some());
        assert!(resolved.unwrap().is_ok());
    }

    #[tokio::test]
    async fn resolver_composition_returns_none_for_unknown() {
        let resolvers: Vec<Box<dyn AsyncResolver>> =
            vec![Box::new(KeyResolver), Box::new(PeerResolver)];

        let did: DID = "did:web:example.com".parse().unwrap();

        let mut resolved: Resolution = None;
        for resolver in &resolvers {
            if let Some(result) = resolver.resolve(&did).await {
                resolved = Some(result);
                break;
            }
        }
        assert!(resolved.is_none());
    }
}
