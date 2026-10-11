/*!
 * OpenID4VP 1.0 client identifiers and their prefixes (§5.9).
 *
 * A verifier's `client_id` carries a prefix naming how the wallet is to
 * authenticate it: `decentralized_identifier:<did>` (the request object is
 * signed by a key of that DID), `x509_hash:<b64url SHA-256 of the leaf
 * certificate DER>` and `x509_san_dns:<dns name>` (signed by the key of an
 * `x5c` certificate), `redirect_uri:<uri>` (unsigned), and others. The full
 * string, prefix included, is what the wallet's key-binding JWT names as its
 * audience — so a verifier compares against the whole thing, never the value
 * after the colon.
 */

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use crate::error::Oid4vpError;

/// A client identifier prefix (OpenID4VP 1.0 §5.9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientIdPrefix {
    /// `decentralized_identifier` — the value is a DID.
    DecentralizedIdentifier,
    /// `x509_hash` — the value is the base64url SHA-256 of the leaf
    /// certificate's DER.
    X509Hash,
    /// `x509_san_dns` — the value is a DNS name in the leaf certificate's SAN.
    X509SanDns,
    /// `redirect_uri` — the value is the redirect or response URI; the request
    /// is unsigned.
    RedirectUri,
    /// `verifier_attestation` — authenticated by a Verifier Attestation JWT.
    VerifierAttestation,
    /// `openid_federation` — the value is an OpenID Federation entity id.
    OpenidFederation,
    /// `origin` — reserved for the Digital Credentials API.
    Origin,
}

impl ClientIdPrefix {
    /// The prefix as written before the `:`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DecentralizedIdentifier => "decentralized_identifier",
            Self::X509Hash => "x509_hash",
            Self::X509SanDns => "x509_san_dns",
            Self::RedirectUri => "redirect_uri",
            Self::VerifierAttestation => "verifier_attestation",
            Self::OpenidFederation => "openid_federation",
            Self::Origin => "origin",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "decentralized_identifier" => Self::DecentralizedIdentifier,
            "x509_hash" => Self::X509Hash,
            "x509_san_dns" => Self::X509SanDns,
            "redirect_uri" => Self::RedirectUri,
            "verifier_attestation" => Self::VerifierAttestation,
            "openid_federation" => Self::OpenidFederation,
            "origin" => Self::Origin,
            _ => return None,
        })
    }
}

/// A verifier's client identifier: a prefix and its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientId {
    prefix: ClientIdPrefix,
    value: String,
}

impl ClientId {
    /// `decentralized_identifier:<did>`.
    pub fn decentralized_identifier(did: &str) -> Result<Self, Oid4vpError> {
        if !did.starts_with("did:") || did.contains('#') {
            return Err(Oid4vpError::InvalidRequest(format!(
                "`{did}` is not a DID (without a fragment)"
            )));
        }
        Ok(Self {
            prefix: ClientIdPrefix::DecentralizedIdentifier,
            value: did.to_string(),
        })
    }

    /// `x509_hash:<hash>`, computed from the DER of the leaf certificate whose
    /// key signs the request object (the first entry of its `x5c`).
    pub fn x509_hash(leaf_certificate_der: &[u8]) -> Self {
        Self {
            prefix: ClientIdPrefix::X509Hash,
            value: URL_SAFE_NO_PAD.encode(Sha256::digest(leaf_certificate_der)),
        }
    }

    /// `x509_san_dns:<dns name>`.
    pub fn x509_san_dns(dns_name: &str) -> Self {
        Self {
            prefix: ClientIdPrefix::X509SanDns,
            value: dns_name.to_string(),
        }
    }

    /// Parse a `client_id` string. A string with no recognised prefix is
    /// refused rather than guessed at: OpenID4VP reads an unprefixed identifier
    /// as one the wallet already knows (pre-registered), which a verifier that
    /// builds its own identifiers has no use for.
    pub fn parse(client_id: &str) -> Result<Self, Oid4vpError> {
        let (prefix, value) = client_id
            .split_once(':')
            .and_then(|(p, v)| ClientIdPrefix::parse(p).map(|p| (p, v)))
            .ok_or_else(|| {
                Oid4vpError::InvalidRequest(format!(
                    "client_id `{client_id}` has no recognised prefix"
                ))
            })?;
        if value.is_empty() {
            return Err(Oid4vpError::InvalidRequest(format!(
                "client_id `{client_id}` has an empty value"
            )));
        }
        Ok(Self {
            prefix,
            value: value.to_string(),
        })
    }

    /// The prefix.
    pub fn prefix(&self) -> &ClientIdPrefix {
        &self.prefix
    }

    /// The value after the prefix.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Whether `leaf_certificate_der` is the certificate an `x509_hash`
    /// identifier names. Always false for any other prefix.
    pub fn matches_x509_leaf(&self, leaf_certificate_der: &[u8]) -> bool {
        self.prefix == ClientIdPrefix::X509Hash
            && self.value == URL_SAFE_NO_PAD.encode(Sha256::digest(leaf_certificate_der))
    }
}

impl std::fmt::Display for ClientId {
    /// The full identifier, prefix included — the key-binding JWT's audience.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.prefix.as_str(), self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_did_client_id_round_trips() {
        let id = ClientId::decentralized_identifier("did:webvh:Qm123:verifier.example").unwrap();
        let s = id.to_string();
        assert_eq!(
            s,
            "decentralized_identifier:did:webvh:Qm123:verifier.example"
        );
        assert_eq!(ClientId::parse(&s).unwrap(), id);
        assert_eq!(id.value(), "did:webvh:Qm123:verifier.example");
    }

    #[test]
    fn a_did_with_a_fragment_or_a_non_did_is_refused() {
        assert!(ClientId::decentralized_identifier("did:web:v.example#key-1").is_err());
        assert!(ClientId::decentralized_identifier("https://v.example").is_err());
    }

    /// The hash is the base64url SHA-256 of the DER, and only that certificate
    /// matches it.
    #[test]
    fn x509_hash_names_exactly_its_certificate() {
        let der = b"not really DER, but the hash does not care";
        let id = ClientId::x509_hash(der);
        assert_eq!(
            id.value(),
            URL_SAFE_NO_PAD.encode(Sha256::digest(der)).as_str()
        );
        assert!(id.to_string().starts_with("x509_hash:"));
        assert!(id.matches_x509_leaf(der));
        assert!(!id.matches_x509_leaf(b"another certificate"));
        assert!(!ClientId::x509_san_dns("v.example").matches_x509_leaf(der));
    }

    #[test]
    fn an_unprefixed_or_empty_client_id_is_refused() {
        assert!(ClientId::parse("did:web:v.example").is_err());
        assert!(ClientId::parse("https://v.example/cb").is_err());
        assert!(ClientId::parse("x509_hash:").is_err());
    }
}
