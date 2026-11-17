use affinidi_encoding::Codec;

use super::DIDMethod;
use crate::{
    DIDError,
    did_method::{
        identifier::validate_identifier_format,
        peer::{PeerNumAlgo, PeerPurpose},
    },
};

/// Decode a multikey that must be a public key of its codec's length: the
/// rule did:key, and each key of a did:peer, is held to.
fn decode_public_multikey(key: &str, what: &str) -> Result<(Codec, Vec<u8>), DIDError> {
    let (codec, key_bytes) = affinidi_encoding::decode_multikey_checked(key)
        .map_err(|e| DIDError::InvalidMethodSpecificId(format!("invalid {what} key: {e}")))?;
    if !codec.is_public() {
        return Err(DIDError::InvalidMethodSpecificId(format!(
            "unsupported {what} codec: 0x{:x}",
            codec.to_u64()
        )));
    }
    Ok((codec, key_bytes))
}

fn parse_key(identifier: &str) -> Result<DIDMethod, DIDError> {
    let (codec, key_bytes) = decode_public_multikey(identifier, "did:key")?;

    Ok(DIDMethod::Key {
        identifier: identifier.to_string(),
        codec,
        key_bytes,
    })
}

fn parse_peer(identifier: &str) -> Result<DIDMethod, DIDError> {
    let first_char = identifier
        .chars()
        .next()
        .ok_or_else(|| DIDError::InvalidMethodSpecificId("empty peer DID".into()))?;

    let numalgo = PeerNumAlgo::from_char(first_char).ok_or_else(|| {
        DIDError::InvalidMethodSpecificId(format!("invalid peer numalgo: '{first_char}'"))
    })?;

    // Validate based on numalgo
    match numalgo {
        PeerNumAlgo::InceptionKey => {
            // Type 0: rest is a did:key identifier
            decode_public_multikey(&identifier[1..], "did:peer:0")?;
        }
        PeerNumAlgo::GenesisDoc => {
            return Err(DIDError::InvalidMethodSpecificId(
                "did:peer type 1 (genesis doc) is not supported".into(),
            ));
        }
        PeerNumAlgo::MultipleKeys => {
            // Type 2: validate structure
            if identifier.len() < 2 || !identifier[1..].starts_with('.') {
                return Err(DIDError::InvalidMethodSpecificId(
                    "did:peer:2 must have format 2.<parts>".into(),
                ));
            }

            let parts = identifier[2..].split('.');
            for part in parts {
                if part.is_empty() {
                    continue;
                }

                let purpose_char = part.chars().next().unwrap();
                let purpose = PeerPurpose::from_char(purpose_char).ok_or_else(|| {
                    DIDError::InvalidMethodSpecificId(format!(
                        "invalid did:peer:2 purpose code: '{purpose_char}'"
                    ))
                })?;

                if purpose.is_key() {
                    let key_data = &part[1..];
                    if key_data.is_empty() {
                        return Err(DIDError::InvalidMethodSpecificId(
                            "did:peer:2 key entry has no key data".into(),
                        ));
                    }
                    // The same rule as numalgo 0 and did:key: a public key
                    // of its codec's length.
                    decode_public_multikey(key_data, "did:peer:2")?;
                }
            }
        }
    }

    Ok(DIDMethod::Peer {
        identifier: identifier.to_string(),
        numalgo,
    })
}

fn parse_web(identifier: &str) -> Result<DIDMethod, DIDError> {
    // Split on colons: first part is domain, rest are path segments
    let segments: Vec<&str> = identifier.split(':').collect();
    let domain = segments.first().unwrap_or(&"").to_string();
    let path_segments = segments[1..].iter().map(|s| s.to_string()).collect();

    Ok(DIDMethod::Web {
        identifier: identifier.to_string(),
        domain,
        path_segments,
    })
}

/// `did:webs:<domain>[:<path>...]:<aid>`: at least a domain and an AID, no
/// empty label, and an AID that is plausibly a CESR primitive (four or more
/// characters of the base64url alphabet). This is a syntax check, not a
/// security one: the AID is proven by its key event log, which
/// `affinidi-did-webs` verifies. That crate also decodes and checks the
/// domain label as a host and optional port.
fn parse_webs(identifier: &str) -> Result<DIDMethod, DIDError> {
    let labels: Vec<&str> = identifier.split(':').collect();
    if labels.len() < 2 {
        return Err(DIDError::InvalidMethodSpecificId(
            "did:webs requires a host and a trailing AID".into(),
        ));
    }
    if labels.iter().any(|label| label.is_empty()) {
        return Err(DIDError::InvalidMethodSpecificId(
            "did:webs identifier contains an empty label".into(),
        ));
    }
    let (domain, aid) = (labels[0], labels[labels.len() - 1]);
    if aid.len() < 4 {
        return Err(DIDError::InvalidMethodSpecificId(format!(
            "did:webs AID is too short to be a CESR primitive: {aid:?}"
        )));
    }
    if !aid
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(DIDError::InvalidMethodSpecificId(format!(
            "did:webs AID has characters outside the CESR base64url alphabet: {aid:?}"
        )));
    }

    Ok(DIDMethod::Webs {
        identifier: identifier.to_string(),
        domain: domain.to_string(),
        path_segments: labels[1..labels.len() - 1]
            .iter()
            .map(|label| (*label).to_string())
            .collect(),
        aid: aid.to_string(),
    })
}

fn parse_pkh(identifier: &str) -> Result<DIDMethod, DIDError> {
    // Format: <chain_namespace>:<chain_reference>:<account_address>
    let segments: Vec<&str> = identifier.split(':').collect();
    if segments.len() < 3 {
        return Err(DIDError::InvalidMethodSpecificId(
            "did:pkh requires format <namespace>:<reference>:<address>".into(),
        ));
    }
    let chain_namespace = segments[0].to_string();
    let chain_reference = segments[1].to_string();
    let account_address = segments[2..].join(":");

    Ok(DIDMethod::Pkh {
        identifier: identifier.to_string(),
        chain_namespace,
        chain_reference,
        account_address,
    })
}

fn parse_webvh(identifier: &str) -> Result<DIDMethod, DIDError> {
    // Format: <scid>:<domain>:<path_segments>
    let segments: Vec<&str> = identifier.split(':').collect();
    if segments.len() < 2 {
        return Err(DIDError::InvalidMethodSpecificId(
            "did:webvh requires at least <scid>:<domain>".into(),
        ));
    }
    let scid = segments[0].to_string();
    let domain = segments[1].to_string();
    let path_segments = segments[2..].iter().map(|s| s.to_string()).collect();

    Ok(DIDMethod::Webvh {
        identifier: identifier.to_string(),
        scid,
        domain,
        path_segments,
    })
}

fn parse_cheqd(identifier: &str) -> Result<DIDMethod, DIDError> {
    // Format: <network>:<uuid>
    let segments: Vec<&str> = identifier.split(':').collect();
    if segments.len() < 2 {
        return Err(DIDError::InvalidMethodSpecificId(
            "did:cheqd requires format <network>:<uuid>".into(),
        ));
    }
    let network = segments[0].to_string();
    let uuid = segments[1..].join(":");

    Ok(DIDMethod::Cheqd {
        identifier: identifier.to_string(),
        network,
        uuid,
    })
}

fn parse_scid(identifier: &str) -> Result<DIDMethod, DIDError> {
    // Format: <underlying_method>:<version>:<scid>
    let segments: Vec<&str> = identifier.split(':').collect();
    if segments.len() < 3 {
        return Err(DIDError::InvalidMethodSpecificId(
            "did:scid requires format <method>:<version>:<scid>".into(),
        ));
    }
    let underlying_method = segments[0].to_string();
    let version = segments[1].to_string();
    let scid = segments[2..].join(":");

    Ok(DIDMethod::Scid {
        identifier: identifier.to_string(),
        underlying_method,
        version,
        scid,
    })
}

fn parse_ebsi(identifier: &str) -> Result<DIDMethod, DIDError> {
    // EBSI identifiers must start with 'z' (base58btc multibase prefix)
    // and decode to version_byte (0x01) + 16 random bytes = 17 bytes
    if !identifier.starts_with('z') {
        return Err(DIDError::InvalidMethodSpecificId(
            "did:ebsi identifier must start with 'z' (base58btc)".into(),
        ));
    }

    // Validate the base58btc content (21-22 chars after 'z')
    let b58_content = &identifier[1..];
    if b58_content.len() < 21 || b58_content.len() > 23 {
        return Err(DIDError::InvalidMethodSpecificId(format!(
            "did:ebsi identifier has invalid length: {} (expected 22-24 total)",
            identifier.len()
        )));
    }

    Ok(DIDMethod::Ebsi {
        identifier: identifier.to_string(),
    })
}

/// Parse method name and identifier into a rich DIDMethod variant
pub fn parse_method(method_name: &str, identifier: &str) -> Result<DIDMethod, DIDError> {
    // First validate basic identifier format (common to all methods)
    validate_identifier_format(identifier)?;

    match method_name {
        "key" => parse_key(identifier),
        "peer" => parse_peer(identifier),
        "web" => parse_web(identifier),
        "jwk" => Ok(DIDMethod::Jwk {
            identifier: identifier.to_string(),
        }),
        "ethr" => Ok(DIDMethod::Ethr {
            identifier: identifier.to_string(),
        }),
        "pkh" => parse_pkh(identifier),
        "webvh" => parse_webvh(identifier),
        "cheqd" => parse_cheqd(identifier),
        "scid" => parse_scid(identifier),
        "ebsi" => parse_ebsi(identifier),
        "webs" => parse_webs(identifier),
        other => Ok(DIDMethod::Other {
            method: other.to_string(),
            identifier: identifier.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use crate::DID;

    const ED25519: &str = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    const AID: &str = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";

    #[test]
    fn webs_parses_domain_path_and_aid() {
        let did: DID = format!("did:webs:example.com%3A3000:dids:alice:{AID}")
            .parse()
            .unwrap();
        match did.method() {
            crate::DIDMethod::Webs {
                identifier,
                domain,
                path_segments,
                aid,
            } => {
                assert_eq!(identifier, format!("example.com%3A3000:dids:alice:{AID}"));
                assert_eq!(domain, "example.com%3A3000");
                assert_eq!(path_segments, vec!["dids", "alice"]);
                assert_eq!(aid, AID);
            }
            other => panic!("expected DIDMethod::Webs, got {other:?}"),
        }

        let did: DID = format!("did:webs:example.com:{AID}").parse().unwrap();
        assert!(matches!(
            did.method(),
            crate::DIDMethod::Webs { path_segments, .. } if path_segments.is_empty()
        ));
    }

    #[test]
    fn webs_refuses_a_missing_or_malformed_aid() {
        for did in [
            "did:webs:example.com".to_string(),
            format!("did:webs:example.com::{AID}"),
            "did:webs:example.com:EAb".to_string(),
            "did:webs:example.com:EA.b-c".to_string(),
        ] {
            assert!(did.parse::<DID>().is_err(), "{did} should not parse");
        }
    }

    #[test]
    fn peer_2_refuses_a_private_key() {
        let private = affinidi_encoding::encode_multikey(affinidi_encoding::ED25519_PRIV, &[7; 32]);
        let err = format!("did:peer:2.V{private}")
            .parse::<DID>()
            .expect_err("a private key");
        assert!(err.to_string().contains("codec"), "{err}");
    }

    #[test]
    fn peer_2_refuses_a_key_of_the_wrong_length() {
        let short = affinidi_encoding::encode_multikey(affinidi_encoding::ED25519_PUB, &[7; 31]);
        assert!(format!("did:peer:2.V{short}").parse::<DID>().is_err());
        let p256_uncompressed =
            affinidi_encoding::encode_multikey(affinidi_encoding::P256_PUB, &[4; 65]);
        assert!(
            format!("did:peer:2.V{p256_uncompressed}")
                .parse::<DID>()
                .is_err()
        );
    }

    #[test]
    fn peer_2_accepts_public_keys_of_their_length() {
        assert!(format!("did:peer:2.V{ED25519}").parse::<DID>().is_ok());
    }
}
