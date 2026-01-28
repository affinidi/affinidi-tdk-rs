use affinidi_encoding::Codec;

use super::DIDMethod;
use crate::{
    DIDError,
    did_method::{
        identifier::validate_identifier_format,
        peer::{PeerNumAlgo, PeerPurpose},
    },
};

fn parse_key(identifier: &str) -> Result<DIDMethod, DIDError> {
    let (codec_value, key_bytes) = affinidi_encoding::decode_multikey_with_codec(identifier)
        .map_err(|e| DIDError::InvalidMethodSpecificId(format!("invalid did:key encoding: {e}")))?;

    let codec = Codec::from_u64(codec_value);

    if !codec.is_public() {
        return Err(DIDError::InvalidMethodSpecificId(format!(
            "unsupported did:key codec: 0x{codec_value:x}"
        )));
    }

    if let Some(expected_len) = codec.expected_key_length()
        && key_bytes.len() != expected_len
    {
        return Err(DIDError::InvalidMethodSpecificId(format!(
            "invalid key length for codec 0x{codec_value:x}: expected {expected_len}, got {}",
            key_bytes.len()
        )));
    }

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
            let key_id = &identifier[1..];
            let (codec_value, key_bytes) = affinidi_encoding::decode_multikey_with_codec(key_id)
                .map_err(|e| {
                    DIDError::InvalidMethodSpecificId(format!(
                        "invalid did:peer:0 key encoding: {e}"
                    ))
                })?;

            let codec = Codec::from_u64(codec_value);
            if !codec.is_public() {
                return Err(DIDError::InvalidMethodSpecificId(format!(
                    "unsupported did:peer:0 codec: 0x{codec_value:x}"
                )));
            }

            if let Some(expected_len) = codec.expected_key_length()
                && key_bytes.len() != expected_len
            {
                return Err(DIDError::InvalidMethodSpecificId(format!(
                    "invalid key length for did:peer:0: expected {expected_len}, got {}",
                    key_bytes.len()
                )));
            }
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
                    affinidi_encoding::decode_multikey_with_codec(key_data).map_err(|e| {
                        DIDError::InvalidMethodSpecificId(format!(
                            "invalid did:peer:2 key encoding: {e}"
                        ))
                    })?;
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
        other => Ok(DIDMethod::Other {
            method: other.to_string(),
            identifier: identifier.to_string(),
        }),
    }
}
