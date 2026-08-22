/*!
 * did:pkh — Public Key Hash DID method resolver.
 *
 * Implements resolution of `did:pkh` identifiers per the
 * [did:pkh method draft](https://github.com/w3c-ccg/did-pkh/blob/main/did-pkh-method-draft.md).
 *
 * # DID Format
 *
 * The current form names a [CAIP-10](https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-10.md)
 * account:
 *
 * ```text
 * did:pkh:{chain-namespace}:{chain-reference}:{account-address}
 * ```
 *
 * Supported namespaces are `tezos`, `eip155`, `bip122`, `solana` and `aleo`.
 * A set of deprecated single-token prefixes (`tz`, `eth`, `celo`, `poly`,
 * `sol`, `btc`, `doge`) is still resolved, each pinned to its mainnet.
 *
 * Resolution is a pure derivation from the identifier: no network access, no
 * chain state. The document describes the account the DID names, and nothing
 * about what that account currently holds.
 *
 * # Why this crate exists
 *
 * The spruceid `did-pkh` crate reaches the rest of the `ssi-*` stack, which
 * pulls `im`, `sized-chunks`, `bitmaps`, `smallstr` and `proc-macro-error` —
 * all unmaintained and archived upstream with no fixed release — plus
 * `reqwest 0.11` and the vulnerable `h2 0.3.x`. Most of that weight is JSON-LD
 * `@context` machinery, which our `Document` carries as plain JSON. See the
 * sibling `affinidi-did-ethr` crate for the full rationale.
 *
 * Every document this crate emits is checked byte-for-byte against the
 * fixtures from the crate it replaced — see `tests/`.
 *
 * # Usage
 *
 * ```
 * # fn main() -> Result<(), affinidi_did_pkh::DidPkhError> {
 * let doc = affinidi_did_pkh::resolve("did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a")?;
 * assert_eq!(doc.verification_method.len(), 1);
 * # Ok(()) }
 * ```
 */

use affinidi_did_common::verification_method::VerificationMethod;
use affinidi_did_common::{DocumentBuilder, VerificationMethodBuilder};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use affinidi_did_common::Document;

/// did:pkh resolver errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DidPkhError {
    /// The supplied string was not a `did:pkh` DID.
    #[error("not a did:pkh DID: {0}")]
    NotPkh(String),

    /// The identifier was not a CAIP-10 account id or a known legacy prefix.
    #[error("invalid did:pkh method-specific id: {0}")]
    InvalidIdentifier(String),

    /// The chain namespace is not one this resolver knows how to describe.
    ///
    /// Refused rather than resolved generically: a document naming a chain we
    /// cannot pick verification-method types for would assert key material
    /// semantics we have not established.
    #[error("unsupported did:pkh chain namespace: {0}")]
    UnsupportedNamespace(String),

    /// The account address is not valid for its chain namespace.
    #[error("invalid {namespace} account address: {address}")]
    InvalidAddress {
        /// CAIP-2 chain namespace the address was checked against.
        namespace: &'static str,
        /// The offending address.
        address: String,
    },

    /// The DID could not be expressed as a document (unparseable as a URL).
    #[error("did:pkh document could not be built: {0}")]
    InvalidDocument(String),
}

// Mainnet references for the deprecated single-token prefixes.
// CAIP-3 / CAIP-4 / CAIP-26 / CAIP-30 respectively.
const REFERENCE_EIP155_ETHEREUM_MAINNET: &str = "1";
const REFERENCE_EIP155_CELO_MAINNET: &str = "42220";
const REFERENCE_EIP155_POLYGON_MAINNET: &str = "137";
const REFERENCE_BIP122_BITCOIN_MAINNET: &str = "000000000019d6689c085ae165831e93";
const REFERENCE_BIP122_DOGECOIN_MAINNET: &str = "1a91e3dace36e2be3bf030a65679fe82";
const REFERENCE_TEZOS_MAINNET: &str = "NetXdQprcVkpaWU";
const REFERENCE_SOLANA_MAINNET: &str = "4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ";

const IRI_BLOCKCHAIN_ACCOUNT_ID: &str = "https://w3id.org/security#blockchainAccountId";
const IRI_PUBLIC_KEY_JWK: &str = "https://w3id.org/security#publicKeyJwk";
const IRI_PUBLIC_KEY_BASE58: &str = "https://w3id.org/security#publicKeyBase58";
const IRI_RECOVERY_2020: &str = "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020";
const CONTEXT_BLOCKCHAIN_2021_V1: &str = "https://w3id.org/security/suites/blockchain-2021/v1";
const CONTEXT_DID_V1: &str = "https://www.w3.org/ns/did/v1";

/// A `w3id.org/security#` term IRI for a verification-method type name.
fn security_iri(name: &str) -> String {
    format!("https://w3id.org/security#{name}")
}

/// Resolve a `did:pkh` DID into its DID Document.
pub fn resolve(did: &str) -> Result<Document, DidPkhError> {
    let identifier = did
        .strip_prefix("did:pkh:")
        .ok_or_else(|| DidPkhError::NotPkh(did.to_string()))?;
    resolve_identifier(identifier)
}

/// Resolve the method-specific identifier of a `did:pkh` DID — everything after
/// `did:pkh:` — into its DID Document.
pub fn resolve_identifier(identifier: &str) -> Result<Document, DidPkhError> {
    let (prefix, rest) = identifier
        .split_once(':')
        .ok_or_else(|| DidPkhError::InvalidIdentifier(identifier.to_string()))?;

    let did = format!("did:pkh:{identifier}");

    // The deprecated prefixes name a chain outright; everything else is read as
    // a CAIP-10 account id.
    match prefix {
        "tz" => tezos(&did, rest, REFERENCE_TEZOS_MAINNET),
        "eth" => eip155(&did, rest, REFERENCE_EIP155_ETHEREUM_MAINNET, true),
        "celo" => eip155(&did, rest, REFERENCE_EIP155_CELO_MAINNET, true),
        "poly" => eip155(&did, rest, REFERENCE_EIP155_POLYGON_MAINNET, true),
        "sol" => solana(&did, rest, REFERENCE_SOLANA_MAINNET),
        "btc" => bip122(&did, rest, REFERENCE_BIP122_BITCOIN_MAINNET),
        "doge" => bip122(&did, rest, REFERENCE_BIP122_DOGECOIN_MAINNET),
        _ => caip10(&did, identifier),
    }
}

/// Resolve a CAIP-10 `namespace:reference:address` account id.
fn caip10(did: &str, account_id: &str) -> Result<Document, DidPkhError> {
    let mut parts = account_id.splitn(3, ':');
    let namespace = parts.next().unwrap_or_default();
    let reference = parts
        .next()
        .ok_or_else(|| DidPkhError::InvalidIdentifier(account_id.to_string()))?;
    let address = parts
        .next()
        .ok_or_else(|| DidPkhError::InvalidIdentifier(account_id.to_string()))?;

    // CAIP-2 / CAIP-10 grammar. Enforced so a malformed account id is refused
    // here rather than copied into `blockchainAccountId`, where it would read
    // as a real account to every consumer of the document.
    let valid_namespace = (3..=8).contains(&namespace.len())
        && namespace
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    let valid_reference = (1..=32).contains(&reference.len())
        && reference
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    let valid_address = (1..=128).contains(&address.len())
        && address
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '%'));
    if !valid_namespace || !valid_reference || !valid_address {
        return Err(DidPkhError::InvalidIdentifier(account_id.to_string()));
    }

    match namespace {
        "tezos" => tezos(did, address, reference),
        "eip155" => eip155(did, address, reference, false),
        "bip122" => bip122(did, address, reference),
        "solana" => solana(did, address, reference),
        "aleo" => aleo(did, address, reference),
        other => Err(DidPkhError::UnsupportedNamespace(other.to_string())),
    }
}

/// Tezos accounts: the `tz1`/`tz2`/`tz3` prefix selects the key algorithm, and
/// so the verification-method type.
fn tezos(did: &str, address: &str, reference: &str) -> Result<Document, DidPkhError> {
    let invalid = || DidPkhError::InvalidAddress {
        namespace: "tezos",
        address: address.to_string(),
    };

    let key_type = match address.get(0..3) {
        Some("tz1") => "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
        Some("tz2") => "EcdsaSecp256k1RecoveryMethod2020",
        Some("tz3") => "P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
        _ => return Err(invalid()),
    };
    require_base58check(address, 27).ok_or_else(invalid)?;

    let account = format!("tezos:{reference}:{address}");
    let type_iri = if key_type == "EcdsaSecp256k1RecoveryMethod2020" {
        IRI_RECOVERY_2020.to_string()
    } else {
        security_iri(key_type)
    };

    build(
        did,
        json!([
            CONTEXT_DID_V1,
            {
                "blockchainAccountId": IRI_BLOCKCHAIN_ACCOUNT_ID,
                key_type: type_iri,
                "TezosMethod2021": security_iri("TezosMethod2021"),
            }
        ]),
        vec![
            account_method(did, "blockchainAccountId", key_type, &account, None)?,
            account_method(did, "TezosMethod2021", "TezosMethod2021", &account, None)?,
        ],
    )
}

/// EIP-155 (Ethereum and friends) accounts.
///
/// `legacy` selects the verification-method fragment: the deprecated `eth` /
/// `celo` / `poly` prefixes use `#Recovery2020`, CAIP-10 uses
/// `#blockchainAccountId` (see spruceid/ssi#297).
fn eip155(
    did: &str,
    address: &str,
    reference: &str,
    legacy: bool,
) -> Result<Document, DidPkhError> {
    // Upstream checked only for a `0x` prefix, so a non-hex "address" resolved
    // to a document naming an account that cannot exist. Validate it properly.
    let hex_body = address
        .strip_prefix("0x")
        .filter(|body| body.len() == 40 && body.chars().all(|c| c.is_ascii_hexdigit()));
    if hex_body.is_none() {
        return Err(DidPkhError::InvalidAddress {
            namespace: "eip155",
            address: address.to_string(),
        });
    }

    let account = format!("eip155:{reference}:{address}");
    let fragment = if legacy {
        "Recovery2020"
    } else {
        "blockchainAccountId"
    };

    build(
        did,
        json!([
            CONTEXT_DID_V1,
            {
                "blockchainAccountId": IRI_BLOCKCHAIN_ACCOUNT_ID,
                "EcdsaSecp256k1RecoveryMethod2020": IRI_RECOVERY_2020,
            }
        ]),
        vec![account_method(
            did,
            fragment,
            "EcdsaSecp256k1RecoveryMethod2020",
            &account,
            None,
        )?],
    )
}

/// BIP-122 (Bitcoin-family) accounts.
fn bip122(did: &str, address: &str, reference: &str) -> Result<Document, DidPkhError> {
    // Only the two chains whose address prefix we know are checked; an
    // unrecognised chain reference carries no prefix expectation.
    let expected_prefix = match reference {
        REFERENCE_BIP122_BITCOIN_MAINNET => Some('1'),
        REFERENCE_BIP122_DOGECOIN_MAINNET => Some('D'),
        _ => None,
    };
    if let Some(prefix) = expected_prefix
        && !address.starts_with(prefix)
    {
        return Err(DidPkhError::InvalidAddress {
            namespace: "bip122",
            address: address.to_string(),
        });
    }

    let account = format!("bip122:{reference}:{address}");

    build(
        did,
        json!([
            CONTEXT_DID_V1,
            {
                "blockchainAccountId": IRI_BLOCKCHAIN_ACCOUNT_ID,
                "EcdsaSecp256k1RecoveryMethod2020": IRI_RECOVERY_2020,
            }
        ]),
        vec![account_method(
            did,
            "blockchainAccountId",
            "EcdsaSecp256k1RecoveryMethod2020",
            &account,
            None,
        )?],
    )
}

/// Solana accounts. The address *is* the Ed25519 public key, so unlike the
/// other namespaces the document can carry real key material.
fn solana(did: &str, address: &str, reference: &str) -> Result<Document, DidPkhError> {
    let key_bytes = bs58::decode(address)
        .into_vec()
        .ok()
        .filter(|bytes| bytes.len() == 32)
        .ok_or_else(|| DidPkhError::InvalidAddress {
            namespace: "solana",
            address: address.to_string(),
        })?;

    let account = format!("solana:{reference}:{address}");

    build(
        did,
        json!([
            CONTEXT_DID_V1,
            {
                "blockchainAccountId": IRI_BLOCKCHAIN_ACCOUNT_ID,
                "publicKeyBase58": IRI_PUBLIC_KEY_BASE58,
                "publicKeyJwk": {
                    "@id": IRI_PUBLIC_KEY_JWK,
                    "@type": "@json",
                },
                "Ed25519VerificationKey2018": security_iri("Ed25519VerificationKey2018"),
                "SolanaMethod2021": security_iri("SolanaMethod2021"),
            }
        ]),
        vec![
            account_method(
                did,
                "controller",
                "Ed25519VerificationKey2018",
                &account,
                Some(("publicKeyBase58", json!(address))),
            )?,
            account_method(
                did,
                "SolanaMethod2021",
                "SolanaMethod2021",
                &account,
                Some((
                    "publicKeyJwk",
                    json!({
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": BASE64_URL_SAFE_NO_PAD.encode(&key_bytes),
                    }),
                )),
            )?,
        ],
    )
}

/// Aleo accounts. Validated as bech32 with the `aleo` human-readable part; the
/// decoded payload is used for validation only, never published.
fn aleo(did: &str, address: &str, reference: &str) -> Result<Document, DidPkhError> {
    let invalid = || DidPkhError::InvalidAddress {
        namespace: "aleo",
        address: address.to_string(),
    };

    let (hrp, data) = bech32::decode(address).map_err(|_| invalid())?;
    if hrp.as_str() != "aleo" || data.len() != 32 {
        return Err(invalid());
    }

    let account = format!("aleo:{reference}:{address}");

    // The blockchain-2021 context already defines `BlockchainVerificationMethod2021`
    // and `blockchainAccountId`, so no inline term definitions are emitted.
    build(
        did,
        json!([CONTEXT_DID_V1, CONTEXT_BLOCKCHAIN_2021_V1]),
        vec![account_method(
            did,
            "blockchainAccountId",
            "BlockchainVerificationMethod2021",
            &account,
            None,
        )?],
    )
}

/// Verify a Tezos-style base58check string and return its payload length.
///
/// Base58check is `payload || sha256(sha256(payload))[..4]`; upstream checked
/// only the three-character prefix, so a mistyped address resolved happily.
fn require_base58check(address: &str, expected_len: usize) -> Option<()> {
    let decoded = bs58::decode(address).into_vec().ok()?;
    if decoded.len() != expected_len {
        return None;
    }
    let (payload, checksum) = decoded.split_at(expected_len - 4);
    let digest = Sha256::digest(Sha256::digest(payload));
    (digest[..4] == *checksum).then_some(())
}

/// Build one verification method for an account, optionally carrying key material.
fn account_method(
    did: &str,
    fragment: &str,
    type_: &str,
    account: &str,
    public_key: Option<(&str, Value)>,
) -> Result<VerificationMethod, DidPkhError> {
    let id = format!("{did}#{fragment}");
    let mut builder = VerificationMethodBuilder::new(&id, type_, did)
        .map_err(|e| DidPkhError::InvalidDocument(format!("{id}: {e}")))?
        .property("blockchainAccountId", json!(account));
    if let Some((property, value)) = public_key {
        builder = builder.property(property, value);
    }
    Ok(builder.build())
}

/// Assemble the document: every verification method is referenced from both
/// `authentication` and `assertionMethod`, in declaration order.
fn build(
    did: &str,
    context: Value,
    methods: Vec<VerificationMethod>,
) -> Result<Document, DidPkhError> {
    let mut builder = DocumentBuilder::new(did)
        .map_err(|e| DidPkhError::InvalidDocument(format!("{did}: {e}")))?
        .context(context);

    for vm in &methods {
        let id = vm.id.as_str();
        builder = builder
            .authentication_reference(id)
            .and_then(|b| b.assertion_method_reference(id))
            .map_err(|e| DidPkhError::InvalidDocument(format!("{id}: {e}")))?;
    }

    Ok(builder.verification_methods(methods).build())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real mainnet address, used as the base for the mutation tests below.
    const TZ1: &str = "tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8";
    const ETH: &str = "0xb9c5714089478a327f09197987f16f9e5d936e8a";

    #[test]
    fn non_pkh_did_is_rejected() {
        assert!(matches!(
            resolve("did:key:z6Mk"),
            Err(DidPkhError::NotPkh(_))
        ));
    }

    #[test]
    fn identifier_without_a_colon_is_rejected() {
        assert!(matches!(
            resolve("did:pkh:solo"),
            Err(DidPkhError::InvalidIdentifier(_))
        ));
    }

    #[test]
    fn caip10_needs_all_three_segments() {
        assert!(matches!(
            resolve("did:pkh:eip155:1"),
            Err(DidPkhError::InvalidIdentifier(_))
        ));
    }

    #[test]
    fn unknown_namespace_is_refused_not_guessed() {
        let err =
            resolve("did:pkh:cosmos:cosmoshub-3:cosmos1t2uflqwqe0fsj0shcfkrvpukewcw40yjj6hdc0");
        assert!(matches!(err, Err(DidPkhError::UnsupportedNamespace(ns)) if ns == "cosmos"));
    }

    #[test]
    fn malformed_caip2_is_rejected() {
        // Namespace too short, and outside the CAIP-2 character set.
        for bad in ["did:pkh:ab:1:0xabc", "did:pkh:EIP155:1:0xabc"] {
            assert!(
                matches!(resolve(bad), Err(DidPkhError::InvalidIdentifier(_))),
                "{bad}"
            );
        }
    }

    /// Upstream accepted any string starting with `0x`, so a mistyped address
    /// resolved to a document naming an account that cannot exist.
    #[test]
    fn eip155_address_must_be_hex_of_the_right_length() {
        for bad in [
            "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "0xb9c5714089",
            "b9c5714089478a327f09197987f16f9e5d936e8a",
        ] {
            assert!(
                matches!(
                    resolve(&format!("did:pkh:eip155:1:{bad}")),
                    Err(DidPkhError::InvalidAddress { .. })
                ),
                "{bad}"
            );
        }
    }

    /// Upstream checked only the three-character prefix.
    #[test]
    fn tezos_address_checksum_is_verified() {
        // Flip the final character to break the base58check checksum.
        let mut corrupted = TZ1.to_string();
        corrupted.pop();
        corrupted.push(if TZ1.ends_with('9') { '8' } else { '9' });
        assert_ne!(corrupted, TZ1);
        assert!(matches!(
            resolve(&format!("did:pkh:tezos:NetXdQprcVkpaWU:{corrupted}")),
            Err(DidPkhError::InvalidAddress { .. })
        ));
    }

    #[test]
    fn tezos_prefix_must_be_tz1_tz2_or_tz3() {
        assert!(matches!(
            resolve("did:pkh:tezos:NetXdQprcVkpaWU:tz9TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8"),
            Err(DidPkhError::InvalidAddress { .. })
        ));
    }

    #[test]
    fn solana_address_must_be_32_bytes_of_base58() {
        for bad in ["CKg5d12", "not-base58-0OIl"] {
            assert!(
                matches!(
                    resolve(&format!(
                        "did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:{bad}"
                    )),
                    Err(DidPkhError::InvalidAddress { .. })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn aleo_address_must_be_bech32_with_the_aleo_hrp() {
        // Valid bech32, wrong human-readable part.
        assert!(matches!(
            resolve("did:pkh:aleo:1:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
            Err(DidPkhError::InvalidAddress { .. })
        ));
    }

    #[test]
    fn bip122_mainnet_address_prefixes_are_checked() {
        // A Bitcoin-mainnet address must start with `1`, Dogecoin with `D`.
        assert!(matches!(
            resolve(
                "did:pkh:bip122:000000000019d6689c085ae165831e93:Dnn4Fp9dHnMBFFYUJnsLhHhWbXBHUcHnb1"
            ),
            Err(DidPkhError::InvalidAddress { .. })
        ));
        assert!(matches!(
            resolve(
                "did:pkh:bip122:1a91e3dace36e2be3bf030a65679fe82:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6"
            ),
            Err(DidPkhError::InvalidAddress { .. })
        ));
    }

    /// An unrecognised bip122 chain carries no prefix expectation, so the
    /// address is accepted as given rather than checked against the wrong rule.
    #[test]
    fn bip122_unknown_chain_skips_the_prefix_check() {
        assert!(
            resolve(
                "did:pkh:bip122:000000000933ea01ad0ee984209779ba:Xnn4Fp9dHnMBFFYUJnsLhHhWbXBHUcHnb1"
            )
            .is_ok()
        );
    }

    #[test]
    fn legacy_prefixes_pin_their_mainnet() {
        let doc = serde_json::to_value(resolve(&format!("did:pkh:eth:{ETH}")).unwrap()).unwrap();
        assert_eq!(
            doc["verificationMethod"][0]["blockchainAccountId"],
            json!(format!("eip155:1:{ETH}"))
        );
        // The legacy form keeps its distinct fragment (spruceid/ssi#297).
        assert!(
            doc["verificationMethod"][0]["id"]
                .as_str()
                .unwrap()
                .ends_with("#Recovery2020")
        );
    }
}
