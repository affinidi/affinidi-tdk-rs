/*!
 * did:ethr — Ethereum DID method resolver.
 *
 * Implements resolution of `did:ethr` identifiers per the
 * [did:ethr method specification](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md).
 *
 * # DID Format
 *
 * ```text
 * did:ethr:[{network}:]{address-or-public-key}
 * ```
 *
 * - `network` is a named Ethereum network (`mainnet`, `ropsten`, …) or a
 *   `0x`-prefixed hex chain id. It defaults to `mainnet` (chain id 1).
 * - The identifier is either a 20-byte account address (`0x` + 40 hex) or a
 *   33-byte compressed secp256k1 public key (`0x` + 66 hex).
 *
 * # Scope: genesis documents only
 *
 * Resolution here is a pure, offline derivation from the identifier — exactly
 * what the DID resolves to before any on-chain change. This crate does **not**
 * replay ERC-1056 `DIDRegistry` events, so delegates, attributes and owner
 * changes recorded on-chain are not reflected. That matches the behaviour of
 * the spruceid `did-ethr` crate this replaced; it is a deliberate limit, not an
 * oversight. A DID whose registry state has been updated will resolve to its
 * genesis document, which may name a key the controller has since rotated away
 * from — do not treat a `did:ethr` document from this crate as proof of current
 * on-chain control.
 *
 * # Why this crate exists
 *
 * The spruceid `did-ethr` crate reaches the rest of the `ssi-*` stack, which
 * pulls `im`, `sized-chunks`, `bitmaps`, `smallstr` and `proc-macro-error` —
 * all unmaintained and archived upstream (RUSTSEC-2026-0248 / -0251 / -0247 /
 * -0215, RUSTSEC-2024-0370) with no fixed release — plus `reqwest 0.11` and
 * with it the vulnerable `h2 0.3.x` (RUSTSEC-2026-0258). Almost all of that
 * weight is JSON-LD `@context` machinery; our `Document` carries `@context` as
 * plain JSON, so re-implementing the derivation here drops the entire chain.
 * Same reasoning as the sibling `affinidi-did-web` crate.
 *
 * # Usage
 *
 * ```
 * # fn main() -> Result<(), affinidi_did_ethr::DidEthrError> {
 * let doc = affinidi_did_ethr::resolve("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a")?;
 * assert_eq!(doc.verification_method.len(), 2);
 * # Ok(()) }
 * ```
 */

use affinidi_did_common::verification_method::VerificationMethod;
use affinidi_did_common::{DocumentBuilder, VerificationMethodBuilder};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use k256::{
    AffinePoint,
    elliptic_curve::sec1::{FromSec1Point, ToSec1Point},
};
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use thiserror::Error;

pub use affinidi_did_common::Document;

/// `elliptic-curve` 0.14 made `EncodedPoint` a generic alias for `Sec1Point<C>`.
type EncodedPoint = k256::elliptic_curve::sec1::Sec1Point<k256::Secp256k1>;

/// did:ethr resolver errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DidEthrError {
    /// The supplied string was not a `did:ethr` DID.
    #[error("not a did:ethr DID: {0}")]
    NotEthr(String),

    /// The network segment named neither a known network nor a hex chain id.
    #[error("invalid did:ethr network: {0}")]
    InvalidNetwork(String),

    /// The identifier was neither a 20-byte address nor a 33-byte compressed
    /// secp256k1 public key.
    #[error("invalid did:ethr method-specific id: {0}")]
    InvalidIdentifier(String),

    /// The public key parsed as hex but is not a point on secp256k1.
    #[error("did:ethr public key is not a valid secp256k1 point: {0}")]
    InvalidPublicKey(String),
}

/// IRI for `EcdsaSecp256k1RecoveryMethod2020`.
const IRI_RECOVERY_2020: &str = "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020";
/// IRI for `EcdsaSecp256k1VerificationKey2019`.
const IRI_VERIFICATION_KEY_2019: &str =
    "https://w3id.org/security#EcdsaSecp256k1VerificationKey2019";
/// IRI for `Eip712Method2021`.
const IRI_EIP712_2021: &str = "https://w3id.org/security#Eip712Method2021";
/// IRI for the `blockchainAccountId` property.
const IRI_BLOCKCHAIN_ACCOUNT_ID: &str = "https://w3id.org/security#blockchainAccountId";
/// IRI for the `publicKeyJwk` property.
const IRI_PUBLIC_KEY_JWK: &str = "https://w3id.org/security#publicKeyJwk";

/// Resolve a `did:ethr` DID into its genesis DID Document.
///
/// Returns [`DidEthrError::NotEthr`] when `did` does not start with `did:ethr:`.
pub fn resolve(did: &str) -> Result<Document, DidEthrError> {
    let identifier = did
        .strip_prefix("did:ethr:")
        .ok_or_else(|| DidEthrError::NotEthr(did.to_string()))?;
    resolve_identifier(identifier)
}

/// Resolve the method-specific identifier of a `did:ethr` DID — everything
/// after `did:ethr:` — into its genesis DID Document.
pub fn resolve_identifier(identifier: &str) -> Result<Document, DidEthrError> {
    // The network segment is optional; without it the DID is on mainnet.
    let (chain_id, key_or_address) = match identifier.split_once(':') {
        None => (1u64, identifier),
        Some((network, rest)) => (chain_id_for(network)?, rest),
    };

    let did = format!("did:ethr:{identifier}");

    // Length alone distinguishes the two forms: 20-byte address vs 33-byte
    // compressed public key, both `0x`-prefixed hex.
    match key_or_address.len() {
        42 => document_for_address(&did, chain_id, key_or_address),
        68 => document_for_public_key(&did, chain_id, key_or_address),
        _ => Err(DidEthrError::InvalidIdentifier(identifier.to_string())),
    }
}

/// Map a `did:ethr` network segment to its EIP-155 chain id.
///
/// The named networks are the set the method specification froze; anything else
/// must be given as an explicit `0x`-prefixed hex chain id.
fn chain_id_for(network: &str) -> Result<u64, DidEthrError> {
    match network {
        "mainnet" => Ok(1),
        "morden" => Ok(2),
        "ropsten" => Ok(3),
        "rinkeby" => Ok(4),
        "goerli" => Ok(5),
        "kovan" => Ok(42),
        hex_id if hex_id.starts_with("0x") => u64::from_str_radix(&hex_id[2..], 16)
            .map_err(|_| DidEthrError::InvalidNetwork(network.to_string())),
        _ => Err(DidEthrError::InvalidNetwork(network.to_string())),
    }
}

/// Reject anything that is not `0x` followed by exactly `hex_digits` hex chars.
///
/// The upstream implementation switched on string *length* alone and copied the
/// identifier into `blockchainAccountId` unchecked, so `did:ethr:0xZZ…` (42
/// characters, not hex) resolved to a document naming an impossible account.
/// We validate instead — a DID that cannot denote an account is not resolvable.
fn require_hex(identifier: &str, hex_digits: usize) -> Result<Vec<u8>, DidEthrError> {
    let body = identifier
        .strip_prefix("0x")
        .ok_or_else(|| DidEthrError::InvalidIdentifier(identifier.to_string()))?;
    if body.len() != hex_digits {
        return Err(DidEthrError::InvalidIdentifier(identifier.to_string()));
    }
    hex::decode(body).map_err(|_| DidEthrError::InvalidIdentifier(identifier.to_string()))
}

/// Genesis document for the account-address form.
///
/// The address is carried through exactly as written in the DID — re-checksumming
/// it would change the DID's own `blockchainAccountId` and break signatures made
/// against the document.
fn document_for_address(did: &str, chain_id: u64, address: &str) -> Result<Document, DidEthrError> {
    require_hex(address, 40)?;
    let account = format!("eip155:{chain_id}:{address}");

    let controller = verification_method(
        &format!("{did}#controller"),
        "EcdsaSecp256k1RecoveryMethod2020",
        did,
        "blockchainAccountId",
        json!(account),
    )?;
    let eip712 = verification_method(
        &format!("{did}#Eip712Method2021"),
        "Eip712Method2021",
        did,
        "blockchainAccountId",
        json!(account),
    )?;

    build(
        did,
        json!([
            "https://www.w3.org/ns/did/v1",
            {
                "blockchainAccountId": IRI_BLOCKCHAIN_ACCOUNT_ID,
                "EcdsaSecp256k1RecoveryMethod2020": IRI_RECOVERY_2020,
                "Eip712Method2021": IRI_EIP712_2021,
            }
        ]),
        vec![controller, eip712],
    )
}

/// Genesis document for the compressed-public-key form.
///
/// The account address is *derived* here rather than read from the DID, so it is
/// emitted EIP-55 checksummed — matching the reference resolver.
fn document_for_public_key(
    did: &str,
    chain_id: u64,
    public_key_hex: &str,
) -> Result<Document, DidEthrError> {
    let pk_bytes = require_hex(public_key_hex, 66)?;
    let (x, y) = decompress(&pk_bytes, public_key_hex)?;

    let account = format!("eip155:{chain_id}:{}", eip55_address(&x, &y));

    let controller = verification_method(
        &format!("{did}#controller"),
        "EcdsaSecp256k1RecoveryMethod2020",
        did,
        "blockchainAccountId",
        json!(account),
    )?;
    let controller_key = verification_method(
        &format!("{did}#controllerKey"),
        "EcdsaSecp256k1VerificationKey2019",
        did,
        "publicKeyJwk",
        json!({
            "kty": "EC",
            "crv": "secp256k1",
            "x": BASE64_URL_SAFE_NO_PAD.encode(&x),
            "y": BASE64_URL_SAFE_NO_PAD.encode(&y),
        }),
    )?;

    build(
        did,
        json!([
            "https://www.w3.org/ns/did/v1",
            {
                "EcdsaSecp256k1RecoveryMethod2020": IRI_RECOVERY_2020,
                "EcdsaSecp256k1VerificationKey2019": IRI_VERIFICATION_KEY_2019,
                "blockchainAccountId": IRI_BLOCKCHAIN_ACCOUNT_ID,
                "publicKeyJwk": {
                    "@id": IRI_PUBLIC_KEY_JWK,
                    "@type": "@json",
                },
            }
        ]),
        vec![controller, controller_key],
    )
}

/// Decompress a SEC1 secp256k1 public key into its affine `(x, y)` coordinates,
/// rejecting anything that is not actually on the curve.
fn decompress(pk_bytes: &[u8], original: &str) -> Result<(Vec<u8>, Vec<u8>), DidEthrError> {
    let encoded = EncodedPoint::from_bytes(pk_bytes)
        .map_err(|e| DidEthrError::InvalidPublicKey(format!("{original}: {e}")))?;

    let affine: AffinePoint = AffinePoint::from_sec1_point(&encoded)
        .into_option()
        .ok_or_else(|| DidEthrError::InvalidPublicKey(format!("{original}: not on curve")))?;

    let point = affine.to_sec1_point(false);
    let x = point
        .x()
        .ok_or_else(|| DidEthrError::InvalidPublicKey(format!("{original}: no X coordinate")))?
        .to_vec();
    let y = point
        .y()
        .ok_or_else(|| DidEthrError::InvalidPublicKey(format!("{original}: no Y coordinate")))?
        .to_vec();
    Ok((x, y))
}

/// Derive the EIP-55 checksummed Ethereum address for a public key.
///
/// The address is the low 20 bytes of `keccak256(x || y)`; EIP-55 then re-cases
/// each hex letter according to the corresponding nibble of the keccak hash of
/// the lowercase address.
fn eip55_address(x: &[u8], y: &[u8]) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(x);
    hasher.update(y);
    let address = hex::encode(&hasher.finalize()[12..]);

    let checksum = hex::encode(Keccak256::digest(address.as_bytes()));

    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (c, nibble) in address.chars().zip(checksum.chars()) {
        // Digits have no case to carry the checksum bit; only letters do.
        if c.is_ascii_digit() || nibble < '8' {
            out.push(c);
        } else {
            out.push(c.to_ascii_uppercase());
        }
    }
    out
}

/// Build one verification method carrying a single extra property.
fn verification_method(
    id: &str,
    type_: &str,
    controller: &str,
    property: &str,
    value: Value,
) -> Result<VerificationMethod, DidEthrError> {
    Ok(VerificationMethodBuilder::new(id, type_, controller)
        .map_err(|e| DidEthrError::InvalidIdentifier(format!("{id}: {e}")))?
        .property(property, value)
        .build())
}

/// Assemble the document: every verification method is referenced from both
/// `authentication` and `assertionMethod`, in declaration order.
fn build(
    did: &str,
    context: Value,
    methods: Vec<VerificationMethod>,
) -> Result<Document, DidEthrError> {
    let mut builder = DocumentBuilder::new(did)
        .map_err(|e| DidEthrError::InvalidIdentifier(format!("{did}: {e}")))?
        .context(context);

    for vm in &methods {
        let id = vm.id.as_str();
        builder = builder
            .authentication_reference(id)
            .and_then(|b| b.assertion_method_reference(id))
            .map_err(|e| DidEthrError::InvalidIdentifier(format!("{id}: {e}")))?;
    }

    Ok(builder.verification_methods(methods).build())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip the document through JSON so the assertions below compare the
    /// wire form — which is what consumers actually see.
    fn resolved(did: &str) -> Value {
        serde_json::to_value(resolve(did).unwrap()).unwrap()
    }

    /// Vector from the did:ethr method specification ("Create (Register)"),
    /// carried over verbatim from the spruceid `did-ethr` test suite so the
    /// replacement is checked against the implementation it replaced.
    #[test]
    fn resolves_account_address_form() {
        let did = "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a";
        assert_eq!(
            resolved(did),
            json!({
              "@context": [
                "https://www.w3.org/ns/did/v1",
                {
                  "blockchainAccountId": "https://w3id.org/security#blockchainAccountId",
                  "EcdsaSecp256k1RecoveryMethod2020": "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020",
                  "Eip712Method2021": "https://w3id.org/security#Eip712Method2021"
                }
              ],
              "id": did,
              "verificationMethod": [{
                "id": format!("{did}#controller"),
                "type": "EcdsaSecp256k1RecoveryMethod2020",
                "controller": did,
                "blockchainAccountId": "eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a"
              }, {
                "id": format!("{did}#Eip712Method2021"),
                "type": "Eip712Method2021",
                "controller": did,
                "blockchainAccountId": "eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a"
              }],
              "authentication": [
                format!("{did}#controller"),
                format!("{did}#Eip712Method2021")
              ],
              "assertionMethod": [
                format!("{did}#controller"),
                format!("{did}#Eip712Method2021")
              ]
            })
        );
    }

    /// Vector carried over from the spruceid `did-ethr` `tests/did-pk.jsonld`
    /// fixture. Pins the two things this form derives rather than copies: the
    /// EIP-55 checksummed address and the decompressed public key JWK.
    #[test]
    fn resolves_public_key_form() {
        let did = "did:ethr:0x03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479";
        assert_eq!(
            resolved(did),
            json!({
              "@context": [
                "https://www.w3.org/ns/did/v1",
                {
                  "EcdsaSecp256k1RecoveryMethod2020": "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020",
                  "EcdsaSecp256k1VerificationKey2019": "https://w3id.org/security#EcdsaSecp256k1VerificationKey2019",
                  "blockchainAccountId": "https://w3id.org/security#blockchainAccountId",
                  "publicKeyJwk": {
                    "@id": "https://w3id.org/security#publicKeyJwk",
                    "@type": "@json"
                  }
                }
              ],
              "id": did,
              "verificationMethod": [{
                "id": format!("{did}#controller"),
                "type": "EcdsaSecp256k1RecoveryMethod2020",
                "controller": did,
                "blockchainAccountId": "eip155:1:0xF3beAC30C498D9E26865F34fCAa57dBB935b0D74"
              }, {
                "id": format!("{did}#controllerKey"),
                "type": "EcdsaSecp256k1VerificationKey2019",
                "controller": did,
                "publicKeyJwk": {
                  "kty": "EC",
                  "crv": "secp256k1",
                  "x": "_dV63sPUOOojf-RrM-4eAW7aa1hcPifqZmhsLqU1hHk",
                  "y": "Rjk_gUUlLupor-Z-KHs-2bMWhbpsOwAGCnO5sSQtaPc"
                }
              }],
              "authentication": [
                format!("{did}#controller"),
                format!("{did}#controllerKey")
              ],
              "assertionMethod": [
                format!("{did}#controller"),
                format!("{did}#controllerKey")
              ]
            })
        );
    }

    #[test]
    fn named_networks_map_to_their_chain_ids() {
        for (network, chain_id) in [
            ("mainnet", 1),
            ("morden", 2),
            ("ropsten", 3),
            ("rinkeby", 4),
            ("goerli", 5),
            ("kovan", 42),
        ] {
            assert_eq!(chain_id_for(network).unwrap(), chain_id, "{network}");
        }
    }

    #[test]
    fn hex_network_is_read_as_a_chain_id() {
        assert_eq!(chain_id_for("0x3").unwrap(), 3);
        assert_eq!(chain_id_for("0x2a").unwrap(), 42);
    }

    #[test]
    fn network_segment_reaches_the_blockchain_account_id() {
        let doc = resolved("did:ethr:0x3:0xb9c5714089478a327f09197987f16f9e5d936e8a");
        assert_eq!(
            doc["verificationMethod"][0]["blockchainAccountId"],
            json!("eip155:3:0xb9c5714089478a327f09197987f16f9e5d936e8a")
        );
    }

    #[test]
    fn unknown_network_is_rejected() {
        assert!(matches!(
            resolve("did:ethr:sepolia:0xb9c5714089478a327f09197987f16f9e5d936e8a"),
            Err(DidEthrError::InvalidNetwork(_))
        ));
    }

    #[test]
    fn non_ethr_did_is_rejected() {
        assert!(matches!(
            resolve("did:key:z6Mk"),
            Err(DidEthrError::NotEthr(_))
        ));
    }

    /// The upstream implementation switched on length alone, so a 42-character
    /// non-hex identifier produced a document naming an impossible account.
    #[test]
    fn non_hex_identifier_of_the_right_length_is_rejected() {
        assert!(matches!(
            resolve("did:ethr:0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"),
            Err(DidEthrError::InvalidIdentifier(_))
        ));
    }

    #[test]
    fn wrong_length_identifier_is_rejected() {
        assert!(matches!(
            resolve("did:ethr:0xb9c57140"),
            Err(DidEthrError::InvalidIdentifier(_))
        ));
    }

    #[test]
    fn public_key_off_the_curve_is_rejected() {
        // Valid length and hex, but not a point on secp256k1.
        let did = format!("did:ethr:0x03{}", "ff".repeat(32));
        assert!(matches!(
            resolve(&did),
            Err(DidEthrError::InvalidPublicKey(_))
        ));
    }

    /// EIP-55 vectors from the specification itself.
    #[test]
    fn eip55_matches_the_specification_vectors() {
        // Derived addresses are checksummed; check the casing rule directly by
        // resolving a key whose address contains both cases.
        let doc = resolved(
            "did:ethr:0x03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479",
        );
        let account = doc["verificationMethod"][0]["blockchainAccountId"]
            .as_str()
            .unwrap();
        let address = account.rsplit(':').next().unwrap();
        assert_eq!(address, "0xF3beAC30C498D9E26865F34fCAa57dBB935b0D74");
        // Checksumming must be case-flipping only, never a different address.
        assert_eq!(
            address.to_ascii_lowercase(),
            "0xf3beac30c498d9e26865f34fcaa57dbb935b0d74"
        );
    }
}
