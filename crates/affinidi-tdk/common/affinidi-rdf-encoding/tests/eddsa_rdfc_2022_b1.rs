use sha2::{Digest, Sha256};

use affinidi_rdf_encoding::jsonld;
use affinidi_rdf_encoding::rdfc1;

/// W3C vc-di-eddsa B.1 Test Vector — Credential
///
/// Input: Alumni Credential JSON-LD (Example 8)
/// Expected: 8 canonical N-Quads lines (Example 9)
/// Expected hash: 517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017
#[test]
fn b1_credential_canonicalization() {
    let credential: serde_json::Value = serde_json::from_str(
        r#"{
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
            "type": ["VerifiableCredential", "AlumniCredential"],
            "name": "Alumni Credential",
            "description": "A minimum viable example of an Alumni Credential.",
            "issuer": "https://vc.example/issuers/5678",
            "validFrom": "2023-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:abcdefgh",
                "alumniOf": "The School of Examples"
            }
        }"#,
    )
    .unwrap();

    // Step 1: Expand and convert to RDF
    let dataset = jsonld::expand_and_to_rdf(&credential).unwrap();

    // Step 2: Canonicalize
    let canonical = rdfc1::canonicalize(&dataset).unwrap();

    // Expected canonical N-Quads (sorted, from W3C spec Example 9)
    let expected_nquads = "\
<did:example:abcdefgh> <https://www.w3.org/ns/credentials/examples#alumniOf> \"The School of Examples\" .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/credentials/examples#AlumniCredential> .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://schema.org/description> \"A minimum viable example of an Alumni Credential.\" .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://schema.org/name> \"Alumni Credential\" .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:abcdefgh> .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://www.w3.org/2018/credentials#issuer> <https://vc.example/issuers/5678> .
<urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33> <https://www.w3.org/2018/credentials#validFrom> \"2023-01-01T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
";

    assert_eq!(
        canonical, expected_nquads,
        "Credential canonical N-Quads mismatch.\nGot:\n{canonical}\nExpected:\n{expected_nquads}"
    );

    // Step 3: Verify SHA-256 hash
    let hash = Sha256::digest(canonical.as_bytes());
    let hash_hex = hex_encode(&hash);
    assert_eq!(
        hash_hex, "517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017",
        "Credential hash mismatch"
    );
}

/// W3C vc-di-eddsa B.1 Test Vector — Proof Options
///
/// Input: Proof options JSON-LD (Example 11)
/// Expected: 5 canonical N-Quads lines with _:c14n0 (Example 12)
/// Expected hash: bea7b7acfbad0126b135104024a5f1733e705108f42d59668b05c0c50004c6b0
#[test]
fn b1_proof_options_canonicalization() {
    let proof_options: serde_json::Value = serde_json::from_str(
        r#"{
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-rdfc-2022",
            "created": "2023-02-24T23:36:38Z",
            "verificationMethod": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
            "proofPurpose": "assertionMethod",
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ]
        }"#,
    )
    .unwrap();

    let dataset = jsonld::expand_and_to_rdf(&proof_options).unwrap();
    let canonical = rdfc1::canonicalize(&dataset).unwrap();

    let expected_nquads = "\
_:c14n0 <http://purl.org/dc/terms/created> \"2023-02-24T23:36:38Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://w3id.org/security#DataIntegrityProof> .
_:c14n0 <https://w3id.org/security#cryptosuite> \"eddsa-rdfc-2022\"^^<https://w3id.org/security#cryptosuiteString> .
_:c14n0 <https://w3id.org/security#proofPurpose> <https://w3id.org/security#assertionMethod> .
_:c14n0 <https://w3id.org/security#verificationMethod> <did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2> .
";

    assert_eq!(
        canonical, expected_nquads,
        "Proof options canonical N-Quads mismatch.\nGot:\n{canonical}\nExpected:\n{expected_nquads}"
    );

    let hash = Sha256::digest(canonical.as_bytes());
    let hash_hex = hex_encode(&hash);
    assert_eq!(
        hash_hex, "bea7b7acfbad0126b135104024a5f1733e705108f42d59668b05c0c50004c6b0",
        "Proof options hash mismatch"
    );
}

/// W3C vc-di-eddsa B.1 Test Vector — Combined Hash
///
/// Verify that proof_hash || credential_hash matches the expected combined hash.
#[test]
fn b1_combined_hash() {
    let proof_hash_hex = "bea7b7acfbad0126b135104024a5f1733e705108f42d59668b05c0c50004c6b0";
    let credential_hash_hex = "517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017";

    let combined = format!("{proof_hash_hex}{credential_hash_hex}");
    assert_eq!(
        combined,
        "bea7b7acfbad0126b135104024a5f1733e705108f42d59668b05c0c50004c6b0517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017"
    );

    // Also verify with actual bytes
    let proof_hash = hex_decode(proof_hash_hex);
    let credential_hash = hex_decode(credential_hash_hex);
    let mut combined_bytes = Vec::with_capacity(64);
    combined_bytes.extend_from_slice(&proof_hash);
    combined_bytes.extend_from_slice(&credential_hash);
    assert_eq!(combined_bytes.len(), 64);
    assert_eq!(hex_encode(&combined_bytes), combined);
}

/// W3C vc-di-eddsa B.1 — Full pipeline test using the convenience function.
#[test]
fn b1_full_pipeline() {
    let credential: serde_json::Value = serde_json::from_str(
        r#"{
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
            "type": ["VerifiableCredential", "AlumniCredential"],
            "name": "Alumni Credential",
            "description": "A minimum viable example of an Alumni Credential.",
            "issuer": "https://vc.example/issuers/5678",
            "validFrom": "2023-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:abcdefgh",
                "alumniOf": "The School of Examples"
            }
        }"#,
    )
    .unwrap();

    let hash = affinidi_rdf_encoding::expand_canonicalize_and_hash(&credential).unwrap();
    assert_eq!(
        hex_encode(&hash),
        "517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017"
    );
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
