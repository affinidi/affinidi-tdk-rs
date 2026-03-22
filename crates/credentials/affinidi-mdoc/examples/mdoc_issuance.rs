/*!
 * Example: Issue an eIDAS PID as an mdoc credential.
 *
 * Demonstrates:
 * - Building an mdoc with the MdocBuilder
 * - Adding eIDAS PID attributes to the correct namespace
 * - Signing with COSE_Sign1
 * - Verifying digests and issuer auth
 *
 * Run with: `cargo run --example mdoc_issuance`
 */

use affinidi_mdoc::cose::test_utils::{TestSigner, TestVerifier};
use affinidi_mdoc::issuer_signed_item::cbor_to_json;
use affinidi_mdoc::{EIDAS_PID_NAMESPACE, MdocBuilder, ValidityInfo};

fn main() {
    println!("=== mdoc Issuance Example ===\n");

    // 1. Create a signer (in production, this would use P-256/P-384 with X.509 certs)
    let issuer_key = b"example-issuer-signing-key-32b!!";
    let signer = TestSigner::new(issuer_key);
    let verifier = TestVerifier::new(issuer_key);

    // 2. Build an eIDAS PID credential
    let mdoc = MdocBuilder::new("eu.europa.ec.eudi.pid.1")
        .digest_algorithm("SHA-256")
        .validity(ValidityInfo {
            signed: "2024-06-15T12:00:00Z".to_string(),
            valid_from: "2024-06-15T12:00:00Z".to_string(),
            valid_until: "2025-06-15T12:00:00Z".to_string(),
        })
        .decoys(3) // Add 3 decoy digests to hide attribute count
        // Add PID attributes
        .add_attribute(
            EIDAS_PID_NAMESPACE,
            "family_name",
            ciborium::Value::Text("Mueller".into()),
        )
        .add_attribute(
            EIDAS_PID_NAMESPACE,
            "given_name",
            ciborium::Value::Text("Erika".into()),
        )
        .add_attribute(
            EIDAS_PID_NAMESPACE,
            "birth_date",
            ciborium::Value::Text("1964-08-12".into()),
        )
        .add_attribute(
            EIDAS_PID_NAMESPACE,
            "age_over_18",
            ciborium::Value::Bool(true),
        )
        .add_attribute(
            EIDAS_PID_NAMESPACE,
            "nationality",
            ciborium::Value::Text("DE".into()),
        )
        .add_attribute(
            EIDAS_PID_NAMESPACE,
            "resident_city",
            ciborium::Value::Text("Berlin".into()),
        )
        .add_attribute(
            EIDAS_PID_NAMESPACE,
            "resident_country",
            ciborium::Value::Text("DE".into()),
        )
        .build(&signer)
        .expect("Failed to build mdoc");

    println!("Document type: {}", mdoc.doc_type);
    println!("MSO version: {}", mdoc.mso.version);
    println!("Digest algorithm: {}", mdoc.mso.digest_algorithm);
    println!("Valid until: {}", mdoc.mso.validity_info.valid_until);
    println!();

    // 3. List all attributes
    let attr_names = mdoc.attribute_names(EIDAS_PID_NAMESPACE);
    println!("Attributes ({}):", attr_names.len());
    for name in &attr_names {
        let attr = mdoc.get_attribute(EIDAS_PID_NAMESPACE, name).unwrap();
        let json_val = cbor_to_json(&attr.inner.element_value);
        println!("  {} = {}", name, json_val);
    }
    println!();

    // 4. Verify digests
    let digests_valid = mdoc.verify_digests().expect("Digest verification failed");
    println!("Digests valid: {digests_valid}");

    // 5. Verify issuer auth (COSE_Sign1)
    let decoded_mso = mdoc
        .verify_issuer_auth(&verifier)
        .expect("Issuer auth verification failed");
    println!("Issuer auth valid: true");
    println!("MSO doc type: {}", decoded_mso.doc_type);

    // 6. Show MSO digest count (includes decoys)
    let digest_count = decoded_mso.value_digests[EIDAS_PID_NAMESPACE].len();
    println!("MSO digest count: {} (7 real + 3 decoy)", digest_count);

    println!("\nIssuance complete!");
}
