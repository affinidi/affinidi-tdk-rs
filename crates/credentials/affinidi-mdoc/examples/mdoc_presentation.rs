/*!
 * Example: Present selected attributes from an mdoc to a verifier.
 *
 * Demonstrates the full flow:
 * 1. Issuer creates a signed mdoc (PID credential)
 * 2. Holder receives the mdoc
 * 3. Verifier requests specific attributes
 * 4. Holder creates a DeviceResponse with only the requested attributes
 * 5. Verifier validates the response
 *
 * Run with: `cargo run --example mdoc_presentation`
 */

use std::collections::BTreeMap;

use affinidi_mdoc::cose::test_utils::{TestSigner, TestVerifier};
use affinidi_mdoc::issuer_signed_item::cbor_to_json;
use affinidi_mdoc::{DeviceResponse, EIDAS_PID_NAMESPACE, MdocBuilder, ValidityInfo};

fn main() {
    println!("=== mdoc Selective Disclosure Presentation ===\n");

    // ── Step 1: Issuer creates the credential ──
    println!("--- Step 1: Issuer creates PID credential ---");

    let issuer_key = b"example-issuer-signing-key-32b!!";
    let signer = TestSigner::new(issuer_key);

    let mdoc = MdocBuilder::new("eu.europa.ec.eudi.pid.1")
        .validity(ValidityInfo {
            signed: "2024-06-15T12:00:00Z".to_string(),
            valid_from: "2024-06-15T12:00:00Z".to_string(),
            valid_until: "2025-06-15T12:00:00Z".to_string(),
        })
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
        .build(&signer)
        .unwrap();

    println!(
        "  Credential issued with {} attributes\n",
        mdoc.attribute_names(EIDAS_PID_NAMESPACE).len()
    );

    // ── Step 2: Verifier requests specific attributes ──
    println!("--- Step 2: Verifier requests age_over_18 and nationality ---");

    let mut request = BTreeMap::new();
    request.insert(
        EIDAS_PID_NAMESPACE.to_string(),
        vec!["age_over_18".to_string(), "nationality".to_string()],
    );

    println!("  Requested: {:?}\n", request[EIDAS_PID_NAMESPACE]);

    // ── Step 3: Holder creates a selective disclosure response ──
    println!("--- Step 3: Holder creates DeviceResponse ---");

    let response = DeviceResponse::create(&mdoc, &request).unwrap();

    let disclosed = response.disclosed_names(EIDAS_PID_NAMESPACE);
    println!("  Disclosed attributes: {:?}", disclosed);
    println!("  Hidden attributes: family_name, given_name, birth_date, resident_city");
    println!();

    // ── Step 4: Verifier validates the response ──
    println!("--- Step 4: Verifier validates ---");

    let verifier = TestVerifier::new(issuer_key);

    // 4a. Verify issuer auth (COSE_Sign1 signature)
    let mso = response.verify_issuer_auth(&verifier).unwrap();
    println!("  Issuer auth: VALID");
    println!("  Document type: {}", mso.doc_type);

    // 4b. Verify digests (each disclosed attribute matches its MSO digest)
    let digests_ok = response.verify_digests().unwrap();
    println!(
        "  Digest verification: {}",
        if digests_ok { "VALID" } else { "FAILED" }
    );

    // 4c. Read the disclosed values
    println!("\n  Disclosed claims:");
    for (ns, items) in &response.disclosed {
        for item in items {
            let name = &item.inner.element_identifier;
            let value = cbor_to_json(&item.inner.element_value);
            println!("    {ns}/{name} = {value}");
        }
    }

    // 4d. Confirm what was NOT disclosed
    println!("\n  Verifier cannot see: family_name, given_name, birth_date, resident_city");
    println!("  (These attributes exist in the MSO digests but were not presented)");

    println!("\nPresentation complete!");
}
