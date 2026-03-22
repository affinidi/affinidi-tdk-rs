/*!
 * Example: SIOPv2 authentication with DID-based subject.
 *
 * Demonstrates DID-based authentication where:
 * - The wallet identifies itself with a DID
 * - The RP resolves the DID to get the verification key
 * - No sub_jwk claim is needed (key comes from DID Document)
 *
 * Run with: `cargo run --example did_authentication`
 */

use affinidi_siopv2::*;

fn main() {
    println!("=== SIOPv2 DID-Based Authentication ===\n");

    // ── RP: Advertise DID method support ──
    println!("--- RP: Create request supporting DID methods ---");

    let metadata = SiopMetadata::siopv2_default()
        .with_did_support(vec!["did:key".into(), "did:web".into(), "did:ebsi".into()])
        .with_eddsa();

    println!("  Supported subject types:");
    for sst in &metadata.subject_syntax_types_supported {
        println!("    - {sst}");
    }
    println!(
        "  Signing algorithms: {:?}\n",
        metadata.id_token_signing_alg_values_supported
    );

    let request = AuthorizationRequest::new(
        "https://verifier.example.com",
        "https://verifier.example.com/siop/callback",
        "DID-auth-nonce-xyz",
    )
    .with_response_mode(ResponseMode::DirectPost)
    .with_client_metadata(ClientMetadata {
        client_name: Some("eIDAS Verifier".into()),
        subject_syntax_types_supported: Some(vec![
            "did:key".into(),
            "did:web".into(),
            "did:ebsi".into(),
        ]),
        ..Default::default()
    });

    request.validate().unwrap();
    println!("  Request created for: {}\n", request.client_id);

    // ── Wallet: Create DID-based ID Token ──
    println!("--- Wallet: Create DID-based ID Token ---");

    let wallet_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    let id_token = IdTokenBuilder::new(&request.client_id, &request.nonce)
        .with_did(wallet_did)
        .expires_in(300)
        .build()
        .unwrap();

    println!("  DID: {}", id_token.sub);
    println!("  iss == sub: {}", id_token.iss == id_token.sub);
    println!(
        "  sub_jwk present: {} (correct for DID)",
        id_token.sub_jwk.is_some()
    );
    println!("  Is DID subject: {}\n", id_token.is_did_subject());

    // ── RP: Validate ──
    println!("--- RP: Validate DID-based ID Token ---");

    match id_token.validate(&request.client_id, &request.nonce) {
        Ok(()) => {
            println!("  Structural validation: PASSED");
            println!("  Next steps for full validation:");
            println!("    1. Resolve DID: {}", id_token.sub);
            println!("    2. Find verificationMethod matching JWT kid header");
            println!("    3. Verify JWT signature with that key");
            println!("    4. Check verificationMethod has 'authentication' relationship");
        }
        Err(e) => println!("  Validation: FAILED - {e}"),
    }

    // ── EBSI DID example ──
    println!("\n--- EBSI DID Authentication ---");

    let ebsi_token = IdTokenBuilder::new(&request.client_id, &request.nonce)
        .with_did("did:ebsi:zfEmvX5twhXjQJiCWsukvQA")
        .expires_in(300)
        .build()
        .unwrap();

    println!("  EBSI DID: {}", ebsi_token.sub);
    println!("  Is DID subject: {}", ebsi_token.is_did_subject());
    assert!(
        ebsi_token
            .validate(&request.client_id, &request.nonce)
            .is_ok()
    );
    println!("  Validation: PASSED");
    println!("  Resolution: via EBSI DID Registry API (api-pilot.ebsi.eu)");

    println!("\nDone!");
}
