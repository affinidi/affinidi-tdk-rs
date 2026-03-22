/*!
 * Example: SIOPv2 authentication with JWK Thumbprint subject.
 *
 * Demonstrates the full flow:
 * 1. RP creates an authorization request
 * 2. Wallet (Self-Issued OP) creates a self-issued ID Token
 * 3. RP validates the ID Token
 *
 * Run with: `cargo run --example siop_authentication`
 */

use affinidi_siopv2::*;
use serde_json::json;

fn main() {
    println!("=== SIOPv2 Authentication (JWK Thumbprint) ===\n");

    // ── Step 1: RP creates authorization request ──
    println!("--- Step 1: RP creates authorization request ---");

    let request = AuthorizationRequest::new(
        "https://rp.example.com",
        "https://rp.example.com/callback",
        "Ky4MsZJKBO-i81LnybRGow", // Random nonce
    )
    .with_response_mode(ResponseMode::DirectPost)
    .with_state("session-abc123")
    .with_client_metadata(ClientMetadata {
        client_name: Some("Example Relying Party".into()),
        subject_syntax_types_supported: Some(vec!["urn:ietf:params:oauth:jwk-thumbprint".into()]),
        ..Default::default()
    });

    request.validate().expect("Request should be valid");

    let req_json = serde_json::to_string_pretty(&request).unwrap();
    println!("  Response type: {}", request.response_type);
    println!("  Client ID: {}", request.client_id);
    println!("  Nonce: {}", request.nonce);
    println!("  Response mode: {:?}\n", request.response_mode);

    // ── Step 2: Wallet creates self-issued ID Token ──
    println!("--- Step 2: Wallet creates self-issued ID Token ---");

    let holder_jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
        "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
    });

    let thumbprint = compute_jwk_thumbprint(&holder_jwk).unwrap();
    println!("  Holder JWK Thumbprint: {thumbprint}");

    let id_token = IdTokenBuilder::new(&request.client_id, &request.nonce)
        .with_jwk_thumbprint(holder_jwk)
        .unwrap()
        .expires_in(300)
        .claim("name", json!("Alice Wonderland"))
        .claim("email", json!("alice@example.com"))
        .build()
        .unwrap();

    println!(
        "  iss == sub: {} (self-issued invariant)",
        id_token.iss == id_token.sub
    );
    println!("  Subject: {}", id_token.sub);
    println!("  Audience: {}", id_token.aud);
    println!("  Self-attested claims: name, email\n");

    // ── Step 3: RP validates the ID Token ──
    println!("--- Step 3: RP validates the ID Token ---");

    match id_token.validate(&request.client_id, &request.nonce) {
        Ok(()) => println!("  Validation: PASSED"),
        Err(e) => println!("  Validation: FAILED - {e}"),
    }

    println!("  Checks performed:");
    println!("    1. iss == sub (self-issued invariant)");
    println!("    2. aud matches client_id");
    println!("    3. nonce matches request nonce");
    println!("    4. Token not expired");
    println!("    5. sub == JWK Thumbprint(sub_jwk)");

    // ── Step 4: RP reads self-attested claims ──
    println!("\n--- Step 4: RP reads claims ---");
    println!(
        "  Name: {}",
        id_token.additional_claims.get("name").unwrap()
    );
    println!(
        "  Email: {}",
        id_token.additional_claims.get("email").unwrap()
    );
    println!("  (These are self-attested — the RP may request VCs for verified claims)");

    println!("\nDone!");
}
