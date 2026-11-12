/*!
 * Example: SIOPv2 authentication with DID-based subject.
 *
 * Demonstrates DID-based authentication where:
 * - The wallet identifies itself with a DID
 * - The RP resolves the DID to get the verification key (a stand-in
 *   resolver here; a real RP resolves the DID Document)
 * - No sub_jwk claim is needed (key comes from DID Document)
 *
 * Run with: `cargo run --example did_authentication`
 */

use affinidi_oid4vc_core::eddsa::{EdDsaSigner, EdDsaVerifier};
use affinidi_oid4vc_core::jwt::JwtVerifier;
use affinidi_siopv2::*;

/// Stand-in for DID resolution: knows one verification method's key.
struct KnownKey {
    kid: String,
    jwk: serde_json::Value,
}

impl DidKeyResolver for KnownKey {
    fn resolve(&self, kid: &str, alg: &str) -> Result<Box<dyn JwtVerifier>, SiopError> {
        if kid != self.kid || alg != "EdDSA" {
            return Err(SiopError::InvalidIdToken(format!("unknown key {kid}")));
        }
        let verifier = EdDsaVerifier::from_jwk(&self.jwk)
            .map_err(|e| SiopError::InvalidIdToken(e.to_string()))?;
        Ok(Box::new(verifier))
    }
}

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
    let kid = format!("{wallet_did}#key-1");
    let wallet_key = EdDsaSigner::generate().with_kid(kid.clone());

    let id_token = IdTokenBuilder::new(&request.client_id, &request.nonce)
        .with_did(wallet_did)
        .expires_in(300)
        .build()
        .unwrap();
    let id_token_jwt = id_token.sign(&wallet_key).unwrap();

    println!("  DID: {}", id_token.sub);
    println!("  kid: {kid}");
    println!("  iss == sub: {}", id_token.iss == id_token.sub);
    println!(
        "  sub_jwk present: {} (correct for DID)",
        id_token.sub_jwk.is_some()
    );
    println!("  Is DID subject: {}\n", id_token.is_did_subject());

    // ── RP: Verify ──
    println!("--- RP: Verify DID-based ID Token ---");

    let resolver = KnownKey {
        kid,
        jwk: wallet_key.public_key_jwk(),
    };
    let expected = IdTokenExpectations::new(&["EdDSA"], &request.client_id, &request.nonce);
    match verify_id_token(&id_token_jwt, &expected, Some(&resolver)) {
        Ok(token) => {
            println!("  Verification: PASSED for {}", token.sub);
            println!("  A real resolver must also check the verification method is");
            println!("  listed under the DID's 'authentication' relationship.");
        }
        Err(e) => println!("  Verification: FAILED - {e}"),
    }

    println!("\nDone!");
}
