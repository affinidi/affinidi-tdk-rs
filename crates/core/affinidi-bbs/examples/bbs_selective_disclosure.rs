/*!
 * Example: BBS selective disclosure for eIDAS PID attributes.
 *
 * Demonstrates the full flow:
 * 1. Issuer generates a key pair and signs PID attributes
 * 2. Holder creates a proof revealing only requested attributes
 * 3. Verifier validates the proof without seeing hidden attributes
 * 4. Multiple verifiers get unlinkable proofs from the same credential
 *
 * Run with: `cargo run --example bbs_selective_disclosure`
 */

use affinidi_bbs::*;

fn main() {
    println!("=== BBS Selective Disclosure for eIDAS PID ===\n");

    // ── Step 1: Issuer generates key pair ──
    let sk = keygen(b"issuer-key-material-must-be-32+!", b"eidas-pid").unwrap();
    let pk = sk_to_pk(&sk);
    println!("Public key: {} bytes (compressed G2)", pk.to_bytes().len());

    // ── Step 2: Issuer signs PID attributes ──
    let messages: Vec<&[u8]> = vec![
        b"family_name:Mueller",       // 0
        b"given_name:Erika",          // 1
        b"birth_date:1964-08-12",     // 2
        b"age_over_18:true",          // 3
        b"nationality:DE",            // 4
        b"resident_city:Berlin",      // 5
        b"document_number:T22000129", // 6
    ];

    let signature = sign(&sk, &pk, b"eidas-pid-v1", &messages).unwrap();
    println!(
        "Signed {} attributes in {} bytes\n",
        messages.len(),
        signature.to_bytes().len()
    );

    // ── Step 3: Age verification (disclose only age_over_18) ──
    println!("--- Scenario 1: Age Verification ---");
    println!("  Verifier requests: age_over_18 only");

    let proof1 = proof_gen(
        &pk,
        &signature,
        b"eidas-pid-v1",
        b"age-check-001",
        &messages,
        &[3],
    )
    .unwrap();

    let valid = proof_verify(
        &pk,
        &proof1,
        b"eidas-pid-v1",
        b"age-check-001",
        &[b"age_over_18:true"],
        &[3],
    )
    .unwrap();

    println!(
        "  Proof: {} bytes, Valid: {}",
        proof1.to_bytes().len(),
        valid
    );
    println!("  Hidden: name, birth_date, nationality, city, doc_number\n");

    // ── Step 4: Border control (name + nationality) ──
    println!("--- Scenario 2: Border Control ---");
    println!("  Verifier requests: family_name, given_name, nationality");

    let proof2 = proof_gen(
        &pk,
        &signature,
        b"eidas-pid-v1",
        b"border-002",
        &messages,
        &[0, 1, 4],
    )
    .unwrap();

    let valid = proof_verify(
        &pk,
        &proof2,
        b"eidas-pid-v1",
        b"border-002",
        &[
            b"family_name:Mueller",
            b"given_name:Erika",
            b"nationality:DE",
        ],
        &[0, 1, 4],
    )
    .unwrap();

    println!(
        "  Proof: {} bytes, Valid: {}",
        proof2.to_bytes().len(),
        valid
    );
    println!("  Hidden: birth_date, age_over_18, city, doc_number\n");

    // ── Step 5: Zero-knowledge existence proof ──
    println!("--- Scenario 3: Existence Proof (nothing revealed) ---");

    let proof3 = proof_gen(
        &pk,
        &signature,
        b"eidas-pid-v1",
        b"existence-003",
        &messages,
        &[],
    )
    .unwrap();

    let valid = proof_verify(&pk, &proof3, b"eidas-pid-v1", b"existence-003", &[], &[]).unwrap();

    println!(
        "  Proof: {} bytes, Valid: {}",
        proof3.to_bytes().len(),
        valid
    );
    println!("  Proves credential exists WITHOUT revealing ANY attributes\n");

    // ── Step 6: Unlinkability ──
    println!("--- Unlinkability ---");
    println!("  Proof 1 (first 16): {:02x?}", &proof1.to_bytes()[..16]);
    println!("  Proof 2 (first 16): {:02x?}", &proof2.to_bytes()[..16]);
    println!("  Proof 3 (first 16): {:02x?}", &proof3.to_bytes()[..16]);
    println!("  All three are cryptographically unlinkable!");

    println!("\nDone!");
}
