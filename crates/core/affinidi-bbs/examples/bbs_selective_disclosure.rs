/*!
 * Example: BBS signatures and proofs for eIDAS PID attributes.
 *
 * Demonstrates:
 * 1. Key generation
 * 2. Multi-message signing (7 PID attributes in one signature)
 * 3. Signature verification
 * 4. Zero-knowledge proof with all messages disclosed
 * 5. Proof unlinkability
 *
 * NOTE: Selective disclosure proofs (partial disclosure) are under
 * development — see the `proof` module tests for status.
 *
 * Run with: `cargo run --example bbs_selective_disclosure`
 */

use affinidi_bbs::*;

fn main() {
    println!("=== BBS Signatures for eIDAS PID ===\n");

    // ── Step 1: Key generation ──
    let sk = keygen(b"issuer-key-material-must-be-32+!", b"eidas-pid").unwrap();
    let pk = sk_to_pk(&sk);
    println!("Secret key: 32 bytes");
    println!(
        "Public key: {} bytes (compressed G2)\n",
        pk.to_bytes().len()
    );

    // ── Step 2: Sign multiple PID attributes in one signature ──
    let messages: Vec<&[u8]> = vec![
        b"family_name:Mueller",
        b"given_name:Erika",
        b"birth_date:1964-08-12",
        b"age_over_18:true",
        b"nationality:DE",
        b"resident_city:Berlin",
        b"document_number:T22000129",
    ];

    let signature = sign(&sk, &pk, b"eidas-pid-v1", &messages).unwrap();
    println!("Signed {} attributes in one BBS signature", messages.len());
    println!("Signature size: {} bytes\n", signature.to_bytes().len());

    // ── Step 3: Verify the signature ──
    let valid = verify(&pk, &signature, b"eidas-pid-v1", &messages).unwrap();
    println!(
        "Signature verification: {}\n",
        if valid { "PASS" } else { "FAIL" }
    );

    // ── Step 4: Generate proof (all disclosed) ──
    let all_indexes: Vec<usize> = (0..messages.len()).collect();
    let proof = proof_gen(
        &pk,
        &signature,
        b"eidas-pid-v1",
        b"session-001",
        &messages,
        &all_indexes,
    )
    .unwrap();

    println!("Zero-knowledge proof generated");
    println!("Proof size: {} bytes\n", proof.to_bytes().len());

    // ── Step 5: Verify the proof ──
    let proof_valid = proof_verify(
        &pk,
        &proof,
        b"eidas-pid-v1",
        b"session-001",
        &messages,
        &all_indexes,
    )
    .unwrap();

    println!(
        "Proof verification: {}\n",
        if proof_valid { "PASS" } else { "FAIL" }
    );

    // ── Step 6: Demonstrate unlinkability ──
    let proof2 = proof_gen(
        &pk,
        &signature,
        b"eidas-pid-v1",
        b"session-002",
        &messages,
        &all_indexes,
    )
    .unwrap();

    println!("--- Unlinkability ---");
    println!("Proof 1 (first 16 bytes): {:02x?}", &proof.to_bytes()[..16]);
    println!(
        "Proof 2 (first 16 bytes): {:02x?}",
        &proof2.to_bytes()[..16]
    );
    println!("Same credential, different sessions -> completely different proof bytes");
    println!("Cryptographically impossible to link these proofs!\n");

    // ── Step 7: Wrong message fails ──
    let wrong_valid = proof_verify(
        &pk,
        &proof,
        b"eidas-pid-v1",
        b"session-001",
        &[
            b"family_name:FAKE".as_ref(),
            b"given_name:Erika",
            b"birth_date:1964-08-12",
            b"age_over_18:true",
            b"nationality:DE",
            b"resident_city:Berlin",
            b"document_number:T22000129",
        ],
        &all_indexes,
    )
    .unwrap();

    println!(
        "Tampered message verification: {}",
        if wrong_valid {
            "PASS (BAD!)"
        } else {
            "FAIL (correct)"
        }
    );

    println!("\nDone!");
}
