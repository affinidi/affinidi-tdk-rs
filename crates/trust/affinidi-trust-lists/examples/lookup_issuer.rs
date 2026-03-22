/*!
 * Example: Look up a credential issuer against EU Trusted Lists.
 *
 * Demonstrates the credential verification flow:
 * 1. Build a trust list registry from multiple Member State TLs
 * 2. Receive a credential with an issuer certificate
 * 3. Look up the issuer in the registry
 * 4. Verify the issuer is authorized (active, correct service type)
 *
 * Run with: `cargo run --example lookup_issuer`
 */

use affinidi_trust_lists::*;

fn main() {
    println!("=== eIDAS Trust List — Issuer Lookup ===\n");

    // ── Step 1: Build the trust list registry ──
    println!("--- Step 1: Loading Trust Lists ---");

    let mut registry = TrustListRegistry::new();

    // Simulate loading national trust lists with their providers
    // In production, these would be parsed from ETSI TS 119 612 XML

    // Germany: PID provider + Wallet provider
    let de_pid_cert = b"DE-PID-CERTIFICATE-PLACEHOLDER-BYTES";
    let de_wallet_cert = b"DE-WALLET-CERT-PLACEHOLDER-BYTES!!";
    registry.add_provider(
        "DE",
        "Bundesdruckerei GmbH",
        ServiceType::Pid,
        ServiceStatus::Granted,
        de_pid_cert,
    );
    registry.add_provider(
        "DE",
        "Telekom Wallet Solutions",
        ServiceType::WalletProvider,
        ServiceStatus::Granted,
        de_wallet_cert,
    );

    // Austria: QEAA provider
    let at_qeaa_cert = b"AT-QEAA-CERTIFICATE-PLACEHOLDER!!";
    registry.add_provider(
        "AT",
        "A-Trust GmbH",
        ServiceType::QEaa,
        ServiceStatus::Granted,
        at_qeaa_cert,
    );

    // France: PID provider (withdrawn)
    let fr_pid_cert = b"FR-PID-CERT-OLD-WITHDRAWN-BYTES!!!";
    registry.add_provider(
        "FR",
        "ANTS (Agence Nationale)",
        ServiceType::Pid,
        ServiceStatus::Withdrawn,
        fr_pid_cert,
    );

    // Spain: Access CA
    let es_access_cert = b"ES-ACCESS-CA-CERT-PLACEHOLDER-OK!";
    registry.add_provider(
        "ES",
        "FNMT-RCM",
        ServiceType::AccessCa,
        ServiceStatus::Granted,
        es_access_cert,
    );

    println!(
        "  Loaded {} entries from {} territories\n",
        registry.entry_count(),
        registry.territories().len()
    );

    // ── Step 2: Simulate receiving credentials ──
    println!("--- Step 2: Credential Verification ---\n");

    // Scenario A: German PID — should be trusted
    println!("  Credential: German PID");
    println!("  Issuer certificate: DE-PID-CERTIFICATE...");
    let result = registry.lookup_by_certificate(de_pid_cert);
    print_result(&result);

    // Scenario B: Austrian QEAA — should be trusted
    println!("  Credential: Austrian University Diploma (QEAA)");
    let result = registry.lookup_by_certificate(at_qeaa_cert);
    print_result(&result);

    // Scenario C: French PID with withdrawn status
    println!("  Credential: French PID (old issuer)");
    let result = registry.lookup_by_certificate(fr_pid_cert);
    print_result(&result);

    // Scenario D: Unknown issuer
    println!("  Credential: Unknown issuer");
    let result = registry.lookup_by_certificate(b"UNKNOWN-CERTIFICATE-NOT-IN-TL!!");
    print_result(&result);

    // ── Step 3: Query by service type ──
    println!("--- Step 3: Service Type Queries ---\n");

    let active_pids = registry.pid_providers();
    println!("  Active PID providers: {}", active_pids.len());
    for p in &active_pids {
        println!("    - {} ({})", p.provider_name, p.territory);
    }

    let wallets = registry.wallet_providers();
    println!("  Active Wallet providers: {}", wallets.len());
    for w in &wallets {
        println!("    - {} ({})", w.provider_name, w.territory);
    }

    let qeaas = registry.qeaa_providers();
    println!("  Active QEAA providers: {}", qeaas.len());
    for q in &qeaas {
        println!("    - {} ({})", q.provider_name, q.territory);
    }

    println!("\nDone!");
}

fn print_result(result: &LookupResult) {
    match result {
        LookupResult::Trusted(entry) => {
            println!("    Result: TRUSTED");
            println!("    Provider: {}", entry.provider_name);
            println!("    Territory: {}", entry.territory);
            println!("    Service: {}", entry.service.service_type);
            println!("    Status: {}", entry.service.service_status);
            if entry.service.service_type.is_eidas2() {
                println!("    Type: eIDAS 2.0 entity");
            }
            if entry.service.service_type.is_qualified() {
                println!("    Qualified: Yes");
            }
        }
        LookupResult::Inactive { entry, reason } => {
            println!("    Result: NOT TRUSTED (inactive)");
            println!("    Provider: {}", entry.provider_name);
            println!("    Reason: {reason}");
        }
        LookupResult::NotFound => {
            println!("    Result: NOT FOUND — issuer not in any EU Trusted List");
        }
    }
    println!();
}
