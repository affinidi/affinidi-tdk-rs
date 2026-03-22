/*!
 * Example: Browse the contents of an EU Trusted List.
 *
 * Demonstrates building a TrustServiceStatusList programmatically
 * and querying its contents — simulating what a trust list browser does.
 *
 * Run with: `cargo run --example browse_trust_list`
 */

use chrono::Utc;

use affinidi_trust_lists::*;

fn main() {
    println!("=== eIDAS Trust List Browser ===\n");

    // ── Build a sample national trust list (Germany) ──
    let tl = TrustServiceStatusList {
        scheme_information: SchemeInformation {
            tsl_version: 5,
            tsl_sequence_number: 42,
            tsl_type: TslType::EuGeneric,
            scheme_operator_name: "Bundesnetzagentur".into(),
            scheme_territory: "DE".into(),
            list_issue_date_time: Utc::now(),
            next_update: None,
            pointers_to_other_tsl: Vec::new(),
        },
        trust_service_providers: vec![
            TrustServiceProvider {
                name: "Bundesdruckerei GmbH".into(),
                trade_name: Some("BDr".into()),
                territory: "DE".into(),
                information_uris: vec!["https://www.bundesdruckerei.de".into()],
                services: vec![
                    ServiceInformation {
                        service_type: ServiceType::Pid,
                        service_name: "German eID PID Issuance".into(),
                        digital_identity: ServiceDigitalIdentity::X509Certificate(
                            b"BDR-PID-SIGNING-CERT".to_vec(),
                        ),
                        service_status: ServiceStatus::Granted,
                        status_starting_time: Utc::now(),
                        history: Vec::new(),
                    },
                    ServiceInformation {
                        service_type: ServiceType::CaQc,
                        service_name: "D-Trust Qualified CA".into(),
                        digital_identity: ServiceDigitalIdentity::X509Certificate(
                            b"DTRUST-CA-QC-CERT".to_vec(),
                        ),
                        service_status: ServiceStatus::Granted,
                        status_starting_time: Utc::now(),
                        history: Vec::new(),
                    },
                ],
            },
            TrustServiceProvider {
                name: "Deutsche Telekom Security GmbH".into(),
                trade_name: None,
                territory: "DE".into(),
                information_uris: vec!["https://www.telesec.de".into()],
                services: vec![
                    ServiceInformation {
                        service_type: ServiceType::WalletProvider,
                        service_name: "T-Wallet EUDI Solution".into(),
                        digital_identity: ServiceDigitalIdentity::X509Certificate(
                            b"TELEKOM-WALLET-CERT".to_vec(),
                        ),
                        service_status: ServiceStatus::Granted,
                        status_starting_time: Utc::now(),
                        history: Vec::new(),
                    },
                    ServiceInformation {
                        service_type: ServiceType::TsaQtst,
                        service_name: "TeleSec TimeStamp Service".into(),
                        digital_identity: ServiceDigitalIdentity::X509Certificate(
                            b"TELESEC-TSA-CERT".to_vec(),
                        ),
                        service_status: ServiceStatus::Granted,
                        status_starting_time: Utc::now(),
                        history: Vec::new(),
                    },
                ],
            },
            TrustServiceProvider {
                name: "Legacy Cert Authority".into(),
                trade_name: None,
                territory: "DE".into(),
                information_uris: vec![],
                services: vec![ServiceInformation {
                    service_type: ServiceType::CaPkc,
                    service_name: "Old PKI CA".into(),
                    digital_identity: ServiceDigitalIdentity::X509Certificate(
                        b"LEGACY-CA-CERT".to_vec(),
                    ),
                    service_status: ServiceStatus::Withdrawn,
                    status_starting_time: Utc::now(),
                    history: vec![ServiceHistoryEntry {
                        service_type: ServiceType::CaPkc,
                        service_status: ServiceStatus::Granted,
                        status_starting_time: Utc::now(),
                    }],
                }],
            },
        ],
    };

    // ── Display Trust List Info ──
    println!("Trust List: {}", tl.scheme_information.scheme_operator_name);
    println!("Territory:  {}", tl.scheme_information.scheme_territory);
    println!("Version:    {}", tl.scheme_information.tsl_version);
    println!("Sequence:   {}", tl.scheme_information.tsl_sequence_number);
    println!(
        "Issued:     {}",
        tl.scheme_information
            .list_issue_date_time
            .format("%Y-%m-%d %H:%M UTC")
    );
    println!();

    // ── List All Providers ──
    println!(
        "--- Trust Service Providers ({}) ---\n",
        tl.trust_service_providers.len()
    );

    for (i, tsp) in tl.trust_service_providers.iter().enumerate() {
        println!("  {}. {}", i + 1, tsp.name);
        if let Some(trade) = &tsp.trade_name {
            println!("     Trade name: {trade}");
        }
        for uri in &tsp.information_uris {
            println!("     URI: {uri}");
        }
        println!("     Services ({}):", tsp.services.len());
        for svc in &tsp.services {
            let status_icon = if svc.service_status.is_active() {
                "+"
            } else {
                "x"
            };
            let qualified = if svc.service_type.is_qualified() {
                " [QUALIFIED]"
            } else {
                ""
            };
            let eidas2 = if svc.service_type.is_eidas2() {
                " [eIDAS 2.0]"
            } else {
                ""
            };
            println!(
                "       [{status_icon}] {} — {}{qualified}{eidas2}",
                svc.service_name, svc.service_status
            );
            if !svc.history.is_empty() {
                println!(
                    "           History: {} status transitions",
                    svc.history.len()
                );
            }
        }
        println!();
    }

    // ── Load into Registry and Query ──
    println!("--- Registry Queries ---\n");

    let mut registry = TrustListRegistry::new();
    registry.load_trust_list(&tl);

    println!("  Total entries: {}", registry.entry_count());
    println!("  Active PID providers: {}", registry.pid_providers().len());
    println!(
        "  Active Wallet providers: {}",
        registry.wallet_providers().len()
    );
    println!(
        "  Active QEAA providers: {}",
        registry.qeaa_providers().len()
    );
    println!(
        "  eIDAS 2.0 services: {}",
        registry
            .find_by_territory("DE")
            .iter()
            .filter(|e| e.service.service_type.is_eidas2())
            .count()
    );

    println!("\nDone!");
}
