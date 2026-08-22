//! Conformance against the crate this one replaced.
//!
//! Every `did-*.jsonld` file in this directory is a fixture copied verbatim
//! from the spruceid `did-pkh` 0.3.2 test suite. Each one is resolved by DID —
//! taken from the fixture's own `id` — and compared in full, so any divergence
//! in document shape, `@context`, verification-method type or relationship
//! ordering fails the build.

use serde_json::Value;

/// Fixtures and the DID each one describes, keyed by file so a failure names
/// the case. Loaded at compile time so a missing fixture is a build error
/// rather than a silently skipped test.
const FIXTURES: &[(&str, &str)] = &[
    ("did-tz1.jsonld", include_str!("did-tz1.jsonld")),
    ("did-tz2.jsonld", include_str!("did-tz2.jsonld")),
    ("did-tz3.jsonld", include_str!("did-tz3.jsonld")),
    (
        "did-tz1-legacy.jsonld",
        include_str!("did-tz1-legacy.jsonld"),
    ),
    (
        "did-tz2-legacy.jsonld",
        include_str!("did-tz2-legacy.jsonld"),
    ),
    (
        "did-tz3-legacy.jsonld",
        include_str!("did-tz3-legacy.jsonld"),
    ),
    ("did-eth.jsonld", include_str!("did-eth.jsonld")),
    (
        "did-eth-legacy.jsonld",
        include_str!("did-eth-legacy.jsonld"),
    ),
    ("did-celo.jsonld", include_str!("did-celo.jsonld")),
    (
        "did-celo-legacy.jsonld",
        include_str!("did-celo-legacy.jsonld"),
    ),
    ("did-poly.jsonld", include_str!("did-poly.jsonld")),
    (
        "did-poly-legacy.jsonld",
        include_str!("did-poly-legacy.jsonld"),
    ),
    ("did-btc.jsonld", include_str!("did-btc.jsonld")),
    (
        "did-btc-legacy.jsonld",
        include_str!("did-btc-legacy.jsonld"),
    ),
    ("did-doge.jsonld", include_str!("did-doge.jsonld")),
    (
        "did-doge-legacy.jsonld",
        include_str!("did-doge-legacy.jsonld"),
    ),
    ("did-sol.jsonld", include_str!("did-sol.jsonld")),
    (
        "did-sol-legacy.jsonld",
        include_str!("did-sol-legacy.jsonld"),
    ),
    ("did-aleo.jsonld", include_str!("did-aleo.jsonld")),
];

#[test]
fn every_fixture_resolves_identically() {
    for (name, contents) in FIXTURES {
        let expected: Value = serde_json::from_str(contents)
            .unwrap_or_else(|e| panic!("{name} is not valid JSON: {e}"));
        let did = expected["id"]
            .as_str()
            .unwrap_or_else(|| panic!("{name} has no string `id`"));

        let resolved = affinidi_did_pkh::resolve(did)
            .unwrap_or_else(|e| panic!("{name}: resolving {did} failed: {e}"));
        let actual = serde_json::to_value(resolved).unwrap();

        assert_eq!(actual, expected, "{name} ({did})");
    }
}

/// The suite is only meaningful if it actually covers every namespace and both
/// identifier forms; guard against a fixture being dropped from the list above.
#[test]
fn fixture_coverage_is_complete() {
    assert_eq!(FIXTURES.len(), 19);

    let dids: Vec<&str> = FIXTURES
        .iter()
        .map(|(_, c)| {
            serde_json::from_str::<Value>(c).unwrap()["id"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .map(|s| Box::leak(s.into_boxed_str()) as &str)
        .collect();

    for namespace in ["tezos", "eip155", "bip122", "solana", "aleo"] {
        assert!(
            dids.iter()
                .any(|d| d.starts_with(&format!("did:pkh:{namespace}:"))),
            "no CAIP-10 fixture for {namespace}"
        );
    }
    for legacy in ["tz", "eth", "celo", "poly", "btc", "doge", "sol"] {
        assert!(
            dids.iter()
                .any(|d| d.starts_with(&format!("did:pkh:{legacy}:"))),
            "no legacy fixture for {legacy}"
        );
    }
}
