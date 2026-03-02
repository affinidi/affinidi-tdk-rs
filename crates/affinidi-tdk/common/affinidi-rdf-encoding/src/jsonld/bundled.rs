use std::sync::LazyLock;
use serde_json::Value;

static CREDENTIALS_V2: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("contexts/credentials-v2.jsonld"))
        .expect("bundled credentials-v2.jsonld is valid JSON")
});

static CREDENTIALS_EXAMPLES_V2: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("contexts/credentials-examples-v2.jsonld"))
        .expect("bundled credentials-examples-v2.jsonld is valid JSON")
});

static DATA_INTEGRITY_V2: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("contexts/data-integrity-v2.jsonld"))
        .expect("bundled data-integrity-v2.jsonld is valid JSON")
});

/// Look up a bundled JSON-LD context by URL.
///
/// Returns the parsed `@context` value (not the wrapping object) if found.
pub fn get_bundled_context(url: &str) -> Option<&'static Value> {
    match url {
        "https://www.w3.org/ns/credentials/v2" => Some(&CREDENTIALS_V2),
        "https://www.w3.org/ns/credentials/examples/v2" => Some(&CREDENTIALS_EXAMPLES_V2),
        "https://w3id.org/security/data-integrity/v2" => Some(&DATA_INTEGRITY_V2),
        _ => None,
    }
}
