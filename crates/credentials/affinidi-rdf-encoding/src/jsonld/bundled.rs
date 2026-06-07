use serde_json::Value;
use std::sync::LazyLock;

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

static CREDENTIALS_V1: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("contexts/credentials-v1.jsonld"))
        .expect("bundled credentials-v1.jsonld is valid JSON")
});

static VDL_V1: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("contexts/vdl-v1.jsonld"))
        .expect("bundled vdl-v1.jsonld is valid JSON")
});

static VDL_AAMVA_V1: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("contexts/vdl-aamva-v1.jsonld"))
        .expect("bundled vdl-aamva-v1.jsonld is valid JSON")
});

/// Look up a bundled JSON-LD context by URL.
///
/// Returns the parsed `@context` value (not the wrapping object) if found.
pub fn get_bundled_context(url: &str) -> Option<&'static Value> {
    match url {
        "https://www.w3.org/ns/credentials/v2" => Some(&CREDENTIALS_V2),
        "https://www.w3.org/ns/credentials/examples/v2" => Some(&CREDENTIALS_EXAMPLES_V2),
        "https://w3id.org/security/data-integrity/v2" => Some(&DATA_INTEGRITY_V2),
        // AAMVA driver's license (vc-di-bbs pseudonym test credential).
        "https://www.w3.org/2018/credentials/v1" => Some(&CREDENTIALS_V1),
        "https://w3id.org/vdl/v1" => Some(&VDL_V1),
        "https://w3id.org/vdl/aamva/v1" => Some(&VDL_AAMVA_V1),
        _ => None,
    }
}
