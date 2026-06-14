//! Regenerate the committed seed corpus for the fuzz targets.
//!
//! Run from the `fuzz/` directory:
//!
//! ```text
//! cargo run --bin gen_corpus
//! ```
//!
//! Writes valid envelopes (addressed to the fixed fuzz keys) under
//! `seeds/<target>/` (committed, read-only). The live, mutable `corpus/` that
//! libFuzzer writes to is gitignored — pass both dirs when running, e.g.
//! `cargo fuzz run unpack corpus/unpack seeds/unpack`.
//!
//! The envelopes are not byte-stable across runs (encryption draws a fresh
//! ephemeral key + IV), but they always decrypt under the fixed keys, so
//! re-running just refreshes an equivalent seed set. The `message` /
//! `message_structured` targets seed fine from the plaintext shapes.

use std::fs;
use std::path::Path;

use affinidi_messaging_didcomm_fuzz::seed_corpus;

fn main() -> std::io::Result<()> {
    let root = Path::new("seeds");
    let mut written = 0usize;
    for (rel, bytes) in seed_corpus() {
        let path = root.join(&rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, &bytes)?;
        written += 1;
    }
    // Mirror the encrypted/plaintext seeds into the message-parser corpora too,
    // so those targets start from realistic JSON.
    for (rel, bytes) in seed_corpus() {
        if rel.starts_with("unpack/plaintext-") {
            let name = rel.trim_start_matches("unpack/");
            for target in ["message", "message_structured"] {
                let path = root.join(target).join(name);
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&path, &bytes)?;
                written += 1;
            }
        }
    }
    // The decrypt target shares the JWE seeds from the unpack corpus.
    for (rel, bytes) in seed_corpus() {
        if rel.starts_with("unpack/anoncrypt-") || rel.starts_with("unpack/authcrypt-") {
            let name = rel.trim_start_matches("unpack/");
            let path = root.join("decrypt").join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, &bytes)?;
            written += 1;
        }
    }
    println!("wrote {written} seed files under seeds/");
    Ok(())
}
