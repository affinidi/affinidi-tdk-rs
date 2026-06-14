//! Regenerate the committed seed corpus for the SD-JWT fuzz targets.
//!
//! Run from the `fuzz/` directory:
//!
//! ```text
//! cargo run --bin gen_corpus
//! ```
//!
//! Writes serialized valid SD-JWTs under `seeds/<target>/` (committed,
//! read-only). The live, mutable `corpus/` libFuzzer writes to is gitignored —
//! run with both dirs, e.g. `cargo fuzz run verify corpus/verify seeds/verify`.

use std::fs;
use std::path::Path;

use affinidi_sd_jwt_fuzz::seed_corpus;

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
    println!("wrote {written} seed files under seeds/");
    Ok(())
}
