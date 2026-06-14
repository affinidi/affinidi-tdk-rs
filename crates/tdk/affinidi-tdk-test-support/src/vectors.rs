/*!
 * Shared test-vector layout + loader (TI7).
 *
 * Test vectors (IETF/DIF KATs, W3C suites, JOSE fixtures, …) lived in four
 * crates with a bespoke `format!("{}/tests/fixtures/...", env!("CARGO_MANIFEST_DIR"))`
 * incantation each. This module defines one convention and one loader so adding
 * a vector is a drop-in.
 *
 * ## Convention
 *
 * Each crate keeps its vectors under **`<crate>/tests/vectors/<source>/…`**,
 * grouped by upstream source — e.g.:
 *
 * ```text
 * tests/vectors/
 *   bls12-381-sha-256/signature001.json   # DIF bbs-signature suite
 *   blind/bls12-381-sha-256.json          # draft-irtf-cfrg-bbs-blind-signatures
 *   rdfc10/test004-rdfc10.nq              # W3C rdf-canon suite (raw N-Quads)
 * ```
 *
 * The loader takes the crate's `CARGO_MANIFEST_DIR` plus a path **relative to
 * `tests/vectors/`**, so a test never hand-builds an absolute path:
 *
 * ```no_run
 * use affinidi_tdk_test_support::vectors;
 *
 * // JSON vector → serde_json::Value
 * let v = vectors::load_json(env!("CARGO_MANIFEST_DIR"), "bls12-381-sha-256/signature001.json").unwrap();
 * // Raw text vector (e.g. N-Quads)
 * let nq = vectors::load_str(env!("CARGO_MANIFEST_DIR"), "rdfc10/test004-rdfc10.nq").unwrap();
 * // Every *.json in a directory, sorted by file name
 * for (name, value) in vectors::load_json_dir(env!("CARGO_MANIFEST_DIR"), "bls12-381-sha-256").unwrap() {
 *     let _ = (name, value);
 * }
 * ```
 */

use std::path::{Path, PathBuf};

use serde_json::Value;

/// Errors from loading a test vector.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VectorError {
    /// The vector file could not be read.
    #[error("reading vector `{path}`: {source}")]
    Read {
        /// Path that failed.
        path: String,
        /// Underlying IO error.
        source: std::io::Error,
    },

    /// The vector file is not valid JSON.
    #[error("parsing vector `{path}` as JSON: {source}")]
    Parse {
        /// Path that failed.
        path: String,
        /// Underlying JSON error.
        source: serde_json::Error,
    },

    /// A directory could not be listed.
    #[error("listing vector directory `{path}`: {source}")]
    List {
        /// Directory that failed.
        path: String,
        /// Underlying IO error.
        source: std::io::Error,
    },
}

/// The `tests/vectors` root for a crate, given its `CARGO_MANIFEST_DIR`.
pub fn vectors_root(manifest_dir: impl AsRef<Path>) -> PathBuf {
    manifest_dir.as_ref().join("tests").join("vectors")
}

/// Load a vector file as raw text — for non-JSON vectors (N-Quads, PEM, …).
/// `rel` is relative to `tests/vectors/`.
pub fn load_str(
    manifest_dir: impl AsRef<Path>,
    rel: impl AsRef<Path>,
) -> Result<String, VectorError> {
    let path = vectors_root(manifest_dir).join(rel);
    std::fs::read_to_string(&path).map_err(|source| VectorError::Read {
        path: path.display().to_string(),
        source,
    })
}

/// Load and parse a JSON vector into a [`serde_json::Value`]. `rel` is relative
/// to `tests/vectors/`.
pub fn load_json(
    manifest_dir: impl AsRef<Path>,
    rel: impl AsRef<Path>,
) -> Result<Value, VectorError> {
    let manifest_dir = manifest_dir.as_ref();
    let rel = rel.as_ref();
    let text = load_str(manifest_dir, rel)?;
    serde_json::from_str(&text).map_err(|source| VectorError::Parse {
        path: vectors_root(manifest_dir).join(rel).display().to_string(),
        source,
    })
}

/// Load every `*.json` vector directly in `rel_dir` (relative to
/// `tests/vectors/`), returned as `(file_stem, value)` pairs sorted by file
/// name so iteration order is deterministic across platforms.
pub fn load_json_dir(
    manifest_dir: impl AsRef<Path>,
    rel_dir: impl AsRef<Path>,
) -> Result<Vec<(String, Value)>, VectorError> {
    let dir = vectors_root(&manifest_dir).join(rel_dir.as_ref());

    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map_err(|source| VectorError::List {
            path: dir.display().to_string(),
            source,
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();

    let mut out = Vec::with_capacity(files.len());
    for path in files {
        let text = std::fs::read_to_string(&path).map_err(|source| VectorError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let value = serde_json::from_str(&text).map_err(|source| VectorError::Parse {
            path: path.display().to_string(),
            source,
        })?;
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        out.push((stem, value));
    }
    Ok(out)
}
