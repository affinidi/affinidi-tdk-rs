//! Resolving a relative path written in a mediator configuration file.
//!
//! A path in a config file is resolved against **that file's directory**, the
//! way a reader would expect. Until this existed every such path was resolved
//! against the process's working directory instead, so starting the mediator
//! with `--config /etc/mediator/mediator.toml` from anywhere else failed with
//! `Couldn't ready database functions_file (./conf/atm-functions.lua)` —
//! Keyring's VTI-07. The TLS certificate and key paths had the same defect;
//! they only ever worked because everyone started the mediator from the
//! repository root.
//!
//! Switching the rule outright would move where a running deployment finds its
//! TLS private key, so the old behaviour is kept as a **fallback**: a path that
//! is absent beside the config file but present relative to the working
//! directory still resolves, and says so through [`PathSource::WorkingDir`] so
//! the caller can warn. This module logs nothing: config is read before the
//! tracing subscriber exists, and a warning emitted then is silently dropped.
//! Callers warn once logging is up.

use std::path::{Path, PathBuf};

/// Where a configured path was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathSource {
    /// Already absolute; used as written.
    Absolute,
    /// Relative, and found beside the configuration file. The intended rule.
    ConfigDir,
    /// Relative, absent beside the configuration file, and found relative to
    /// the working directory instead. The legacy rule — deprecated, and the
    /// caller should say so.
    WorkingDir,
    /// Relative and found in neither place. The returned path is the
    /// config-relative one, so the error a caller reports names the location
    /// the rule now points at rather than the legacy one.
    Unresolved,
}

/// A configured path after resolution, and how it was resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPath {
    pub path: PathBuf,
    pub source: PathSource,
}

/// Resolve `raw`, a path as written in the configuration file at
/// `config_file`, against that file's directory, falling back to the working
/// directory — see the module docs for why the fallback exists.
pub fn resolve_config_relative(config_file: &Path, raw: &str) -> ResolvedPath {
    let written = Path::new(raw);
    if written.is_absolute() {
        return ResolvedPath {
            path: written.to_path_buf(),
            source: PathSource::Absolute,
        };
    }

    // `parent()` of a bare file name is `Some("")`, which joins to a relative
    // path and would quietly mean "the working directory" — the very rule
    // being replaced. Spell it as `.` so that case is explicit.
    let config_dir = match config_file.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let beside_config = config_dir.join(written);

    if beside_config.exists() {
        ResolvedPath {
            path: beside_config,
            source: PathSource::ConfigDir,
        }
    } else if written.exists() {
        ResolvedPath {
            path: written.to_path_buf(),
            source: PathSource::WorkingDir,
        }
    } else {
        ResolvedPath {
            path: beside_config,
            source: PathSource::Unresolved,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn an_absolute_path_is_used_as_written() {
        let r = resolve_config_relative(Path::new("/etc/m/mediator.toml"), "/abs/x.lua");
        assert_eq!(r.path, PathBuf::from("/abs/x.lua"));
        assert_eq!(r.source, PathSource::Absolute);
    }

    /// VTI-07 itself: a config file elsewhere, started from an unrelated
    /// working directory, finds the file beside the config.
    #[test]
    fn a_relative_path_resolves_beside_the_config_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("atm-functions.lua"), "").unwrap();
        let config = dir.path().join("mediator.toml");

        let r = resolve_config_relative(&config, "./atm-functions.lua");
        assert_eq!(r.source, PathSource::ConfigDir);
        assert_eq!(r.path, dir.path().join("./atm-functions.lua"));
    }

    /// Nothing that works today stops working: a path found only relative to
    /// the working directory still resolves, and is reported as legacy.
    #[test]
    fn a_path_found_only_from_the_working_directory_still_resolves_as_legacy() {
        // `Cargo.toml` exists relative to the test's working directory (the
        // crate root) and not beside a config file in an empty temp dir.
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("mediator.toml");

        let r = resolve_config_relative(&config, "Cargo.toml");
        assert_eq!(r.source, PathSource::WorkingDir);
        assert_eq!(r.path, PathBuf::from("Cargo.toml"));
    }

    /// Present in both places, the config-relative one wins — that is the
    /// behaviour change, and the one case where the answer moves.
    #[test]
    fn beside_the_config_wins_over_the_working_directory() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("Cargo.toml"), "").unwrap();
        let config = dir.path().join("mediator.toml");

        let r = resolve_config_relative(&config, "Cargo.toml");
        assert_eq!(r.source, PathSource::ConfigDir);
        assert_eq!(r.path, dir.path().join("Cargo.toml"));
    }

    /// Found nowhere, the error should name where the rule now looks.
    #[test]
    fn an_unresolved_path_names_the_config_relative_location() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("mediator.toml");

        let r = resolve_config_relative(&config, "nowhere/missing.lua");
        assert_eq!(r.source, PathSource::Unresolved);
        assert_eq!(r.path, dir.path().join("nowhere/missing.lua"));
    }

    /// A bare config file name has an empty parent; that must still resolve
    /// against `.` explicitly rather than by accident.
    #[test]
    fn a_bare_config_file_name_resolves_against_the_current_directory() {
        let r = resolve_config_relative(Path::new("mediator.toml"), "Cargo.toml");
        assert_eq!(r.source, PathSource::ConfigDir);
        assert_eq!(r.path, PathBuf::from("./Cargo.toml"));
    }
}
