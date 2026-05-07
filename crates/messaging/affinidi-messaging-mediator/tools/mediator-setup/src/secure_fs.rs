//! Mode-restricted file writes for sensitive wizard outputs.
//!
//! `std::fs::write` honours the process umask, which on most defaults
//! leaves files world-readable (`0o644`). Anything we generate that
//! holds key material, secret-backend URLs, or DID material we'd rather
//! not have a co-tenant read should land at `0o600`. This module
//! centralises the pattern so callers don't each spell out the
//! `OpenOptions + mode + write_all` dance, and so the non-Unix fallback
//! lives in one place.
//!
//! On Unix the helper opens with `O_CREAT | O_TRUNC | O_WRONLY` and
//! mode `0o600`. The `truncate` flag preserves the historical
//! `fs::write` semantics (clobber existing contents); the mode flag
//! sets the *new file's* permission bits — pre-existing files keep
//! whatever perms they already had, which is fine because the wizard
//! only ever creates fresh artefacts (no in-place edits of secrets).
//!
//! On non-Unix the helper falls back to `fs::write`. Windows ACLs are
//! a different model and the wizard's threat-model on Windows assumes
//! the operator owns the directory anyway.
//!
//! Files that are *not* sensitive (Dockerfile, `atm-functions.lua`,
//! `docker-compose.yml`) deliberately don't go through this helper —
//! their world-readable default is correct.

use std::fs;
use std::io;
use std::path::Path;

/// Mode bits applied to sensitive file writes on Unix.
#[cfg(unix)]
const SENSITIVE_MODE: u32 = 0o600;

/// Write `contents` to `path` with restrictive permissions on Unix
/// (`0o600`); plain `fs::write` semantics on non-Unix.
///
/// Preserves the rest of `fs::write`'s behaviour — creates the file
/// if missing, truncates if present, leaves the parent directory
/// alone (callers are responsible for `create_dir_all` first if the
/// parent might not exist).
pub fn write_sensitive<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> io::Result<()> {
    write_sensitive_inner(path.as_ref(), contents.as_ref())
}

#[cfg(unix)]
fn write_sensitive_inner(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(SENSITIVE_MODE)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_sensitive_inner(path: &Path, contents: &[u8]) -> io::Result<()> {
    // Windows / WASI / other non-Unix targets: fall back to the
    // unrestricted write. The operator's threat model on those
    // platforms is different (per-user profile dirs, ACLs) and
    // the wizard isn't trying to harden against it.
    fs::write(path, contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn write_sensitive_creates_file_with_0o600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.txt");
        write_sensitive(&path, b"hello").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "wizard's sensitive writes must be owner-only readable"
        );
        assert_eq!(fs::read(&path).unwrap(), b"hello");
    }

    #[test]
    fn write_sensitive_truncates_existing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.txt");
        write_sensitive(&path, b"long original contents").unwrap();
        write_sensitive(&path, b"short").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"short");
    }

    #[cfg(unix)]
    #[test]
    fn write_sensitive_preserves_existing_perms_on_clobber() {
        // OpenOptions::mode() only applies on file *creation*. If the
        // operator widens perms manually (`chmod 0o644`), a re-run
        // doesn't silently re-tighten. Documented contract — covered
        // by this test so we don't accidentally start re-applying mode
        // on every write later.
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.txt");
        write_sensitive(&path, b"v1").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_sensitive(&path, b"v2").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "operator-widened perms must persist");
    }
}
