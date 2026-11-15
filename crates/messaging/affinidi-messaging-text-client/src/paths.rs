//! Where the client keeps its state file and log.
//!
//! Both live in a per-user directory, so the client finds its identity
//! wherever it is started from:
//!
//! - `$XDG_CONFIG_HOME/affinidi-messaging-text-client/`, else
//!   `$HOME/.config/affinidi-messaging-text-client/` (Unix);
//! - `%APPDATA%\affinidi-messaging-text-client\` (Windows).
//!
//! For compatibility with earlier versions, a `config.json` in the current
//! directory is still used as the state file when one exists there.

use std::path::{Path, PathBuf};

const APP_DIR: &str = "affinidi-messaging-text-client";
const STATE_FILE: &str = "config.json";
const LOG_FILE: &str = "log.txt";

/// The resolved file locations for this run.
pub struct Paths {
    /// The state file (holds the client's private keys).
    pub state_file: PathBuf,
    /// The debug log.
    pub log_file: PathBuf,
    /// True when the state file is the legacy `./config.json`.
    pub legacy_state_file: bool,
}

impl Paths {
    /// Resolve the locations, creating the per-user directory (owner-only on
    /// Unix) if it does not exist.
    pub fn resolve() -> std::io::Result<Self> {
        let dir = user_dir()?;
        create_private_dir(&dir)?;

        let legacy = Path::new(STATE_FILE);
        let (state_file, legacy_state_file) = if legacy.is_file() {
            (legacy.to_path_buf(), true)
        } else {
            (dir.join(STATE_FILE), false)
        };

        Ok(Paths {
            state_file,
            log_file: dir.join(LOG_FILE),
            legacy_state_file,
        })
    }
}

fn user_dir() -> std::io::Result<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    };
    base.map(|b| b.join(APP_DIR)).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot find a per-user config directory: set XDG_CONFIG_HOME or HOME (APPDATA on Windows)",
        )
    })
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Open the log file for appending, created owner-only (`0600`) on Unix.
pub fn open_log(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    // An existing log from an earlier version may have been created with the
    // default (often world-readable) mode; tighten it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn the_log_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("text-client-log-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        drop(open_log(&path).unwrap());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_file(path).unwrap();
    }
}
