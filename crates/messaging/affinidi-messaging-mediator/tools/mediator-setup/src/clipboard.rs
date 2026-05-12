//! Copy-to-clipboard helper with OSC 52 + `arboard` fallback.
//!
//! The wizard runs over SSH about as often as it runs locally. The
//! `arboard` crate talks directly to the OS clipboard via X11 /
//! Wayland / macOS APIs — that's perfect for a local terminal but
//! useless across an SSH session, where the operator's machine is
//! not the one running the wizard.
//!
//! OSC 52 is a terminal escape sequence (`\x1b]52;c;<base64>\x1b\\`)
//! that the *terminal emulator itself* interprets and writes to the
//! local clipboard. It travels through SSH transparently — the
//! escape bytes flow through the TTY just like any other output, and
//! the operator's terminal handles them.
//!
//! ## Dispatch strategy
//!
//! - On SSH (`SSH_CONNECTION` / `SSH_TTY` / `SSH_CLIENT` set in env):
//!   try OSC 52 first, fall back to `arboard` on failure. Operators
//!   on supporting terminals get clipboard support; the rare
//!   non-supporting case can still hit a local clipboard if the
//!   wizard machine happens to have one.
//! - Locally: try `arboard` first, fall back to OSC 52. `arboard`
//!   is the more reliable path on a local desktop; OSC 52 is the
//!   fallback for headless desktops where `arboard` finds no
//!   clipboard daemon.
//!
//! ## Empty payloads are refused
//!
//! Several terminals treat OSC 52 with an empty base64 payload as
//! "clear the clipboard". A code path that accidentally hands us
//! an empty string would silently wipe whatever the operator just
//! copied — and every subsequent paste would look "blank". The
//! dispatcher rejects empty / whitespace-only input up front with
//! a clear error so the caller can surface a friendlier "nothing
//! to copy" message instead of clobbering the clipboard.
//!
//! ## Multiplexer passthrough
//!
//! Bare OSC 52 dies at a `tmux` or GNU `screen` pane boundary unless
//! the operator has explicitly enabled clipboard forwarding. For
//! both multiplexers we emit a DCS-passthrough-wrapped variant in
//! *addition* to the bare sequence — the multiplexer eats one form
//! and forwards the other, and the outer terminal receives exactly
//! one OSC 52 either way.
//!
//! - tmux: `\x1bPtmux;\x1b<OSC52>\x1b\\` — requires `set -g
//!   allow-passthrough on` (off by default in tmux 3.3+) or
//!   `set -g set-clipboard on`. We send both shapes so either
//!   setting works.
//! - screen: `\x1bP<OSC52 with inner ST replaced by \x1b\\>\x1b\\` —
//!   GNU screen's DCS passthrough convention.
//!
//! ## Terminal transport
//!
//! Under the wizard's TUI, `ratatui` owns `io::stdout()` through a
//! buffered `CrosstermBackend`. Direct writes to `io::stdout()` can
//! race against ratatui's buffered draw cycle. We emit OSC 52 to
//! `/dev/tty` instead — the controlling terminal of the process,
//! reached through a fresh file handle that bypasses ratatui's
//! buffer entirely. Falls back to `io::stdout()` if `/dev/tty`
//! can't be opened (rare: headless CI, non-TTY runs).
//!
//! ## Honesty about confirmation
//!
//! Neither path can confirm the clipboard was *actually* set. OSC 52
//! emits to the TTY and trusts the terminal; `arboard` opens a handle
//! and trusts the OS. The returned [`CopyMethod`] reports which path
//! was *attempted successfully* — an error from the underlying
//! library means we could not even attempt that path. Operators
//! confirm by pasting.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use std::io::Write;

/// Maximum payload accepted by [`copy_to_clipboard`]. Most terminals
/// cap OSC 52 payloads in the 75–100 KB range; 70 KB sits
/// comfortably under the conservative end. No current copyable
/// surface in the wizard approaches this — guard is defensive.
pub const MAX_PAYLOAD_BYTES: usize = 70 * 1024;

/// Which transport delivered the clipboard text to the operator's
/// machine. Surfaced in the wizard's "Copied!" status so operators
/// can tell which path took (helpful when "Copied!" lit up but the
/// local clipboard didn't change — usually a sign the SSH terminal
/// dropped OSC 52 silently).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyMethod {
    /// Sent via the OSC 52 terminal escape sequence. SSH-friendly;
    /// requires terminal support (most modern terminals;
    /// `tmux` needs `set -g set-clipboard on`).
    Osc52,
    /// Sent via the `arboard` crate to the local OS clipboard. Works
    /// on local desktop terminals; fails over SSH when the wizard
    /// host has no clipboard daemon.
    Arboard,
}

impl CopyMethod {
    /// Operator-facing short label for the wizard's status footer.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Osc52 => "OSC 52 (terminal)",
            Self::Arboard => "system clipboard",
        }
    }
}

/// Copy `text` to the operator's clipboard, picking OSC 52 or
/// `arboard` based on whether the wizard appears to be running over
/// SSH.
///
/// Returns the [`CopyMethod`] that successfully attempted the copy,
/// or an error string. Empty / whitespace-only `text` is rejected
/// without dispatching to either transport — see the module docs
/// for why.
pub fn copy_to_clipboard(text: &str) -> Result<CopyMethod, String> {
    copy_with(text, Env::from_process(), try_arboard, try_osc52_with_env)
}

/// Subset of the process environment that influences clipboard
/// dispatch. Bundled so tests can stub the whole thing without
/// touching real env vars (which would race across parallel tests).
#[derive(Debug, Clone, Default)]
struct Env {
    on_ssh: bool,
    /// Value of `$TMUX`, when set + non-empty. Drives DCS-passthrough
    /// wrapping for the tmux clipboard path.
    tmux: Option<String>,
    /// Value of `$STY`, when set + non-empty. Drives GNU screen DCS
    /// passthrough wrapping. Detected separately from tmux so the
    /// (very rare) nested screen-in-tmux case still emits both
    /// wrappers.
    screen: Option<String>,
}

impl Env {
    fn from_process() -> Self {
        Self::from_getter(|k| std::env::var(k).ok())
    }

    fn from_getter<F: Fn(&str) -> Option<String>>(getter: F) -> Self {
        let nonempty = |k: &str| getter(k).filter(|v| !v.is_empty());
        Self {
            on_ssh: ["SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT"]
                .iter()
                .any(|k| nonempty(k).is_some()),
            tmux: nonempty("TMUX"),
            screen: nonempty("STY"),
        }
    }
}

/// Internal dispatch point — visible for tests so we can stub the
/// two transports independently and exercise both fallback paths
/// without touching the real OS clipboard or stdout.
fn copy_with<A, O>(text: &str, env: Env, arboard: A, osc52: O) -> Result<CopyMethod, String>
where
    A: FnOnce(&str) -> Result<(), String>,
    O: FnOnce(&str, &Env) -> Result<(), String>,
{
    if text.is_empty() {
        return Err("nothing to copy (empty payload)".to_string());
    }
    if text.chars().all(char::is_whitespace) {
        return Err("nothing to copy (whitespace only)".to_string());
    }
    if text.len() > MAX_PAYLOAD_BYTES {
        return Err(format!(
            "payload {} bytes exceeds OSC 52 cap of {} bytes — truncate before copying",
            text.len(),
            MAX_PAYLOAD_BYTES
        ));
    }
    if env.on_ssh {
        match osc52(text, &env) {
            Ok(()) => Ok(CopyMethod::Osc52),
            Err(osc52_err) => match arboard(text) {
                Ok(()) => Ok(CopyMethod::Arboard),
                Err(arboard_err) => Err(format!("OSC 52: {osc52_err}; arboard: {arboard_err}")),
            },
        }
    } else {
        match arboard(text) {
            Ok(()) => Ok(CopyMethod::Arboard),
            Err(arboard_err) => match osc52(text, &env) {
                Ok(()) => Ok(CopyMethod::Osc52),
                Err(osc52_err) => Err(format!("arboard: {arboard_err}; OSC 52: {osc52_err}")),
            },
        }
    }
}

/// Build the OSC 52 escape sequence for `text`. Pure — separated
/// from the IO so tests can inspect the exact bytes.
///
/// Format: `\x1b]52;c;<base64>\x1b\\`. The trailing `\x1b\\` is the
/// String Terminator (ST). We intentionally do not use the BEL
/// (`\x07`) terminator some implementations accept — `tmux` only
/// honours ST in passthrough mode, and modern terminals all accept
/// ST.
fn format_osc52(text: &str) -> String {
    let encoded = B64.encode(text.as_bytes());
    format!("\x1b]52;c;{encoded}\x1b\\")
}

/// Wrap an OSC 52 sequence in tmux DCS passthrough. Inside the DCS
/// payload, every literal `\x1b` is replaced with `\x1b\x1b` per
/// the tmux passthrough protocol — otherwise the inner ST would
/// terminate the outer DCS prematurely.
///
/// Works when the operator has `set -g allow-passthrough on` in
/// tmux. tmux 3.3+ defaults this off for security, so we ALSO
/// send the bare OSC 52 (see [`build_osc52_payload`]) — the
/// other branch covers operators relying on `set -g set-clipboard
/// on` instead.
fn wrap_tmux(osc52: &str) -> String {
    let inner = osc52.replace('\x1b', "\x1b\x1b");
    format!("\x1bPtmux;{inner}\x1b\\")
}

/// Wrap an OSC 52 sequence in GNU screen's DCS passthrough. screen's
/// passthrough swallows the inner ST, so we rewrite the inner
/// `\x1b\\` (the OSC 52 ST) into the screen-specific `\x1b\\`
/// sequence inside a DCS frame. Implementation matches the
/// `terminfo` / vim / neovim convention for screen passthrough.
fn wrap_screen(osc52: &str) -> String {
    // screen's DCS payload may not contain a raw ST. Re-emit the
    // inner OSC 52 with its ST stripped, wrap with the outer DCS,
    // and re-add a single ST at the end.
    let stripped = osc52.trim_end_matches("\x1b\\");
    format!("\x1bP{stripped}\x1b\\")
}

/// Build the full byte stream we'll write to the terminal:
/// the bare OSC 52, optionally followed by tmux / screen DCS
/// passthrough variants. Each is a no-op on terminals that don't
/// recognise it, so emitting both forms is safe and gives us the
/// widest reach across tmux configurations.
fn build_osc52_payload(text: &str, env: &Env) -> String {
    let bare = format_osc52(text);
    let mut out = String::with_capacity(bare.len() * 2);
    out.push_str(&bare);
    if env.tmux.is_some() {
        out.push_str(&wrap_tmux(&bare));
    }
    if env.screen.is_some() {
        out.push_str(&wrap_screen(&bare));
    }
    out
}

/// Write the OSC 52 sequence to `w` and flush.
fn emit_osc52_to<W: Write>(text: &str, env: &Env, w: &mut W) -> std::io::Result<()> {
    let seq = build_osc52_payload(text, env);
    w.write_all(seq.as_bytes())?;
    w.flush()
}

/// Production OSC 52 emitter — writes to `/dev/tty` when available,
/// falling back to `io::stdout()`. Going via `/dev/tty` keeps the
/// escape sequence off ratatui's `BufWriter` so it can't race with
/// a buffered TUI redraw.
fn try_osc52_with_env(text: &str, env: &Env) -> Result<(), String> {
    if let Some(mut tty) = open_tty_writer() {
        return emit_osc52_to(text, env, &mut tty).map_err(|e| format!("/dev/tty: {e}"));
    }
    emit_osc52_to(text, env, &mut std::io::stdout()).map_err(|e| format!("stdout: {e}"))
}

/// Open `/dev/tty` for writing. Returns `None` on Windows (no
/// `/dev/tty`) or when the file can't be opened — typically a
/// non-interactive run (cron, CI) where there is no controlling
/// terminal. Callers fall back to stdout in that case.
#[cfg(unix)]
fn open_tty_writer() -> Option<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .ok()
}

#[cfg(not(unix))]
fn open_tty_writer() -> Option<std::fs::File> {
    None
}

/// Production arboard caller. Constructs a fresh clipboard handle
/// each call — `arboard::Clipboard` is not `Send` and we don't
/// keep a long-lived handle anywhere in the wizard.
fn try_arboard(text: &str) -> Result<(), String> {
    arboard::Clipboard::new()
        .and_then(|mut c| c.set_text(text))
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_with(map: &[(&str, &str)]) -> Env {
        let owned: HashMap<String, String> = map
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect();
        Env::from_getter(move |k| owned.get(k).cloned())
    }

    #[test]
    fn ssh_env_detected_via_ssh_connection() {
        assert!(env_with(&[("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 5000")]).on_ssh);
    }

    #[test]
    fn ssh_env_detected_via_ssh_tty() {
        assert!(env_with(&[("SSH_TTY", "/dev/pts/3")]).on_ssh);
    }

    #[test]
    fn ssh_env_detected_via_ssh_client() {
        assert!(env_with(&[("SSH_CLIENT", "10.0.0.1 5000 22")]).on_ssh);
    }

    #[test]
    fn ssh_env_returns_false_when_no_vars_set() {
        assert!(!env_with(&[]).on_ssh);
    }

    #[test]
    fn ssh_env_ignores_empty_string_values() {
        // Some shells export the var as empty when not actually
        // inside an SSH session; treat that as "not SSH".
        assert!(!env_with(&[("SSH_CONNECTION", "")]).on_ssh);
    }

    #[test]
    fn tmux_detected_when_var_set() {
        let env = env_with(&[("TMUX", "/tmp/tmux-1000/default,12345,0")]);
        assert!(env.tmux.is_some());
    }

    #[test]
    fn tmux_ignored_when_empty() {
        let env = env_with(&[("TMUX", "")]);
        assert!(env.tmux.is_none());
    }

    #[test]
    fn screen_detected_via_sty() {
        let env = env_with(&[("STY", "12345.pts-0.host")]);
        assert!(env.screen.is_some());
    }

    #[test]
    fn osc52_format_uses_st_terminator() {
        let s = format_osc52("hi");
        assert!(s.starts_with("\x1b]52;c;"));
        assert!(s.ends_with("\x1b\\"));
        // The base64 of "hi" is "aGk=".
        assert!(s.contains("aGk="));
    }

    #[test]
    fn osc52_emits_to_writer_bare_when_no_multiplexer() {
        let mut buf: Vec<u8> = Vec::new();
        emit_osc52_to("hi", &env_with(&[]), &mut buf).unwrap();
        let written = String::from_utf8(buf).unwrap();
        assert_eq!(written, format_osc52("hi"));
    }

    #[test]
    fn tmux_wrap_doubles_inner_escape_bytes() {
        let inner = format_osc52("hi");
        let wrapped = wrap_tmux(&inner);
        assert!(wrapped.starts_with("\x1bPtmux;"));
        assert!(wrapped.ends_with("\x1b\\"));
        // The inner OSC 52's leading \x1b]52;c; becomes
        // \x1b\x1b]52;c; under tmux DCS passthrough.
        assert!(wrapped.contains("\x1b\x1b]52;c;"));
        // And the inner ST gets its \x1b doubled too.
        assert!(wrapped.contains("aGk=\x1b\x1b\\"));
    }

    #[test]
    fn screen_wrap_drops_inner_st_and_re_adds_outer() {
        let inner = format_osc52("hi");
        let wrapped = wrap_screen(&inner);
        assert!(wrapped.starts_with("\x1bP\x1b]52;c;"));
        assert!(wrapped.ends_with("\x1b\\"));
        // Exactly one ST at the end — the inner one is consumed.
        assert_eq!(wrapped.matches("\x1b\\").count(), 1);
    }

    #[test]
    fn osc52_payload_includes_tmux_wrap_when_tmux_set() {
        let env = env_with(&[("TMUX", "/tmp/tmux/sock,1,0")]);
        let payload = build_osc52_payload("hi", &env);
        // Bare form first…
        assert!(payload.starts_with(&format_osc52("hi")));
        // …then the tmux DCS passthrough.
        assert!(payload.contains("\x1bPtmux;\x1b\x1b]52;c;"));
    }

    #[test]
    fn osc52_payload_includes_screen_wrap_when_sty_set() {
        let env = env_with(&[("STY", "12345.pts-0.host")]);
        let payload = build_osc52_payload("hi", &env);
        assert!(payload.contains("\x1bP\x1b]52;c;"));
    }

    #[test]
    fn osc52_payload_skips_wrappers_outside_multiplexers() {
        let env = env_with(&[]);
        let payload = build_osc52_payload("hi", &env);
        assert!(!payload.contains("\x1bPtmux;"));
        // Outside screen we shouldn't see a leading DCS introducer.
        assert!(!payload.contains("\x1bP\x1b]"));
    }

    #[test]
    fn dispatch_on_ssh_tries_osc52_first() {
        let result = copy_with(
            "test",
            env_with(&[("SSH_CONNECTION", "1.1.1.1 22 2.2.2.2 5000")]),
            |_| Err("arboard would have been called".into()),
            |_, _| Ok(()),
        );
        assert_eq!(result, Ok(CopyMethod::Osc52));
    }

    #[test]
    fn dispatch_on_ssh_falls_back_to_arboard_when_osc52_fails() {
        let result = copy_with(
            "test",
            env_with(&[("SSH_CONNECTION", "1.1.1.1 22 2.2.2.2 5000")]),
            |_| Ok(()),
            |_, _| Err("terminal does not support OSC 52".into()),
        );
        assert_eq!(result, Ok(CopyMethod::Arboard));
    }

    #[test]
    fn dispatch_locally_tries_arboard_first() {
        let result = copy_with(
            "test",
            env_with(&[]),
            |_| Ok(()),
            |_, _| Err("osc52 would have been called".into()),
        );
        assert_eq!(result, Ok(CopyMethod::Arboard));
    }

    #[test]
    fn dispatch_locally_falls_back_to_osc52_when_arboard_fails() {
        let result = copy_with(
            "test",
            env_with(&[]),
            |_| Err("no clipboard daemon".into()),
            |_, _| Ok(()),
        );
        assert_eq!(result, Ok(CopyMethod::Osc52));
    }

    #[test]
    fn dispatch_returns_combined_err_when_both_methods_fail() {
        let err = copy_with(
            "test",
            env_with(&[("SSH_CONNECTION", "1.1.1.1 22 2.2.2.2 5000")]),
            |_| Err("no clipboard daemon".into()),
            |_, _| Err("OSC 52 not supported".into()),
        )
        .unwrap_err();
        assert!(err.contains("OSC 52: OSC 52 not supported"));
        assert!(err.contains("arboard: no clipboard daemon"));
    }

    #[test]
    fn dispatch_rejects_empty_payload() {
        // Empty payload would emit an OSC 52 with empty base64, which
        // many terminals interpret as "clear the clipboard". The
        // dispatcher catches it before either transport runs.
        let err = copy_with(
            "",
            env_with(&[]),
            |_| panic!("arboard called for empty payload"),
            |_, _| panic!("osc52 called for empty payload"),
        )
        .unwrap_err();
        assert!(err.contains("nothing to copy"));
    }

    #[test]
    fn dispatch_rejects_whitespace_payload() {
        let err = copy_with(
            "   \t\n",
            env_with(&[]),
            |_| panic!("arboard called for whitespace payload"),
            |_, _| panic!("osc52 called for whitespace payload"),
        )
        .unwrap_err();
        assert!(err.contains("nothing to copy"));
    }

    #[test]
    fn dispatch_rejects_oversized_payload() {
        let huge = "x".repeat(MAX_PAYLOAD_BYTES + 1);
        // Both fns should be unreachable — the size guard fires
        // before dispatch. Failing-by-default closures catch any
        // regression that bypasses the guard.
        let err = copy_with(
            &huge,
            env_with(&[("SSH_CONNECTION", "1.1.1.1 22 2.2.2.2 5000")]),
            |_| panic!("arboard called despite oversized payload"),
            |_, _| panic!("osc52 called despite oversized payload"),
        )
        .unwrap_err();
        assert!(err.contains("exceeds"));
        assert!(err.contains(&MAX_PAYLOAD_BYTES.to_string()));
    }

    #[test]
    fn copy_method_label_is_operator_friendly() {
        assert_eq!(CopyMethod::Osc52.label(), "OSC 52 (terminal)");
        assert_eq!(CopyMethod::Arboard.label(), "system clipboard");
    }
}
