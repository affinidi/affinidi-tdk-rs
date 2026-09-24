//! Log output kept off the terminal while the console owns it.
//!
//! A full-screen console draws only the cells that changed since its last
//! frame. Anything else that writes to the terminal — a `tracing` subscriber
//! printing to stderr is the usual culprit — lands on top of the drawing and
//! stays there, because the console doesn't know those cells changed. While a
//! mediator is unreachable the SDK logs an error every few seconds, and the
//! screen fills with them.
//!
//! [`LogCapture`] is a writer to give the host's subscriber in place of
//! stderr. Until a console starts it passes everything through to stderr; while
//! one runs it keeps the lines instead, and the console shows them (`l`).
//!
//! ```no_run
//! use affinidi_messaging_mediator_tui::LogCapture;
//!
//! let logs = LogCapture::new();
//! // tracing_subscriber::fmt().with_writer(logs.make_writer()).init();
//! // … later: App::new(console).with_logs(logs.clone()).run(&mut terminal)
//! ```

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::Notify;

/// Log lines kept while capturing; older ones are dropped.
const KEEP: usize = 1000;

/// How serious a captured line is, read from the level the subscriber printed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// One captured log line.
#[derive(Clone, Debug)]
pub struct LogLine {
    /// The level, when the line names one.
    pub level: Option<LogLevel>,
    /// The line as printed, without colour codes.
    pub text: String,
    /// How many times in a row it was printed.
    pub repeats: u64,
}

#[derive(Default)]
struct State {
    /// Consoles running with this capture; lines are kept while any is.
    holders: usize,
    lines: VecDeque<LogLine>,
    /// A line written without its newline yet.
    partial: Vec<u8>,
    /// Errors and warnings captured since the console last showed the log.
    unseen: u64,
    /// Lines ever captured, including repeats: tells a reader what's new.
    written: u64,
}

/// A writer that passes log output through to stderr, except while a console
/// is running, when it keeps the lines for the console to show. Clones share
/// one log.
#[derive(Clone, Default)]
pub struct LogCapture {
    state: Arc<Mutex<State>>,
    changed: Arc<Notify>,
}

impl LogCapture {
    pub fn new() -> Self {
        Self::default()
    }

    /// A writer for one log event; `tracing_subscriber::fmt().with_writer`
    /// takes this directly.
    pub fn make_writer(&self) -> impl Fn() -> LogWriter + Send + Sync + 'static {
        let capture = self.clone();
        move || LogWriter {
            capture: capture.clone(),
        }
    }

    /// Keep lines rather than printing them until the guard is dropped.
    pub fn hold(&self) -> CaptureGuard {
        self.lock().holders += 1;
        CaptureGuard {
            capture: self.clone(),
        }
    }

    /// The lines kept, oldest first.
    pub fn lines(&self) -> Vec<LogLine> {
        self.lock().lines.iter().cloned().collect()
    }

    /// Errors and warnings captured since [`LogCapture::mark_seen`].
    pub fn unseen(&self) -> u64 {
        self.lock().unseen
    }

    pub fn mark_seen(&self) {
        self.lock().unseen = 0;
    }

    /// Forget every line kept.
    pub fn clear(&self) {
        let mut state = self.lock();
        state.lines.clear();
        state.unseen = 0;
    }

    /// Lines captured so far, counting repeats.
    pub fn written(&self) -> u64 {
        self.lock().written
    }

    /// Resolves when a line has been captured since the last call.
    pub async fn changed(&self) {
        self.changed.notified().await
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic while holding the lock leaves only log lines behind.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Keeps a [`LogCapture`] capturing; printing resumes when the last is dropped.
pub struct CaptureGuard {
    capture: LogCapture,
}

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        let mut state = self.capture.lock();
        state.holders -= 1;
        if state.holders == 0 && !state.partial.is_empty() {
            let rest = std::mem::take(&mut state.partial);
            drop(state);
            let _ = io::stderr().write_all(&rest);
        }
    }
}

/// Writes one log event to a [`LogCapture`].
pub struct LogWriter {
    capture: LogCapture,
}

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.capture.lock();
        if state.holders == 0 {
            drop(state);
            return io::stderr().write(buf);
        }
        state.partial.extend_from_slice(buf);
        let mut captured = false;
        while let Some(end) = state.partial.iter().position(|b| *b == b'\n') {
            let raw: Vec<u8> = state.partial.drain(..=end).collect();
            let text = clean(&String::from_utf8_lossy(&raw));
            if !text.trim().is_empty() {
                keep(&mut state, text);
                captured = true;
            }
        }
        drop(state);
        if captured {
            self.capture.changed.notify_one();
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn keep(state: &mut State, text: String) {
    let level = level_of(&text);
    state.written += 1;
    if level >= Some(LogLevel::Warn) {
        state.unseen += 1;
    }
    // A mediator that can't be reached logs the same failure every few
    // seconds: count it rather than fill the log with it.
    if let Some(last) = state.lines.back_mut()
        && last.text == text
    {
        last.repeats += 1;
        return;
    }
    state.lines.push_back(LogLine {
        level,
        text,
        repeats: 1,
    });
    while state.lines.len() > KEEP {
        state.lines.pop_front();
    }
}

/// The level a formatted line leads with, if any.
fn level_of(text: &str) -> Option<LogLevel> {
    text.split_whitespace().take(4).find_map(|word| match word {
        "ERROR" => Some(LogLevel::Error),
        "WARN" => Some(LogLevel::Warn),
        "INFO" => Some(LogLevel::Info),
        "DEBUG" => Some(LogLevel::Debug),
        "TRACE" => Some(LogLevel::Trace),
        _ => None,
    })
}

/// `text` without colour codes or control characters, which would move the
/// terminal's cursor rather than show as text.
fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => {
                // CSI: ESC [ parameters… final byte in @..~
                if chars.next_if_eq(&'[').is_some() {
                    for c in chars.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
            }
            '\t' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(capture: &LogCapture, s: &str) {
        capture.make_writer()().write_all(s.as_bytes()).unwrap();
    }

    #[test]
    fn colour_codes_are_stripped_and_the_level_read() {
        let logs = LogCapture::new();
        let _hold = logs.hold();
        write(&logs, "\u{1b}[31mERROR\u{1b}[0m could not\tconnect\n");
        let lines = logs.lines();
        assert_eq!(lines[0].text, "ERROR could not connect");
        assert_eq!(lines[0].level, Some(LogLevel::Error));
        assert_eq!(logs.unseen(), 1);
    }

    #[test]
    fn a_repeated_line_is_counted_not_kept_twice() {
        let logs = LogCapture::new();
        let _hold = logs.hold();
        for _ in 0..3 {
            write(&logs, " WARN retrying\n");
        }
        write(&logs, " INFO connected\n");
        let lines = logs.lines();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].repeats, 3);
        assert_eq!(logs.unseen(), 3);
        assert_eq!(logs.written(), 4);
    }

    #[test]
    fn a_line_split_across_writes_is_joined() {
        let logs = LogCapture::new();
        let _hold = logs.hold();
        write(&logs, "ERROR half");
        assert!(logs.lines().is_empty());
        write(&logs, " and half\nINFO next\n");
        let lines = logs.lines();
        assert_eq!(lines[0].text, "ERROR half and half");
        assert_eq!(lines[1].text, "INFO next");
    }

    #[test]
    fn nothing_is_kept_unless_a_console_holds_the_capture() {
        let logs = LogCapture::new();
        write(&logs, "ERROR to stderr\n");
        assert!(logs.lines().is_empty());
        {
            let _hold = logs.hold();
            write(&logs, "ERROR kept\n");
        }
        write(&logs, "ERROR to stderr again\n");
        assert_eq!(logs.lines().len(), 1);
    }

    #[test]
    fn the_log_keeps_a_bounded_number_of_lines() {
        let logs = LogCapture::new();
        let _hold = logs.hold();
        for i in 0..KEEP + 10 {
            write(&logs, &format!("INFO line {i}\n"));
        }
        let lines = logs.lines();
        assert_eq!(lines.len(), KEEP);
        assert_eq!(lines[0].text, "INFO line 10");
    }
}
