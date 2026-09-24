//! The console application: state, keys, rendering and background work.
//!
//! [`App`] is a component, not a program. A host owns the terminal and the
//! event loop and calls [`App::handle_key`], [`App::apply`] and
//! [`App::render`]; [`App::run`] is that loop for hosts that want it done for
//! them (the `mediator-console` binary does). Work against the mediator runs
//! on background tasks and comes back as [`Update`]s, so rendering never
//! waits on the network.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use affinidi_messaging_mediator_admin::{
    AddressBook, ConsoleError, InspectedMessage, MediatorConsole, Mode, MonitorFilter,
    MonitorUpdate, PurgePlan, PurgeRequest, account_hash, specs,
};
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures_util::StreamExt;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Tabs, Wrap,
};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::account_edit::{AccountEdit, Setting};
use crate::logs::{CaptureGuard, LogCapture, LogLevel};
use crate::quota::{ColorDepth, QuotaBar, quota_line};
use crate::tally::TrafficTally;

/// How often the current view refreshes on its own.
const REFRESH: Duration = Duration::from_secs(5);
/// How long a notice stays in the footer before the key hints come back.
const NOTICE_FOR: Duration = Duration::from_secs(12);

/// A feed this long without even a heartbeat (the mediator sends one every
/// 30 s) is taken as gone, the way a mediator restart leaves it, and replaced.
const MONITOR_SILENCE: Duration = Duration::from_secs(90);
/// First wait before resubscribing the monitor; it doubles up to the cap.
const RESUBSCRIBE: Duration = Duration::from_secs(2);
const RESUBSCRIBE_MAX: Duration = Duration::from_secs(30);

/// Monitor lines kept for scrolling back; older ones are dropped.
const MONITOR_LINES: usize = 2000;

/// The console's screens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Tab {
    Dashboard,
    Queues,
    Account,
    Audit,
    /// Every account on the mediator (administrators).
    Accounts,
    /// The mediator's configuration; a rootAdmin can change its limits.
    Config,
}

impl Tab {
    fn title(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Queues => "Queues",
            Tab::Account => "Account",
            Tab::Audit => "Audit",
            Tab::Accounts => "Accounts",
            Tab::Config => "Config",
        }
    }
}

/// A result of background work, applied with [`App::apply`].
#[non_exhaustive]
pub enum Update {
    Stats(Result<Value, ConsoleError>),
    Queues(Result<Value, ConsoleError>),
    Status(Result<Value, ConsoleError>),
    Messages(Result<Value, ConsoleError>),
    Audit(Result<Value, ConsoleError>),
    /// Every account, all pages.
    Accounts(Result<Vec<Value>, ConsoleError>),
    /// The mediator's configuration fields.
    Config(Result<Value, ConsoleError>),
    /// The account on the Account tab, as `account/get` reports it.
    AccountInfo(Result<Value, ConsoleError>),
    /// The mediator's answer to a configuration change.
    Patched(Result<Value, ConsoleError>),
    Inspected(Box<Result<InspectedMessage, ConsoleError>>),
    PurgePreview(Result<PurgePlan, ConsoleError>),
    /// A finished action: what to tell the user.
    Done(Result<String, ConsoleError>),
    Monitor(MonitorUpdate),
    /// The monitor could not start, or was refused: it stays stopped.
    MonitorFailed(ConsoleError),
    /// The monitor's feed ended or went silent; it resubscribes `after` this.
    MonitorRetrying {
        reason: String,
        after: Duration,
    },
}

/// What the host should do after a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    Continue,
    Quit,
}

enum Popup {
    Text {
        title: String,
        body: String,
    },
    ConfirmDelete {
        target: Option<String>,
        ids: Vec<String>,
    },
    ConfirmPurge(PurgePlan),
    /// Name an account: `hash` is the selected account, if any; the user
    /// fills in its DID (optional when `hash` is known) and a nickname.
    Name {
        hash: Option<String>,
        did: String,
        name: String,
        /// Which field typing goes to: the name (true) or the DID.
        on_name: bool,
    },
    /// The address book, with the selected entry.
    Book {
        selected: usize,
    },
    /// Change one configuration key.
    EditConfig {
        key: String,
        value: String,
    },
    /// Change an account's role, ACL and queue limits.
    EditAccount(AccountEdit),
    /// The captured log, `back` rows up from its newest.
    Logs {
        back: usize,
    },
}

/// One line of the monitor pane. Events are kept raw and drawn on each frame,
/// so naming an account renames it in the lines already shown.
enum MonitorLine {
    Event(Value),
    Note(Line<'static>),
    /// The feed was interrupted; one line however many attempts it takes.
    Retry {
        reason: String,
        attempts: u32,
    },
}

struct MonitorPane {
    visible: bool,
    failures_only: bool,
    lines: VecDeque<MonitorLine>,
    dropped: u64,
    gaps: u64,
    last_seen: Option<Instant>,
    watching: String,
    task: Option<JoinHandle<()>>,
    /// Totals since the monitor (re)started.
    tally: TrafficTally,
    /// Show the per-account totals instead of the live lines.
    show_totals: bool,
    /// Lines scrolled back from the newest; 0 follows new traffic.
    back: usize,
    /// Rows the pane showed last frame: a page, for scrolling.
    page: usize,
    /// When the monitor resubscribes, while it's between feeds.
    retry_at: Option<Instant>,
}

/// The console application.
pub struct App {
    console: Arc<MediatorConsole>,
    depth: ColorDepth,
    tab: Tab,
    tx: mpsc::UnboundedSender<Update>,
    rx: mpsc::UnboundedReceiver<Update>,

    stats: Option<Value>,
    queues: Option<Value>,
    queue_state: TableState,
    queue_send: bool,
    sort: usize,

    /// The account the Account tab shows: `None` is the console's own.
    target: Option<String>,
    status: Option<Value>,
    messages: Vec<Value>,
    message_state: TableState,
    message_send: bool,

    audit: Vec<Value>,
    accounts: Vec<Value>,
    accounts_state: TableState,
    config: Vec<Value>,
    config_state: TableState,
    /// The Account tab's account: role, ACL, limits.
    account_info: Option<Value>,
    monitor: MonitorPane,
    popup: Option<Popup>,
    notice: Option<(String, bool)>,
    /// When `notice` was set; it gives way to the key hints after [`NOTICE_FOR`].
    notice_at: Option<Instant>,
    updated: Option<Instant>,

    /// Nicknames for account hashes; saved to `book_path` when it is set.
    book: AddressBook,
    book_path: Option<PathBuf>,

    /// The host's log output, kept off the terminal while the console runs.
    logs: Option<(LogCapture, CaptureGuard)>,
}

const SORTS: [(&str, &str); 4] = [
    ("count", "depth"),
    ("bytes", "bytes"),
    ("oldest", "oldest"),
    ("saturation", "saturation"),
];

impl App {
    /// A console application over a connected session.
    pub fn new(console: MediatorConsole) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let admin = matches!(console.mode(), Mode::Admin { .. });
        // A mediator too old for the operations tasks still serves the audit
        // log, so an administrator starts there rather than on a dashboard
        // that cannot fill.
        let tab = match (admin, console.serves_operations()) {
            (true, true) => Tab::Dashboard,
            (true, false) => Tab::Audit,
            (false, _) => Tab::Account,
        };
        let mut app = Self {
            console: Arc::new(console),
            depth: ColorDepth::detect(),
            tab,
            tx,
            rx,
            stats: None,
            queues: None,
            queue_state: TableState::default().with_selected(Some(0)),
            queue_send: false,
            sort: 0,
            target: None,
            status: None,
            messages: Vec::new(),
            message_state: TableState::default().with_selected(Some(0)),
            message_send: false,
            audit: Vec::new(),
            accounts: Vec::new(),
            accounts_state: TableState::default().with_selected(Some(0)),
            config: Vec::new(),
            config_state: TableState::default().with_selected(Some(0)),
            account_info: None,
            monitor: MonitorPane {
                visible: false,
                failures_only: false,
                lines: VecDeque::new(),
                dropped: 0,
                gaps: 0,
                last_seen: None,
                watching: String::new(),
                task: None,
                tally: TrafficTally::new(Instant::now()),
                show_totals: false,
                back: 0,
                page: 0,
                retry_at: None,
            },
            popup: None,
            notice: None,
            notice_at: None,
            updated: None,
            book: AddressBook::new(),
            book_path: None,
            logs: None,
        };
        app.know_self();
        app.refresh();
        app
    }

    /// Keep the host's log output off the screen while the console runs, and
    /// show it on request (`l`) instead. Give the same capture to the host's
    /// `tracing` subscriber as its writer; see [`LogCapture`].
    pub fn with_logs(mut self, logs: LogCapture) -> Self {
        let guard = logs.hold();
        self.logs = Some((logs, guard));
        self
    }

    /// Resolves when a log line was captured, so a host running its own loop
    /// knows to redraw. Never resolves without [`App::with_logs`].
    pub async fn log_changed(&self) {
        match &self.logs {
            Some((logs, _)) => logs.changed().await,
            None => std::future::pending().await,
        }
    }

    /// Show `notice` in the footer for a while.
    fn set_notice(&mut self, notice: (String, bool)) {
        self.notice = Some(notice);
        self.notice_at = Some(Instant::now());
    }

    /// Use `book` for account nicknames, saving changes to `path` when given.
    /// The console's own account and the mediator are named automatically
    /// unless the book names them.
    pub fn with_address_book(mut self, book: AddressBook, path: Option<PathBuf>) -> Self {
        self.book = book;
        self.book_path = path;
        self.know_self();
        self
    }

    fn know_self(&mut self) {
        let own = self.console.did().to_string();
        self.book.know(&own, "you");
        let mediator = self.console.mediator_did().to_string();
        self.book.know(&mediator, "mediator");
    }

    /// Text pasted into the console (bracketed paste): goes to the field being
    /// edited, if any. Control characters (line breaks) are dropped.
    pub fn handle_paste(&mut self, text: &str) {
        if let Some(Popup::EditConfig { value, .. }) = &mut self.popup {
            value.push_str(text.trim());
            return;
        }
        if let Some(Popup::Name {
            did, name, on_name, ..
        }) = &mut self.popup
        {
            let clean: String = text.chars().filter(|c| !c.is_control()).collect();
            if *on_name {
                name.push_str(&clean);
            } else {
                did.push_str(clean.trim());
            }
        }
    }

    /// The account the user is looking at, to name with `n`.
    fn account_in_view(&self) -> Option<String> {
        match self.tab {
            Tab::Queues | Tab::Dashboard => self.selected_queue_did(),
            Tab::Accounts => self.selected_account_did(),
            Tab::Account => self
                .selected_message_field(if self.message_send { "to" } else { "from" })
                .or_else(|| self.target.clone())
                .or_else(|| Some(self.console.did_hash().to_string())),
            Tab::Audit | Tab::Config => None,
        }
    }

    fn name_popup(&self, hash: Option<String>) -> Popup {
        let entry = hash.as_deref().and_then(|h| self.book.lookup(h));
        Popup::Name {
            did: entry
                .filter(|e| !e.is_bare_hash())
                .map(|e| e.did.clone())
                .unwrap_or_default(),
            name: entry.map(|e| e.name.clone()).unwrap_or_default(),
            on_name: hash.is_some(),
            hash,
        }
    }

    /// Save a Name popup. Returns the popup to keep open when the input needs
    /// correcting.
    fn save_name(&mut self, hash: Option<String>, did: String, name: String) -> Option<Popup> {
        let (did, name) = (did.trim().to_string(), name.trim().to_string());
        let key = match (&hash, did.is_empty()) {
            (_, false) => {
                if let Some(h) = &hash
                    && account_hash(&did) != *h
                {
                    self.set_notice((
                        format!(
                            "that DID is account {}, not {}",
                            short(&account_hash(&did)),
                            short(h)
                        ),
                        true,
                    ));
                    return Some(Popup::Name {
                        hash,
                        did,
                        name,
                        on_name: false,
                    });
                }
                did
            }
            (Some(h), true) => h.clone(),
            (None, true) => {
                self.set_notice(("paste a DID (or an account hash) to name".into(), true));
                return Some(Popup::Name {
                    hash,
                    did,
                    name,
                    on_name: false,
                });
            }
        };
        let hash = account_hash(&key);
        if name.is_empty() {
            self.book.remove(&hash);
            self.set_notice((format!("{} unnamed", short(&hash)), false));
        } else {
            self.book.insert(&key, &name);
            self.set_notice((format!("{} is now {name}", short(&hash)), false));
        }
        self.save_book();
        None
    }

    fn save_book(&mut self) {
        if let Some(path) = &self.book_path
            && let Err(e) = self.book.save(path)
        {
            self.set_notice((format!("address book not saved: {e}"), true));
        }
    }

    /// Show one account on the Account tab — `None` is the console's own.
    pub fn open_account(&mut self, did_hash: Option<String>) {
        self.target = did_hash;
        self.account_info = None;
        self.tab = Tab::Account;
        self.message_state.select(Some(0));
        self.refresh();
    }

    /// Force a colour depth (the default is detected from the environment).
    pub fn with_color_depth(mut self, depth: ColorDepth) -> Self {
        self.depth = depth;
        self
    }

    fn admin(&self) -> bool {
        matches!(self.console.mode(), Mode::Admin { .. })
    }

    fn tabs(&self) -> Vec<Tab> {
        if self.admin() {
            vec![
                Tab::Dashboard,
                Tab::Queues,
                Tab::Account,
                Tab::Audit,
                Tab::Accounts,
                Tab::Config,
            ]
        } else {
            vec![Tab::Account]
        }
    }

    /// Run `work` in the background and deliver its result as an update.
    fn spawn<F, Fut>(&self, work: F)
    where
        F: FnOnce(Arc<MediatorConsole>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Update> + Send + 'static,
    {
        let (console, tx) = (self.console.clone(), self.tx.clone());
        tokio::spawn(async move {
            let _ = tx.send(work(console).await);
        });
    }

    /// Reload what the current screen shows.
    pub fn refresh(&mut self) {
        // On a mediator too old to serve them, these screens explain that
        // instead of asking (see `render_unsupported`).
        if !self.console.serves_operations()
            && !matches!(self.tab, Tab::Audit | Tab::Accounts | Tab::Config)
        {
            self.updated = Some(Instant::now());
            return;
        }
        match self.tab {
            Tab::Dashboard => {
                self.spawn(|c| async move { Update::Stats(to_value(c.stats().await)) });
                self.load_queues();
            }
            Tab::Queues => self.load_queues(),
            Tab::Account => {
                let target = self.target.clone();
                let send = self.message_send;
                let t = target.clone();
                self.spawn(move |c| async move {
                    Update::Status(to_value(c.queue_status(t, Some(10)).await))
                });
                let t = target.clone();
                self.spawn(
                    move |c| async move { Update::AccountInfo(to_value(c.account_of(t).await)) },
                );
                self.spawn(move |c| async move {
                    let queue = if send {
                        specs::message::list::v0_1::Queue::Send
                    } else {
                        specs::message::list::v0_1::Queue::Receive
                    };
                    Update::Messages(to_value(
                        c.messages(target, queue, None, None, Some(200)).await,
                    ))
                });
            }
            Tab::Audit => {
                self.spawn(
                    |c| async move { Update::Audit(to_value(c.audit(None, Some(200)).await)) },
                );
            }
            Tab::Accounts => {
                self.spawn(|c| async move { Update::Accounts(all_accounts(&c).await) })
            }
            Tab::Config => {
                self.spawn(|c| async move { Update::Config(to_value(c.config().await)) })
            }
        }
    }

    fn load_queues(&self) {
        let send = self.queue_send;
        let sort = self.sort;
        self.spawn(move |c| async move {
            use specs::queue::list::v0_1::{PayloadSort, Queue};
            let queue = if send { Queue::Send } else { Queue::Receive };
            let sort = match sort {
                1 => PayloadSort::Bytes,
                2 => PayloadSort::Oldest,
                3 => PayloadSort::Saturation,
                _ => PayloadSort::Count,
            };
            Update::Queues(to_value(
                c.queues(Some(queue), Some(sort), None, Some(200)).await,
            ))
        });
    }

    /// Apply the result of background work.
    pub fn apply(&mut self, update: Update) {
        let ok = |this: &mut Self| this.updated = Some(Instant::now());
        match update {
            Update::Stats(r) => match r {
                Ok(v) => {
                    self.stats = Some(v);
                    ok(self)
                }
                Err(e) => self.error(e),
            },
            Update::Queues(r) => match r {
                Ok(v) => {
                    self.queues = Some(v);
                    ok(self)
                }
                Err(e) => self.error(e),
            },
            Update::Status(r) => match r {
                Ok(v) => {
                    self.status = Some(v);
                    ok(self)
                }
                Err(e) => self.error(e),
            },
            Update::Messages(r) => match r {
                Ok(v) => {
                    self.messages = v["messages"].as_array().cloned().unwrap_or_default();
                    ok(self)
                }
                Err(e) => self.error(e),
            },
            Update::Audit(r) => match r {
                Ok(v) => {
                    self.audit = v["entries"].as_array().cloned().unwrap_or_default();
                    ok(self)
                }
                Err(e) => self.error(e),
            },
            Update::Accounts(r) => match r {
                Ok(mut accounts) => {
                    let book = &self.book;
                    accounts.sort_by_key(|a| account_order(a, book));
                    self.accounts = accounts;
                    let len = self.accounts.len();
                    if self.accounts_state.selected().is_none_or(|i| i >= len) {
                        self.accounts_state.select(Some(0));
                    }
                    ok(self)
                }
                Err(e) => self.error(e),
            },
            Update::AccountInfo(r) => match r {
                Ok(v) => {
                    self.account_info = Some(v);
                    ok(self)
                }
                Err(e) => self.error(e),
            },
            Update::Config(r) => match r {
                Ok(v) => {
                    let mut fields = v["fields"].as_array().cloned().unwrap_or_default();
                    // Limits first (they are what can be changed), then the rest.
                    fields.sort_by_key(|f| {
                        let key = f["key"].as_str().unwrap_or("").to_string();
                        (!key.starts_with("limits."), key)
                    });
                    self.config = fields;
                    ok(self)
                }
                Err(e) => self.error(e),
            },
            Update::Patched(r) => {
                match r {
                    Ok(v) => self.set_notice(patch_summary(&v)),
                    Err(e) => self.error(e),
                }
                self.refresh();
            }
            Update::Inspected(r) => match *r {
                Ok(m) => self.popup = Some(inspect_popup(&m)),
                Err(e) => self.error(e),
            },
            Update::PurgePreview(r) => match r {
                Ok(plan) if plan.matched == 0 => {
                    self.set_notice(("nothing to purge".into(), false))
                }
                Ok(plan) => self.popup = Some(Popup::ConfirmPurge(plan)),
                Err(e) => self.error(e),
            },
            Update::Done(r) => {
                match r {
                    Ok(msg) => self.set_notice((msg, false)),
                    Err(e) => self.error(e),
                }
                self.refresh();
            }
            Update::Monitor(u) => self.monitor_update(u),
            Update::MonitorFailed(e) => {
                self.monitor.task = None;
                self.monitor.retry_at = None;
                self.monitor.lines.push_back(MonitorLine::Note(Line::styled(
                    format!("── monitor stopped: {e} ──"),
                    Style::default().fg(Color::Red),
                )));
                self.error(e);
            }
            Update::MonitorRetrying { reason, after } => {
                self.monitor.retry_at = Some(Instant::now() + after);
                let attempts = match self.monitor.lines.back() {
                    Some(MonitorLine::Retry { attempts, .. }) => {
                        let n = *attempts;
                        self.monitor.lines.pop_back();
                        n + 1
                    }
                    _ => 1,
                };
                self.monitor
                    .lines
                    .push_back(MonitorLine::Retry { reason, attempts });
            }
        }
    }

    /// Wait for the next result of background work — for a host running its
    /// own loop. Apply it with [`App::apply`].
    pub async fn next_update(&mut self) -> Option<Update> {
        self.rx.recv().await
    }

    fn error(&mut self, e: ConsoleError) {
        self.set_notice((e.to_string(), true));
    }

    // ─── Keys ────────────────────────────────────────────────────────────

    /// Handle a key press.
    pub fn handle_key(&mut self, key: KeyEvent) -> Control {
        if key.kind != KeyEventKind::Press {
            return Control::Continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Control::Quit;
        }
        if let Some(popup) = self.popup.take() {
            self.popup_key(popup, key.code);
            return Control::Continue;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Control::Quit,
            KeyCode::Char(c @ '1'..='6') => {
                if let Some(tab) = self.tabs().get((c as u8 - b'1') as usize) {
                    self.tab = *tab;
                    self.refresh();
                }
            }
            KeyCode::Tab => {
                let tabs = self.tabs();
                let i = tabs.iter().position(|t| *t == self.tab).unwrap_or(0);
                self.tab = tabs[(i + 1) % tabs.len()];
                self.refresh();
            }
            KeyCode::Char('r') => self.refresh(),
            KeyCode::Char('n') => self.popup = Some(self.name_popup(self.account_in_view())),
            KeyCode::Char('b') => self.popup = Some(Popup::Book { selected: 0 }),
            KeyCode::Char('m') => self.toggle_monitor(),
            KeyCode::Char('l') => match &self.logs {
                Some((logs, _)) => {
                    logs.mark_seen();
                    self.popup = Some(Popup::Logs { back: 0 });
                }
                None => self.set_notice(("this console isn't keeping a log".into(), true)),
            },
            KeyCode::PageUp if self.monitor.visible => {
                self.scroll_monitor(self.monitor.page as i64)
            }
            KeyCode::PageDown if self.monitor.visible => {
                self.scroll_monitor(-(self.monitor.page as i64))
            }
            KeyCode::Up if self.monitor.visible && key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.scroll_monitor(1)
            }
            KeyCode::Down
                if self.monitor.visible && key.modifiers.contains(KeyModifiers::SHIFT) =>
            {
                self.scroll_monitor(-1)
            }
            KeyCode::Home if self.monitor.visible => self.scroll_monitor(i64::MAX),
            KeyCode::End if self.monitor.visible => self.monitor.back = 0,
            KeyCode::Char('t') if self.monitor.visible => {
                self.monitor.show_totals = !self.monitor.show_totals;
            }
            KeyCode::Char('f') => {
                self.monitor.failures_only = !self.monitor.failures_only;
                if self.monitor.visible {
                    self.start_monitor();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            _ => self.tab_key(key.code),
        }
        Control::Continue
    }

    fn tab_key(&mut self, code: KeyCode) {
        match (self.tab, code) {
            (Tab::Queues | Tab::Dashboard, KeyCode::Char('s')) => {
                self.sort = (self.sort + 1) % SORTS.len();
                self.load_queues();
            }
            (Tab::Queues | Tab::Dashboard, KeyCode::Char('x')) => {
                self.queue_send = !self.queue_send;
                self.load_queues();
            }
            (Tab::Queues | Tab::Dashboard, KeyCode::Enter) => {
                if let Some(did) = self.selected_queue_did() {
                    self.open_account(Some(did));
                }
            }
            (Tab::Config, KeyCode::Enter) if self.console.can_patch_config() => {
                if let Some(field) = self.selected_config() {
                    let key = field["key"].as_str().unwrap_or("").to_string();
                    if key.starts_with("limits.") {
                        let value = field["value"].to_string();
                        self.popup = Some(Popup::EditConfig { key, value });
                    } else {
                        self.set_notice(("only limits can be changed at runtime".into(), true));
                    }
                }
            }
            (Tab::Config, KeyCode::Char('x')) if self.console.can_patch_config() => {
                if let Some(field) = self.selected_config()
                    && field["source"] == "override"
                {
                    let key = field["key"].as_str().unwrap_or("").to_string();
                    self.patch(key, Value::Null);
                }
            }
            (Tab::Accounts, KeyCode::Enter) => {
                if let Some(did) = self.selected_account_did() {
                    self.open_account(Some(did));
                }
            }
            (Tab::Account, KeyCode::Char('x')) => {
                self.message_send = !self.message_send;
                self.message_state.select(Some(0));
                self.refresh();
            }
            (Tab::Account, KeyCode::Char('e')) => {
                if let Some(info) = &self.account_info {
                    let hash = info["did"]
                        .as_str()
                        .map(str::to_string)
                        .or_else(|| self.target.clone())
                        .unwrap_or_else(|| self.console.did_hash().to_string());
                    self.popup = Some(Popup::EditAccount(AccountEdit::new(
                        hash,
                        info,
                        self.admin(),
                    )));
                } else {
                    self.set_notice(("the account's settings are still loading".into(), true));
                }
            }
            (Tab::Account, KeyCode::Char('o')) => {
                self.target = None;
                self.refresh();
            }
            (Tab::Account, KeyCode::Char('i')) => {
                if let Some(id) = self.selected_message_field("msgId") {
                    let target = self.target.clone();
                    self.spawn(move |c| async move {
                        Update::Inspected(Box::new(c.inspect(target, &id).await))
                    });
                }
            }
            (Tab::Account, KeyCode::Char('d')) => {
                if let Some(id) = self.selected_message_field("msgId") {
                    self.popup = Some(Popup::ConfirmDelete {
                        target: self.target.clone(),
                        ids: vec![id],
                    });
                }
            }
            (Tab::Account, KeyCode::Char('p') | KeyCode::Char('P')) => {
                let peer = if code == KeyCode::Char('P') {
                    self.selected_message_field(if self.message_send { "to" } else { "from" })
                } else {
                    None
                };
                let request = PurgeRequest {
                    target: self.target.clone(),
                    queue: if self.message_send {
                        specs::queue::purge::v0_1::Queue::Send
                    } else {
                        specs::queue::purge::v0_1::Queue::Receive
                    },
                    peer,
                    older_than_seconds: None,
                };
                self.spawn(
                    move |c| async move { Update::PurgePreview(c.purge_preview(request).await) },
                );
            }
            _ => {}
        }
    }

    fn popup_key(&mut self, popup: Popup, code: KeyCode) {
        let yes = matches!(code, KeyCode::Char('y') | KeyCode::Char('Y'));
        match popup {
            Popup::Logs { back } => {
                const PAGE: usize = 10;
                let back = match code {
                    KeyCode::Up | KeyCode::Char('k') => back.saturating_add(1),
                    KeyCode::Down | KeyCode::Char('j') => back.saturating_sub(1),
                    KeyCode::PageUp => back.saturating_add(PAGE),
                    KeyCode::PageDown => back.saturating_sub(PAGE),
                    KeyCode::Home => usize::MAX,
                    KeyCode::End => 0,
                    KeyCode::Char('c') => {
                        if let Some((logs, _)) = &self.logs {
                            logs.clear();
                        }
                        0
                    }
                    // Esc, q, l or anything else closes it.
                    _ => {
                        if let Some((logs, _)) = &self.logs {
                            logs.mark_seen();
                        }
                        return;
                    }
                };
                self.popup = Some(Popup::Logs { back });
            }
            Popup::Name {
                hash,
                mut did,
                mut name,
                on_name,
            } => match code {
                KeyCode::Esc => self.set_notice(("cancelled".into(), false)),
                KeyCode::Enter => self.popup = self.save_name(hash, did, name),
                KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down => {
                    self.popup = Some(Popup::Name {
                        hash,
                        did,
                        name,
                        on_name: !on_name,
                    })
                }
                other => {
                    let field = if on_name { &mut name } else { &mut did };
                    match other {
                        KeyCode::Backspace => {
                            field.pop();
                        }
                        KeyCode::Char(c) => field.push(c),
                        _ => {}
                    }
                    self.popup = Some(Popup::Name {
                        hash,
                        did,
                        name,
                        on_name,
                    });
                }
            },
            Popup::Book { selected } => {
                let len = self.book.entries().len();
                match code {
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.popup = Some(Popup::Book {
                            selected: (selected + 1).min(len.saturating_sub(1)),
                        })
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.popup = Some(Popup::Book {
                            selected: selected.saturating_sub(1),
                        })
                    }
                    KeyCode::Char('x') | KeyCode::Delete => {
                        if let Some(entry) = self.book.entries().get(selected).cloned() {
                            self.book.remove(&entry.hash());
                            self.save_book();
                            self.set_notice((format!("{} removed", entry.name), false));
                        }
                        self.popup = Some(Popup::Book {
                            selected: selected.min(len.saturating_sub(2)),
                        });
                    }
                    KeyCode::Char('n') | KeyCode::Enter => {
                        let hash = self.book.entries().get(selected).map(|e| e.hash());
                        self.popup = Some(self.name_popup(hash));
                    }
                    KeyCode::Char('a') => self.popup = Some(self.name_popup(None)),
                    _ => {}
                }
            }
            Popup::EditAccount(mut edit) => match code {
                KeyCode::Esc => self.set_notice(("cancelled".into(), false)),
                KeyCode::Char('s') => {
                    if edit.changed() {
                        self.save_account(edit);
                    } else {
                        self.set_notice(("nothing changed".into(), false));
                    }
                }
                other => {
                    match other {
                        KeyCode::Up | KeyCode::Char('k') => edit.up(),
                        KeyCode::Down | KeyCode::Char('j') => edit.down(),
                        KeyCode::Char(' ') | KeyCode::Enter => edit.toggle(),
                        KeyCode::Backspace => edit.backspace(),
                        KeyCode::Char(c) => edit.type_char(c),
                        _ => {}
                    }
                    self.popup = Some(Popup::EditAccount(edit));
                }
            },
            Popup::EditConfig { key, mut value } => match code {
                KeyCode::Esc => self.set_notice(("cancelled".into(), false)),
                KeyCode::Enter => {
                    // A number when it reads as one; otherwise the text as given.
                    let parsed = serde_json::from_str::<Value>(value.trim())
                        .unwrap_or_else(|_| Value::String(value.trim().to_string()));
                    self.patch(key, parsed);
                }
                other => {
                    match other {
                        KeyCode::Backspace => {
                            value.pop();
                        }
                        KeyCode::Char(c) => value.push(c),
                        _ => {}
                    }
                    self.popup = Some(Popup::EditConfig { key, value });
                }
            },
            Popup::Text { .. } => {}
            Popup::ConfirmDelete { target, ids } if yes => {
                self.spawn(move |c| async move {
                    Update::Done(c.delete(target, &ids).await.map(|r| {
                        let deleted = serde_json::to_value(&r)
                            .ok()
                            .and_then(|v| v["results"].as_array().cloned())
                            .unwrap_or_default()
                            .iter()
                            .filter(|x| x["deleted"] == true)
                            .count();
                        format!("deleted {deleted} message(s)")
                    }))
                });
            }
            Popup::ConfirmPurge(plan) if yes => {
                self.spawn(move |c| async move {
                    Update::Done(
                        c.purge(plan)
                            .await
                            .map(|r| format!("purged {} message(s)", r.purged)),
                    )
                });
            }
            // Anything but "y" cancels a confirmation.
            Popup::ConfirmDelete { .. } | Popup::ConfirmPurge(_) => {
                self.set_notice(("cancelled".into(), false));
            }
        }
    }

    fn move_selection(&mut self, delta: i32) {
        let (state, len) = match self.tab {
            Tab::Queues | Tab::Dashboard => (&mut self.queue_state, queue_rows(&self.queues).len()),
            Tab::Account => (&mut self.message_state, self.messages.len()),
            Tab::Accounts => (&mut self.accounts_state, self.accounts.len()),
            Tab::Config => (&mut self.config_state, self.config.len()),
            Tab::Audit => return,
        };
        if len == 0 {
            return;
        }
        let i = state.selected().unwrap_or(0) as i32 + delta;
        state.select(Some(i.clamp(0, len as i32 - 1) as usize));
    }

    /// Send an account edit's changes with `account/update`.
    fn save_account(&mut self, mut edit: AccountEdit) {
        use specs::account::update::v0_1::{AccountType, MediatorAcl, QueueLimits};
        let (role, acl, limits) = edit.changes();
        let role: Option<AccountType> = match role.map(serde_json::from_value).transpose() {
            Ok(v) => v,
            Err(e) => return self.set_notice((format!("role: {e}"), true)),
        };
        let acl: Option<MediatorAcl> = match acl.map(serde_json::from_value).transpose() {
            Ok(v) => v,
            Err(e) => return self.set_notice((format!("acl: {e}"), true)),
        };
        let limits: Option<QueueLimits> = match limits.map(serde_json::from_value).transpose() {
            Ok(v) => v,
            Err(e) => return self.set_notice((format!("limits: {e}"), true)),
        };
        let target = (edit.target != self.console.did_hash()).then(|| edit.target.clone());
        self.spawn(move |c| async move {
            Update::Done(
                c.update_account(target, role, acl, limits)
                    .await
                    .map(|_| "account updated".to_string()),
            )
        });
    }

    fn selected_config(&self) -> Option<Value> {
        let i = self.config_state.selected()?;
        self.config.get(i).cloned()
    }

    /// Ask the mediator to set `key` to `value` (`null` removes its override).
    fn patch(&self, key: String, value: Value) {
        self.spawn(move |c| async move {
            let mut overrides = serde_json::Map::new();
            overrides.insert(key, value);
            Update::Patched(to_value(c.patch_config(overrides).await))
        });
    }

    fn selected_account_did(&self) -> Option<String> {
        let i = self.accounts_state.selected()?;
        self.accounts.get(i)?["did"].as_str().map(str::to_string)
    }

    fn selected_queue_did(&self) -> Option<String> {
        let rows = queue_rows(&self.queues);
        let i = self.queue_state.selected()?;
        rows.get(i)?["did"].as_str().map(str::to_string)
    }

    fn selected_message_field(&self, field: &str) -> Option<String> {
        let i = self.message_state.selected()?;
        self.messages.get(i)?[field].as_str().map(str::to_string)
    }

    // ─── Monitor ─────────────────────────────────────────────────────────

    fn toggle_monitor(&mut self) {
        self.monitor.visible = !self.monitor.visible;
        if self.monitor.visible {
            self.start_monitor();
        } else if let Some(task) = self.monitor.task.take() {
            // Dropping the feed inside the task unsubscribes.
            task.abort();
        }
    }

    fn start_monitor(&mut self) {
        if let Some(task) = self.monitor.task.take() {
            task.abort();
        }
        // New subscription, new totals.
        self.monitor.tally = TrafficTally::new(Instant::now());
        let dids = match (&self.target, self.tab) {
            (Some(t), Tab::Account) => Some(vec![t.clone()]),
            _ => None,
        };
        self.monitor.watching = match (&dids, self.admin()) {
            (Some(d), _) => format!("account {}", label(&self.book, &d[0])),
            (None, true) => "all traffic".into(),
            (None, false) => "your traffic".into(),
        };
        let mut filter = serde_json::json!({});
        if let Some(d) = dids {
            filter["dids"] = serde_json::json!(d);
        }
        if self.monitor.failures_only {
            filter["failuresOnly"] = serde_json::json!(true);
        }
        let filter: MonitorFilter = serde_json::from_value(filter).unwrap_or_else(|_| {
            serde_json::from_value(serde_json::json!({})).expect("empty filter")
        });
        let (console, tx) = (self.console.clone(), self.tx.clone());
        self.monitor.retry_at = None;
        self.monitor.task = Some(tokio::spawn(watch(console, filter, tx)));
    }

    /// This console's own requests to the mediator, and the clean-up of their
    /// replies. From mediator 0.28.22 the mediator leaves all of that out
    /// itself. Before that, a `received` event carried no recipient and a
    /// `deleted` event no sender, so the console's own polling showed through;
    /// this filter keeps the pane clean on those mediators.
    fn is_own_console_traffic(&self, e: &Value) -> bool {
        let me = self.console.did_hash();
        let mediator = sha256_hex(self.console.mediator_did());
        let from = e["from"].as_str();
        let to = e["to"].as_str();
        let own_request = from == Some(me) && to.is_none_or(|to| to == mediator);
        let own_reply_cleanup = e["stage"] == "deleted" && to == Some(me) && from.is_none();
        own_request || own_reply_cleanup
    }

    /// Scroll the monitor `by` lines towards older traffic (negative: newer).
    fn scroll_monitor(&mut self, by: i64) {
        let oldest = self
            .monitor
            .lines
            .len()
            .saturating_sub(self.monitor.page.max(1));
        let back = (self.monitor.back as i64).saturating_add(by);
        self.monitor.back = back.clamp(0, oldest as i64) as usize;
    }

    fn monitor_update(&mut self, update: MonitorUpdate) {
        self.monitor.last_seen = Some(Instant::now());
        self.monitor.retry_at = None;
        let before = self.monitor.lines.len();
        match update {
            MonitorUpdate::Events { events, dropped } => {
                self.monitor.dropped += dropped;
                for e in events {
                    let v = serde_json::to_value(e).unwrap_or(Value::Null);
                    if !self.is_own_console_traffic(&v) {
                        self.monitor.tally.record(&v, Instant::now());
                        self.monitor.lines.push_back(MonitorLine::Event(v));
                    }
                }
            }
            MonitorUpdate::Gap { missing } => {
                self.monitor.gaps += missing;
                self.monitor.lines.push_back(MonitorLine::Note(Line::styled(
                    format!("── {missing} batch(es) lost in transit ──"),
                    Style::default().fg(Color::Yellow),
                )));
            }
            MonitorUpdate::Heartbeat => {}
            MonitorUpdate::Ended(reason) => {
                self.monitor.task = None;
                self.monitor.lines.push_back(MonitorLine::Note(Line::styled(
                    format!("── monitor ended: {reason} ──"),
                    Style::default().fg(Color::Red),
                )));
            }
        }
        // Scrolled back, the view stays on the lines being read while new
        // ones arrive below.
        if self.monitor.back > 0 {
            self.monitor.back += self.monitor.lines.len() - before;
        }
        while self.monitor.lines.len() > MONITOR_LINES {
            self.monitor.lines.pop_front();
        }
        self.scroll_monitor(0);
    }

    // ─── Loop ────────────────────────────────────────────────────────────

    /// Run the console on `terminal` until the user quits.
    pub async fn run<B: ratatui::backend::Backend>(
        mut self,
        terminal: &mut ratatui::Terminal<B>,
    ) -> std::io::Result<()>
    where
        std::io::Error: From<B::Error>,
    {
        let mut events = EventStream::new();
        let mut tick = tokio::time::interval(REFRESH);
        tick.tick().await;
        let logs = self.logs.as_ref().map(|(logs, _)| logs.clone());
        loop {
            terminal.draw(|f| self.render(f, f.area()))?;
            let log_changed = async {
                match &logs {
                    Some(logs) => logs.changed().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                Some(Ok(event)) = events.next() => match event {
                    // Repaint every cell, whatever wrote over them.
                    Event::Key(key)
                        if key.kind == KeyEventKind::Press
                            && key.modifiers.contains(KeyModifiers::CONTROL)
                            && key.code == KeyCode::Char('l') =>
                    {
                        terminal.clear()?;
                    }
                    Event::Key(key) if self.handle_key(key) == Control::Quit => break,
                    Event::Paste(text) => self.handle_paste(&text),
                    _ => {}
                },
                Some(update) = self.rx.recv() => self.apply(update),
                _ = log_changed => {}
                _ = tick.tick() => if self.popup.is_none() { self.refresh() },
            }
        }
        if let Some(task) = self.monitor.task.take() {
            task.abort();
        }
        Ok(())
    }

    // ─── Rendering ───────────────────────────────────────────────────────

    /// Draw the console into `area`.
    pub fn render(&mut self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(5),
                Constraint::Length(1),
            ])
            .split(area);
        self.render_header(f, rows[0]);
        self.render_tabs(f, rows[1]);

        let body = if self.monitor.visible {
            let split = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                .split(rows[2]);
            self.render_monitor(f, split[1]);
            split[0]
        } else {
            rows[2]
        };
        if !self.console.serves_operations()
            && !matches!(self.tab, Tab::Audit | Tab::Accounts | Tab::Config)
        {
            self.render_unsupported(f, body);
        } else {
            self.render_screen(f, body);
        }
        self.render_footer(f, rows[3]);
        match &self.popup {
            Some(Popup::Logs { back }) => {
                // Keep the position in range, so scrolling from the top
                // moves at once.
                let back = self.render_logs(f, area, *back);
                self.popup = Some(Popup::Logs { back });
            }
            Some(popup) => render_popup(f, area, popup, &self.book),
            None => {}
        }
    }

    fn render_screen(&mut self, f: &mut Frame, body: Rect) {
        match self.tab {
            Tab::Dashboard => self.render_dashboard(f, body),
            Tab::Queues => self.render_queues(f, body),
            Tab::Account => self.render_account(f, body),
            Tab::Audit => self.render_audit(f, body),
            Tab::Accounts => self.render_accounts(f, body),
            Tab::Config => self.render_config(f, body),
        }
    }

    /// What a screen shows when the mediator predates the tasks it needs.
    fn render_unsupported(&self, f: &mut Frame, area: Rect) {
        let (major, minor, patch) = affinidi_messaging_mediator_admin::OPERATIONS_SINCE;
        let version = self.console.mediator_version().unwrap_or("unknown");
        let admin = matches!(self.console.mode(), Mode::Admin { .. });
        let mut text = vec![
            Line::styled(
                format!("This mediator is version {version}."),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Line::raw(""),
            Line::raw(format!(
                "Statistics, queues, messages and the traffic monitor need \
                 affinidi-messaging-mediator {major}.{minor}.{patch} or later."
            )),
            Line::raw("Upgrade the mediator to use this screen."),
        ];
        if admin {
            text.push(Line::raw(""));
            text.push(Line::raw(
                "The Audit screen works on this mediator: press 4 or Tab.",
            ));
        }
        f.render_widget(
            Paragraph::new(text)
                .wrap(ratatui::widgets::Wrap { trim: false })
                .block(Block::bordered().title(" Not available on this mediator ")),
            area,
        );
    }

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let (badge, color) = match self.console.mode() {
            Mode::Admin { root: true } => (" ROOT ", Color::Red),
            Mode::Admin { root: false } => (" ADMIN ", Color::Yellow),
            Mode::SelfService => (" SELF ", Color::Cyan),
        };
        let age = self
            .updated
            .map(|t| format!("updated {}s ago", t.elapsed().as_secs()))
            .unwrap_or_else(|| "loading…".into());
        let line = Line::from(vec![
            Span::styled(
                " mediator-console ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(badge, Style::default().fg(Color::Black).bg(color)),
            Span::raw(format!(
                "  {} → {}  ",
                label(&self.book, self.console.did_hash()),
                short_did(self.console.mediator_did())
            )),
            Span::styled(age, Style::default().fg(Color::DarkGray)),
        ]);
        let mut line = line;
        match self.console.mediator_version() {
            Some(v) if !self.console.serves_operations() => line.push_span(Span::styled(
                format!("  ⚠ mediator {v} is too old for most screens"),
                Style::default().fg(Color::Yellow),
            )),
            Some(v) => line.push_span(Span::styled(
                format!("  mediator {v}"),
                Style::default().fg(Color::DarkGray),
            )),
            None => {}
        }
        if let Some((logs, _)) = &self.logs {
            let unseen = logs.unseen();
            if unseen > 0 {
                line.push_span(Span::styled(
                    format!("  ⚠ {unseen} log warning(s) — l to read"),
                    Style::default().fg(Color::Yellow),
                ));
            }
        }
        f.render_widget(Paragraph::new(line), area);
    }

    /// The captured log over the screen, newest at the bottom, each line
    /// wrapped to the width so none of it is cut off. Returns `back` within
    /// what there is to scroll.
    fn render_logs(&self, f: &mut Frame, area: Rect, back: usize) -> usize {
        let w = area.width.saturating_sub(4);
        let h = area.height.saturating_sub(2);
        let rect = Rect::new(
            area.x + (area.width - w) / 2,
            area.y + (area.height - h) / 2,
            w,
            h,
        );
        let inner_w = w.saturating_sub(2).max(1) as usize;
        let inner_h = h.saturating_sub(2) as usize;
        let mut rows: Vec<Line> = Vec::new();
        let lines = self
            .logs
            .as_ref()
            .map(|(logs, _)| logs.lines())
            .unwrap_or_default();
        for line in &lines {
            let color = match line.level {
                Some(LogLevel::Error) => Color::Red,
                Some(LogLevel::Warn) => Color::Yellow,
                Some(LogLevel::Info) => Color::Reset,
                _ => Color::DarkGray,
            };
            let text = match line.repeats {
                1 => line.text.clone(),
                n => format!("{}  ×{n}", line.text),
            };
            for chunk in wrap_hard(&text, inner_w) {
                rows.push(Line::styled(chunk, Style::default().fg(color)));
            }
        }
        let back = back.min(rows.len().saturating_sub(inner_h));
        let skip = rows.len().saturating_sub(inner_h + back);
        let shown: Vec<Line> = rows.into_iter().skip(skip).take(inner_h).collect();
        let position = if back > 0 {
            format!(" {back} row(s) newer below · End ")
        } else {
            String::new()
        };
        f.render_widget(Clear, rect);
        f.render_widget(
            Paragraph::new(shown).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan))
                    .title(format!(" Log — {} line(s) ", lines.len()))
                    .title_bottom(Line::from(format!(
                        "{position} ↑↓ PgUp PgDn Home End scroll  c clear  Esc close "
                    ))),
            ),
            rect,
        );
        back
    }

    fn render_tabs(&self, f: &mut Frame, area: Rect) {
        let tabs = self.tabs();
        let titles: Vec<Line> = tabs
            .iter()
            .enumerate()
            .map(|(i, t)| Line::from(format!("{} {}", i + 1, t.title())))
            .collect();
        let selected = tabs.iter().position(|t| *t == self.tab).unwrap_or(0);
        f.render_widget(
            Tabs::new(titles).select(selected).highlight_style(
                Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED),
            ),
            area,
        );
    }

    fn render_footer(&self, f: &mut Frame, area: Rect) {
        let fresh = self.notice_at.is_some_and(|t| t.elapsed() < NOTICE_FOR);
        let notice = if fresh { self.notice.as_ref() } else { None };
        let line = match notice {
            Some((text, true)) => {
                Line::styled(format!(" ✗ {text}"), Style::default().fg(Color::Red))
            }
            Some((text, false)) => {
                Line::styled(format!(" ✓ {text}"), Style::default().fg(Color::Green))
            }
            None => {
                let keys = match self.tab {
                    Tab::Dashboard | Tab::Queues => {
                        "↑↓ select  ⏎ open  s sort  x recv/send  n name  b book  m monitor  f failures  q quit"
                    }
                    Tab::Account => {
                        "↑↓ select  e edit account  i inspect  d delete  p purge  P purge peer  x recv/send  o own  n name  b book  m monitor  q quit"
                    }
                    Tab::Audit => "n name  b book  m monitor  r refresh  q quit",
                    Tab::Accounts => {
                        "↑↓ select  ⏎ open  n name  b book  m monitor  r refresh  q quit"
                    }
                    Tab::Config if self.console.can_patch_config() => {
                        "↑↓ select  ⏎ change a limit  x reset override  r refresh  q quit"
                    }
                    Tab::Config => {
                        "↑↓ select  r refresh  q quit  (changing limits needs a rootAdmin)"
                    }
                };
                let monitor_keys = match (self.monitor.visible, self.monitor.show_totals) {
                    (true, false) => "  t totals  PgUp PgDn End scroll",
                    (true, true) => "  t live",
                    (false, _) => "",
                };
                Line::styled(
                    format!(" {keys}{monitor_keys}"),
                    Style::default().fg(Color::DarkGray),
                )
            }
        };
        f.render_widget(Paragraph::new(line), area);
    }

    fn render_dashboard(&mut self, f: &mut Frame, area: Rect) {
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(9), Constraint::Min(4)])
            .split(area);
        let top = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(parts[0]);

        let s = self.stats.as_ref();
        let get = |p: &str| s.and_then(|s| s.pointer(p)).cloned().unwrap_or(Value::Null);
        let n = |p: &str| get(p).as_u64().map(|v| v.to_string()).unwrap_or("–".into());
        let breaker = get("/forwarding/circuitBreaker");
        let breaker_color = match breaker.as_str() {
            Some("open") => Color::Red,
            Some("halfOpen") => Color::Yellow,
            _ => Color::Green,
        };
        let lines = vec![
            Line::from(format!(
                "version {}   up {}",
                get("/version").as_str().unwrap_or("–"),
                human_secs(get("/uptimeSeconds").as_u64())
            )),
            Line::from(format!(
                "websockets {} / {}",
                n("/connections/websocketActive"),
                n("/connections/websocketMax")
            )),
            Line::from(format!(
                "stored {}   delivered {}   deleted {}",
                n("/totals/receivedCount"),
                n("/totals/sentCount"),
                n("/totals/deletedCount")
            )),
            Line::from(format!(
                "sessions {} ({} authenticated)",
                n("/totals/sessionsCreated"),
                n("/totals/sessionsAuthenticated")
            )),
            Line::from(vec![
                Span::raw(format!(
                    "forwarding {} / {}   breaker ",
                    n("/forwarding/queueLength"),
                    n("/forwarding/queueLimit")
                )),
                Span::styled(
                    breaker.as_str().unwrap_or("–").to_string(),
                    Style::default().fg(breaker_color),
                ),
            ]),
        ];
        f.render_widget(
            Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Mediator ")),
            top[0],
        );

        // Aggregate queue pressure: the fullest single queue, as a gradient.
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Queue pressure ");
        let inner = block.inner(top[1]);
        f.render_widget(block, top[1]);
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1); 6])
            .split(inner);
        for (i, (label, side)) in [("receive", "receive"), ("send", "send")]
            .iter()
            .enumerate()
        {
            let depth = get(&format!("/queues/{side}"));
            let sat = depth["saturation"].as_f64();
            f.render_widget(
                Paragraph::new(format!(
                    "{label}: {} msgs, worst queue {}, oldest {}",
                    depth["count"].as_u64().unwrap_or(0),
                    sat.map_or("–".into(), |s| format!("{:.0}%", s * 100.0)),
                    human_secs(depth["oldestAgeSeconds"].as_u64())
                )),
                rows[i * 3],
            );
            f.render_widget(QuotaBar::new(sat, self.depth), rows[i * 3 + 1]);
        }

        self.render_queue_table(f, parts[1], " Busiest queues ");
    }

    fn render_queues(&mut self, f: &mut Frame, area: Rect) {
        self.render_queue_table(f, area, " Queues ");
    }

    fn render_queue_table(&mut self, f: &mut Frame, area: Rect, title: &str) {
        let rows = queue_rows(&self.queues);
        // The account column fits the longest name (within reason) and the two
        // quota bars share whatever width is left, so the table uses the pane.
        let names: Vec<String> = rows
            .iter()
            .map(|q| label(&self.book, q["did"].as_str().unwrap_or("?")))
            .collect();
        let inner = area.width.saturating_sub(2);
        const FIXED: u16 = 9 + 11 + 11 + 8 + 6; // role, two counts, oldest, gaps
        let account_width = fit_width(&names, 15, 40);
        let bar_width = (inner.saturating_sub(account_width + FIXED) / 2).clamp(8, 40);
        let depth = self.depth;
        let table_rows: Vec<Row> = rows
            .iter()
            .map(|q| {
                let side = |s: &str| {
                    let d = &q[s];
                    (
                        d["count"].as_u64().unwrap_or(0),
                        d["limit"].as_i64().unwrap_or(-1),
                        d["saturation"].as_f64(),
                        d["oldestAgeSeconds"].as_u64(),
                    )
                };
                let (rc, rl, rs, ro) = side("receive");
                let (sc, sl, ss, so) = side("send");
                let limit = |l: i64| {
                    if l < 0 {
                        "∞".to_string()
                    } else {
                        l.to_string()
                    }
                };
                Row::new(vec![
                    Cell::from(label(&self.book, q["did"].as_str().unwrap_or("?"))),
                    Cell::from(q["accountType"].as_str().unwrap_or("").to_string()),
                    Cell::from(format!("{rc}/{}", limit(rl))),
                    Cell::from(quota_line(rs, bar_width, depth)),
                    Cell::from(format!("{sc}/{}", limit(sl))),
                    Cell::from(quota_line(ss, bar_width, depth)),
                    Cell::from(human_secs(ro.max(so))),
                ])
            })
            .collect();
        let snapshot = self
            .queues
            .as_ref()
            .and_then(|q| q["snapshotAt"].as_str())
            .map(|s| format!(" survey {s} "))
            .unwrap_or_default();
        let title = format!(
            "{title}— by {} of {} queue{snapshot}",
            SORTS[self.sort].1,
            if self.queue_send { "send" } else { "receive" }
        );
        let table = Table::new(
            table_rows,
            [
                Constraint::Length(account_width),
                Constraint::Length(9),
                Constraint::Length(11),
                Constraint::Length(bar_width),
                Constraint::Length(11),
                Constraint::Length(bar_width),
                Constraint::Length(8),
            ],
        )
        .header(
            Row::new(vec!["account", "role", "receive", "", "send", "", "oldest"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .block(Block::default().borders(Borders::ALL).title(title));
        f.render_stateful_widget(table, area, &mut self.queue_state);
    }

    fn render_account(&mut self, f: &mut Frame, area: Rect) {
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(9),
                Constraint::Length(7),
                Constraint::Min(4),
            ])
            .split(area);
        let top = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(parts[0]);
        self.render_account_settings(f, top[1]);
        let who = self.target.as_deref().map_or_else(
            || format!("{} (you)", short(self.console.did_hash())),
            |t| label(&self.book, t),
        );

        // Two gradient bars: how full each queue is against its limit.
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" Account {who} "));
        let inner = block.inner(top[0]);
        f.render_widget(block, top[0]);
        let lines = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1); 4])
            .split(inner);
        let q = self.status.as_ref().map(|s| &s["queues"]);
        for (i, side) in ["receive", "send"].iter().enumerate() {
            let d = q.map(|q| &q[side]).cloned().unwrap_or(Value::Null);
            let limit = d["limit"].as_i64().unwrap_or(-1);
            let sat = d["saturation"].as_f64();
            f.render_widget(
                Paragraph::new(format!(
                    "{side:>7}: {} / {}  {}  oldest {}",
                    d["count"].as_u64().unwrap_or(0),
                    if limit < 0 {
                        "∞".into()
                    } else {
                        limit.to_string()
                    },
                    sat.map_or(String::new(), |s| format!("{:.0}%", s * 100.0)),
                    human_secs(d["oldestAgeSeconds"].as_u64()),
                )),
                lines[i * 2],
            );
            f.render_widget(QuotaBar::new(sat, self.depth), lines[i * 2 + 1]);
        }

        // Who has not collected: the send queue by recipient.
        let peers = self
            .status
            .as_ref()
            .and_then(|s| s["sendPeers"].as_array().cloned())
            .unwrap_or_default();
        let peer_rows: Vec<Row> = peers
            .iter()
            .map(|p| {
                Row::new(vec![
                    label(&self.book, p["peer"].as_str().unwrap_or("?")),
                    p["count"].as_u64().unwrap_or(0).to_string(),
                    human_bytes(p["bytes"].as_u64()),
                    human_secs(p["oldestAgeSeconds"].as_u64()),
                ])
            })
            .collect();
        f.render_widget(
            Table::new(
                peer_rows,
                [
                    Constraint::Fill(1),
                    Constraint::Length(7),
                    Constraint::Length(9),
                    Constraint::Length(9),
                ],
            )
            .header(
                Row::new(vec!["recipient", "waiting", "bytes", "oldest"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Send queue by recipient — who hasn't collected "),
            ),
            parts[1],
        );

        let rows: Vec<Row> = self
            .messages
            .iter()
            .map(|m| {
                let state = m["deliveryState"].as_str().unwrap_or("");
                let color = if state == "delivered" {
                    Color::Yellow
                } else {
                    Color::Reset
                };
                Row::new(vec![
                    Cell::from(m["receivedAt"].as_str().map(time_of).unwrap_or_default()),
                    Cell::from(
                        m["from"]
                            .as_str()
                            .map_or_else(|| "anon".to_string(), |h| label(&self.book, h)),
                    ),
                    Cell::from(label(&self.book, m["to"].as_str().unwrap_or("?"))),
                    Cell::from(human_bytes(m["size"].as_u64())),
                    Cell::from(Span::styled(state.to_string(), Style::default().fg(color))),
                    Cell::from(short(m["msgId"].as_str().unwrap_or(""))),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(9),
                Constraint::Fill(2),
                Constraint::Fill(2),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Fill(1),
            ],
        )
        .header(
            Row::new(vec!["at", "from", "to", "size", "state", "id"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .block(Block::default().borders(Borders::ALL).title(format!(
            " {} queue — {} messages ",
            if self.message_send { "Send" } else { "Receive" },
            self.messages.len()
        )));
        f.render_stateful_widget(table, parts[2], &mut self.message_state);
    }

    /// The Account tab's settings panel: role, limits, access list, ACL flags.
    fn render_account_settings(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Settings — e to edit ");
        let Some(a) = &self.account_info else {
            f.render_widget(Paragraph::new("loading…").block(block), area);
            return;
        };
        let limit = |k: &str| match a["queueLimits"][k].as_i64() {
            Some(-1) => "unlimited".to_string(),
            Some(n) => n.to_string(),
            None => "default".to_string(),
        };
        let role = a["accountType"].as_str().unwrap_or("?").to_string();
        let role_style = match role.as_str() {
            "rootAdmin" => Style::default().fg(Color::Red),
            "admin" => Style::default().fg(Color::Yellow),
            _ => Style::default(),
        };
        let mut flags: Vec<Span> = Vec::new();
        if let Some(acl) = a["acl"].as_object() {
            let mut entries: Vec<(&String, bool)> = acl
                .iter()
                .filter_map(|(k, v)| v.as_bool().map(|b| (k, b)))
                .collect();
            entries.sort_by(|x, y| x.0.cmp(y.0));
            for (k, on) in entries {
                flags.push(Span::styled(
                    format!("{}{k} ", if on { "✓" } else { "✗" }),
                    Style::default().fg(if on { Color::Green } else { Color::DarkGray }),
                ));
            }
        }
        let text = vec![
            Line::from(vec![Span::raw("role "), Span::styled(role, role_style)]),
            Line::raw(format!(
                "limits  send {}  receive {}",
                limit("sendQueueLimit"),
                limit("receiveQueueLimit")
            )),
            Line::raw(format!(
                "access list  {} ({} entries)",
                a["acl"]["accessListMode"].as_str().unwrap_or("?"),
                a["accessListCount"].as_u64().unwrap_or(0)
            )),
            Line::raw(format!(
                "last message {} ago  last login {} ago",
                ago(a["lastReceivedAt"].as_u64()),
                ago(a["lastAuthenticatedAt"].as_u64())
            )),
            Line::raw(lifetime_totals(&a["stats"])),
            Line::from(flags),
        ];
        f.render_widget(
            Paragraph::new(text)
                .wrap(ratatui::widgets::Wrap { trim: false })
                .block(block),
            area,
        );
    }

    fn render_accounts(&mut self, f: &mut Frame, area: Rect) {
        let names: Vec<String> = self
            .accounts
            .iter()
            .map(|a| label(&self.book, a["did"].as_str().unwrap_or("?")))
            .collect();
        let name_width = fit_width(&names, 15, 40);
        let rows: Vec<Row> = self
            .accounts
            .iter()
            .zip(&names)
            .map(|(a, name)| {
                let hash = a["did"].as_str().unwrap_or("?");
                let n = |k: &str| a[k].as_u64().map_or("–".into(), |v| v.to_string());
                let bytes = a["receiveQueueBytes"].as_u64().unwrap_or(0)
                    + a["sendQueueBytes"].as_u64().unwrap_or(0);
                let role = a["accountType"].as_str().unwrap_or("").to_string();
                let style = match role.as_str() {
                    "rootAdmin" => Style::default().fg(Color::Red),
                    "admin" => Style::default().fg(Color::Yellow),
                    "mediator" => Style::default().fg(Color::Cyan),
                    _ => Style::default(),
                };
                Row::new(vec![
                    Cell::from(name.clone()),
                    Cell::from(if self.book.name_of(hash).is_some() {
                        short(hash)
                    } else {
                        String::new()
                    }),
                    Cell::from(role).style(style),
                    Cell::from(n("receiveQueueCount")),
                    Cell::from(n("sendQueueCount")),
                    Cell::from(human_bytes(Some(bytes))),
                    Cell::from(ago(a["lastReceivedAt"].as_u64())),
                    Cell::from(ago(a["lastAuthenticatedAt"].as_u64())),
                    Cell::from(n("accessListCount")),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(name_width),
                Constraint::Length(14),
                Constraint::Length(10),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Fill(1),
            ],
        )
        .header(
            Row::new(vec![
                "account",
                "hash",
                "role",
                "receive",
                "send",
                "queued",
                "msg ago",
                "login ago",
                "access list",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Accounts — {} ", self.accounts.len())),
        );
        f.render_stateful_widget(table, area, &mut self.accounts_state);
    }

    fn render_config(&mut self, f: &mut Frame, area: Rect) {
        let keys: Vec<String> = self
            .config
            .iter()
            .map(|c| c["key"].as_str().unwrap_or("").to_string())
            .collect();
        let rows: Vec<Row> = self
            .config
            .iter()
            .zip(&keys)
            .map(|(c, key)| {
                let value = match &c["value"] {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                let source = c["source"].as_str().unwrap_or("").to_string();
                let applies = if c["requiresRestart"] == false {
                    "live"
                } else {
                    "restart"
                };
                Row::new(vec![
                    Cell::from(key.clone()),
                    Cell::from(value),
                    Cell::from(source.clone()).style(if source == "override" {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default()
                    }),
                    Cell::from(applies),
                ])
            })
            .collect();
        let overrides = self
            .config
            .iter()
            .filter(|c| c["source"] == "override")
            .count();
        let table = Table::new(
            rows,
            [
                Constraint::Length(fit_width(&keys, 20, 48)),
                Constraint::Fill(2),
                Constraint::Length(10),
                Constraint::Length(8),
            ],
        )
        .header(
            Row::new(vec!["key", "value", "from", "applies"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .block(Block::default().borders(Borders::ALL).title(format!(
            " Configuration — {} keys, {overrides} overridden ",
            self.config.len()
        )));
        f.render_stateful_widget(table, area, &mut self.config_state);
    }

    fn render_audit(&self, f: &mut Frame, area: Rect) {
        let rows: Vec<Row> = self
            .audit
            .iter()
            .map(|e| {
                let pick = |keys: &[&str]| {
                    keys.iter()
                        .find_map(|k| e.get(*k).filter(|v| !v.is_null()))
                        .map(|v| {
                            v.as_str()
                                .map(str::to_string)
                                .unwrap_or_else(|| v.to_string())
                        })
                        .unwrap_or_default()
                };
                Row::new(vec![
                    pick(&["at", "timestamp", "recordedAt"]),
                    label(&self.book, &pick(&["actor"])),
                    pick(&["action"]),
                    label(&self.book, &pick(&["target", "subject"])),
                    pick(&["summary", "detail", "description"]),
                ])
            })
            .collect();
        f.render_widget(
            Table::new(
                rows,
                [
                    Constraint::Length(20),
                    Constraint::Fill(1),
                    Constraint::Length(20),
                    Constraint::Fill(1),
                    Constraint::Fill(2),
                ],
            )
            .header(
                Row::new(vec!["when", "actor", "action", "target", "detail"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .block(Block::default().borders(Borders::ALL).title(" Audit log ")),
            area,
        );
    }

    fn render_monitor(&mut self, f: &mut Frame, area: Rect) {
        let alive = match (self.monitor.task.is_some(), self.monitor.last_seen) {
            (false, _) => Span::styled("○ stopped", Style::default().fg(Color::Red)),
            (true, _) if let Some(at) = self.monitor.retry_at => Span::styled(
                format!(
                    "↻ resubscribing in {}s",
                    at.saturating_duration_since(Instant::now()).as_secs()
                ),
                Style::default().fg(Color::Yellow),
            ),
            (true, Some(t)) if t.elapsed() < Duration::from_secs(45) => {
                Span::styled("● live", Style::default().fg(Color::Green))
            }
            (true, Some(_)) => Span::styled("● silent", Style::default().fg(Color::Yellow)),
            (true, None) => Span::styled("◌ connecting", Style::default().fg(Color::DarkGray)),
        };
        let now = Instant::now();
        let tally = &self.monitor.tally;
        let title = Line::from(vec![
            Span::raw(format!(" Traffic — {} ", self.monitor.watching)),
            alive,
            Span::styled(
                format!(
                    "  {} msgs · {:.1}/s (now {:.1}/s) · {}",
                    tally.messages,
                    tally.rate(now),
                    tally.rate_now(now),
                    human_secs(Some(now.duration_since(tally.started()).as_secs())),
                ),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                protocol_mix(&tally.protocols),
                Style::default().fg(Color::Blue),
            ),
            Span::raw(format!(
                "  dropped {}  lost {}{} ",
                self.monitor.dropped,
                self.monitor.gaps,
                if self.monitor.failures_only {
                    "  failures only"
                } else {
                    ""
                },
            )),
        ]);
        let mut block = Block::default().borders(Borders::ALL).title(title);
        // On the bottom edge: the title is often wider than the pane.
        if self.monitor.back > 0 && !self.monitor.show_totals {
            block = block.title_bottom(
                Line::styled(
                    format!(" ⏸ {} newer · End to follow ", self.monitor.back),
                    Style::default().fg(Color::Black).bg(Color::Yellow),
                )
                .right_aligned(),
            );
        }
        if self.monitor.show_totals {
            self.render_totals(f, area, block, now);
            return;
        }
        let inner = block.inner(area);
        let height = inner.height as usize;
        self.monitor.page = height;
        // Sender and recipient as aligned columns, sharing what the fixed
        // columns (time, stage, protocol, channel, size) leave.
        const FIXED: u16 = 8 + 3 + 10 + 10 + 10 + 3 + 6;
        let name_w = (inner.width.saturating_sub(FIXED) / 2).clamp(14, 32) as usize; // a short hash is 13
        let back = self
            .monitor
            .back
            .min(self.monitor.lines.len().saturating_sub(height));
        let skip = self.monitor.lines.len().saturating_sub(height + back);
        let lines: Vec<Line> = self
            .monitor
            .lines
            .iter()
            .skip(skip)
            .take(height)
            .map(|l| match l {
                MonitorLine::Event(v) => event_line(v, &self.book, name_w),
                MonitorLine::Note(line) => line.clone(),
                // The count ahead of the reason, which is often a long error
                // the pane cuts off.
                MonitorLine::Retry { reason, attempts } => Line::styled(
                    match attempts {
                        1 => format!("── monitor interrupted: {reason} ──"),
                        n => format!("── monitor interrupted ×{n}: {reason} ──"),
                    },
                    Style::default().fg(Color::Yellow),
                ),
            })
            .collect();
        f.render_widget(Paragraph::new(lines).block(block), area);
    }

    /// The monitor's per-account totals: the busiest accounts since it started.
    fn render_totals(&self, f: &mut Frame, area: Rect, block: Block, now: Instant) {
        let top = self
            .monitor
            .tally
            .top(area.height.saturating_sub(3) as usize);
        let names: Vec<String> = top.iter().map(|(h, _)| label(&self.book, h)).collect();
        let rows: Vec<Row> = top
            .iter()
            .zip(&names)
            .map(|((_, a), name)| {
                Row::new(vec![
                    Cell::from(name.clone()),
                    Cell::from(a.sent.to_string()),
                    Cell::from(a.addressed.to_string()),
                    Cell::from(a.delivered.to_string()),
                    Cell::from(a.refused.to_string()).style(if a.refused > 0 {
                        Style::default().fg(Color::Red)
                    } else {
                        Style::default()
                    }),
                    Cell::from(human_bytes(Some(a.bytes))),
                    Cell::from(human_secs(a.last.map(|t| now.duration_since(t).as_secs()))),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Length(fit_width(&names, 14, 32)),
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Length(9),
                Constraint::Length(7),
                Constraint::Length(8),
                Constraint::Fill(1),
            ],
        )
        .header(
            Row::new(vec![
                "account",
                "sent",
                "to it",
                "delivered",
                "refused",
                "bytes",
                "last",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(block);
        f.render_widget(table, area);
    }
}

/// A one-line account of the mediator's answer to a `config/patch`.
fn patch_summary(v: &Value) -> (String, bool) {
    let list = |k: &str| -> Vec<String> {
        v[k].as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let rejected: Vec<String> = v["rejected"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|r| {
                    format!(
                        "{}: {}",
                        r["key"].as_str().unwrap_or("?"),
                        r["reason"].as_str().unwrap_or("?")
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    if !rejected.is_empty() {
        return (format!("refused — {}", rejected.join("; ")), true);
    }
    let applied = list("applied");
    let pending = list("pendingRestart");
    let mut parts = Vec::new();
    if !applied.is_empty() {
        parts.push(format!("in effect now: {}", applied.join(", ")));
    }
    if !pending.is_empty() {
        parts.push(format!("applies after a restart: {}", pending.join(", ")));
    }
    (parts.join("; "), false)
}

/// Every account on the mediator, reading all pages of `account/list`.
async fn all_accounts(console: &MediatorConsole) -> Result<Vec<Value>, ConsoleError> {
    const PAGE: u32 = 500;
    const MAX_PAGES: usize = 200;
    let mut all = Vec::new();
    let mut cursor = None;
    for _ in 0..MAX_PAGES {
        let page = serde_json::to_value(console.accounts(cursor, Some(PAGE)).await?)
            .unwrap_or(Value::Null);
        all.extend(page["accounts"].as_array().cloned().unwrap_or_default());
        cursor = page["nextCursor"].as_str().map(str::to_string);
        if cursor.is_none() {
            break;
        }
    }
    Ok(all)
}

/// The Accounts list's order: the mediator and administrators first, then
/// accounts you have named (by name), then the rest by hash.
fn account_order(a: &Value, book: &AddressBook) -> (u8, String) {
    let hash = a["did"].as_str().unwrap_or("");
    let rank = match a["accountType"].as_str() {
        Some("mediator") => 0,
        Some("rootAdmin") => 1,
        Some("admin") => 2,
        _ if book.name_of(hash).is_some() => 3,
        _ => 4,
    };
    let key = book
        .name_of(hash)
        .map(str::to_lowercase)
        .unwrap_or_else(|| hash.to_string());
    (rank, key)
}

/// `s` padded or cut (with `…`) to exactly `width` characters.
fn fit(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n <= width {
        format!("{s}{}", " ".repeat(width - n))
    } else {
        let cut: String = s.chars().take(width.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

/// A column width that fits the longest of `labels` (plus a space), held
/// between `min` and `max`.
fn fit_width(labels: &[String], min: u16, max: u16) -> u16 {
    let longest = labels.iter().map(|l| l.chars().count()).max().unwrap_or(0) as u16;
    (longest + 1).clamp(min, max)
}

/// An account hash as the user knows it: its nickname, else a short hash.
fn label(book: &AddressBook, hash: &str) -> String {
    book.name_of(hash)
        .map(str::to_string)
        .unwrap_or_else(|| short(hash))
}

/// One monitor event as a coloured line.
fn event_line(e: &Value, book: &AddressBook, name_w: usize) -> Line<'static> {
    let s = |k: &str| e[k].as_str().unwrap_or("").to_string();
    let stage = s("stage");
    let color = match stage.as_str() {
        "refused" => Color::Red,
        "delivered" => Color::Green,
        "forwarded" => Color::Cyan,
        "stored" => Color::Blue,
        "deleted" | "purged" | "expired" => Color::Magenta,
        _ => Color::Reset,
    };
    let arrow = match s("direction").as_str() {
        "inbound" => "▶",
        "outbound" => "◀",
        _ => "·",
    };
    let mut spans = vec![
        Span::styled(time_of(&s("at")), Style::default().fg(Color::DarkGray)),
        Span::raw(format!(" {arrow} ")),
        Span::styled(format!("{stage:<9}"), Style::default().fg(color)),
        Span::raw(format!(" {:<9} {:<9} ", s("protocol"), s("channel"))),
        Span::raw(format!(
            "{} → {} ",
            fit(
                &e["from"].as_str().map_or("·".into(), |h| label(book, h)),
                name_w
            ),
            fit(
                &e["to"].as_str().map_or("·".into(), |h| label(book, h)),
                name_w
            )
        )),
        Span::styled(
            human_bytes(e["size"].as_u64()),
            Style::default().fg(Color::DarkGray),
        ),
    ];
    if let Some(code) = e["outcome"]["code"].as_str() {
        spans.push(Span::styled(
            format!("  {code}"),
            Style::default().fg(Color::Red),
        ));
    }
    Line::from(spans)
}

fn inspect_popup(m: &InspectedMessage) -> Popup {
    let meta = serde_json::to_string_pretty(&m.meta).unwrap_or_default();
    let body = match &m.opened {
        Some((message, _)) => format!(
            "{meta}\n\n── decrypted ──\n{}",
            serde_json::to_string_pretty(message).unwrap_or_default()
        ),
        None => format!(
            "{meta}\n\n── encrypted ──\nThis session does not hold the recipient's key.\n\n{}",
            m.envelope.chars().take(2_000).collect::<String>()
        ),
    };
    Popup::Text {
        title: " Message ".into(),
        body,
    }
}

fn render_popup(f: &mut Frame, area: Rect, popup: &Popup, book: &AddressBook) {
    let (title, body, danger) = match popup {
        Popup::Name {
            hash,
            did,
            name,
            on_name,
        } => {
            let cursor = |on: bool| if on { "▏" } else { "" };
            let account = match hash {
                Some(h) => format!("Account  {h}\n\n"),
                None => String::new(),
            };
            let check = match (hash, did.trim()) {
                (Some(h), d) if !d.is_empty() => {
                    if account_hash(d) == *h {
                        "      ✓ this is the account\n"
                    } else {
                        "      ✗ a different account\n"
                    }
                }
                _ => "",
            };
            (
                " Name an account ".into(),
                format!(
                    "{account}DID   {did}{}\n{check}Name  {name}{}\n\n\
                     Paste or type. Tab switches field, ⏎ saves, Esc cancels.\n\
                     The DID is optional when an account is selected. An empty name \
                     removes the entry.",
                    cursor(!*on_name),
                    cursor(*on_name),
                ),
                false,
            )
        }
        Popup::Book { selected } => {
            let entries = book.entries();
            let body = if entries.is_empty() {
                "No names yet. Select an account and press n, or press a here to add one.".into()
            } else {
                entries
                    .iter()
                    .enumerate()
                    .map(|(i, e)| {
                        format!(
                            "{} {:<24} {}  {}",
                            if i == *selected { "▶" } else { " " },
                            e.name,
                            short(&e.hash()),
                            if e.is_bare_hash() {
                                "(no DID)".to_string()
                            } else {
                                short_did(&e.did)
                            }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            (
                " Address book ".into(),
                format!("{body}\n\n↑↓ select  n rename  a add  x remove  any other key closes"),
                false,
            )
        }
        // Drawn by `App::render_logs`, which has the log.
        Popup::Logs { .. } => return,
        Popup::EditAccount(edit) => {
            let rows = edit
                .rows
                .iter()
                .enumerate()
                .map(|(i, r)| {
                    let here = i == edit.selected;
                    let value = match (&edit.typing, r) {
                        (Some(t), Setting::Limit(..)) if here => format!("{t}▏"),
                        _ => r.shown(),
                    };
                    format!("{} {:<30} {value}", if here { "▶" } else { " " }, r.name())
                })
                .collect::<Vec<_>>()
                .join("\n");
            (
                format!(" Edit account {} ", short(&edit.target)),
                format!(
                    "{rows}\n\n↑↓ select  space toggle / cycle  digits set a limit (-1 = unlimited)\n\
                     s save  Esc cancel. The mediator decides what this session may change."
                ),
                false,
            )
        }
        Popup::EditConfig { key, value } => (
            " Change a limit ".into(),
            format!(
                "{key}\n\nNew value  {value}▏\n\n\
                 ⏎ applies, Esc cancels. A patch can make a limit stricter than the\n\
                 configuration, not looser; the mediator says which keys apply now,\n\
                 which from its next start, and why any are refused."
            ),
            false,
        ),
        Popup::Text { title, body } => (
            title.clone(),
            format!("{body}\n\n(any key to close)"),
            false,
        ),
        Popup::ConfirmDelete { ids, .. } => (
            " Delete ".into(),
            format!(
                "Delete {} message(s)? This cannot be undone.\n\ny to confirm, any other key to cancel",
                ids.len()
            ),
            true,
        ),
        Popup::ConfirmPurge(plan) => (
            " Purge ".into(),
            format!(
                "Purge {} message(s) ({}) from the {} queue{}?\nUndelivered messages are gone, not returned to their senders.\n\ny to confirm, any other key to cancel",
                plan.matched,
                human_bytes(Some(plan.matched_bytes)),
                format!("{:?}", plan.request.queue).to_lowercase(),
                plan.request
                    .peer
                    .as_deref()
                    .map(|p| format!(" exchanged with {}", label(book, p)))
                    .unwrap_or_default(),
            ),
            true,
        ),
    };
    let w = area.width.saturating_sub(8).min(100);
    let h = area
        .height
        .saturating_sub(4)
        .min(if danger { 9 } else { 40 });
    let rect = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );
    f.render_widget(Clear, rect);
    let border = if danger { Color::Red } else { Color::Cyan };
    f.render_widget(
        Paragraph::new(body)
            .wrap(Wrap { trim: false })
            .alignment(Alignment::Left)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border))
                    .title(title),
            ),
        rect,
    );
}

/// The monitor's feed, kept up for as long as the pane is open: a feed that
/// ends (its lease renewal failed, say, with the connection down) or goes
/// silent is replaced, after a backoff. Only a refusal stops it, since asking
/// again would get the same answer.
async fn watch(
    console: Arc<MediatorConsole>,
    filter: MonitorFilter,
    tx: mpsc::UnboundedSender<Update>,
) {
    let mut failures = 0;
    loop {
        let reason = match console.monitor(filter.clone()).await {
            Ok(mut feed) => loop {
                match tokio::time::timeout(MONITOR_SILENCE, feed.next()).await {
                    Ok(Some(MonitorUpdate::Ended(reason))) => break reason,
                    Ok(Some(update)) => {
                        failures = 0;
                        if tx.send(Update::Monitor(update)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => break "the feed closed".to_string(),
                    Err(_) => {
                        break format!(
                            "nothing from the mediator for {}s",
                            MONITOR_SILENCE.as_secs()
                        );
                    }
                }
                // Dropping the feed on the way out unsubscribes it.
            },
            Err(e) if is_refusal(&e) => {
                let _ = tx.send(Update::MonitorFailed(e));
                return;
            }
            Err(e) => e.to_string(),
        };
        let after = resubscribe_after(failures);
        failures += 1;
        if tx.send(Update::MonitorRetrying { reason, after }).is_err() {
            return;
        }
        tokio::time::sleep(after).await;
    }
}

/// A subscribe the mediator (or the console, knowing its answer) turned down.
fn is_refusal(e: &ConsoleError) -> bool {
    matches!(
        e,
        ConsoleError::Refused { .. } | ConsoleError::NotPermitted(_)
    )
}

/// How long to wait before the next subscribe, after `failures` in a row.
fn resubscribe_after(failures: u32) -> Duration {
    RESUBSCRIBE
        .saturating_mul(2u32.saturating_pow(failures.min(8)))
        .min(RESUBSCRIBE_MAX)
}

/// `text` cut into rows of at most `width` characters.
fn wrap_hard(text: &str, width: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    if chars.is_empty() {
        return vec![String::new()];
    }
    chars
        .chunks(width.max(1))
        .map(|c| c.iter().collect())
        .collect()
}

fn sha256_hex(s: &str) -> String {
    sha256::digest(s)
}

fn queue_rows(queues: &Option<Value>) -> Vec<Value> {
    queues
        .as_ref()
        .and_then(|q| q["queues"].as_array().cloned())
        .unwrap_or_default()
}

fn to_value<T: serde::Serialize>(r: Result<T, ConsoleError>) -> Result<Value, ConsoleError> {
    r.map(|v| serde_json::to_value(v).unwrap_or(Value::Null))
}

/// A DID hash shortened for a column.
fn short(s: &str) -> String {
    if s.chars().count() <= 14 {
        s.to_string()
    } else {
        let head: String = s.chars().take(8).collect();
        let tail: String = s
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("{head}…{tail}")
    }
}

fn short_did(s: &str) -> String {
    if s.len() <= 32 {
        s.to_string()
    } else {
        format!("{}…", &s[..30])
    }
}

fn time_of(ts: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|_| ts.chars().take(8).collect())
}

fn human_secs(s: Option<u64>) -> String {
    match s {
        None => "–".into(),
        Some(s) if s < 60 => format!("{s}s"),
        Some(s) if s < 3_600 => format!("{}m", s / 60),
        Some(s) if s < 86_400 => format!("{}h", s / 3_600),
        Some(s) => format!("{}d", s / 86_400),
    }
}

/// How long ago a Unix-seconds timestamp was, for the activity columns. A
/// mediator that doesn't serve the times, or has none for the account, gives
/// `None` — shown the same as any other unknown ("–").
fn ago(at: Option<u64>) -> String {
    let (Some(at), Ok(now)) = (at, std::time::SystemTime::UNIX_EPOCH.elapsed()) else {
        return "–".into();
    };
    // A time slightly in the future (clock skew between mediator and console)
    // reads as "now" rather than as a wrapped-around age.
    human_secs(Some(now.as_secs().saturating_sub(at)))
}

/// The wire mix of what arrived: TSP's share, and the counts behind it.
/// Empty until something has arrived — a share of nothing is not 0%.
fn protocol_mix(mix: &crate::tally::ProtocolMix) -> String {
    let Some(share) = mix.tsp_share() else {
        return String::new();
    };
    let mut parts = vec![format!("tsp {share:.0}%")];
    for (name, n) in [
        ("tsp", mix.tsp),
        ("didcomm", mix.didcomm),
        ("v1", mix.didcomm_v1),
        ("other", mix.other),
    ] {
        if n > 0 {
            parts.push(format!("{name} {n}"));
        }
    }
    format!("  {} ", parts.join(" · "))
}

/// An account's lifetime totals as the mediator counted them — not the
/// monitor's view, which only covers the current session. Empty against a
/// mediator that doesn't serve them.
fn lifetime_totals(stats: &Value) -> String {
    let Some(stats) = stats.as_object() else {
        return String::new();
    };
    let n = |k: &str| stats.get(k).and_then(Value::as_u64).unwrap_or(0);
    let mix = |k: &str| {
        let counts = &stats[k];
        let at = |p: &str| counts[p].as_u64().unwrap_or(0);
        let (tsp, didcomm) = (at("tsp"), at("didcomm") + at("didcommV1"));
        match tsp + didcomm {
            0 => String::new(),
            total => format!(" ({}% tsp)", tsp * 100 / total),
        }
    };
    format!(
        "lifetime  in {} / {}{}   out {} / {}{}",
        n("messagesReceived"),
        human_bytes(Some(n("bytesReceived"))),
        mix("receivedByProtocol"),
        n("messagesSent"),
        human_bytes(Some(n("bytesSent"))),
        mix("sentByProtocol"),
    )
}

fn human_bytes(b: Option<u64>) -> String {
    match b {
        None => "–".into(),
        Some(b) if b < 1_024 => format!("{b}B"),
        Some(b) if b < 1_048_576 => format!("{:.1}K", b as f64 / 1_024.0),
        Some(b) => format!("{:.1}M", b as f64 / 1_048_576.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resubscribing_backs_off_to_a_ceiling() {
        let waits: Vec<u64> = (0..6).map(|n| resubscribe_after(n).as_secs()).collect();
        assert_eq!(waits, [2, 4, 8, 16, 30, 30]);
        assert_eq!(resubscribe_after(u32::MAX), RESUBSCRIBE_MAX);
    }

    #[test]
    fn only_a_refusal_stops_the_monitor() {
        assert!(is_refusal(&ConsoleError::Refused {
            code: "e.p.req.unauthorized".into(),
            comment: "no".into(),
        }));
        assert!(is_refusal(&ConsoleError::NotPermitted("monitor")));
        assert!(!is_refusal(&ConsoleError::Connect("dns error".into())));
    }

    #[test]
    fn short_keeps_ends_of_a_hash() {
        assert_eq!(short("abcdefghijklmnopqrstuvwxyz"), "abcdefgh…wxyz");
        assert_eq!(short("short"), "short");
    }

    #[test]
    fn human_units() {
        assert_eq!(human_secs(Some(59)), "59s");
        assert_eq!(human_secs(Some(7_200)), "2h");
        assert_eq!(human_bytes(Some(2_048)), "2.0K");
        assert_eq!(human_bytes(None), "–");
    }

    #[test]
    fn a_named_account_shows_by_its_name_and_others_by_short_hash() {
        let alice = "did:example:alice";
        let mut book = AddressBook::new();
        book.insert(alice, "alice");
        let bob_hash = sha256::digest("did:example:bob");
        let line = event_line(
            &serde_json::json!({
                "at": "2026-09-21T10:00:00Z", "direction": "inbound", "stage": "stored",
                "channel": "rest", "protocol": "didcomm",
                "from": sha256::digest(alice), "to": bob_hash,
            }),
            &book,
            14,
        );
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        // Aligned: the sender is padded to the column width.
        assert!(text.contains("alice          → "), "{text}");
        assert!(text.contains(&short(&bob_hash)), "{text}");
    }

    #[test]
    fn a_patch_answer_is_summarised_in_one_line() {
        let (text, bad) = patch_summary(&serde_json::json!({
            "applied": ["limits.listed_messages"],
            "pendingRestart": ["limits.rate_limit_per_ip"],
            "rejected": [],
        }));
        assert!(!bad);
        assert!(
            text.contains("in effect now: limits.listed_messages"),
            "{text}"
        );
        assert!(
            text.contains("after a restart: limits.rate_limit_per_ip"),
            "{text}"
        );

        let (text, bad) = patch_summary(&serde_json::json!({
            "applied": [], "pendingRestart": [],
            "rejected": [{ "key": "limits.listed_messages", "reason": "above the configured value" }],
        }));
        assert!(bad);
        assert!(text.contains("above the configured value"), "{text}");
    }

    #[test]
    fn text_is_fitted_to_its_column() {
        assert_eq!(fit("abc", 5), "abc  ");
        assert_eq!(fit("abcdef", 4), "abc…");
        assert_eq!(fit("abcd", 4), "abcd");
        let names = vec![
            "short".to_string(),
            "a much longer account name".to_string(),
        ];
        assert_eq!(fit_width(&names, 15, 40), 27);
        assert_eq!(fit_width(&names, 15, 20), 20);
        assert_eq!(fit_width(&[], 15, 40), 15);
    }

    #[test]
    fn a_refusal_event_shows_its_code_in_red() {
        let line = event_line(
            &serde_json::json!({
                "at": "2026-09-21T10:00:00Z", "direction": "inbound", "stage": "refused",
                "channel": "rest", "protocol": "tsp", "from": "a", "size": 10,
                "outcome": { "code": "authorization.send" },
            }),
            &AddressBook::new(),
            14,
        );
        let text: String = line.spans.iter().map(|s| s.content.to_string()).collect();
        assert!(text.contains("refused") && text.contains("authorization.send"));
        assert!(line.spans.iter().any(|s| s.style.fg == Some(Color::Red)));
    }
}
