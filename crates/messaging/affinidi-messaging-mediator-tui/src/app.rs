//! The console application: state, keys, rendering and background work.
//!
//! [`App`] is a component, not a program. A host owns the terminal and the
//! event loop and calls [`App::handle_key`], [`App::apply`] and
//! [`App::render`]; [`App::run`] is that loop for hosts that want it done for
//! them (the `mediator-console` binary does). Work against the mediator runs
//! on background tasks and comes back as [`Update`]s, so rendering never
//! waits on the network.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use affinidi_messaging_mediator_admin::{
    ConsoleError, InspectedMessage, MediatorConsole, Mode, MonitorFilter, MonitorUpdate, PurgePlan,
    PurgeRequest, specs,
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

use crate::quota::{ColorDepth, QuotaBar, quota_line};

/// How often the current view refreshes on its own.
const REFRESH: Duration = Duration::from_secs(5);
/// Monitor lines kept on screen.
const MONITOR_LINES: usize = 500;

/// The console's screens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Queues,
    Account,
    Audit,
}

impl Tab {
    fn title(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Queues => "Queues",
            Tab::Account => "Account",
            Tab::Audit => "Audit",
        }
    }
}

/// A result of background work, applied with [`App::apply`].
pub enum Update {
    Stats(Result<Value, ConsoleError>),
    Queues(Result<Value, ConsoleError>),
    Status(Result<Value, ConsoleError>),
    Messages(Result<Value, ConsoleError>),
    Audit(Result<Value, ConsoleError>),
    Inspected(Box<Result<InspectedMessage, ConsoleError>>),
    PurgePreview(Result<PurgePlan, ConsoleError>),
    /// A finished action: what to tell the user.
    Done(Result<String, ConsoleError>),
    Monitor(MonitorUpdate),
    MonitorFailed(ConsoleError),
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
}

struct MonitorPane {
    visible: bool,
    failures_only: bool,
    lines: VecDeque<Line<'static>>,
    dropped: u64,
    gaps: u64,
    last_seen: Option<Instant>,
    watching: String,
    task: Option<JoinHandle<()>>,
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
    monitor: MonitorPane,
    popup: Option<Popup>,
    notice: Option<(String, bool)>,
    updated: Option<Instant>,
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
        let mut app = Self {
            console: Arc::new(console),
            depth: ColorDepth::detect(),
            tab: if admin { Tab::Dashboard } else { Tab::Account },
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
            monitor: MonitorPane {
                visible: false,
                failures_only: false,
                lines: VecDeque::new(),
                dropped: 0,
                gaps: 0,
                last_seen: None,
                watching: String::new(),
                task: None,
            },
            popup: None,
            notice: None,
            updated: None,
        };
        app.refresh();
        app
    }

    /// Show one account on the Account tab — `None` is the console's own.
    pub fn open_account(&mut self, did_hash: Option<String>) {
        self.target = did_hash;
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
            vec![Tab::Dashboard, Tab::Queues, Tab::Account, Tab::Audit]
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
            Update::Inspected(r) => match *r {
                Ok(m) => self.popup = Some(inspect_popup(&m)),
                Err(e) => self.error(e),
            },
            Update::PurgePreview(r) => match r {
                Ok(plan) if plan.matched == 0 => {
                    self.notice = Some(("nothing to purge".into(), false))
                }
                Ok(plan) => self.popup = Some(Popup::ConfirmPurge(plan)),
                Err(e) => self.error(e),
            },
            Update::Done(r) => {
                match r {
                    Ok(msg) => self.notice = Some((msg, false)),
                    Err(e) => self.error(e),
                }
                self.refresh();
            }
            Update::Monitor(u) => self.monitor_update(u),
            Update::MonitorFailed(e) => {
                self.monitor.task = None;
                self.error(e);
            }
        }
    }

    /// Wait for the next result of background work — for a host running its
    /// own loop. Apply it with [`App::apply`].
    pub async fn next_update(&mut self) -> Option<Update> {
        self.rx.recv().await
    }

    fn error(&mut self, e: ConsoleError) {
        self.notice = Some((e.to_string(), true));
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
            KeyCode::Char(c @ '1'..='4') => {
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
            KeyCode::Char('m') => self.toggle_monitor(),
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
            (Tab::Account, KeyCode::Char('x')) => {
                self.message_send = !self.message_send;
                self.message_state.select(Some(0));
                self.refresh();
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
                self.notice = Some(("cancelled".into(), false));
            }
        }
    }

    fn move_selection(&mut self, delta: i32) {
        let (state, len) = match self.tab {
            Tab::Queues | Tab::Dashboard => (&mut self.queue_state, queue_rows(&self.queues).len()),
            Tab::Account => (&mut self.message_state, self.messages.len()),
            Tab::Audit => return,
        };
        if len == 0 {
            return;
        }
        let i = state.selected().unwrap_or(0) as i32 + delta;
        state.select(Some(i.clamp(0, len as i32 - 1) as usize));
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
        let dids = match (&self.target, self.tab) {
            (Some(t), Tab::Account) => Some(vec![t.clone()]),
            _ => None,
        };
        self.monitor.watching = match (&dids, self.admin()) {
            (Some(d), _) => format!("account {}", short(&d[0])),
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
        self.monitor.task = Some(tokio::spawn(async move {
            match console.monitor(filter).await {
                Ok(mut feed) => {
                    while let Some(update) = feed.next().await {
                        if tx.send(Update::Monitor(update)).is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Update::MonitorFailed(e));
                }
            }
        }));
    }

    /// This console's own requests to the mediator, and the clean-up of their
    /// replies. The mediator leaves out most of a subscriber's management
    /// traffic, but a `received` event carries no recipient yet and a REST
    /// `deleted` event no sender, so the console's own polling would still
    /// show.
    fn is_own_console_traffic(&self, e: &Value) -> bool {
        let me = self.console.did_hash();
        let mediator = sha256_hex(self.console.mediator_did());
        let from = e["from"].as_str();
        let to = e["to"].as_str();
        let own_request = from == Some(me) && to.is_none_or(|to| to == mediator);
        let own_reply_cleanup = e["stage"] == "deleted" && to == Some(me) && from.is_none();
        own_request || own_reply_cleanup
    }

    fn monitor_update(&mut self, update: MonitorUpdate) {
        self.monitor.last_seen = Some(Instant::now());
        match update {
            MonitorUpdate::Events { events, dropped } => {
                self.monitor.dropped += dropped;
                for e in events {
                    let v = serde_json::to_value(e).unwrap_or(Value::Null);
                    if !self.is_own_console_traffic(&v) {
                        self.monitor.lines.push_back(event_line(&v));
                    }
                }
            }
            MonitorUpdate::Gap { missing } => {
                self.monitor.gaps += missing;
                self.monitor.lines.push_back(Line::styled(
                    format!("── {missing} batch(es) lost in transit ──"),
                    Style::default().fg(Color::Yellow),
                ));
            }
            MonitorUpdate::Heartbeat => {}
            MonitorUpdate::Ended(reason) => {
                self.monitor.task = None;
                self.monitor.lines.push_back(Line::styled(
                    format!("── monitor ended: {reason} ──"),
                    Style::default().fg(Color::Red),
                ));
            }
        }
        while self.monitor.lines.len() > MONITOR_LINES {
            self.monitor.lines.pop_front();
        }
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
        loop {
            terminal.draw(|f| self.render(f, f.area()))?;
            tokio::select! {
                Some(Ok(event)) = events.next() => {
                    if let Event::Key(key) = event
                        && self.handle_key(key) == Control::Quit
                    {
                        break;
                    }
                }
                Some(update) = self.rx.recv() => self.apply(update),
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
        match self.tab {
            Tab::Dashboard => self.render_dashboard(f, body),
            Tab::Queues => self.render_queues(f, body),
            Tab::Account => self.render_account(f, body),
            Tab::Audit => self.render_audit(f, body),
        }
        self.render_footer(f, rows[3]);
        if let Some(popup) = &self.popup {
            render_popup(f, area, popup);
        }
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
                short(self.console.did_hash()),
                short_did(self.console.mediator_did())
            )),
            Span::styled(age, Style::default().fg(Color::DarkGray)),
        ]);
        f.render_widget(Paragraph::new(line), area);
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
        let line = match &self.notice {
            Some((text, true)) => {
                Line::styled(format!(" ✗ {text}"), Style::default().fg(Color::Red))
            }
            Some((text, false)) => {
                Line::styled(format!(" ✓ {text}"), Style::default().fg(Color::Green))
            }
            None => {
                let keys = match self.tab {
                    Tab::Dashboard | Tab::Queues => {
                        "↑↓ select  ⏎ open  s sort  x recv/send  m monitor  f failures  r refresh  q quit"
                    }
                    Tab::Account => {
                        "↑↓ select  i inspect  d delete  p purge  P purge peer  x recv/send  o own  m monitor  q quit"
                    }
                    Tab::Audit => "m monitor  r refresh  q quit",
                };
                Line::styled(format!(" {keys}"), Style::default().fg(Color::DarkGray))
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
        let bar_width = 16;
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
                    Cell::from(short(q["did"].as_str().unwrap_or("?"))),
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
                Constraint::Length(15),
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
                Constraint::Length(6),
                Constraint::Length(7),
                Constraint::Min(4),
            ])
            .split(area);
        let who = self.target.as_deref().map_or_else(
            || format!("{} (you)", short(self.console.did_hash())),
            short,
        );

        // Two gradient bars: how full each queue is against its limit.
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" Account {who} "));
        let inner = block.inner(parts[0]);
        f.render_widget(block, parts[0]);
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
                    short(p["peer"].as_str().unwrap_or("?")),
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
                    Constraint::Length(15),
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
                    Cell::from(short(m["from"].as_str().unwrap_or("anon"))),
                    Cell::from(short(m["to"].as_str().unwrap_or("?"))),
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
                Constraint::Length(15),
                Constraint::Length(15),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Min(10),
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
                    short(&pick(&["actor"])),
                    pick(&["action"]),
                    short(&pick(&["target", "subject"])),
                    pick(&["summary", "detail", "description"]),
                ])
            })
            .collect();
        f.render_widget(
            Table::new(
                rows,
                [
                    Constraint::Length(20),
                    Constraint::Length(15),
                    Constraint::Length(20),
                    Constraint::Length(15),
                    Constraint::Min(20),
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

    fn render_monitor(&self, f: &mut Frame, area: Rect) {
        let alive = match (self.monitor.task.is_some(), self.monitor.last_seen) {
            (false, _) => Span::styled("○ stopped", Style::default().fg(Color::Red)),
            (true, Some(t)) if t.elapsed() < Duration::from_secs(45) => {
                Span::styled("● live", Style::default().fg(Color::Green))
            }
            (true, Some(_)) => Span::styled("● silent", Style::default().fg(Color::Yellow)),
            (true, None) => Span::styled("◌ connecting", Style::default().fg(Color::DarkGray)),
        };
        let title = Line::from(vec![
            Span::raw(format!(" Traffic — {} ", self.monitor.watching)),
            alive,
            Span::raw(format!(
                "  dropped {}  lost {}{} ",
                self.monitor.dropped,
                self.monitor.gaps,
                if self.monitor.failures_only {
                    "  failures only"
                } else {
                    ""
                }
            )),
        ]);
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        let height = inner.height as usize;
        let skip = self.monitor.lines.len().saturating_sub(height);
        let lines: Vec<Line> = self.monitor.lines.iter().skip(skip).cloned().collect();
        f.render_widget(Paragraph::new(lines).block(block), area);
    }
}

/// One monitor event as a coloured line.
fn event_line(e: &Value) -> Line<'static> {
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
            e["from"].as_str().map_or("·".into(), short),
            e["to"].as_str().map_or("·".into(), short)
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

fn render_popup(f: &mut Frame, area: Rect, popup: &Popup) {
    let (title, body, danger) = match popup {
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
                    .map(|p| format!(" exchanged with {}", short(p)))
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
    fn a_refusal_event_shows_its_code_in_red() {
        let line = event_line(&serde_json::json!({
            "at": "2026-09-21T10:00:00Z", "direction": "inbound", "stage": "refused",
            "channel": "rest", "protocol": "tsp", "from": "a", "size": 10,
            "outcome": { "code": "authorization.send" },
        }));
        let text: String = line.spans.iter().map(|s| s.content.to_string()).collect();
        assert!(text.contains("refused") && text.contains("authorization.send"));
        assert!(line.spans.iter().any(|s| s.style.fg == Some(Color::Red)));
    }
}
