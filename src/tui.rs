use std::{
    collections::VecDeque,
    io::{self, stdout},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use chrono::Local;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    prelude::*,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

const MAX_EVENTS: usize = 300;
const MAX_RECENT: usize = 14;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventLevel {
    Ok,
    Inf,
    Wrn,
    Err,
}

impl EventLevel {
    fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK ",
            Self::Inf => "INF",
            Self::Wrn => "WRN",
            Self::Err => "ERR",
        }
    }

    fn color(self) -> Color {
        match self {
            Self::Ok => Color::Green,
            Self::Inf => Color::Cyan,
            Self::Wrn => Color::Yellow,
            Self::Err => Color::Red,
        }
    }
}

#[derive(Clone)]
pub struct WhitelistInfo {
    pub label: String,
    pub enabled: bool,
    pub check_before: bool,
    pub check_after: bool,
}

impl WhitelistInfo {
    pub fn off() -> Self {
        Self {
            label: "выкл".to_string(),
            enabled: false,
            check_before: false,
            check_after: false,
        }
    }
}

#[derive(Clone)]
pub struct ScanUiConfig {
    pub scan_name: String,
    pub total_subnets: usize,
    pub resume_count: usize,
    pub endpoint: String,
    pub operator: Option<String>,
    pub network_interface: Option<String>,
    pub whitelist: WhitelistInfo,
    pub tcp_ports: Vec<u16>,
    pub socket_type: String,
    pub ping_types: Vec<String>,
    pub subnet_parallelism: usize,
    pub result_jsonl: String,
    pub last_stop: Option<String>,
}

#[derive(Clone)]
struct EventLine {
    time: String,
    level: EventLevel,
    message: String,
}

#[derive(Clone)]
struct SubnetRow {
    index: usize,
    total: usize,
    subnet: String,
    icmp: usize,
    tcp: usize,
    rejected: usize,
    seconds: f64,
    status: SubnetStatus,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SubnetStatus {
    Scanning,
    Alive,
    IcmpOnly,
    Dead,
    Error,
}

impl SubnetStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Scanning => "…",
            Self::Alive => "tcp",
            Self::IcmpOnly => "icmp",
            Self::Dead => "—",
            Self::Error => "err",
        }
    }

    fn color(self) -> Color {
        match self {
            Self::Scanning => Color::LightBlue,
            Self::Alive => Color::Green,
            Self::IcmpOnly => Color::Yellow,
            Self::Dead => Color::DarkGray,
            Self::Error => Color::Red,
        }
    }
}

struct ScanDashboard {
    started_at: Instant,
    config: ScanUiConfig,
    scanned_total: usize,
    scanned_this_run: usize,
    completed_subnet_seconds: f64,
    completion_marks: VecDeque<Instant>,
    alive_subnets: usize,
    icmp_only_subnets: usize,
    dead_subnets: usize,
    icmp_hosts_total: usize,
    tcp_hosts_total: usize,
    rejected_hosts_total: usize,
    errors: usize,
    inflight: Vec<(SubnetRow, Instant)>,
    inflight_subnets: usize,
    recent: VecDeque<SubnetRow>,
    events: VecDeque<EventLine>,
    whitelist_status: String,
    endpoint_ok: bool,
    done_message: Option<String>,
    running: bool,
    stopping: bool,
}

impl ScanDashboard {
    fn new(config: ScanUiConfig) -> Self {
        let whitelist_enabled = config.whitelist.enabled;
        let total = config.total_subnets;
        let resume_count = config.resume_count;
        let mut dash = Self {
            started_at: Instant::now(),
            scanned_total: resume_count,
            config,
            whitelist_status: if whitelist_enabled {
                "не проверен".to_string()
            } else {
                "выкл".to_string()
            },
            endpoint_ok: true,
            running: true,
            stopping: false,
            ..Default::default()
        };
        dash.push_event(EventLevel::Inf, format!("Старт · {total} /24"));
        if resume_count > 0 {
            dash.push_event(
                EventLevel::Inf,
                format!("Resume: {resume_count} /24 пропускаем"),
            );
        }
        let ports: Vec<String> = dash.config.tcp_ports.iter().map(|p| p.to_string()).collect();
        dash.push_event(
            EventLevel::Inf,
            format!(
                "Probe: {} · ports {} · endpoint {}",
                dash.config.ping_types.join("+"),
                ports.join(","),
                dash.config.endpoint
            ),
        );
        if dash.config.whitelist.enabled {
            dash.push_event(
                EventLevel::Inf,
                format!(
                    "Whitelist: {} (до={}, после={})",
                    dash.config.whitelist.label,
                    if dash.config.whitelist.check_before {
                        "да"
                    } else {
                        "нет"
                    },
                    if dash.config.whitelist.check_after {
                        "да"
                    } else {
                        "нет"
                    },
                ),
            );
        }
        dash
    }

    fn push_event(&mut self, level: EventLevel, message: impl Into<String>) {
        self.events.push_back(EventLine {
            time: Local::now().format("%H:%M:%S").to_string(),
            level,
            message: message.into(),
        });
        while self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
    }

    fn set_scanning(&mut self, index: usize, subnet: &str) {
        if let Some((row, _)) = self.inflight.iter_mut().find(|(row, _)| row.subnet == subnet) {
            row.index = index;
            row.total = self.config.total_subnets;
            row.status = SubnetStatus::Scanning;
            return;
        }
        self.inflight.push((
            SubnetRow {
                index,
                total: self.config.total_subnets,
                subnet: subnet.to_string(),
                icmp: 0,
                tcp: 0,
                rejected: 0,
                seconds: 0.0,
                status: SubnetStatus::Scanning,
            },
            Instant::now(),
        ));
        self.inflight_subnets = self.inflight.len();
    }

    fn tick_current(&mut self) {
        for (row, started) in &mut self.inflight {
            row.seconds = started.elapsed().as_secs_f64();
        }
    }

    fn complete_subnet(
        &mut self,
        index: usize,
        subnet: &str,
        icmp: usize,
        tcp: usize,
        rejected: usize,
        seconds: f64,
        is_error: bool,
    ) {
        let status = if is_error {
            self.errors += 1;
            SubnetStatus::Error
        } else if tcp > 0 {
            self.alive_subnets += 1;
            SubnetStatus::Alive
        } else if icmp > 0 {
            self.icmp_only_subnets += 1;
            SubnetStatus::IcmpOnly
        } else {
            self.dead_subnets += 1;
            SubnetStatus::Dead
        };

        if !is_error {
            self.icmp_hosts_total += icmp;
            self.tcp_hosts_total += tcp;
            self.rejected_hosts_total += rejected;
            self.scanned_this_run += 1;
            self.scanned_total += 1;
            self.completed_subnet_seconds += seconds;
            self.completion_marks.push_back(Instant::now());
            while self.completion_marks.len() > 120 {
                self.completion_marks.pop_front();
            }
        }

        let row = SubnetRow {
            index,
            total: self.config.total_subnets,
            subnet: subnet.to_string(),
            icmp,
            tcp,
            rejected,
            seconds,
            status,
        };

        if let Some(pos) = self
            .inflight
            .iter()
            .position(|(row, _)| row.subnet == subnet)
        {
            self.inflight.swap_remove(pos);
        }
        self.inflight_subnets = self.inflight.len();
        self.recent.push_front(row);
        while self.recent.len() > MAX_RECENT {
            self.recent.pop_back();
        }

        if !is_error {
            let level = if tcp > 0 {
                EventLevel::Ok
            } else if icmp > 0 {
                EventLevel::Inf
            } else {
                EventLevel::Inf
            };
            let tag = status.label();
            self.push_event(
                level,
                format!(
                    "{subnet} · icmp {icmp} tcp {tcp} rej {rejected} · {seconds:.1}s [{tag}]"
                ),
            );
        }
    }

    fn progress_position(&self) -> usize {
        (self.scanned_total + self.inflight.len()).min(self.config.total_subnets)
    }

    fn progress_ratio(&self) -> f64 {
        if self.config.total_subnets == 0 {
            return 0.0;
        }
        (self.progress_position() as f64 / self.config.total_subnets as f64).min(1.0)
    }

    fn progress_percent(&self) -> f64 {
        self.progress_ratio() * 100.0
    }

    fn subnets_per_minute(&self) -> f64 {
        let marks = self.completion_marks.len();
        if marks >= 2 {
            let first = self.completion_marks.front().unwrap();
            let last = self.completion_marks.back().unwrap();
            let span = (*last - *first).as_secs_f64();
            if span > 0.0 {
                // Completion cadence reflects real throughput in both sequential and parallel modes.
                return ((marks - 1) as f64 / span) * 60.0;
            }
        }

        // Fallback for startup phase (0-1 completed subnet): stable estimate from finished subnet durations.
        let avg_secs = self.avg_subnet_seconds();
        if avg_secs <= 0.0 {
            0.0
        } else {
            60.0 / avg_secs
        }
    }

    fn avg_subnet_seconds(&self) -> f64 {
        if self.scanned_this_run == 0 {
            return 0.0;
        }
        self.completed_subnet_seconds / self.scanned_this_run as f64
    }

    fn eta_label(&self) -> String {
        let subnets_per_min = self.subnets_per_minute();
        if subnets_per_min <= 0.0 {
            return "—".to_string();
        }
        let remaining = self
            .config
            .total_subnets
            .saturating_sub(self.scanned_total);
        let mins = remaining as f64 / subnets_per_min;
        if mins < 60.0 {
            format!("~{:.0}m", mins)
        } else if mins < 60.0 * 48.0 {
            format!("~{:.1}h", mins / 60.0)
        } else {
            format!("~{:.1}d", mins / 60.0 / 24.0)
        }
    }
}

impl Default for ScanDashboard {
    fn default() -> Self {
        Self {
            started_at: Instant::now(),
            config: ScanUiConfig {
                scan_name: String::new(),
                total_subnets: 0,
                resume_count: 0,
                endpoint: String::new(),
                operator: None,
                network_interface: None,
                whitelist: WhitelistInfo::off(),
                tcp_ports: vec![],
                socket_type: String::new(),
                ping_types: vec![],
                subnet_parallelism: 1,
                result_jsonl: String::new(),
                last_stop: None,
            },
            scanned_total: 0,
            scanned_this_run: 0,
            completed_subnet_seconds: 0.0,
            completion_marks: VecDeque::new(),
            alive_subnets: 0,
            icmp_only_subnets: 0,
            dead_subnets: 0,
            icmp_hosts_total: 0,
            tcp_hosts_total: 0,
            rejected_hosts_total: 0,
            errors: 0,
            inflight: Vec::new(),
            inflight_subnets: 0,
            recent: VecDeque::new(),
            events: VecDeque::new(),
            whitelist_status: String::new(),
            endpoint_ok: true,
            done_message: None,
            running: true,
            stopping: false,
        }
    }
}

pub struct ScanUi {
    state: Arc<Mutex<ScanDashboard>>,
    cancel: Arc<AtomicBool>,
    shutdown: std::sync::mpsc::Sender<()>,
    draw_thread: Option<JoinHandle<()>>,
}

impl ScanUi {
    pub fn try_start(config: ScanUiConfig) -> io::Result<Self> {
        let state = Arc::new(Mutex::new(ScanDashboard::new(config)));
        let cancel = Arc::new(AtomicBool::new(false));
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let draw_state = Arc::clone(&state);
        let draw_cancel = Arc::clone(&cancel);

        let handler_cancel = Arc::clone(&cancel);
        let _ = ctrlc::set_handler(move || {
            handler_cancel.store(true, Ordering::SeqCst);
        });

        let draw_thread = thread::spawn(move || {
            let _ = run_loop(draw_state, draw_cancel, shutdown_rx, ready_tx);
        });

        match ready_rx.recv_timeout(Duration::from_secs(3)) {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                let _ = draw_thread.join();
                return Err(io::Error::other(err));
            }
            Err(_) => {
                cancel.store(true, Ordering::SeqCst);
                let _ = shutdown_tx.send(());
                let _ = draw_thread.join();
                return Err(io::Error::other("TUI draw thread timeout"));
            }
        }

        let ui = Self {
            state,
            cancel,
            shutdown: shutdown_tx,
            draw_thread: Some(draw_thread),
        };
        Ok(ui)
    }

    pub fn cancel_flag(&self) -> &AtomicBool {
        &self.cancel
    }

    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn log(&self, level: EventLevel, message: impl Into<String>) {
        if let Ok(mut dash) = self.state.lock() {
            dash.push_event(level, message);
        }
    }

    pub fn set_scanning(&self, index: usize, subnet: &str) {
        if let Ok(mut dash) = self.state.lock() {
            dash.set_scanning(index, subnet);
        }
    }

    pub fn set_inflight_subnets(&self, count: usize) {
        if let Ok(mut dash) = self.state.lock() {
            dash.inflight_subnets = count;
        }
    }

    pub fn complete_subnet(
        &self,
        index: usize,
        subnet: &str,
        icmp: usize,
        tcp: usize,
        rejected: usize,
        seconds: f64,
    ) {
        if let Ok(mut dash) = self.state.lock() {
            dash.complete_subnet(index, subnet, icmp, tcp, rejected, seconds, false);
        }
    }

    pub fn subnet_error(&self, index: usize, subnet: &str, error: &str) {
        if let Ok(mut dash) = self.state.lock() {
            dash.complete_subnet(index, subnet, 0, 0, 0, 0.0, true);
            dash.push_event(EventLevel::Err, format!("{subnet}: {error}"));
        }
    }

    pub fn set_whitelist_status(&self, status: impl Into<String>) {
        if let Ok(mut dash) = self.state.lock() {
            dash.whitelist_status = status.into();
        }
    }

    pub fn set_endpoint_ok(&self, ok: bool) {
        if let Ok(mut dash) = self.state.lock() {
            dash.endpoint_ok = ok;
        }
    }

    pub fn finish(mut self, message: impl Into<String>) {
        if let Ok(mut dash) = self.state.lock() {
            dash.done_message = Some(message.into());
            dash.running = false;
            dash.stopping = false;
        }
        let _ = self.shutdown.send(());
        if let Some(handle) = self.draw_thread.take() {
            let _ = handle.join();
        }
        if let Ok(dash) = self.state.lock() {
            if let Some(msg) = &dash.done_message {
                println!("{msg}");
            }
        }
    }
}

impl Drop for ScanUi {
    fn drop(&mut self) {
        if let Ok(mut dash) = self.state.lock() {
            dash.running = false;
        }
        let _ = self.shutdown.send(());
        if let Some(handle) = self.draw_thread.take() {
            let _ = handle.join();
        }
    }
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), LeaveAlternateScreen);
    let _ = execute!(stdout(), crossterm::cursor::Show);
}

fn run_loop(
    state: Arc<Mutex<ScanDashboard>>,
    cancel: Arc<AtomicBool>,
    shutdown: std::sync::mpsc::Receiver<()>,
    ready: std::sync::mpsc::Sender<Result<(), String>>,
) -> Result<(), String> {
    if enable_raw_mode().is_err() {
        let _ = ready.send(Err("enable_raw_mode failed".to_string()));
        return Err("enable_raw_mode failed".into());
    }
    if execute!(stdout(), EnterAlternateScreen).is_err() {
        let _ = disable_raw_mode();
        let _ = ready.send(Err("EnterAlternateScreen failed".to_string()));
        return Err("EnterAlternateScreen failed".into());
    }

    let _guard = TerminalGuard;

    let mut terminal = match Terminal::new(CrosstermBackend::new(stdout())) {
        Ok(terminal) => terminal,
        Err(err) => {
            let _ = ready.send(Err(format!("Terminal::new failed: {err}")));
            return Err(format!("Terminal::new failed: {err}"));
        }
    };

    if terminal
        .draw(|frame| {
            if let Ok(dash) = state.lock() {
                render(frame, &dash);
            }
        })
        .is_err()
    {
        let _ = ready.send(Err("initial draw failed".to_string()));
        return Err("initial draw failed".into());
    }
    let _ = ready.send(Ok(()));

    loop {
        if shutdown.try_recv().is_ok() {
            break;
        }

        if event::poll(Duration::from_millis(50)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                if key.kind == KeyEventKind::Press
                    && key.code == KeyCode::Char('c')
                    && key.modifiers.contains(KeyModifiers::CONTROL)
                {
                    cancel.store(true, Ordering::SeqCst);
                }
            }
        }

        if let Ok(mut dash) = state.lock() {
            if cancel.load(Ordering::Relaxed) && !dash.stopping {
                dash.stopping = true;
                dash.push_event(EventLevel::Wrn, "Остановка сканирования, ждите…");
            }
            dash.tick_current();
            if !dash.running {
                break;
            }
        }

        if terminal
            .draw(|frame| {
                if let Ok(dash) = state.lock() {
                    render(frame, &dash);
                }
            })
            .is_err()
        {
            break;
        }

        thread::sleep(Duration::from_millis(80));
    }

    Ok(())
}

fn render(frame: &mut Frame, dash: &ScanDashboard) {
    let area = frame.area();
    if area.width < 10 || area.height < 6 {
        frame.render_widget(
            Paragraph::new("Terminal too small for TUI"),
            area,
        );
        return;
    }

    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(8)])
        .split(frame.area());

    render_stats(frame, root[0], dash);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
        .split(root[1]);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(body[0]);

    render_recent(frame, left[0], dash);
    render_events(frame, left[1], dash);
    render_side(frame, body[1], dash);
}

fn render_stats(frame: &mut Frame, area: Rect, dash: &ScanDashboard) {
    let inner = area.inner(Margin::new(1, 0));
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(2)])
        .split(inner);

    let uptime = format_duration(dash.started_at.elapsed());
    let rate = format!("{:.1}", dash.subnets_per_minute());
    let avg = if dash.avg_subnet_seconds() > 0.0 {
        format!("{:.1}s/subnet", dash.avg_subnet_seconds())
    } else {
        "—".to_string()
    };
    let done = dash.progress_position();
    let total = dash.config.total_subnets;
    let pct = dash.progress_percent();

    let line1 = Line::from(vec![
        Span::styled("time ", Style::default().fg(Color::DarkGray)),
        Span::styled(uptime, Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("  │  "),
        Span::styled(format!("{rate}/min"), Style::default().fg(Color::Cyan)),
        Span::raw("  │  "),
        Span::styled(avg, Style::default().fg(Color::DarkGray)),
        Span::raw("  │  ETA "),
        Span::styled(dash.eta_label(), Style::default().fg(Color::Cyan)),
        Span::raw("  │  "),
        Span::styled("tcp ", Style::default().fg(Color::DarkGray)),
        Span::styled(dash.tcp_hosts_total.to_string(), Style::default().fg(Color::Green)),
        Span::raw("  │  "),
        Span::styled("rej ", Style::default().fg(Color::DarkGray)),
        Span::styled(dash.rejected_hosts_total.to_string(), Style::default().fg(Color::Yellow)),
        Span::raw("  │  "),
        Span::styled("живые ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!(
                "{}+{} dead {}",
                dash.alive_subnets, dash.icmp_only_subnets, dash.dead_subnets
            ),
            Style::default().fg(Color::Green),
        ),
        Span::raw("  │  "),
        Span::styled(&dash.config.scan_name, Style::default().fg(Color::Cyan)),
    ]);

    let bar_width = chunks[1].width.saturating_sub(2) as usize;
    let (bar, _) = subnet_progress_bar(done, total, bar_width.max(20));
    let scanning = !dash.inflight.is_empty();
    let status = if scanning { " ▶" } else { "" };
    let stopping = if dash.stopping {
        "  ⏳ Остановка сканирования, ждите…"
    } else {
        ""
    };

    let progress_line = Line::from(vec![
        Span::styled(format!("{done}/{total}"), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(bar, Style::default().fg(Color::Cyan)),
        Span::raw(" "),
        Span::styled(format_pct(pct), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(status, Style::default().fg(Color::LightBlue)),
        Span::styled(stopping, Style::default().fg(Color::Yellow)),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Span::styled(
            " pizdos-scanner · Ctrl+C — стоп ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));

    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(line1), chunks[0]);
    frame.render_widget(Paragraph::new(progress_line), chunks[1]);
}

fn subnet_progress_bar(done: usize, total: usize, width: usize) -> (String, f64) {
    let ratio = if total == 0 {
        0.0
    } else {
        (done as f64 / total as f64).min(1.0)
    };
    let filled = ((width as f64) * ratio).round() as usize;
    let filled = filled.min(width);
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(width.saturating_sub(filled)));
    (bar, ratio * 100.0)
}

fn format_pct(pct: f64) -> String {
    if pct >= 10.0 {
        format!("{pct:.1}%")
    } else if pct >= 1.0 {
        format!("{pct:.2}%")
    } else {
        format!("{pct:.3}%")
    }
}

fn render_recent(frame: &mut Frame, area: Rect, dash: &ScanDashboard) {
    let header = Row::new(vec!["#", "Подсеть", "ICMP", "TCP", "Rej", "s", ""])
        .style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .height(1);

    let mut rows: Vec<Row> = Vec::new();
    let mut inflight_rows: Vec<&SubnetRow> = dash.inflight.iter().map(|(row, _)| row).collect();
    inflight_rows.sort_by_key(|row| std::cmp::Reverse(row.index));
    for row in inflight_rows {
        rows.push(subnet_row(row));
    }
    for row in &dash.recent {
        rows.push(subnet_row(row));
    }

    let table = Table::new(rows, [
        Constraint::Length(9),
        Constraint::Min(14),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(4),
        Constraint::Length(5),
        Constraint::Length(4),
    ])
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(Span::styled(" /24 ", Style::default().fg(Color::Cyan))),
    );

    frame.render_widget(table, area);
}

fn subnet_row(row: &SubnetRow) -> Row<'static> {
    let idx = format!("[{}/{}]", row.index, row.total);
    Row::new(vec![
        Cell::from(idx),
        Cell::from(row.subnet.clone()),
        Cell::from(row.icmp.to_string()),
        Cell::from(row.tcp.to_string()),
        Cell::from(row.rejected.to_string()),
        Cell::from(format!("{:.1}", row.seconds)),
        Cell::from(row.status.label()).style(Style::default().fg(row.status.color())),
    ])
    .style(if row.status == SubnetStatus::Scanning {
        Style::default().fg(Color::LightBlue)
    } else {
        Style::default()
    })
}

fn render_events(frame: &mut Frame, area: Rect, dash: &ScanDashboard) {
    let visible = area.height.saturating_sub(2) as usize;
    let skip = dash.events.len().saturating_sub(visible);
    let lines: Vec<Line> = dash
        .events
        .iter()
        .skip(skip)
        .map(|event| {
            Line::from(vec![
                Span::styled(format!("{} ", event.time), Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{} ", event.level.label()),
                    Style::default().fg(event.level.color()).add_modifier(Modifier::BOLD),
                ),
                Span::raw(event.message.clone()),
            ])
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta))
        .title(Span::styled(" События ", Style::default().fg(Color::Magenta)));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_side(frame: &mut Frame, area: Rect, dash: &ScanDashboard) {
    let endpoint_color = if dash.endpoint_ok {
        Color::Green
    } else {
        Color::Red
    };
    let endpoint_status = if dash.endpoint_ok { "OK" } else { "FAIL" };

    let wl_color = if dash.config.whitelist.enabled {
        match dash.whitelist_status.as_str() {
            "доступен" => Color::Red,
            "недоступен" => Color::Green,
            _ => Color::Yellow,
        }
    } else {
        Color::DarkGray
    };

    let ports: String = dash
        .config
        .tcp_ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let interface_label = dash
        .config
        .network_interface
        .as_deref()
        .filter(|v| !v.is_empty())
        .map(|v| format!("{v} (forced)"))
        .unwrap_or_else(|| "auto (system route)".to_string());

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Endpoint   ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{} ", dash.config.endpoint), Style::default().fg(endpoint_color)),
            Span::styled(format!("[{endpoint_status}]"), Style::default().fg(endpoint_color)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Whitelist  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                if dash.config.whitelist.enabled {
                    dash.config.whitelist.label.clone()
                } else {
                    "выкл — раскомментируй [stop_on_available]".to_string()
                },
                Style::default().fg(if dash.config.whitelist.enabled { Color::White } else { Color::DarkGray }),
            ),
        ]),
        Line::from(vec![
            Span::styled("WL probe   ", Style::default().fg(Color::DarkGray)),
            Span::styled(&dash.whitelist_status, Style::default().fg(wl_color)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Probe      ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!(
                "{} · {} · ports {ports}",
                dash.config.ping_types.join("+"),
                dash.config.socket_type,
            )),
        ]),
        Line::from(vec![
            Span::styled("Workers    ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!(
                "{}/{}",
                dash.inflight_subnets, dash.config.subnet_parallelism
            )),
        ]),
        Line::from(vec![
            Span::styled("Operator   ", Style::default().fg(Color::DarkGray)),
            Span::raw(
                dash.config
                    .operator
                    .as_deref()
                    .filter(|v| !v.is_empty())
                    .unwrap_or("—"),
            ),
        ]),
        Line::from(vec![
            Span::styled("Interface  ", Style::default().fg(Color::DarkGray)),
            Span::raw(interface_label),
        ]),
        Line::from(vec![
            Span::styled("Сессия     ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!(
                "+{} /24 · resume {} · err {}",
                dash.scanned_this_run, dash.config.resume_count, dash.errors
            )),
        ]),
        Line::from(vec![
            Span::styled("Хосты      ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!(
                "icmp {} · tcp {} · rej {}",
                dash.icmp_hosts_total, dash.tcp_hosts_total, dash.rejected_hosts_total
            )),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("JSONL      ", Style::default().fg(Color::DarkGray)),
            Span::raw(truncate(&dash.config.result_jsonl, 32)),
        ]),
    ];

    if let Some(last_stop) = &dash.config.last_stop {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("Last stop  ", Style::default().fg(Color::DarkGray)),
            Span::styled(truncate(last_stop, 30), Style::default().fg(Color::Yellow)),
        ]));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .title(Span::styled(" Контроль ", Style::default().fg(Color::Yellow)));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}

fn truncate(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        s.to_string()
    } else {
        format!(
            "…{}",
            chars[chars.len().saturating_sub(max - 1)..]
                .iter()
                .collect::<String>()
        )
    }
}
