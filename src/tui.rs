use std::{
    collections::VecDeque,
    io,
    path::PathBuf,
    process::Command,
    time::{Duration, Instant, SystemTime},
};

use anyhow::Result;
use crossterm::{
    event::{self, Event as CEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Sparkline, Table, Wrap},
};
use sysinfo::{ProcessesToUpdate, System};
use tokio::{
    sync::broadcast,
    sync::mpsc,
    time::{MissedTickBehavior, interval},
};

use crate::telemetry::{
    DashboardSnapshot, MonitorContext, RecentTargetSnapshot, TraceEvent, attach_socket,
    event_impacts_health,
};

const HISTORY_LEN: usize = 48;
const RECENT_EVENTS: usize = 40;
const RECENT_TARGETS: usize = RECENT_EVENTS;
const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

#[derive(Clone, Debug)]
pub struct DashboardContext {
    pub command_label: String,
    pub mode_label: String,
    pub listen: Option<String>,
    pub upstream: Option<String>,
    pub path: Option<String>,
    pub log_file: PathBuf,
    pub log_filter: String,
}

pub async fn run(
    context: DashboardContext,
    mut receiver: broadcast::Receiver<TraceEvent>,
) -> Result<()> {
    run_loop(DashboardApp::new(context), move || receiver.try_recv()).await
}

pub async fn run_attached(socket_path: PathBuf) -> Result<()> {
    let (snapshot, mut receiver) = attach_socket(&socket_path).await?;
    run_loop(DashboardApp::from_snapshot(snapshot), move || {
        receiver.try_recv().map_err(map_mpsc_try_recv)
    })
    .await
}

async fn run_loop<F>(mut app: DashboardApp, mut next_event: F) -> Result<()>
where
    F: FnMut() -> std::result::Result<TraceEvent, broadcast::error::TryRecvError>,
{
    let _terminal_guard = TerminalGuard::enter()?;
    let stdout = io::stdout();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut ticker = interval(Duration::from_millis(160));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        loop {
            match next_event() {
                Ok(event) => app.ingest(event),
                Err(broadcast::error::TryRecvError::Empty) => break,
                Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
                Err(broadcast::error::TryRecvError::Closed) => return Ok(()),
            }
        }

        terminal.draw(|frame| draw_dashboard(frame, &app))?;

        if event::poll(Duration::from_millis(0))?
            && let CEvent::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && is_exit_key(key)
        {
            return Ok(());
        }

        ticker.tick().await;
        app.on_tick();
    }
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

fn is_exit_key(key: KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
        || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
}

#[derive(Clone, Debug)]
struct RecentTarget {
    seen_at: String,
    route: String,
    link: String,
    uploaded: u64,
    downloaded: u64,
}

struct DashboardApp {
    context: DashboardContext,
    pid: u32,
    started_at: Instant,
    spinner_index: usize,
    total_relays: u64,
    total_errors: u64,
    total_warnings: u64,
    total_uploaded: u64,
    total_downloaded: u64,
    upload_history: Vec<u64>,
    download_history: Vec<u64>,
    last_bucket_at: Instant,
    last_process_refresh: Instant,
    process_stats: ProcessStats,
    last_event_at: Option<Instant>,
    last_warning_at: Option<Instant>,
    last_traffic_at: Option<Instant>,
    recent_targets: VecDeque<RecentTarget>,
    recent_events: VecDeque<String>,
}

#[derive(Clone, Debug, Default)]
struct ProcessStats {
    memory_bytes: u64,
    threads: Option<usize>,
}

impl From<MonitorContext> for DashboardContext {
    fn from(value: MonitorContext) -> Self {
        Self {
            command_label: value.command_label,
            mode_label: value.mode_label,
            listen: value.listen,
            upstream: value.upstream,
            path: value.path,
            log_file: value.log_file,
            log_filter: value.log_filter,
        }
    }
}

impl From<RecentTargetSnapshot> for RecentTarget {
    fn from(value: RecentTargetSnapshot) -> Self {
        Self {
            seen_at: value.seen_at,
            route: value.route,
            link: value.link,
            uploaded: value.uploaded,
            downloaded: value.downloaded,
        }
    }
}

impl DashboardApp {
    fn new(context: DashboardContext) -> Self {
        let mut app = Self {
            context,
            pid: std::process::id(),
            started_at: Instant::now(),
            spinner_index: 0,
            total_relays: 0,
            total_errors: 0,
            total_warnings: 0,
            total_uploaded: 0,
            total_downloaded: 0,
            upload_history: vec![0; HISTORY_LEN],
            download_history: vec![0; HISTORY_LEN],
            last_bucket_at: Instant::now(),
            last_process_refresh: Instant::now() - Duration::from_secs(3),
            process_stats: ProcessStats::default(),
            last_event_at: None,
            last_warning_at: None,
            last_traffic_at: None,
            recent_targets: VecDeque::with_capacity(RECENT_TARGETS),
            recent_events: VecDeque::with_capacity(RECENT_EVENTS),
        };
        app.refresh_process_stats();
        app
    }

    fn from_snapshot(snapshot: DashboardSnapshot) -> Self {
        let DashboardSnapshot {
            context,
            uptime_secs,
            total_relays,
            total_errors,
            total_warnings,
            total_uploaded,
            total_downloaded,
            upload_history,
            download_history,
            recent_targets,
            recent_events,
            last_event_age_ms,
            last_warning_age_ms,
            last_traffic_age_ms,
        } = snapshot;

        let mut app = Self {
            pid: context.pid,
            context: DashboardContext::from(context),
            started_at: Instant::now() - Duration::from_secs(uptime_secs),
            spinner_index: 0,
            total_relays,
            total_errors,
            total_warnings,
            total_uploaded,
            total_downloaded,
            upload_history: fit_history(upload_history),
            download_history: fit_history(download_history),
            last_bucket_at: Instant::now(),
            last_process_refresh: Instant::now() - Duration::from_secs(3),
            process_stats: ProcessStats::default(),
            last_event_at: age_to_instant(last_event_age_ms),
            last_warning_at: age_to_instant(last_warning_age_ms),
            last_traffic_at: age_to_instant(last_traffic_age_ms),
            recent_targets: recent_targets.into_iter().map(RecentTarget::from).collect(),
            recent_events: recent_events.into_iter().collect(),
        };
        app.refresh_process_stats();
        app
    }

    fn on_tick(&mut self) {
        self.spinner_index = (self.spinner_index + 1) % SPINNER.len();
        while self.last_bucket_at.elapsed() >= Duration::from_secs(1) {
            rotate_history(&mut self.upload_history);
            rotate_history(&mut self.download_history);
            self.last_bucket_at += Duration::from_secs(1);
        }
        if self.last_process_refresh.elapsed() >= Duration::from_secs(2) {
            self.refresh_process_stats();
        }
    }

    fn ingest(&mut self, event: TraceEvent) {
        self.last_event_at = Some(Instant::now());
        let level = event.level.as_str();
        let impacts_health =
            event_impacts_health(Some(self.context.command_label.as_str()), &event);
        if level == "WARN" {
            self.total_warnings += 1;
        }
        if level == "ERROR" || event.message.contains("with error") {
            self.total_errors += 1;
        }
        if impacts_health {
            self.last_warning_at = Some(Instant::now());
        }

        self.capture_listener_context(&event);
        self.capture_recent_event(&event);

        if event.message == "dns query" {
            self.capture_recent_domain(&event);
            return;
        }

        if event.message == "traffic sample" {
            self.last_traffic_at = Some(Instant::now());
            let uploaded = parse_u64(event.fields.get("uploaded"));
            let downloaded = parse_u64(event.fields.get("downloaded"));
            if traffic_sample_is_aggregate(&event) {
                self.total_uploaded += uploaded;
                self.total_downloaded += downloaded;
            }
            if let Some(last) = self.upload_history.last_mut() {
                *last += uploaded;
            }
            if let Some(last) = self.download_history.last_mut() {
                *last += downloaded;
            }
            return;
        }

        if event.message.contains("relay completed") {
            self.total_relays += 1;
            let uploaded = parse_u64(event.fields.get("uploaded"));
            let downloaded = parse_u64(event.fields.get("downloaded"));
            self.total_uploaded += uploaded;
            self.total_downloaded += downloaded;
            if uploaded > 0 || downloaded > 0 {
                self.last_traffic_at = Some(Instant::now());
            }
            let sampled = parse_bool(event.fields.get("sampled"));
            if !sampled {
                if let Some(last) = self.upload_history.last_mut() {
                    *last += uploaded;
                }
                if let Some(last) = self.download_history.last_mut() {
                    *last += downloaded;
                }
            }

            let target = event
                .fields
                .get("target")
                .cloned()
                .unwrap_or_else(|| "-".to_owned());
            let route = event
                .fields
                .get("route")
                .cloned()
                .unwrap_or_else(|| "remote".to_owned());

            self.recent_targets.push_front(RecentTarget {
                seen_at: clock_stamp(event.at),
                link: link_from_target(&target),
                route,
                uploaded,
                downloaded,
            });
            self.recent_targets.truncate(RECENT_TARGETS);
        }
    }

    fn capture_recent_domain(&mut self, event: &TraceEvent) {
        let target = event
            .fields
            .get("target")
            .cloned()
            .unwrap_or_else(|| "-".to_owned());
        let link = event
            .fields
            .get("link")
            .cloned()
            .unwrap_or_else(|| link_from_target(&target));
        let route = event
            .fields
            .get("route")
            .cloned()
            .unwrap_or_else(|| "remote".to_owned());

        self.recent_targets.push_front(RecentTarget {
            seen_at: clock_stamp(event.at),
            link,
            route,
            uploaded: 0,
            downloaded: 0,
        });
        self.recent_targets.truncate(RECENT_TARGETS);
    }

    fn refresh_process_stats(&mut self) {
        self.last_process_refresh = Instant::now();
        self.process_stats = sample_process_stats(self.pid);
    }

    fn status(&self) -> (&'static str, Color) {
        if self
            .last_warning_at
            .is_some_and(|seen| seen.elapsed() <= Duration::from_secs(20))
        {
            ("degraded", Color::Yellow)
        } else if self
            .last_traffic_at
            .is_some_and(|seen| seen.elapsed() <= Duration::from_secs(5))
        {
            ("active", Color::Green)
        } else if self
            .last_event_at
            .is_some_and(|seen| seen.elapsed() <= Duration::from_secs(30))
        {
            ("ready", Color::Cyan)
        } else {
            ("idle", Color::DarkGray)
        }
    }

    fn capture_listener_context(&mut self, event: &TraceEvent) {
        if !event.message.contains("listening") {
            return;
        }

        if self.context.listen.is_none() {
            self.context.listen = event.fields.get("listen").cloned();
        }
        if self.context.upstream.is_none() {
            self.context.upstream = event
                .fields
                .get("server")
                .cloned()
                .or_else(|| event.fields.get("fallback").cloned());
        }
        if self.context.path.is_none() {
            self.context.path = event.fields.get("path").cloned();
        }
        if self.context.mode_label == "-" {
            self.context.mode_label = event
                .fields
                .get("mode")
                .cloned()
                .unwrap_or_else(|| "-".to_owned());
        }
    }

    fn capture_recent_event(&mut self, event: &TraceEvent) {
        if event.message == "traffic sample" || event.message == "dns query" {
            return;
        }
        if event.message.contains("relay completed") && self.recent_events.len() >= RECENT_EVENTS {
            return;
        }

        let mut suffix = String::new();
        if let Some(target) = event.fields.get("target") {
            suffix.push_str(" ");
            suffix.push_str(target);
        } else if let Some(error) = event.fields.get("error") {
            suffix.push_str(" ");
            suffix.push_str(error);
        } else if let Some(listen) = event.fields.get("listen") {
            suffix.push_str(" ");
            suffix.push_str(listen);
        }

        self.recent_events.push_front(format!(
            "{} [{}] {}{}",
            clock_stamp(event.at),
            event.level,
            event.message,
            suffix
        ));
        self.recent_events.truncate(RECENT_EVENTS);
    }
}

fn draw_dashboard(frame: &mut ratatui::Frame<'_>, app: &DashboardApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Length(4),
            Constraint::Length(7),
            Constraint::Min(16),
            Constraint::Length(2),
        ])
        .split(frame.area());
    let (status_label, status_color) = app.status();

    let endpoint_line = if app.context.command_label == "server" {
        Line::from(vec![
            Span::styled("listen ", overview_label_style()),
            Span::styled(
                app.context.listen.as_deref().unwrap_or("-"),
                overview_value_style(),
            ),
            Span::raw("    "),
            Span::styled("path ", overview_label_style()),
            Span::styled(
                app.context.path.as_deref().unwrap_or("-"),
                overview_value_style(),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled("listen ", overview_label_style()),
            Span::styled(
                app.context.listen.as_deref().unwrap_or("-"),
                overview_value_style(),
            ),
            Span::raw("    "),
            Span::styled("upstream ", overview_label_style()),
            Span::styled(
                app.context.upstream.as_deref().unwrap_or("-"),
                overview_value_style(),
            ),
            Span::raw("    "),
            Span::styled("path ", overview_label_style()),
            Span::styled(
                app.context.path.as_deref().unwrap_or("-"),
                overview_value_style(),
            ),
        ])
    };

    let title = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                format!("{} pipit dashboard", SPINNER[app.spinner_index]),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                &app.context.command_label,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("mode ", overview_label_style()),
            Span::styled(&app.context.mode_label, overview_value_style()),
            Span::raw("    "),
            Span::styled("uptime ", overview_label_style()),
            Span::styled(
                format_uptime(app.started_at.elapsed()),
                overview_value_style(),
            ),
            Span::raw("    "),
            Span::styled("status ", overview_label_style()),
            Span::styled(
                status_label,
                Style::default()
                    .fg(status_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("pid ", overview_label_style()),
            Span::styled(app.pid.to_string(), overview_value_style()),
            Span::raw("    "),
            Span::styled("memory ", overview_label_style()),
            Span::styled(
                format_bytes(app.process_stats.memory_bytes),
                overview_value_style(),
            ),
            Span::raw("    "),
            Span::styled("threads ", overview_label_style()),
            Span::styled(
                app.process_stats
                    .threads
                    .map(|threads| threads.to_string())
                    .unwrap_or_else(|| "-".to_owned()),
                overview_value_style(),
            ),
            Span::raw("    "),
            Span::styled("log ", overview_label_style()),
            Span::styled(
                app.context.log_file.display().to_string(),
                Style::default().fg(Color::Green),
            ),
        ]),
        endpoint_line,
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Overview")
            .border_style(Style::default().fg(Color::Cyan)),
    )
    .wrap(Wrap { trim: true });
    frame.render_widget(title, chunks[0]);

    let stats = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(chunks[1]);

    frame.render_widget(
        stat_block("Relays", app.total_relays.to_string(), Color::Cyan),
        stats[0],
    );
    frame.render_widget(
        stat_block("Warnings", app.total_warnings.to_string(), Color::Yellow),
        stats[1],
    );
    frame.render_widget(
        stat_block("Uploaded", format_bytes(app.total_uploaded), Color::Green),
        stats[2],
    );
    frame.render_widget(
        stat_block(
            "Downloaded",
            format_bytes(app.total_downloaded),
            Color::Magenta,
        ),
        stats[3],
    );

    let charts = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[2]);

    render_wave(
        frame,
        charts[0],
        "Upload Wave",
        &app.upload_history,
        Color::Green,
    );
    render_wave(
        frame,
        charts[1],
        "Download Wave",
        &app.download_history,
        Color::Magenta,
    );

    let lower = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[3]);

    let speed = current_speed(app);
    let rows = app.recent_targets.iter().map(|item| {
        Row::new(vec![
            Cell::from(item.seen_at.clone()),
            Cell::from(item.route.clone()),
            Cell::from(item.link.clone()),
            Cell::from(recent_target_activity(item, &app.context, speed)),
        ])
    });
    let table = Table::new(rows, recent_targets_widths())
        .header(
            Row::new(vec![
                "When",
                "Route",
                "Link",
                recent_targets_activity_header(&app.context),
            ])
            .style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(recent_targets_title(&app.context))
                .border_style(Style::default().fg(Color::Blue)),
        )
        .column_spacing(1);
    frame.render_widget(table, lower[0]);

    let items = app
        .recent_events
        .iter()
        .map(|line| ListItem::new(Line::from(line.clone())));
    let events = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Recent Events")
            .border_style(Style::default().fg(Color::Yellow)),
    );
    frame.render_widget(events, lower[1]);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled(
            "q",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" quit  "),
        Span::styled("logs", overview_label_style()),
        Span::raw(format!(" -> {}", app.context.log_file.display())),
        Span::raw("  "),
        Span::styled("filter", overview_label_style()),
        Span::raw(format!(" -> {}", app.context.log_filter)),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Controls"));
    frame.render_widget(footer, chunks[4]);
}

fn stat_block(title: &'static str, value: String, color: Color) -> Paragraph<'static> {
    Paragraph::new(vec![
        Line::from(Span::styled(
            value,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(title.to_owned(), overview_label_style())),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(color)),
    )
}

fn overview_label_style() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

fn overview_value_style() -> Style {
    Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD)
}

fn render_wave(
    frame: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    title: &str,
    history: &[u64],
    color: Color,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(wave_title(title, history))
        .border_style(Style::default().fg(color));
    let width = usize::from(block.inner(area).width);
    let data = fit_wave_data_to_width(history, width);

    frame.render_widget(
        Sparkline::default()
            .block(block)
            .style(Style::default().fg(color))
            .data(&data),
        area,
    );
}

fn rotate_history(history: &mut Vec<u64>) {
    history.rotate_left(1);
    if let Some(last) = history.last_mut() {
        *last = 0;
    }
}

fn fit_history(mut history: Vec<u64>) -> Vec<u64> {
    if history.len() > HISTORY_LEN {
        return history.split_off(history.len() - HISTORY_LEN);
    }
    if history.len() < HISTORY_LEN {
        let mut padded = vec![0; HISTORY_LEN - history.len()];
        padded.extend(history);
        return padded;
    }
    history
}

fn age_to_instant(age_ms: Option<u64>) -> Option<Instant> {
    age_ms.map(|age| Instant::now() - Duration::from_millis(age))
}

fn map_mpsc_try_recv(error: mpsc::error::TryRecvError) -> broadcast::error::TryRecvError {
    match error {
        mpsc::error::TryRecvError::Empty => broadcast::error::TryRecvError::Empty,
        mpsc::error::TryRecvError::Disconnected => broadcast::error::TryRecvError::Closed,
    }
}

fn fit_wave_data_to_width(history: &[u64], width: usize) -> Vec<u64> {
    if width == 0 {
        return Vec::new();
    }

    if history.is_empty() {
        return vec![0; width];
    }

    if width >= history.len() {
        return (0..width)
            .map(|column| {
                let index = column * history.len() / width;
                history[index.min(history.len() - 1)]
            })
            .collect();
    }

    (0..width)
        .map(|column| {
            let start = column * history.len() / width;
            let end = ((column + 1) * history.len() / width).max(start + 1);
            history[start..end].iter().copied().max().unwrap_or(0)
        })
        .collect()
}

fn parse_u64(value: Option<&String>) -> u64 {
    value
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

fn parse_bool(value: Option<&String>) -> bool {
    value
        .map(|value| matches!(value.as_str(), "true" | "1" | "yes"))
        .unwrap_or(false)
}

fn traffic_sample_is_aggregate(event: &TraceEvent) -> bool {
    parse_bool(event.fields.get("aggregate"))
        || event.fields.get("mode").is_some_and(|mode| mode == "wg")
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_uptime(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs() % 60;
    let minutes = (elapsed.as_secs() / 60) % 60;
    let hours = elapsed.as_secs() / 3600;
    if hours > 0 {
        format!("{hours}h {minutes:02}m {seconds:02}s")
    } else {
        format!("{minutes:02}m {seconds:02}s")
    }
}

fn wave_title(label: &str, history: &[u64]) -> String {
    let current = history.last().copied().unwrap_or(0);
    let peak = history.iter().copied().max().unwrap_or(0);
    format!(
        "{label} · {}/s now · {}/s peak",
        format_bytes(current),
        format_bytes(peak)
    )
}

fn clock_stamp(at: SystemTime) -> String {
    let elapsed = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let seconds = elapsed % 60;
    let minutes = (elapsed / 60) % 60;
    let hours = (elapsed / 3600) % 24;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

fn link_from_target(target: &str) -> String {
    let (host, port) = split_target(target);
    match port {
        Some(80) => format!("http://{host}"),
        Some(443) => format!("https://{host}"),
        Some(port) => format!("tcp://{host}:{port}"),
        None => format!("tcp://{target}"),
    }
}

fn recent_targets_title(context: &DashboardContext) -> &'static str {
    if recent_targets_are_domain_events(context) {
        "Recent Domains"
    } else {
        "Recent Domains"
    }
}

fn recent_targets_activity_header(context: &DashboardContext) -> &'static str {
    if recent_targets_are_domain_events(context) {
        "Tunnel Speed"
    } else {
        "Up / Down"
    }
}

fn recent_target_activity(
    item: &RecentTarget,
    context: &DashboardContext,
    speed: (u64, u64),
) -> String {
    if recent_targets_are_domain_events(context) || item.link.starts_with("dns://") {
        return format_speed(speed);
    }

    format!(
        "{} / {}",
        format_bytes(item.uploaded),
        format_bytes(item.downloaded)
    )
}

fn current_speed(app: &DashboardApp) -> (u64, u64) {
    (
        app.upload_history.last().copied().unwrap_or_default(),
        app.download_history.last().copied().unwrap_or_default(),
    )
}

fn format_speed((uploaded_per_sec, downloaded_per_sec): (u64, u64)) -> String {
    format!(
        "{}/s / {}/s",
        format_bytes(uploaded_per_sec),
        format_bytes(downloaded_per_sec)
    )
}

fn recent_targets_are_domain_events(context: &DashboardContext) -> bool {
    context.mode_label == "wg" || context.command_label.starts_with("wg-")
}

fn recent_targets_widths() -> [Constraint; 4] {
    [
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Min(16),
        Constraint::Length(24),
    ]
}

fn sample_process_stats(pid: u32) -> ProcessStats {
    let mut system = System::new();
    let sys_pid = sysinfo::Pid::from_u32(pid);
    system.refresh_processes(ProcessesToUpdate::Some(&[sys_pid]), true);

    let memory_bytes = system
        .process(sys_pid)
        .map(|process| process.memory())
        .unwrap_or(0);

    let threads = sample_thread_count(pid);

    ProcessStats {
        memory_bytes,
        threads,
    }
}

fn sample_thread_count(pid: u32) -> Option<usize> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("ps")
            .args(["-o", "pid=", "-M", "-p", &pid.to_string()])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let count = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        return Some(count.max(1));
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ps")
            .args(["-o", "nlwp=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        return String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<usize>()
            .ok();
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        None
    }
}

fn split_target(target: &str) -> (String, Option<u16>) {
    if let Some(rest) = target.strip_prefix('[')
        && let Some((host, suffix)) = rest.split_once(']')
    {
        let port = suffix.strip_prefix(':').and_then(|port| port.parse().ok());
        return (host.to_owned(), port);
    }

    if let Some((host, port)) = target.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return (host.to_owned(), Some(port));
    }

    (target.to_owned(), None)
}

#[cfg(test)]
mod tests {
    use super::{
        DashboardApp, DashboardContext, RecentTarget, TraceEvent, fit_wave_data_to_width,
        link_from_target, recent_target_activity, recent_targets_activity_header,
        recent_targets_title, recent_targets_widths, split_target,
    };
    use ratatui::layout::Constraint;
    use std::{collections::BTreeMap, path::PathBuf, time::SystemTime};

    #[test]
    fn wave_data_uses_full_width_when_panel_is_wider() {
        assert_eq!(
            fit_wave_data_to_width(&[1, 2, 3], 6),
            vec![1, 1, 2, 2, 3, 3]
        );
    }

    #[test]
    fn wave_data_compresses_history_when_panel_is_narrower() {
        assert_eq!(fit_wave_data_to_width(&[1, 2, 3, 4], 2), vec![2, 4]);
    }

    #[test]
    fn wave_data_handles_empty_history() {
        assert_eq!(fit_wave_data_to_width(&[], 4), vec![0, 0, 0, 0]);
    }

    #[test]
    fn https_link_for_port_443() {
        assert_eq!(link_from_target("example.com:443"), "https://example.com");
    }

    #[test]
    fn split_ipv6_target() {
        assert_eq!(split_target("[::1]:1080"), ("::1".to_owned(), Some(1080)));
    }

    #[test]
    fn traffic_sample_updates_history_without_totals_by_default() {
        let mut app = DashboardApp::new(DashboardContext {
            command_label: "wg-client".to_owned(),
            mode_label: "wg".to_owned(),
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("pipit.log"),
            log_filter: "info".to_owned(),
        });

        app.ingest(trace_event(
            "INFO",
            "traffic sample",
            &[("uploaded", "12"), ("downloaded", "34")],
        ));

        assert_eq!(app.total_uploaded, 0);
        assert_eq!(app.total_downloaded, 0);
        assert_eq!(app.total_relays, 0);
        assert_eq!(app.upload_history.last().copied(), Some(12));
        assert_eq!(app.download_history.last().copied(), Some(34));
        assert!(app.last_traffic_at.is_some());
    }

    #[test]
    fn wg_traffic_sample_updates_totals_without_recent_target() {
        let mut app = DashboardApp::new(DashboardContext {
            command_label: "wg-client".to_owned(),
            mode_label: "wg".to_owned(),
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("pipit.log"),
            log_filter: "info".to_owned(),
        });

        app.ingest(trace_event(
            "INFO",
            "traffic sample",
            &[
                ("uploaded", "12"),
                ("downloaded", "34"),
                ("mode", "wg"),
                ("target", "wireguard"),
                ("link", "wg://wireguard"),
                ("route", "wg-client"),
            ],
        ));

        assert_eq!(app.total_uploaded, 12);
        assert_eq!(app.total_downloaded, 34);
        assert_eq!(app.total_relays, 0);
        assert!(app.recent_targets.is_empty());
    }

    #[test]
    fn traffic_sample_does_not_fill_recent_events_or_targets() {
        let mut app = DashboardApp::new(DashboardContext {
            command_label: "wg-client".to_owned(),
            mode_label: "wg".to_owned(),
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("pipit.log"),
            log_filter: "info".to_owned(),
        });

        app.ingest(trace_event(
            "INFO",
            "traffic sample",
            &[
                ("uploaded", "12"),
                ("downloaded", "34"),
                ("mode", "wg"),
                ("target", "wireguard"),
            ],
        ));

        assert!(app.recent_events.is_empty());
        assert!(app.recent_targets.is_empty());
    }

    #[test]
    fn dns_query_updates_recent_domain_without_recent_event_spam() {
        let mut app = DashboardApp::new(DashboardContext {
            command_label: "wg-client".to_owned(),
            mode_label: "wg".to_owned(),
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("pipit.log"),
            log_filter: "info".to_owned(),
        });

        app.ingest(trace_event(
            "INFO",
            "dns query",
            &[
                ("target", "example.com"),
                ("link", "dns://example.com"),
                ("route", "wg-dns"),
            ],
        ));

        assert!(app.recent_events.is_empty());
        assert_eq!(app.recent_targets.len(), 1);
        assert_eq!(app.recent_targets[0].link, "dns://example.com");
        assert_eq!(app.recent_targets[0].route, "wg-dns");
    }

    #[test]
    fn wg_context_renames_recent_domains_panel() {
        let context = DashboardContext {
            command_label: "wg-client".to_owned(),
            mode_label: "wg".to_owned(),
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("pipit.log"),
            log_filter: "info".to_owned(),
        };

        assert_eq!(recent_targets_title(&context), "Recent Domains");
        assert_eq!(recent_targets_activity_header(&context), "Tunnel Speed");
    }

    #[test]
    fn wg_recent_domain_activity_shows_tunnel_speed() {
        let context = DashboardContext {
            command_label: "client".to_owned(),
            mode_label: "wg".to_owned(),
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("pipit.log"),
            log_filter: "info".to_owned(),
        };
        let item = RecentTarget {
            seen_at: "08:27:01".to_owned(),
            route: "wg-dns".to_owned(),
            link: "dns://example.com".to_owned(),
            uploaded: 0,
            downloaded: 0,
        };

        assert_eq!(
            recent_target_activity(&item, &context, (1536, 2048)),
            "1.5 KiB/s / 2.0 KiB/s"
        );
    }

    #[test]
    fn non_wg_recent_target_activity_keeps_byte_totals() {
        let context = DashboardContext {
            command_label: "client".to_owned(),
            mode_label: "native-http".to_owned(),
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("pipit.log"),
            log_filter: "info".to_owned(),
        };
        let item = RecentTarget {
            seen_at: "08:27:01".to_owned(),
            route: "remote".to_owned(),
            link: "https://example.com".to_owned(),
            uploaded: 1024,
            downloaded: 2048,
        };

        assert_eq!(recent_targets_activity_header(&context), "Up / Down");
        assert_eq!(
            recent_target_activity(&item, &context, (0, 0)),
            "1.0 KiB / 2.0 KiB"
        );
    }

    #[test]
    fn recent_targets_widths_fit_wg_route_and_common_totals() {
        let widths = recent_targets_widths();

        assert!(
            matches!(widths[1], Constraint::Length(width) if width >= "wg-client".len() as u16)
        );
        assert!(
            matches!(widths[3], Constraint::Length(width) if width >= "25.4 KiB / 39.9 KiB".len() as u16)
        );
    }

    fn trace_event(level: &str, message: &str, fields: &[(&str, &str)]) -> TraceEvent {
        TraceEvent {
            at: SystemTime::UNIX_EPOCH,
            level: level.to_owned(),
            message: message.to_owned(),
            fields: fields
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<BTreeMap<_, _>>(),
        }
    }
}
