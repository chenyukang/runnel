use std::{
    collections::VecDeque,
    io,
    net::IpAddr,
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
    DashboardSnapshot, MonitorContext, RecentTargetSnapshot, RouteStats, TraceEvent, TrafficState,
    attach_socket, event_impacts_health, route_bucket_for_event,
};

const HISTORY_LEN: usize = 48;
const RECENT_EVENTS: usize = 40;
const RECENT_TARGETS: usize = RECENT_EVENTS;
const RECENT_DOMAIN_STATUS_WIDTH: usize = 9;
const ROUTE_STAT_LABEL_WIDTH: usize = 9;
const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

#[derive(Clone, Debug)]
pub struct DashboardContext {
    pub command_label: String,
    pub mode_label: String,
    pub traffic_state: TrafficState,
    pub listen: Option<String>,
    pub upstream: Option<String>,
    pub path: Option<String>,
    pub log_file: PathBuf,
    pub log_filter: String,
    pub log_timezone_offset_secs: i32,
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
    detail: String,
    repeat_count: u64,
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
    route_stats: RouteStats,
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
            traffic_state: value.traffic_state,
            listen: value.listen,
            upstream: value.upstream,
            path: value.path,
            log_file: value.log_file,
            log_filter: value.log_filter,
            log_timezone_offset_secs: value.log_timezone_offset_secs,
        }
    }
}

impl From<RecentTargetSnapshot> for RecentTarget {
    fn from(value: RecentTargetSnapshot) -> Self {
        Self {
            seen_at: value.seen_at,
            route: value.route,
            link: value.link,
            detail: value.detail,
            repeat_count: value.repeat_count.max(1),
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
            route_stats: RouteStats::default(),
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
            route_stats,
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
            route_stats,
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

        self.capture_traffic_state(&event);
        self.capture_listener_context(&event);
        self.capture_recent_event(&event);
        self.capture_recent_domain_ip(&event);
        if let Some(bucket) = route_bucket_for_event(&event) {
            self.route_stats.record(bucket);
        }

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
                seen_at: clock_stamp(event.at, self.context.log_timezone_offset_secs),
                link: link_from_target(&target),
                route,
                detail: String::new(),
                repeat_count: 1,
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
        let detail = event
            .fields
            .get("detail")
            .cloned()
            .unwrap_or_else(|| recent_domain_default_detail(&route));
        let seen_at = clock_stamp(event.at, self.context.log_timezone_offset_secs);

        if let Some(index) = self
            .recent_targets
            .iter()
            .position(|recent| recent.link == link && recent.route == route)
        {
            if let Some(mut recent) = self.recent_targets.remove(index) {
                recent.seen_at = seen_at;
                recent.detail = merge_recent_domain_detail(&recent.detail, &detail, &route);
                recent.repeat_count = recent.repeat_count.saturating_add(1).max(2);
                self.recent_targets.push_front(recent);
            }
            return;
        }

        self.recent_targets.push_front(RecentTarget {
            seen_at,
            link,
            route,
            detail,
            repeat_count: 1,
            uploaded: 0,
            downloaded: 0,
        });
        self.recent_targets.truncate(RECENT_TARGETS);
    }

    fn capture_recent_domain_ip(&mut self, event: &TraceEvent) {
        let (Some(domain), Some(ip)) = (event.fields.get("domain"), event.fields.get("ip")) else {
            return;
        };

        let dns_link = format!("dns://{domain}");
        if let Some(target) = self
            .recent_targets
            .iter_mut()
            .find(|target| target.link == dns_link || target.link == domain.as_str())
        {
            append_recent_domain_ip(&mut target.detail, ip);
        }
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

    fn capture_traffic_state(&mut self, event: &TraceEvent) {
        if event.message != "traffic switch" {
            return;
        }
        self.context.traffic_state = match event.fields.get("state").map(String::as_str) {
            Some("bypass") => TrafficState::Bypass,
            Some("proxying") => TrafficState::Proxying,
            _ => self.context.traffic_state,
        };
    }

    fn capture_recent_event(&mut self, event: &TraceEvent) {
        if event.message == "traffic sample" || event.message == "dns query" {
            return;
        }
        if event.message.contains("relay completed") && self.recent_events.len() >= RECENT_EVENTS {
            return;
        }

        let suffix = recent_event_suffix(event);

        self.recent_events.push_front(format!(
            "{} [{}] {}{}",
            clock_stamp(event.at, self.context.log_timezone_offset_secs),
            event.level,
            event.message,
            suffix
        ));
        self.recent_events.truncate(RECENT_EVENTS);
    }
}

fn recent_event_suffix(event: &TraceEvent) -> String {
    if let Some(target) = event.fields.get("target") {
        return format!(" {target}");
    }
    if let Some(error) = event.fields.get("error") {
        return format!(" {error}");
    }
    if let Some(listen) = event.fields.get("listen") {
        return format!(" {listen}");
    }
    match (event.fields.get("domain"), event.fields.get("ip")) {
        (Some(domain), Some(ip)) => format!(" {domain} -> {ip}"),
        (Some(domain), None) => format!(" {domain}"),
        (None, Some(ip)) => format!(" {ip}"),
        (None, None) => String::new(),
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

    let overview_lines = vec![
        Line::from(vec![
            Span::styled(
                format!("{} runnel dashboard", SPINNER[app.spinner_index]),
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
            Span::styled("traffic ", overview_label_style()),
            Span::styled(app.context.traffic_state.as_str(), overview_value_style()),
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
    ];
    let overview_block = Block::default()
        .borders(Borders::ALL)
        .title("Overview")
        .border_style(Style::default().fg(Color::Cyan));
    let overview_inner = overview_block.inner(chunks[0]);
    frame.render_widget(overview_block, chunks[0]);

    let overview = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(48), Constraint::Length(24)])
        .split(overview_inner);
    frame.render_widget(
        Paragraph::new(overview_lines).wrap(Wrap { trim: true }),
        overview[0],
    );
    frame.render_widget(route_stats_panel(app.route_stats), overview[1]);

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

    let rows = app.recent_targets.iter().map(|item| {
        Row::new(vec![
            Cell::from(item.seen_at.clone()),
            Cell::from(recent_target_route(item, &app.context)),
            Cell::from(recent_target_link(item, &app.context)),
            Cell::from(recent_target_activity(item, &app.context)),
        ])
    });
    let table = Table::new(rows, recent_targets_widths())
        .header(
            Row::new(vec![
                "When",
                "Route",
                recent_targets_link_header(&app.context),
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

fn route_stats_panel(stats: RouteStats) -> Paragraph<'static> {
    Paragraph::new(vec![
        Line::from(Span::styled("Routes", overview_label_style())),
        route_stat_line("proxy:", stats.proxy, Color::Blue),
        route_stat_line("direct:", stats.direct, Color::Green),
        route_stat_line("blocked:", stats.blocked, Color::Red),
    ])
}

fn route_stat_line(label: &str, value: u64, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(route_stat_label(label), overview_label_style()),
        Span::styled(value.to_string(), Style::default().fg(color)),
    ])
}

fn route_stat_label(label: &str) -> String {
    format!("{label:<width$}", width = ROUTE_STAT_LABEL_WIDTH)
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
    let inner = block.inner(area);
    let width = usize::from(inner.width);
    let wave_data = fit_wave_data_to_width(history, width);

    frame.render_widget(
        Sparkline::default()
            .block(block)
            .style(Style::default().fg(color))
            .data(&wave_data),
        area,
    );
}

fn rotate_history(history: &mut [u64]) {
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
    let active = history.iter().filter(|value| **value > 0).count();
    format!(
        "{label} · {}/s now · {}/s peak · active {active}/{}",
        format_bytes(current),
        format_bytes(peak),
        history.len()
    )
}

fn clock_stamp(at: SystemTime, offset_secs: i32) -> String {
    let elapsed = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let local_elapsed = (elapsed as i64 + i64::from(offset_secs)).rem_euclid(86_400);
    let seconds = local_elapsed % 60;
    let minutes = (local_elapsed / 60) % 60;
    let hours = local_elapsed / 3600;
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

fn recent_targets_title(_context: &DashboardContext) -> &'static str {
    "Recent Domains"
}

fn recent_targets_activity_header(context: &DashboardContext) -> &'static str {
    if recent_targets_are_domain_events(context) {
        "Resolved"
    } else {
        "Up / Down"
    }
}

fn recent_targets_link_header(context: &DashboardContext) -> &'static str {
    if recent_targets_are_domain_events(context) {
        "Domain"
    } else {
        "Link"
    }
}

fn recent_target_route(item: &RecentTarget, context: &DashboardContext) -> String {
    if recent_targets_are_domain_events(context) || item.link.starts_with("dns://") {
        return recent_domain_route_label(&item.route);
    }

    item.route.clone()
}

fn recent_target_link(item: &RecentTarget, context: &DashboardContext) -> String {
    if recent_targets_are_domain_events(context) || item.link.starts_with("dns://") {
        return item
            .link
            .strip_prefix("dns://")
            .unwrap_or(&item.link)
            .to_owned();
    }

    item.link.clone()
}

fn recent_target_activity(item: &RecentTarget, context: &DashboardContext) -> String {
    if recent_targets_are_domain_events(context) || item.link.starts_with("dns://") {
        return recent_domain_detail(item);
    }

    format!(
        "{} / {}",
        format_bytes(item.uploaded),
        format_bytes(item.downloaded)
    )
}

fn recent_domain_route_label(route: &str) -> String {
    match route {
        "wg-dns-direct" | "direct" => "direct",
        "wg-dns-block" | "block" => "block",
        "wg-dns" | "wg-dns-remote" | "remote" => "proxy",
        _ => route,
    }
    .to_owned()
}

fn recent_domain_default_detail(route: &str) -> String {
    match route {
        "wg-dns-direct" | "direct" => "pending".to_owned(),
        "wg-dns-block" | "block" => "blocked".to_owned(),
        "wg-dns" | "wg-dns-remote" | "remote" => "wg tunnel".to_owned(),
        _ => "-".to_owned(),
    }
}

fn recent_domain_detail(item: &RecentTarget) -> String {
    let detail = if item.detail.is_empty() {
        recent_domain_default_detail(&item.route)
    } else {
        item.detail.clone()
    };
    if resolved_detail_has_ip(&detail) {
        detail
    } else if item.repeat_count > 1 {
        format!(
            "{detail:<width$} x{}",
            item.repeat_count,
            width = RECENT_DOMAIN_STATUS_WIDTH
        )
    } else {
        format!("{detail:<width$}", width = RECENT_DOMAIN_STATUS_WIDTH)
    }
}

fn resolved_detail_has_ip(detail: &str) -> bool {
    detail
        .split(", ")
        .map(str::trim)
        .filter(|part| !part.is_empty() && *part != "...")
        .any(|part| part.parse::<IpAddr>().is_ok())
}

fn merge_recent_domain_detail(current: &str, next: &str, route: &str) -> String {
    if current.is_empty() || current == "-" || current == recent_domain_default_detail(route) {
        return next.to_owned();
    }
    current.to_owned()
}

fn append_recent_domain_ip(detail: &mut String, ip: &str) {
    if matches!(
        detail.as_str(),
        "" | "-" | "pending" | "blocked" | "wg tunnel"
    ) {
        *detail = ip.to_owned();
        return;
    }

    if detail
        .split(", ")
        .any(|known| known == ip || known == "...")
    {
        return;
    }
    if detail.split(", ").count() >= 3 {
        detail.push_str(", ...");
        return;
    }
    detail.push_str(", ");
    detail.push_str(ip);
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
    let memory_bytes = sample_process_memory_bytes(pid);
    let threads = sample_thread_count(pid);

    ProcessStats {
        memory_bytes,
        threads,
    }
}

fn sample_process_memory_bytes(pid: u32) -> u64 {
    let mut system = System::new();
    let sys_pid = sysinfo::Pid::from_u32(pid);
    system.refresh_processes(ProcessesToUpdate::Some(&[sys_pid]), true);

    if let Some(memory_bytes) = system
        .process(sys_pid)
        .map(|process| process.memory())
        .filter(|memory_bytes| *memory_bytes > 0)
    {
        return memory_bytes;
    }

    sample_process_rss_bytes(pid).unwrap_or(0)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn sample_process_rss_bytes(pid: u32) -> Option<u64> {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_ps_rss_kib(&String::from_utf8_lossy(&output.stdout)).map(|kib| kib.saturating_mul(1024))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn sample_process_rss_bytes(_pid: u32) -> Option<u64> {
    None
}

#[cfg(any(test, target_os = "macos", target_os = "linux"))]
fn parse_ps_rss_kib(output: &str) -> Option<u64> {
    output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .find_map(|rss| rss.parse::<u64>().ok())
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
        Some(count.max(1))
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
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<usize>()
            .ok()
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
        link_from_target, parse_ps_rss_kib, recent_target_activity, recent_target_link,
        recent_target_route, recent_targets_activity_header, recent_targets_link_header,
        recent_targets_title, recent_targets_widths, route_stat_label, sample_process_memory_bytes,
        split_target,
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
    fn route_stat_labels_align_values() {
        assert_eq!(route_stat_label("proxy:"), "proxy:   ");
        assert_eq!(route_stat_label("direct:"), "direct:  ");
        assert_eq!(route_stat_label("blocked:"), "blocked: ");
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
    fn parse_ps_rss_reads_kib_value() {
        assert_eq!(parse_ps_rss_kib(" 13568\n"), Some(13568));
    }

    #[test]
    fn parse_ps_rss_skips_blank_and_invalid_lines() {
        assert_eq!(parse_ps_rss_kib("\nRSS\n  2048\n"), Some(2048));
        assert_eq!(parse_ps_rss_kib("\nRSS\n"), None);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn sample_process_memory_reports_current_process() {
        assert!(sample_process_memory_bytes(std::process::id()) > 0);
    }

    #[test]
    fn traffic_sample_updates_history_without_totals_by_default() {
        let mut app = DashboardApp::new(DashboardContext {
            command_label: "wg-client".to_owned(),
            mode_label: "wg".to_owned(),
            traffic_state: crate::telemetry::TrafficState::Proxying,
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("runnel.log"),
            log_filter: "info".to_owned(),
            log_timezone_offset_secs: 0,
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
            traffic_state: crate::telemetry::TrafficState::Proxying,
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("runnel.log"),
            log_filter: "info".to_owned(),
            log_timezone_offset_secs: 0,
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
            traffic_state: crate::telemetry::TrafficState::Proxying,
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("runnel.log"),
            log_filter: "info".to_owned(),
            log_timezone_offset_secs: 0,
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
            traffic_state: crate::telemetry::TrafficState::Proxying,
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("runnel.log"),
            log_filter: "info".to_owned(),
            log_timezone_offset_secs: 0,
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
        assert_eq!(app.recent_targets[0].detail, "wg tunnel");
        assert_eq!(app.recent_targets[0].repeat_count, 1);
        assert_eq!(app.route_stats.proxy, 1);
        assert_eq!(app.route_stats.direct, 0);
        assert_eq!(app.route_stats.blocked, 0);
    }

    #[test]
    fn repeated_dns_queries_update_one_recent_domain_row() {
        let mut app = DashboardApp::new(DashboardContext {
            command_label: "wg-client".to_owned(),
            mode_label: "wg".to_owned(),
            traffic_state: crate::telemetry::TrafficState::Proxying,
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("runnel.log"),
            log_filter: "info".to_owned(),
            log_timezone_offset_secs: 0,
        });

        for _ in 0..3 {
            app.ingest(trace_event(
                "INFO",
                "dns query",
                &[
                    ("target", "tracker.example"),
                    ("link", "dns://tracker.example"),
                    ("route", "wg-dns-block"),
                ],
            ));
        }

        assert_eq!(app.recent_targets.len(), 1);
        assert_eq!(app.recent_targets[0].link, "dns://tracker.example");
        assert_eq!(app.recent_targets[0].detail, "blocked");
        assert_eq!(app.recent_targets[0].repeat_count, 3);
        assert_eq!(
            recent_target_activity(&app.recent_targets[0], &app.context),
            "blocked   x3"
        );
        assert_eq!(app.route_stats.blocked, 3);
    }

    #[test]
    fn overview_route_stats_count_proxy_direct_and_blocked_decisions() {
        let mut app = DashboardApp::new(DashboardContext {
            command_label: "client".to_owned(),
            mode_label: "native-http".to_owned(),
            traffic_state: crate::telemetry::TrafficState::Proxying,
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("runnel.log"),
            log_filter: "info".to_owned(),
            log_timezone_offset_secs: 0,
        });

        app.ingest(trace_event(
            "INFO",
            "client relay completed",
            &[("target", "example.com:443")],
        ));
        app.ingest(trace_event(
            "INFO",
            "client relay completed",
            &[("target", "qq.com:443"), ("route", "direct")],
        ));
        app.ingest(trace_event(
            "INFO",
            "dns query",
            &[("target", "ads.example"), ("route", "wg-dns-block")],
        ));
        app.ingest(trace_event(
            "INFO",
            "route decision",
            &[("target", "tracker.example:443"), ("route", "block")],
        ));
        app.ingest(trace_event(
            "INFO",
            "traffic sample",
            &[("target", "wireguard"), ("route", "wg-client")],
        ));

        assert_eq!(app.route_stats.proxy, 1);
        assert_eq!(app.route_stats.direct, 1);
        assert_eq!(app.route_stats.blocked, 2);
    }

    #[test]
    fn recent_event_shows_domain_and_ip_fields() {
        let mut app = DashboardApp::new(DashboardContext {
            command_label: "wg-client".to_owned(),
            mode_label: "wg".to_owned(),
            traffic_state: crate::telemetry::TrafficState::Proxying,
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("runnel.log"),
            log_filter: "info".to_owned(),
            log_timezone_offset_secs: 0,
        });

        app.ingest(trace_event(
            "INFO",
            "running wg hook",
            &[("domain", "baidu.com"), ("ip", "110.242.74.102")],
        ));

        assert_eq!(app.recent_events.len(), 1);
        assert!(
            app.recent_events[0].contains("baidu.com -> 110.242.74.102"),
            "{}",
            app.recent_events[0]
        );
    }

    #[test]
    fn recent_event_uses_dashboard_timezone() {
        let mut app = DashboardApp::new(DashboardContext {
            command_label: "client".to_owned(),
            mode_label: "native-http".to_owned(),
            traffic_state: crate::telemetry::TrafficState::Proxying,
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("runnel.log"),
            log_filter: "info".to_owned(),
            log_timezone_offset_secs: 8 * 60 * 60,
        });

        app.ingest(trace_event(
            "INFO",
            "client listening",
            &[("listen", "127.0.0.1:1080")],
        ));

        assert!(
            app.recent_events[0].starts_with("08:00:00 [INFO]"),
            "{}",
            app.recent_events[0]
        );
    }

    #[test]
    fn traffic_switch_event_updates_context_state() {
        let mut app = DashboardApp::new(DashboardContext {
            command_label: "client".to_owned(),
            mode_label: "wg".to_owned(),
            traffic_state: crate::telemetry::TrafficState::Proxying,
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("runnel.log"),
            log_filter: "info".to_owned(),
            log_timezone_offset_secs: 0,
        });

        app.ingest(trace_event(
            "INFO",
            "traffic switch",
            &[("state", "bypass")],
        ));

        assert_eq!(
            app.context.traffic_state,
            crate::telemetry::TrafficState::Bypass
        );
    }

    #[test]
    fn wg_context_renames_recent_domains_panel() {
        let context = DashboardContext {
            command_label: "wg-client".to_owned(),
            mode_label: "wg".to_owned(),
            traffic_state: crate::telemetry::TrafficState::Proxying,
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("runnel.log"),
            log_filter: "info".to_owned(),
            log_timezone_offset_secs: 0,
        };

        assert_eq!(recent_targets_title(&context), "Recent Domains");
        assert_eq!(recent_targets_link_header(&context), "Domain");
        assert_eq!(recent_targets_activity_header(&context), "Resolved");
    }

    #[test]
    fn wg_recent_domain_activity_shows_resolved_ips() {
        let context = DashboardContext {
            command_label: "client".to_owned(),
            mode_label: "wg".to_owned(),
            traffic_state: crate::telemetry::TrafficState::Proxying,
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("runnel.log"),
            log_filter: "info".to_owned(),
            log_timezone_offset_secs: 0,
        };
        let item = RecentTarget {
            seen_at: "08:27:01".to_owned(),
            route: "wg-dns-direct".to_owned(),
            link: "dns://example.com".to_owned(),
            detail: "93.184.216.34".to_owned(),
            repeat_count: 1,
            uploaded: 0,
            downloaded: 0,
        };

        assert_eq!(recent_target_route(&item, &context), "direct");
        assert_eq!(recent_target_link(&item, &context), "example.com");
        assert_eq!(recent_target_activity(&item, &context), "93.184.216.34");
    }

    #[test]
    fn repeated_resolved_ip_detail_omits_repeat_count() {
        let context = DashboardContext {
            command_label: "client".to_owned(),
            mode_label: "wg".to_owned(),
            traffic_state: crate::telemetry::TrafficState::Proxying,
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("runnel.log"),
            log_filter: "info".to_owned(),
            log_timezone_offset_secs: 0,
        };
        let item = RecentTarget {
            seen_at: "08:27:01".to_owned(),
            route: "wg-dns-direct".to_owned(),
            link: "dns://example.com".to_owned(),
            detail: "93.184.216.34, 2606:2800:220:1:248:1893:25c8:1946".to_owned(),
            repeat_count: 4,
            uploaded: 0,
            downloaded: 0,
        };

        assert_eq!(
            recent_target_activity(&item, &context),
            "93.184.216.34, 2606:2800:220:1:248:1893:25c8:1946"
        );
    }

    #[test]
    fn repeated_status_detail_aligns_repeat_count() {
        let context = DashboardContext {
            command_label: "client".to_owned(),
            mode_label: "wg".to_owned(),
            traffic_state: crate::telemetry::TrafficState::Proxying,
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("runnel.log"),
            log_filter: "info".to_owned(),
            log_timezone_offset_secs: 0,
        };
        let blocked = RecentTarget {
            seen_at: "08:27:01".to_owned(),
            route: "wg-dns-block".to_owned(),
            link: "dns://ads.example".to_owned(),
            detail: "blocked".to_owned(),
            repeat_count: 4,
            uploaded: 0,
            downloaded: 0,
        };
        let proxied = RecentTarget {
            seen_at: "08:27:02".to_owned(),
            route: "wg-dns".to_owned(),
            link: "dns://example.com".to_owned(),
            detail: "wg tunnel".to_owned(),
            repeat_count: 4,
            uploaded: 0,
            downloaded: 0,
        };

        assert_eq!(recent_target_activity(&blocked, &context), "blocked   x4");
        assert_eq!(recent_target_activity(&proxied, &context), "wg tunnel x4");
    }

    #[test]
    fn wg_hook_updates_recent_domain_resolved_ips() {
        let mut app = DashboardApp::new(DashboardContext {
            command_label: "wg-client".to_owned(),
            mode_label: "wg".to_owned(),
            traffic_state: crate::telemetry::TrafficState::Proxying,
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("runnel.log"),
            log_filter: "info".to_owned(),
            log_timezone_offset_secs: 0,
        });

        app.ingest(trace_event(
            "INFO",
            "dns query",
            &[
                ("target", "baidu.com"),
                ("link", "dns://baidu.com"),
                ("route", "wg-dns-direct"),
            ],
        ));
        app.ingest(trace_event(
            "INFO",
            "running wg hook",
            &[("domain", "baidu.com"), ("ip", "110.242.74.102")],
        ));

        assert_eq!(app.recent_targets.len(), 1);
        assert_eq!(app.recent_targets[0].detail, "110.242.74.102");
        assert_eq!(
            recent_target_activity(&app.recent_targets[0], &app.context),
            "110.242.74.102"
        );
    }

    #[test]
    fn non_wg_recent_target_activity_keeps_byte_totals() {
        let context = DashboardContext {
            command_label: "client".to_owned(),
            mode_label: "native-http".to_owned(),
            traffic_state: crate::telemetry::TrafficState::Proxying,
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("runnel.log"),
            log_filter: "info".to_owned(),
            log_timezone_offset_secs: 0,
        };
        let item = RecentTarget {
            seen_at: "08:27:01".to_owned(),
            route: "remote".to_owned(),
            link: "https://example.com".to_owned(),
            detail: String::new(),
            repeat_count: 1,
            uploaded: 1024,
            downloaded: 2048,
        };

        assert_eq!(recent_targets_activity_header(&context), "Up / Down");
        assert_eq!(recent_target_activity(&item, &context), "1.0 KiB / 2.0 KiB");
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
