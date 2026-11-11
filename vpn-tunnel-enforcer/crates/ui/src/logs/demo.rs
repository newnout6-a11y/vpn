//! [`DemoLogs`]: a fake [`LogsApi`] with realistic data for `demo_logs` and the page tests.
//! Scenes: `full` (default), `empty`, `loading`, `failed` (the history read fails), `partial`
//! (the cleanup cannot delete the snapshots).
use std::cell::{Cell, RefCell};
use std::sync::Arc;
use std::time::Duration;

use jiff::Timestamp;
use jiff::tz::TimeZone;
use tokio::sync::watch;
use vpnte_base::types::{Engine, OutboundFault, UnixMs, now_ms};
use vpnte_base::{AppResult, ErrorKind, Msg};

use super::model::{
    ArtifactReport, ClearReport, DisconnectReason, Evidence, ExportFormat, LogSource, LogTail,
    LogsApi, LogsSnapshot, Mode, Outcome, OutcomeKind, SessionRow, Text,
};
use crate::widgets::{Load, UiError};

const MIN: i64 = 60_000;
const HOUR: i64 = 60 * MIN;
const DAY: i64 = 24 * HOUR;

/// A fake backend for the Logs page.
pub struct DemoLogs {
    scene: String,
    history: watch::Sender<LogsSnapshot>,
    /// Lines appended to the app log since start (the tail grows while the demo runs).
    ticks: Cell<u32>,
    /// What the last `copy_text` put on the "clipboard".
    pub copied: RefCell<Option<String>>,
    /// The page's calls, in order (tests).
    pub calls: RefCell<Vec<String>>,
}

impl DemoLogs {
    /// A demo for `scene` (unknown names fall back to `full`), dated relative to `now`.
    pub fn new(scene: &str, now: UnixMs) -> Self {
        let history = match scene {
            "loading" => Load::Loading,
            "failed" => Load::Failed(UiError {
                kind: ErrorKind::Permission,
                msg: Msg::new(ErrorKind::Permission.i18n_key()),
            }),
            "empty" => Load::Ready(Arc::from(Vec::new())),
            _ => Load::Ready(Arc::from(sessions(now))),
        };
        Self {
            scene: scene.to_owned(),
            history: watch::Sender::new(LogsSnapshot { history }),
            ticks: Cell::new(0),
            copied: RefCell::new(None),
            calls: RefCell::new(Vec::new()),
        }
    }

    /// Replaces the pushed history (tests).
    pub fn push(&self, rows: Vec<SessionRow>) {
        self.history.send_replace(LogsSnapshot {
            history: Load::Ready(Arc::from(rows)),
        });
    }

    fn call(&self, name: impl Into<String>) {
        self.calls.borrow_mut().push(name.into());
    }
}

#[async_trait::async_trait(?Send)]
impl LogsApi for DemoLogs {
    fn history(&self) -> watch::Receiver<LogsSnapshot> {
        self.history.subscribe()
    }

    async fn reload_history(&self) -> AppResult<()> {
        self.call("reload_history");
        tokio::time::sleep(Duration::from_millis(300)).await;
        self.push(sessions(now_ms()));
        Ok(())
    }

    async fn export_history(&self, format: ExportFormat, file_name: String) -> AppResult<String> {
        self.call(format!("export_history:{}:{file_name}", format.extension()));
        tokio::time::sleep(Duration::from_millis(400)).await;
        Ok(file_name)
    }

    async fn clear_all(&self) -> AppResult<ClearReport> {
        self.call("clear_all");
        tokio::time::sleep(Duration::from_millis(700)).await;
        self.push(Vec::new());
        let artifacts = if self.scene == "partial" {
            ArtifactReport {
                cleared: vec!["app-log".into()],
                absent: vec!["traffic-forensics".into()],
                failed: vec![("snapshots".into(), ErrorKind::Permission)],
            }
        } else {
            ArtifactReport {
                cleared: vec!["app-log".into(), "sing-box-log".into(), "snapshots".into()],
                absent: vec!["traffic-forensics".into()],
                failed: Vec::new(),
            }
        };
        self.ticks.set(0);
        Ok(ClearReport {
            history: Ok(()),
            traffic: Ok(()),
            artifacts: Ok(artifacts),
        })
    }

    async fn read_log(&self, source: LogSource) -> AppResult<LogTail> {
        self.call(format!("read_log:{source:?}"));
        tokio::time::sleep(Duration::from_millis(120)).await;
        let now = now_ms();
        Ok(match source {
            LogSource::App => {
                let ticks = self.ticks.get() + 1;
                self.ticks.set(ticks);
                app_tail(now, ticks)
            }
            LogSource::SingBox => singbox_tail(now),
            LogSource::Xray => LogTail::default(),
        })
    }

    async fn open_log_folder(&self) -> AppResult<()> {
        self.call("open_log_folder");
        Ok(())
    }

    async fn copy_text(&self, text: String) -> AppResult<()> {
        self.call("copy_text");
        self.copied.replace(Some(text));
        Ok(())
    }
}

const MB: u64 = 1024 * 1024;

/// One fixture row; `duration` = `None` while running.
#[expect(
    clippy::too_many_arguments,
    reason = "a fixture table reads best as one call per row"
)]
fn row(
    id: &str,
    profile: &str,
    mode: Mode,
    started_at: UnixMs,
    duration: Option<i64>,
    (bytes_down, bytes_up): (u64, u64),
    reason: DisconnectReason,
    outcome: Option<Outcome>,
) -> SessionRow {
    SessionRow {
        id: id.to_owned(),
        started_at,
        ended_at: duration.map(|d| started_at + d),
        duration_ms: duration.map(|d| d.unsigned_abs()),
        profile_name: profile.to_owned(),
        mode,
        bytes_down,
        bytes_up,
        reason,
        error_message: None,
        outcome,
    }
}

fn outcome(kind: OutcomeKind, headline: Msg, evidence: Evidence) -> Option<Outcome> {
    Some(Outcome {
        kind,
        headline: Text::Msg(headline),
        evidence,
    })
}

fn headline(name: &str) -> Msg {
    Msg::new(format!("logs.demo.headline.{name}"))
}

/// The fixture history: sessions of the last weeks (one running), old-format rows, failed starts.
pub fn sessions(now: UnixMs) -> Vec<SessionRow> {
    use DisconnectReason as R;
    use OutcomeKind as K;
    let none = Evidence::default;
    let mut rows = vec![
        row("s-01", "Netherlands · Amsterdam", Mode::Hard, now - 41 * MIN, None, (476 * MB, 52 * MB), R::User, None),
        row("s-02", "Germany · Frankfurt", Mode::Hard, now - 3 * HOUR - 27 * MIN, Some(95 * MIN), (2253 * MB, 200 * MB), R::User,
            outcome(K::UserStop, headline("userStop"), none())),
        row("s-03", "USA · New York", Mode::Direct, now - DAY - 2 * HOUR, Some(3 * MIN), (4 * MB, 976 * 1024), R::Error,
            outcome(K::ServerDown, headline("serverDown"), Evidence {
                outbound_fault: Some(OutboundFault::UpstreamUnreachable),
                adaptive_mode: Some("baseline".into()),
                adaptive_attempts: Some(2),
                proxy_engine: Some(Engine::Xray),
                ..none()
            })),
        row("s-04", "Finland · Helsinki", Mode::Hard, now - DAY - 5 * HOUR, Some(4 * HOUR), (5325 * MB, 381 * MB), R::Rotation,
            outcome(K::Rotation, headline("rotation"), none())),
        row("s-05", "Poland · Warsaw", Mode::Soft, now - 2 * DAY - 3 * HOUR, Some(61 * MIN), (858 * MB, 95 * MB), R::Schedule,
            outcome(K::Schedule, headline("schedule"), none())),
        row("s-06", "Netherlands · Amsterdam", Mode::Hard, now - 3 * DAY, Some(12 * MIN), (190 * MB, 19 * MB), R::Error,
            outcome(K::SingboxCrash, headline("singboxCrash").arg("code", 1).arg("n", 3), Evidence {
                singbox_exit_code: Some(1),
                singbox_stderr_tail: Some("ERROR [3912 0ms] connection: open outbound connection: tls handshake: EOF\nFATAL[0732] start service: router closed".into()),
                outbound_fault: Some(OutboundFault::TlsHandshakeFailed),
                auto_restart_attempts: Some(3),
                kill_switch_engaged: Some(true),
                proxy_engine: Some(Engine::SingBox),
                ..none()
            })),
        row("s-07", "Sweden · Stockholm", Mode::Hard, now - 4 * DAY - 6 * HOUR, Some(130 * MIN), (1210 * MB, 88 * MB), R::Error,
            outcome(K::NetworkLost, headline("networkLost"), Evidence {
                network_transition: Some("Wi-Fi → Ethernet".into()),
                egress_country: Some("SE".into()),
                egress_ip: Some("198.51.100.23".into()),
                leak_detected_during_session: Some(false),
                ..none()
            })),
        row("s-08", "Latvia · Riga", Mode::Hard, now - 5 * DAY, Some(45 * MIN), (310 * MB, 41 * MB), R::Crash,
            outcome(K::Killswitch, headline("killswitch"), Evidence {
                auto_restart_attempts: Some(2),
                kill_switch_engaged: Some(true),
                leak_detected_during_session: Some(false),
                ..none()
            })),
        row("s-09", "Germany · Frankfurt", Mode::Soft, now - 9 * DAY, Some(2 * HOUR), (640 * MB, 70 * MB), R::User, None),
        row("s-10", "Finland · Helsinki", Mode::Hard, now - 12 * DAY, Some(25 * MIN), (120 * MB, 9 * MB), R::Error, None),
        row("s-11", "Poland · Warsaw", Mode::Hard, now - 20 * DAY, Some(6 * HOUR), (3100 * MB, 260 * MB), R::Error,
            outcome(K::SystemSleep, headline("systemSleep"), none())),
        row("f-01", "Germany · Frankfurt", Mode::Hard, now - 50 * MIN, Some(400), (0, 0), R::Error,
            outcome(K::StartFailed, headline("noServer"), Evidence {
                hint: Some(Text::Msg(Msg::new("logs.demo.hint.noServer"))),
                ..none()
            })),
        row("f-02", "USA · New York", Mode::Direct, now - 2 * DAY - 7 * HOUR, Some(2600), (0, 0), R::Error,
            outcome(K::StartFailed, headline("realityKey"), Evidence {
                outbound_fault: Some(OutboundFault::RealityKeyMismatch),
                proxy_engine: Some(Engine::Xray),
                ..none()
            })),
        row("f-03", "Latvia · Riga", Mode::Hard, now - 6 * DAY, Some(300), (0, 0), R::Error, None),
    ];
    // Rows written before the rewrite: no monotonic duration, a stored technical message.
    for old in rows
        .iter_mut()
        .filter(|r| matches!(r.id.as_str(), "s-09" | "s-10" | "f-03"))
    {
        old.duration_ms = None;
    }
    if let Some(r) = rows.iter_mut().find(|r| r.id == "s-10") {
        r.error_message = Some("sing-box exited with code 1".into());
    }
    if let Some(r) = rows.iter_mut().find(|r| r.id == "f-03") {
        r.error_message = Some("Wintun adapter not found".into());
    }
    rows
}

/// (minutes ago, level, target, message, fields as JSON)
type AppLine = (i64, &'static str, &'static str, &'static str, &'static str);

const APP_LINES: &[AppLine] = &[
    (
        44,
        "INFO",
        "vpnte_app",
        "VPN Tunnel Enforcer 2.0.0 started",
        r#"{"elevated":true}"#,
    ),
    (
        44,
        "INFO",
        "vpnte_core::store",
        "settings loaded",
        r#"{"file":"settings.json"}"#,
    ),
    (
        43,
        "INFO",
        "vpnte_servers::list",
        "servers loaded",
        r#"{"count":6}"#,
    ),
    (
        43,
        "WARN",
        "vpnte_probes::ping",
        "server did not answer the key check",
        r#"{"profile":"USA · New York"}"#,
    ),
    (
        42,
        "INFO",
        "vpnte_tunnel::lifecycle",
        "connect requested",
        r#"{"owner":"manual","mode":"hard"}"#,
    ),
    (
        42,
        "INFO",
        "vpnte_engine::singbox",
        "sing-box started",
        r#"{"pid":4242,"version":"1.14.4"}"#,
    ),
    (
        41,
        "INFO",
        "vpnte_winnet::wfp",
        "leak protection filters installed",
        r#"{"level":"standard","filters":14}"#,
    ),
    (
        41,
        "INFO",
        "vpnte_probes::ip",
        "exit IP verified",
        r#"{"ip":"198.51.100.23","country":"NL"}"#,
    ),
    (
        41,
        "INFO",
        "vpnte_tunnel::lifecycle",
        "tunnel connected",
        r#"{"profile":"Netherlands · Amsterdam","engine":"sing-box"}"#,
    ),
    (
        30,
        "DEBUG",
        "vpnte_forensics::traffic",
        "traffic sample",
        r#"{"down_bps":2433000,"up_bps":350000}"#,
    ),
    (
        25,
        "ERROR",
        "vpnte_proxies::slots",
        "external proxy port is taken by another process",
        r#"{"port":18003}"#,
    ),
    (
        24,
        "INFO",
        "vpnte_proxies::slots",
        "external proxy started",
        r#"{"slot":2,"listen":"127.0.0.1:18002"}"#,
    ),
    (
        12,
        "INFO",
        "vpnte_probes::ping",
        "key check finished",
        r#"{"online":4,"offline":1,"unchecked":1}"#,
    ),
    (6, "INFO", "vpnte_ui", "logs page opened", "{}"),
];

/// app.log in the core line format; every read adds one live line.
fn app_tail(now: UnixMs, ticks: u32) -> LogTail {
    let line = |at: UnixMs, level: &str, target: &str, msg: &str, fields: &str| {
        let ts = Timestamp::from_millisecond(at).map_or_else(
            |_| String::new(),
            |t| t.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        );
        format!(
            r#"{{"ts":"{ts}","level":"{level}","target":"{target}","msg":"{msg}","fields":{fields}}}"#
        )
    };
    let mut lines: Vec<String> = APP_LINES
        .iter()
        .map(|(ago, level, target, msg, fields)| line(now - ago * MIN, level, target, msg, fields))
        .collect();
    lines.push("panicked at a plain-text line written before the logger started".to_owned());
    for tick in 0..ticks {
        let at = now - i64::from(ticks - tick) * 5_000;
        lines.push(line(
            at,
            "INFO",
            "vpnte_tunnel::health",
            "tunnel healthy",
            r#"{"rtt_ms":48}"#,
        ));
    }
    LogTail {
        lines,
        exists: true,
        truncated: true,
    }
}

/// sing-box output with full timestamps (`-0700 2006-01-02 15:04:05 LEVEL …`).
fn singbox_tail(now: UnixMs) -> LogTail {
    let stamp = |ago: i64| {
        Timestamp::from_millisecond(now - ago * MIN).map_or_else(
            |_| String::new(),
            |t| {
                t.to_zoned(TimeZone::system())
                    .strftime("%z %Y-%m-%d %H:%M:%S")
                    .to_string()
            },
        )
    };
    let lines = [
        (
            42,
            "INFO",
            "network: updated default interface Ethernet, index 7",
        ),
        (42, "INFO", "inbound/tun[tun-in]: started at tun0"),
        (42, "INFO", "sing-box started (0.31s)"),
        (
            40,
            "INFO",
            "[3912 0ms] inbound/tun[tun-in]: inbound connection to 203.0.113.10:443",
        ),
        (
            40,
            "INFO",
            "[3912 12ms] outbound/vless[proxy]: outbound connection to 203.0.113.10:443",
        ),
        (
            31,
            "WARN",
            "[4410 2.1s] dns: exchange failed for example.org. IN A: context deadline exceeded",
        ),
        (
            18,
            "ERROR",
            "[5120 15s] connection: open outbound connection: dial tcp 192.0.2.7:443: i/o timeout",
        ),
        (
            3,
            "INFO",
            "[6001 0ms] inbound/tun[tun-in]: inbound packet connection to 1.1.1.1:53",
        ),
    ];
    LogTail {
        lines: lines
            .iter()
            .map(|(ago, level, text)| format!("{} {level} {text}", stamp(*ago)))
            .collect(),
        exists: true,
        truncated: false,
    }
}
