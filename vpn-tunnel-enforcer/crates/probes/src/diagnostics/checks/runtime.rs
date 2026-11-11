//! Runtime items: Windows services the tunnel needs, the engine's and the app's own logs.
use std::sync::LazyLock;

use regex::Regex;
use vpnte_base::Msg;
use vpnte_base::types::Verdict;

use crate::diagnostics::sysinfo::{ServiceRow, ServiceStart};
use crate::diagnostics::{Category, CheckItem};

/// Services the kill switch, sing-box `strict_route` and name resolution depend on.
pub const CORE_SERVICES: [&str; 2] = ["BFE", "Dnscache"];
/// Other network services worth a look.
pub const OTHER_SERVICES: [&str; 5] = [
    "Dhcp",
    "iphlpsvc",
    "MpsSvc",
    "WinHttpAutoProxySvc",
    "Winmgmt",
];

fn service_row(s: &ServiceRow) -> String {
    let state = match (s.present, s.running) {
        (false, _) => "missing",
        (true, Some(true)) => "running",
        (true, Some(false)) => "stopped",
        (true, None) => "unknown",
    };
    let start = serde_json::to_value(s.start)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    format!("{}: {state}, start={start}", s.name)
}

/// `services-core` (Network, critical: BFE or Dnscache not running fails the report) and
/// `services` (Windows: a disabled or missing helper service is a warning; a stopped
/// demand-start one is normal). Windows Update / BITS / DO are not network-critical (B-SD-3).
pub fn service_items(core: &[ServiceRow], other: &[ServiceRow]) -> [CheckItem; 2] {
    let down = core
        .iter()
        .filter(|s| !s.present || s.running == Some(false))
        .count();
    let unknown = core.iter().any(|s| s.present && s.running.is_none());
    let core_verdict = match (down, unknown) {
        (0, false) => Verdict::Ok,
        (0, true) => Verdict::NotChecked,
        _ => Verdict::Fail,
    };
    let running = core.iter().filter(|s| s.running == Some(true)).count();
    let bad = other
        .iter()
        .filter(|s| !s.present || s.start == ServiceStart::Disabled)
        .count();
    [
        CheckItem::new(
            "services-core",
            Category::Network,
            "probes.diag.servicesCore.label",
            Some(core_verdict),
            Msg::new("probes.diag.servicesCore.value")
                .arg("running", running)
                .arg("total", core.len()),
        )
        .details(core.iter().map(service_row).collect(), 4),
        CheckItem::new(
            "services",
            Category::Windows,
            "probes.diag.services.label",
            Some(if bad == 0 { Verdict::Ok } else { Verdict::Warn }),
            Msg::new("probes.diag.services.value")
                .arg("bad", bad)
                .arg("total", other.len()),
        )
        .details(other.iter().map(service_row).collect(), 20),
    ]
}

static ENGINE_ERROR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(fatal|error|panic|failed|timeout|refused|denied)\b").expect("static regex")
});
static CLOSED_NOISE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bERROR\b.*connection (upload|download) closed\b.*(forcibly closed by the remote host|operation was canceled|context canceled)")
        .expect("static regex")
});

/// sing-box lines that look like errors but are routine (peer resets, cancelled streams, the
/// process lookup an unelevated run cannot do).
pub fn is_benign_engine_noise(line: &str) -> bool {
    CLOSED_NOISE.is_match(line)
        || line.contains("router: failed to search process: Access is denied")
}

/// Engine log lines that report a problem.
pub fn engine_errors<'a>(lines: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    lines
        .into_iter()
        .filter(|l| ENGINE_ERROR.is_match(l) && !is_benign_engine_noise(l))
        .collect()
}

fn last_redacted(lines: &[&str], n: usize, cut: usize) -> Vec<String> {
    let start = lines.len().saturating_sub(n);
    lines[start..]
        .iter()
        .map(|l| vpnte_core::redact::for_log(&l.chars().take(cut).collect::<String>()).into_owned())
        .collect()
}

/// `tun-log`: errors of the current engine session. A warning only while the TUN runs; with the
/// TUN stopped the lines are history and say nothing about the current route.
pub fn tun_log_item(lines: &[String], tun_running: bool) -> CheckItem {
    let errors = engine_errors(lines.iter().map(String::as_str));
    let (verdict, value) = match (tun_running, errors.len()) {
        (true, 0) => (Some(Verdict::Ok), Msg::new("probes.diag.tunLog.clean")),
        (true, n) => (
            Some(Verdict::Warn),
            Msg::new("probes.diag.tunLog.errors").arg("count", n),
        ),
        (false, n) => (
            None,
            Msg::new("probes.diag.tunLog.historical").arg("count", n),
        ),
    };
    CheckItem::new(
        "tun-log",
        Category::Logs,
        "probes.diag.tunLog.label",
        verdict,
        value,
    )
    .details(last_redacted(&errors, 8, 400), 8)
}

/// Window in which an app warning counts as current.
pub const FRESH_PROBLEM_MS: i64 = 15 * 60_000;

/// `app-log`: warnings / errors of this run within the last 15 minutes. Findings of this report
/// are logged at info level, so they never feed back into the next run.
pub fn app_log_item(problems: &[vpnte_core::logging::Problem], now: i64) -> CheckItem {
    let fresh: Vec<&vpnte_core::logging::Problem> = problems
        .iter()
        .filter(|p| now - p.at <= FRESH_PROBLEM_MS)
        .collect();
    let rows: Vec<String> = fresh
        .iter()
        .map(|p| {
            let ts = jiff::Timestamp::from_millisecond(p.at)
                .map(|t| t.to_string())
                .unwrap_or_default();
            format!(
                "{ts} {} {}: {}",
                p.level,
                p.target,
                p.msg.chars().take(180).collect::<String>()
            )
        })
        .collect();
    let rows: Vec<String> = rows
        .iter()
        .skip(rows.len().saturating_sub(8))
        .map(|r| vpnte_core::redact::for_log(r).into_owned())
        .collect();
    let (verdict, value) = match fresh.len() {
        0 => (Verdict::Ok, Msg::new("probes.diag.appLog.clean")),
        n => (
            Verdict::Warn,
            Msg::new("probes.diag.appLog.problems").arg("count", n),
        ),
    };
    CheckItem::new(
        "app-log",
        Category::Logs,
        "probes.diag.appLog.label",
        Some(verdict),
        value,
    )
    .details(rows, 8)
}
