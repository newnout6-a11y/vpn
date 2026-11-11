//! Pure presentation rules of the live check and the batch comparison (no Dioxus).
use super::live_model::{
    BatchProgress, Finding, HandshakeStatus, LiveCheck, LiveProgress, PmtuDiag, PmtuStatus,
    ProgressStatus, RouteDiag, Severity, StageStatus, Throughput, ThroughputRoute,
};
use super::model::{LatencyStats, ServerView};
use crate::widgets::Tone;

/// The UI keeps at most this many receipts in the history drawer.
pub const HISTORY_CAP: usize = 20;
/// A batch compares at most this many servers (time budget; sequential, same-size probes).
pub const BATCH_MAX: usize = 12;
/// A PMTU lower bound at least this big counts as healthy (WireGuard's default MTU, the usual
/// "safe tunnel MTU" yardstick).
pub const PMTU_HEALTHY: u32 = 1420;
/// Throughput checklist thresholds.
pub const MAX_VARIABILITY_PCT: f64 = 40.0;
pub const MAX_GAP_MS: u32 = 750;

/// Square status mark of a diagnostic box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dot {
    Ok,
    Warn,
    Fail,
    /// Skipped / unsupported / not checked.
    Muted,
}

impl Dot {
    /// Class suffix (`srv-dot is-…`).
    pub fn name(self) -> &'static str {
        match self {
            Dot::Ok => "ok",
            Dot::Warn => "warn",
            Dot::Fail => "fail",
            Dot::Muted => "muted",
        }
    }
}

impl From<StageStatus> for Dot {
    fn from(status: StageStatus) -> Self {
        match status {
            StageStatus::Ok => Dot::Ok,
            StageStatus::Error => Dot::Fail,
            StageStatus::Warning | StageStatus::Timeout => Dot::Warn,
            StageStatus::Skipped | StageStatus::NotChecked => Dot::Muted,
        }
    }
}

impl From<HandshakeStatus> for Dot {
    fn from(status: HandshakeStatus) -> Self {
        match status {
            HandshakeStatus::Ok => Dot::Ok,
            HandshakeStatus::AuthFailed => Dot::Fail,
            HandshakeStatus::TransportFailed | HandshakeStatus::Timeout => Dot::Warn,
            HandshakeStatus::Skipped | HandshakeStatus::Unsupported => Dot::Muted,
        }
    }
}

impl From<PmtuStatus> for Dot {
    fn from(status: PmtuStatus) -> Self {
        match status {
            PmtuStatus::Ok => Dot::Ok,
            PmtuStatus::BlackholeSuspected | PmtuStatus::Error => Dot::Fail,
            PmtuStatus::LowerBound | PmtuStatus::IcmpBlocked => Dot::Warn,
            PmtuStatus::Skipped => Dot::Muted,
        }
    }
}

/// A finished tracert is not proof the destination was reached.
pub fn route_status(route: &RouteDiag) -> StageStatus {
    if route.status == StageStatus::Ok && route.reached_target == Some(false) {
        StageStatus::Warning
    } else {
        route.status
    }
}

/// `ui.servers.live.route.*` key of a throughput path (`None` → «—»).
pub fn throughput_route_key(route: Option<ThroughputRoute>, compact: bool) -> Option<&'static str> {
    let key = match (route?, compact) {
        (ThroughputRoute::PhysicalDirect, false) => "ui.servers.live.route.physicalDirect",
        (ThroughputRoute::PhysicalDirect, true) => "ui.servers.live.route.physicalDirectShort",
        (ThroughputRoute::ActiveTunnel, false) => "ui.servers.live.route.activeTunnel",
        (ThroughputRoute::ActiveTunnel, true) => "ui.servers.live.route.activeTunnelShort",
        (ThroughputRoute::ActiveProfileSelf, false) => "ui.servers.live.route.activeProfile",
        (ThroughputRoute::ActiveProfileSelf, true) => "ui.servers.live.route.activeProfileShort",
        (ThroughputRoute::DirectDetour, false) => "ui.servers.live.route.directDetour",
        (ThroughputRoute::DirectDetour, true) => "ui.servers.live.route.directDetourShort",
    };
    Some(key)
}

/// Key of the «handshake changed» diff badge.
pub fn handshake_change_key(status: Option<HandshakeStatus>) -> &'static str {
    if status == Some(HandshakeStatus::Ok) {
        "ui.servers.live.diff.handshakeRestored"
    } else {
        "ui.servers.live.diff.handshakeChanged"
    }
}

/// How to show an interface name: receipts saved before an encoding fix carry U+FFFD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasText<'a> {
    Index(Option<u32>),
    Corrupted,
    Name(&'a str),
}

/// See [`AliasText`].
pub fn interface_alias(alias: Option<&str>, index: Option<u32>) -> AliasText<'_> {
    match alias.filter(|a| !a.is_empty()) {
        None => AliasText::Index(index),
        Some(a) if a.contains('\u{FFFD}') => AliasText::Corrupted,
        Some(a) => AliasText::Name(a),
    }
}

/// Normalises a legacy tracert line (OEM-866 / 1251 / UTF-8 mojibake): `<1 мс` / `<1 ��` →
/// `<1 ms`, stray U+FFFD removed, the Russian timeout sentence → `Request timed out.`, runs of
/// blanks collapsed. New receipts carry structured hops; this is for imported history.
pub fn sanitize_hop_line(line: &str) -> String {
    const TIMEOUT_RU: &str = "превышен интервал ожидания для запроса";
    let chars: Vec<char> = line.chars().collect();
    let mut units = String::with_capacity(line.len());
    let mut i = 0;
    while i < chars.len() {
        match rtt_at(&chars, i) {
            Some((value_end, next)) => {
                units.extend(&chars[i..value_end]);
                units.push_str(" ms");
                i = next;
            }
            None => {
                units.push(chars[i]);
                i += 1;
            }
        }
    }
    let cleaned: Vec<char> = units.chars().filter(|&c| c != '\u{FFFD}').collect();
    let pattern: Vec<char> = TIMEOUT_RU.chars().collect();
    let mut text = String::with_capacity(cleaned.len());
    let mut i = 0;
    while i < cleaned.len() {
        let hit = cleaned.len() - i >= pattern.len()
            && cleaned[i..i + pattern.len()]
                .iter()
                .zip(&pattern)
                .all(|(c, p)| c.to_lowercase().eq(p.to_lowercase()));
        if hit {
            text.push_str("Request timed out.");
            i += pattern.len();
            if cleaned.get(i) == Some(&'.') {
                i += 1;
            }
        } else {
            text.push(cleaned[i]);
            i += 1;
        }
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let blank = c == ' ' || c == '\t';
        if !(blank && out.ends_with(' ')) {
            out.push(if blank { ' ' } else { c });
        }
    }
    out.trim().to_owned()
}

/// `[<>]?\s*\d+\s*(мс|ms|�+)` at `start` (case-insensitive): the end of the value part and the
/// end of the whole match.
fn rtt_at(chars: &[char], start: usize) -> Option<(usize, usize)> {
    let mut j = start;
    if matches!(chars.get(j), Some('<' | '>')) {
        j += 1;
    }
    while chars.get(j).is_some_and(|c| c.is_whitespace()) {
        j += 1;
    }
    let digits = j;
    while chars.get(j).is_some_and(char::is_ascii_digit) {
        j += 1;
    }
    if j == digits {
        return None;
    }
    let value_end = j;
    while chars.get(j).is_some_and(|c| c.is_whitespace()) {
        j += 1;
    }
    let pair = |a: char, b: char| {
        chars
            .get(j)
            .is_some_and(|c| c.to_lowercase().eq(a.to_lowercase()))
            && chars
                .get(j + 1)
                .is_some_and(|c| c.to_lowercase().eq(b.to_lowercase()))
    };
    if pair('м', 'с') || pair('m', 's') {
        return Some((value_end, j + 2));
    }
    let marks = chars[j..].iter().take_while(|&&c| c == '\u{FFFD}').count();
    (marks > 0).then_some((value_end, j + marks))
}

/// A geo / infrastructure error, worded for people (never the raw "status code 429" text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfraError {
    RateLimited,
    Unreachable,
    Cancelled,
    Raw(String),
}

/// See [`InfraError`]; `None` for an empty text.
pub fn infrastructure_error(err: &str) -> Option<InfraError> {
    let trimmed = err.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| lower.contains(n));
    let rate_limit = lower.match_indices("rate").any(|(at, _)| {
        let rest = &lower[at + 4..];
        rest.starts_with("limit")
            || rest
                .char_indices()
                .nth(1)
                .is_some_and(|(i, _)| rest[i..].starts_with("limit"))
    });
    Some(if has(&["429", "too many requests"]) || rate_limit {
        InfraError::RateLimited
    } else if has(&[
        "enotfound",
        "eai_again",
        "econnrefused",
        "etimedout",
        "network error",
        "timed out",
    ]) {
        InfraError::Unreachable
    } else if has(&["aborted", "cancelled", "canceled"]) {
        InfraError::Cancelled
    } else {
        InfraError::Raw(trimmed.to_owned())
    })
}

/// Progress caption numbers: the current step (1-based while a stage runs), the total, and the
/// bar width in percent (never under 5 %, so the bar is visible at the start).
pub fn progress_step(p: &LiveProgress) -> (u8, u8, f64) {
    let running = u8::from(p.status == ProgressStatus::Running);
    let current = p.completed.saturating_add(running).min(p.total);
    let pct = f64::from(current) / f64::from(p.total.max(1)) * 100.0;
    (current, p.total, pct.clamp(5.0, 100.0))
}

/// «20% (1/5)»: failed connects, with counts only when they are known (L-8).
pub fn loss_text(latency: &LatencyStats) -> String {
    let pct = (latency.loss * 100.0).round();
    match latency.attempted {
        Some(attempted) => {
            let ok = latency
                .succeeded
                .unwrap_or(u32::try_from(latency.samples.len()).unwrap_or(u32::MAX));
            format!("{pct}% ({}/{attempted})", attempted.saturating_sub(ok))
        }
        None => format!("{pct}%"),
    }
}

/// Certificate lifetime tone: a week or less fails, a month or less warns.
pub fn tls_days_tone(days: i64) -> Tone {
    if days <= 7 {
        Tone::Fail
    } else if days <= 30 {
        Tone::Warn
    } else {
        Tone::Ok
    }
}

/// PMTU status label (`ui.servers.live.pmtu.*`, `{{pmtu}}` argument) and its tone.
pub fn pmtu_verdict(p: &PmtuDiag) -> (&'static str, Tone) {
    match p.status {
        PmtuStatus::Ok => ("ui.servers.live.pmtu.stable", Tone::Ok),
        PmtuStatus::LowerBound if p.pmtu.is_some_and(|v| v >= PMTU_HEALTHY) => {
            ("ui.servers.live.pmtu.atLeast", Tone::Ok)
        }
        PmtuStatus::LowerBound => ("ui.servers.live.pmtu.reduced", Tone::Warn),
        PmtuStatus::BlackholeSuspected => ("ui.servers.live.pmtu.blackhole", Tone::Fail),
        PmtuStatus::IcmpBlocked => ("ui.servers.live.pmtu.icmpBlocked", Tone::Fail),
        // The old panel called a skipped ladder a probe error; it was simply not run.
        PmtuStatus::Skipped => ("ui.servers.live.pmtu.skipped", Tone::Unknown),
        PmtuStatus::Error => ("ui.servers.live.pmtu.error", Tone::Fail),
    }
}

/// The throughput pass list: spread under 40 %, no stalls, longest pause under 750 ms, all
/// samples complete (`None` = not measured).
pub fn throughput_checklist(t: &Throughput) -> [Option<bool>; 4] {
    [
        t.variability_pct.map(|v| v < MAX_VARIABILITY_PCT),
        t.stall_count.map(|s| s == 0),
        t.max_gap_ms.map(|g| g < MAX_GAP_MS),
        Some(t.error.is_none()),
    ]
}

/// Mono badge of a receipt's throughput status in the history list.
pub fn throughput_badge(status: StageStatus) -> (&'static str, Tone) {
    match status {
        StageStatus::Ok => ("OK", Tone::Ok),
        StageStatus::Warning => ("WARN", Tone::Warn),
        StageStatus::Error | StageStatus::Timeout => ("ERR", Tone::Fail),
        StageStatus::Skipped | StageStatus::NotChecked => ("—", Tone::Unknown),
    }
}

/// Tone of a findings counter: any error fails, any warning warns.
pub fn findings_tone(findings: &[Finding]) -> Tone {
    match findings.iter().map(|f| f.severity).max() {
        Some(Severity::Error) => Tone::Fail,
        Some(Severity::Warning) => Tone::Warn,
        _ => Tone::Neutral,
    }
}

/// History after a run: the new receipt first, older ones without its id, at most 20.
pub fn history_merge(history: &[LiveCheck], fresh: LiveCheck) -> Vec<LiveCheck> {
    let id = fresh.id.clone();
    let rest = history.iter().filter(|c| c.id != id).cloned();
    std::iter::once(fresh)
        .chain(rest)
        .take(HISTORY_CAP)
        .collect()
}

/// Verdict of one batch row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BatchLabel {
    Stable,
    Unstable,
    /// No throughput result, but the handshake worked.
    Reachable,
    ProbeError,
    Failed,
}

impl BatchLabel {
    /// `ui.servers.batch.label.*` key.
    pub fn key(self) -> &'static str {
        match self {
            BatchLabel::Stable => "ui.servers.batch.label.stable",
            BatchLabel::Unstable => "ui.servers.batch.label.unstable",
            BatchLabel::Reachable => "ui.servers.batch.label.reachable",
            BatchLabel::ProbeError => "ui.servers.batch.label.probeError",
            BatchLabel::Failed => "ui.servers.batch.label.failed",
        }
    }

    pub fn tone(self) -> Tone {
        match self {
            BatchLabel::Stable | BatchLabel::Reachable => Tone::Ok,
            BatchLabel::Unstable => Tone::Warn,
            BatchLabel::ProbeError | BatchLabel::Failed => Tone::Fail,
        }
    }
}

/// See [`BatchLabel`].
pub fn batch_label(check: &LiveCheck) -> BatchLabel {
    match check.throughput.as_ref().map(|t| t.status) {
        Some(StageStatus::Error) => BatchLabel::ProbeError,
        Some(StageStatus::Warning) => BatchLabel::Unstable,
        Some(StageStatus::Ok) => BatchLabel::Stable,
        _ if check.handshake.as_ref().map(|h| h.status) == Some(HandshakeStatus::Ok) => {
            BatchLabel::Reachable
        }
        _ => BatchLabel::Failed,
    }
}

/// Throughput paths of a batch: numbers measured over different paths do not compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSummary {
    Unknown,
    Single(ThroughputRoute),
    Mixed,
}

/// See [`RouteSummary`].
pub fn route_summary<'a>(checks: impl IntoIterator<Item = &'a LiveCheck>) -> RouteSummary {
    let mut routes = checks
        .into_iter()
        .filter_map(|c| c.throughput.as_ref().and_then(|t| t.route));
    match routes.next() {
        None => RouteSummary::Unknown,
        Some(first) if routes.all(|r| r == first) => RouteSummary::Single(first),
        Some(_) => RouteSummary::Mixed,
    }
}

/// `12.34 Mbps`, or «—».
pub fn format_mbps(value: Option<f64>) -> String {
    match value.filter(|v| v.is_finite()) {
        Some(v) => format!("{v:.2} Mbps"),
        None => "—".to_owned(),
    }
}

/// Batch bar width in percent (never under 4 %).
pub fn batch_bar(p: &BatchProgress) -> f64 {
    let done = f64::from(p.index)
        + if p.status == ProgressStatus::Completed {
            1.0
        } else {
            0.0
        };
    (done / f64::from(p.total.max(1)) * 100.0).clamp(4.0, 100.0)
}

/// Servers whose name, host or port contains the query (case-insensitive).
pub fn batch_filter<'a>(servers: &'a [ServerView], query: &str) -> Vec<&'a ServerView> {
    let needle = query.trim().to_lowercase();
    servers
        .iter()
        .filter(|s| {
            needle.is_empty()
                || s.name.to_lowercase().contains(&needle)
                || s.host.to_lowercase().contains(&needle)
                || s.port.to_string().contains(&needle)
        })
        .collect()
}

/// Toggles `id`; a 13th server is refused (its row is disabled, B-1). Returns whether it changed.
pub fn batch_toggle(selected: &mut Vec<String>, id: &str) -> bool {
    if let Some(at) = selected.iter().position(|s| s == id) {
        selected.remove(at);
        true
    } else if selected.len() < BATCH_MAX {
        selected.push(id.to_owned());
        true
    } else {
        false
    }
}

/// Result rows best first: by verdict, then median throughput (unknown last) (B-3).
pub fn batch_sort(rows: &mut [&LiveCheck]) {
    rows.sort_by(|a, b| {
        let median = |c: &LiveCheck| c.throughput.as_ref().and_then(|t| t.median_mbps);
        batch_label(a)
            .cmp(&batch_label(b))
            .then_with(|| match (median(a), median(b)) {
                (Some(x), Some(y)) => y.total_cmp(&x),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            })
    });
}

#[cfg(test)]
mod tests;
