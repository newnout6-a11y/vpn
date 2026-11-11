//! The on-demand leak check card ("Диагностика утечек" / tray "Проверка маршрута"): a few
//! items, each with its own status, and one summary.
//!
//! Rules from the field (B-LC-1…8, owner decisions D-49 / D-60): missing evidence is
//! `NotChecked` with a reason, never "no leaks found"; the summary ranks
//! `Fail > Warn > NotChecked > Ok` (`Info` never counts) and reads "no leaks" only when every
//! leak-relevant item passed; an unreachable IP service is not a leak; a public IPv4 is judged
//! against the IP monitor's evidence, a public IPv6 against the physical adapters' own
//! prefixes; direct-out traffic is judged by the rule that routed it (configured rule =
//! expected, no rule = leak).
use std::net::{IpAddr, Ipv6Addr};
use std::sync::LazyLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::{UnixMs, Verdict, now_ms};
use vpnte_core::net::{self, HostPort};

use super::self_test::{self, SelfTestResult, SelfTestVerdict};
use crate::ip_monitor::IpEvidence;
use crate::public_ip::{Family, IpReader, IpRoute, WAVE_BUDGET};

/// Status of one item and of the card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
    /// Informational: never changes the summary.
    Info,
    NotChecked,
}

impl CheckStatus {
    /// The app-wide verdict scale (`Info` has none).
    pub fn verdict(self) -> Option<Verdict> {
        match self {
            CheckStatus::Ok => Some(Verdict::Ok),
            CheckStatus::Warn => Some(Verdict::Warn),
            CheckStatus::Fail => Some(Verdict::Fail),
            CheckStatus::NotChecked => Some(Verdict::NotChecked),
            CheckStatus::Info => None,
        }
    }
}

/// One line of the card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckItem {
    /// Stable id: `proxy`, `ipv4`, `ipv6`, `self-test`, `adapters`, `dns`, `engine-log`,
    /// `direct-out`.
    pub id: &'static str,
    pub label: Msg,
    pub status: CheckStatus,
    pub value: Msg,
    pub details: Vec<Msg>,
}

impl CheckItem {
    fn new(id: &'static str, status: CheckStatus, value: Msg) -> Self {
        CheckItem {
            id,
            label: Msg::new(format!("probes.leak.check.label.{id}")),
            status,
            value,
            details: Vec::new(),
        }
    }

    fn detail(mut self, detail: Msg) -> Self {
        self.details.push(detail);
        self
    }
}

/// The finished card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    pub ran_at: UnixMs,
    pub summary: CheckStatus,
    /// "No leaks found" only for a conclusive pass; otherwise names the weakest result.
    pub headline: Msg,
    pub items: Vec<CheckItem>,
}

impl CheckReport {
    /// Builds the report from finished items.
    pub fn new(items: Vec<CheckItem>) -> Self {
        let summary = summarize(&items);
        CheckReport {
            ran_at: now_ms(),
            summary,
            headline: headline(summary),
            items,
        }
    }
}

/// `Fail > Warn > NotChecked > Ok`; `Info` is ignored; nothing but `Info` is `NotChecked`.
pub fn summarize(items: &[CheckItem]) -> CheckStatus {
    let has = |s: CheckStatus| items.iter().any(|i| i.status == s);
    if has(CheckStatus::Fail) {
        CheckStatus::Fail
    } else if has(CheckStatus::Warn) {
        CheckStatus::Warn
    } else if has(CheckStatus::NotChecked) || !has(CheckStatus::Ok) {
        CheckStatus::NotChecked
    } else {
        CheckStatus::Ok
    }
}

fn headline(summary: CheckStatus) -> Msg {
    Msg::new(match summary {
        CheckStatus::Ok => "probes.leak.check.summary.ok",
        CheckStatus::Warn => "probes.leak.check.summary.warn",
        CheckStatus::Fail => "probes.leak.check.summary.fail",
        CheckStatus::Info | CheckStatus::NotChecked => "probes.leak.check.summary.notChecked",
    })
}

fn ip_value(ip: IpAddr) -> Msg {
    Msg::new("probes.leak.check.value.ip").arg("ip", ip)
}

/// How the tunnel is set up, as far as the card cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// sing-box itself is the tunnel core: there is no local proxy to probe.
    DirectVpn,
    /// sing-box chains to a local upstream proxy (another VPN client); `None` = not configured.
    LocalProxy { upstream: Option<HostPort> },
}

/// `proxy`: the configured upstream only (never a free-form target, B-LC-5). `reachable` is
/// the TCP probe result (`None` = not probed); `foreign` names another VPN's tunnel.
pub fn proxy_item(
    mode: &Mode,
    tunnel_up: bool,
    reachable: Option<bool>,
    foreign: Option<&str>,
) -> CheckItem {
    let key = |k: &str| Msg::new(format!("probes.leak.check.proxy.{k}"));
    match mode {
        Mode::DirectVpn => {
            CheckItem::new("proxy", CheckStatus::Info, key("directVpn")).detail(key(if tunnel_up {
                "directVpnOn"
            } else {
                "directVpnOff"
            }))
        }
        Mode::LocalProxy {
            upstream: Some(addr),
        } => {
            let value = Msg::new("probes.leak.check.value.text").arg("text", addr);
            match reachable {
                Some(true) => CheckItem::new("proxy", CheckStatus::Ok, value).detail(key("open")),
                Some(false) => {
                    CheckItem::new("proxy", CheckStatus::Fail, value).detail(key("closed"))
                }
                None => CheckItem::new("proxy", CheckStatus::NotChecked, value),
            }
        }
        Mode::LocalProxy { upstream: None } => match foreign {
            Some(name) if !tunnel_up => {
                CheckItem::new("proxy", CheckStatus::Info, key("notNeeded"))
                    .detail(key("externalOnly").arg("name", name))
            }
            _ => CheckItem::new("proxy", CheckStatus::Warn, key("missing"))
                .detail(key("missingDetail")),
        },
    }
}

/// `ipv4`: the address ordinary apps show, against the IP monitor's evidence (B-LC-3): the
/// real IP → `Fail`; the adopted exit → `Ok`; another exit → `Warn`; no answer → `NotChecked`
/// (an unreachable service is not a leak).
pub fn ipv4_item(sample: Option<IpAddr>, evidence: &IpEvidence, tunnel_up: bool) -> CheckItem {
    let key = |k: &str| Msg::new(format!("probes.leak.check.ipv4.{k}"));
    let Some(ip) = sample else {
        return CheckItem::new("ipv4", CheckStatus::NotChecked, key("noAnswer"));
    };
    let (status, detail) = if !tunnel_up {
        (CheckStatus::Info, "tunnelOff")
    } else if evidence.real_ip == Some(ip) {
        (CheckStatus::Fail, "realIp")
    } else if evidence.baseline == Some(ip) {
        (CheckStatus::Ok, "vpnExit")
    } else if evidence.baseline.is_none() {
        (CheckStatus::NotChecked, "noBaseline")
    } else {
        (CheckStatus::Warn, "otherExit")
    };
    CheckItem::new("ipv4", status, ip_value(ip)).detail(key(detail))
}

/// `ipv6` (B-LC-2): no global IPv6 on the physical adapters → `Ok`; an answer inside one of
/// their /64 prefixes → `Fail` (the provider's IPv6 is visible); another answer → `Ok`
/// (through the VPN); no answer although IPv6 exists → `NotChecked`. `physical_v6` is `None`
/// when the adapters could not be enumerated.
pub fn ipv6_item(
    sample: Option<IpAddr>,
    physical_v6: Option<&[Ipv6Addr]>,
    tunnel_up: bool,
) -> CheckItem {
    let key = |k: &str| Msg::new(format!("probes.leak.check.ipv6.{k}"));
    let value = sample.map_or_else(|| key("none"), ip_value);
    let Some(physical) = physical_v6 else {
        return CheckItem::new("ipv6", CheckStatus::NotChecked, value)
            .detail(key("adaptersUnknown"));
    };
    if !tunnel_up {
        return CheckItem::new("ipv6", CheckStatus::Info, value).detail(key("tunnelOff"));
    }
    if physical.is_empty() {
        return CheckItem::new("ipv6", CheckStatus::Ok, key("absent"));
    }
    match sample {
        None => CheckItem::new("ipv6", CheckStatus::NotChecked, value).detail(key("noAnswer")),
        Some(IpAddr::V6(seen)) if physical.iter().any(|p| same_64(*p, seen)) => {
            CheckItem::new("ipv6", CheckStatus::Fail, value).detail(key("realIpv6"))
        }
        Some(_) => CheckItem::new("ipv6", CheckStatus::Ok, value).detail(key("viaVpn")),
    }
}

fn same_64(a: Ipv6Addr, b: Ipv6Addr) -> bool {
    a.segments()[..4] == b.segments()[..4]
}

/// `self-test`: the latest physical-adapter self-test (`None` = not run).
pub fn self_test_item(result: Option<&SelfTestResult>) -> CheckItem {
    let Some(result) = result else {
        return CheckItem::new(
            "self-test",
            CheckStatus::NotChecked,
            Msg::new("probes.leak.check.selfTest.notRun"),
        );
    };
    let report = self_test::report(result);
    let status = match report.verdict {
        SelfTestVerdict::Leak => CheckStatus::Fail,
        SelfTestVerdict::PossibleLeak => CheckStatus::Warn,
        SelfTestVerdict::Ok => CheckStatus::Ok,
        SelfTestVerdict::Inconclusive => CheckStatus::NotChecked,
    };
    let mut item = CheckItem::new("self-test", status, report.headline);
    item.details = report.details;
    item
}

/// `adapters`: other VPNs' tunnels (labels from winnet `foreign_tun::detect`; `None` = the
/// detection failed). With our tunnel off a foreign one is simply the current route.
pub fn adapters_item(foreign: Option<&[String]>, tunnel_up: bool) -> CheckItem {
    let key = |k: &str| Msg::new(format!("probes.leak.check.adapters.{k}"));
    match foreign {
        None => CheckItem::new("adapters", CheckStatus::NotChecked, key("unknown")),
        Some([]) => CheckItem::new("adapters", CheckStatus::Ok, key("none")),
        Some(found) => {
            let names = found.join("; ");
            let value = Msg::new("probes.leak.check.value.text").arg("text", &names);
            if tunnel_up {
                CheckItem::new("adapters", CheckStatus::Warn, value)
                    .detail(key("conflict").arg("name", &names))
            } else {
                CheckItem::new("adapters", CheckStatus::Ok, value)
                    .detail(key("externalRoute").arg("name", &names))
            }
        }
    }
}

/// `dns`: the OS resolver answering for `example.com` (`None` = not probed). Not a leak test:
/// a silent resolver while connected is a warning (B-LC-7), otherwise informational.
pub fn dns_item(resolved: Option<bool>, tunnel_up: bool) -> CheckItem {
    let key = |k: &str| Msg::new(format!("probes.leak.check.dns.{k}"));
    match resolved {
        None => CheckItem::new("dns", CheckStatus::NotChecked, key("notProbed")),
        Some(true) => CheckItem::new("dns", CheckStatus::Info, key("answers")),
        Some(false) if tunnel_up => CheckItem::new("dns", CheckStatus::Warn, key("silent")),
        Some(false) => CheckItem::new("dns", CheckStatus::Info, key("silent")),
    }
}

/// Counts and real errors of the current session's engine log (sing-box INFO level).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ErrorSummary {
    pub proxy_out: u32,
    pub direct_out: u32,
    pub dns_events: u32,
    /// The last 5 real errors (benign noise removed).
    pub errors: Vec<String>,
}

fn rx(pattern: &str) -> regex::Regex {
    regex::Regex::new(pattern).expect("static pattern")
}

static PROXY_OUT: LazyLock<regex::Regex> =
    LazyLock::new(|| rx(r"(?i)outbound/[a-z0-9]+\[proxy-out\]"));
static DIRECT_OUT: LazyLock<regex::Regex> =
    LazyLock::new(|| rx(r"(?i)outbound/direct\[direct-out\]"));
static DNS_EVENT: LazyLock<regex::Regex> = LazyLock::new(|| rx(r"(?i)hijack|dns"));
static ERROR_LEVEL: LazyLock<regex::Regex> = LazyLock::new(|| rx(r"\b(?:FATAL|ERROR|PANIC)\b"));
static ERROR_TEXT: LazyLock<regex::Regex> = LazyLock::new(|| {
    rx(concat!(
        r"(?i)\b(?:connection|dns|router|inbound|outbound)[:/].*",
        r"\b(?:failed|timeout|refused|reset by peer|no such host|network is unreachable)\b"
    ))
});
/// Field-proven noise: the core refusing UDP for traffic deliberately sent to block-out (QUIC
/// on a TCP-only outbound); process lookup denied for SYSTEM / elevated processes (routing
/// continues by the other matchers); peers closing connections.
static BENIGN: LazyLock<[regex::Regex; 5]> = LazyLock::new(|| {
    [
        rx(r"(?i)outbound/block\[block-out\]"),
        rx(r"(?i)listen packet connection using .*block-out: operation not permitted"),
        rx(r"(?i)router: failed to search process: Access is denied"),
        rx(r"(?i)\bconnection upload closed\b"),
        rx(r"(?i)\bforcibly closed by the remote host\b"),
    ]
});

/// Whether `line` is a real error (not field-proven noise).
pub fn is_real_error(line: &str) -> bool {
    (ERROR_LEVEL.is_match(line) || ERROR_TEXT.is_match(line))
        && !BENIGN.iter().any(|b| b.is_match(line))
}

/// Summarises engine log lines (any protocol counts as `proxy-out`).
pub fn summarize_engine_log<'a>(lines: impl IntoIterator<Item = &'a str>) -> ErrorSummary {
    let mut s = ErrorSummary::default();
    let mut errors: Vec<&str> = Vec::new();
    for line in lines {
        s.proxy_out += u32::from(PROXY_OUT.is_match(line));
        s.direct_out += u32::from(DIRECT_OUT.is_match(line));
        s.dns_events += u32::from(DNS_EVENT.is_match(line));
        if is_real_error(line) {
            errors.push(line);
        }
    }
    let skip = errors.len().saturating_sub(5);
    s.errors = errors[skip..].iter().map(|e| e.trim().to_owned()).collect();
    s
}

/// `engine-log`: the current session's engine lines (`None` = unavailable). Missing or empty
/// evidence is `NotChecked` (D-49), never "no errors".
pub fn engine_log_item(lines: Option<&[String]>, tunnel_up: bool) -> CheckItem {
    let key = |k: &str| Msg::new(format!("probes.leak.check.engineLog.{k}"));
    if !tunnel_up {
        return CheckItem::new("engine-log", CheckStatus::Info, key("tunnelOff"));
    }
    let lines = match lines {
        None => return CheckItem::new("engine-log", CheckStatus::NotChecked, key("missing")),
        Some([]) => return CheckItem::new("engine-log", CheckStatus::NotChecked, key("empty")),
        Some(lines) => lines,
    };
    let s = summarize_engine_log(lines.iter().map(String::as_str));
    let counts = key("counts")
        .arg("proxy", s.proxy_out)
        .arg("direct", s.direct_out)
        .arg("dns", s.dns_events);
    if s.errors.is_empty() {
        return CheckItem::new("engine-log", CheckStatus::Ok, key("clean")).detail(counts);
    }
    let value = key("errors").arg("count", s.errors.len());
    let mut item = CheckItem::new("engine-log", CheckStatus::Warn, value).detail(counts);
    for error in &s.errors {
        let text = vpnte_core::redact::text(error).into_owned();
        item = item.detail(Msg::new("probes.leak.check.value.text").arg("text", text));
    }
    item
}

/// One engine connection as the Clash API reports it (`/connections`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnRecord {
    /// Outbound chain, e.g. `["direct-out"]`.
    pub chains: Vec<String>,
    /// The matched rule; `final` (or empty) = no rule matched.
    pub rule: String,
    pub host: Option<String>,
    pub destination_ip: Option<IpAddr>,
    pub process_path: Option<String>,
}

/// Direct-out traffic of the session, classified by what routed it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectAudit {
    /// Public destinations sent direct without any rule (up to 5 examples, IP or host).
    pub leaked: Vec<String>,
    pub leaked_count: usize,
    /// Sent direct by a configured rule (split tunnel, domain rules, Smart RU …).
    pub by_rule: usize,
    /// Of `by_rule`: Russian destinations while Smart RU is on.
    pub smart_ru: usize,
    /// The app's own engines and recognised local VPN cores (anti-loop, always direct).
    pub core: usize,
}

/// Classifies direct-out connections (B-LC-8): private destinations are legitimate (§2.6);
/// a recognised core process is expected; a configured rule is expected; `final` is a leak.
/// `is_core_process` is the engine crate's process list (one list for config and checks).
pub fn audit_direct(
    conns: &[ConnRecord],
    smart_ru: bool,
    is_core_process: &dyn Fn(&str) -> bool,
) -> DirectAudit {
    let mut audit = DirectAudit::default();
    for c in conns
        .iter()
        .filter(|c| c.chains.iter().any(|h| h == "direct-out"))
    {
        if c.destination_ip.is_some_and(|ip| !net::is_public_ip(ip)) {
            continue;
        }
        if c.process_path.as_deref().is_some_and(is_core_process) {
            audit.core += 1;
        } else if !c.rule.is_empty() && !c.rule.eq_ignore_ascii_case("final") {
            audit.by_rule += 1;
            if smart_ru && c.host.as_deref().is_some_and(is_ru_hostname) {
                audit.smart_ru += 1;
            }
        } else {
            audit.leaked_count += 1;
            let target = c
                .destination_ip
                .map(|ip| ip.to_string())
                .or_else(|| c.host.clone());
            if let Some(target) = target
                && audit.leaked.len() < 5
                && !audit.leaked.contains(&target)
            {
                audit.leaked.push(target);
            }
        }
    }
    audit
}

/// `direct-out`: judged only from the current session's connections (`None` = no data).
pub fn direct_out_item(audit: Option<&DirectAudit>, tunnel_up: bool) -> CheckItem {
    let key = |k: &str| Msg::new(format!("probes.leak.check.directOut.{k}"));
    if !tunnel_up {
        return CheckItem::new("direct-out", CheckStatus::NotChecked, key("tunnelOff"));
    }
    let Some(a) = audit else {
        return CheckItem::new("direct-out", CheckStatus::NotChecked, key("noData"));
    };
    if a.leaked_count > 0 {
        let value = key("leaked").arg("count", a.leaked_count);
        return CheckItem::new("direct-out", CheckStatus::Fail, value)
            .detail(key("examples").arg("list", a.leaked.join(", ")));
    }
    let value = key(if a.by_rule + a.core == 0 {
        "none"
    } else {
        "expected"
    });
    let counts = key("counts")
        .arg("rules", a.by_rule)
        .arg("smartRu", a.smart_ru)
        .arg("core", a.core);
    CheckItem::new("direct-out", CheckStatus::Ok, value).detail(counts)
}

/// Russian hostnames: `.ru` / `.su` / `.рф` and the big Russian services on other TLDs (a
/// label for Smart RU traffic only, never a leak decision).
pub fn is_ru_hostname(host: &str) -> bool {
    const TLDS: [&str; 3] = ["ru", "su", "xn--p1ai"];
    const SERVICES: [&str; 21] = [
        ".yandex.net",
        ".yandex.com",
        ".ya.ru",
        ".yandex",
        ".vk.com",
        ".vk.me",
        ".vkuser.net",
        ".userapi.com",
        ".mail.ru",
        ".dzen.ru",
        ".ozon.ru",
        ".wildberries.ru",
        ".wb.ru",
        ".avito.ru",
        ".tinkoff.ru",
        ".tbank.ru",
        ".sberbank.ru",
        ".sber.ru",
        ".rutube.ru",
        ".hh.ru",
        ".kinopoisk.ru",
    ];
    let host = host.trim().trim_end_matches('.').to_lowercase();
    if host.is_empty() {
        return false;
    }
    let by_tld = TLDS.iter().any(|tld| {
        host == *tld
            || host
                .strip_suffix(tld)
                .is_some_and(|rest| rest.ends_with('.'))
    });
    by_tld || SERVICES.iter().any(|s| host.ends_with(s) || host == s[1..])
}

/// What the card cannot measure itself: the tunnel and the engine own it.
#[derive(Debug, Clone)]
pub struct CheckInput {
    pub mode: Mode,
    pub tunnel_up: bool,
    /// IP monitor snapshot (adopted exit and home IP).
    pub evidence: IpEvidence,
    /// Latest self-test of this session, if one ran.
    pub self_test: Option<SelfTestResult>,
    /// The current session's engine log lines; `None` = unavailable.
    pub engine_log: Option<Vec<String>>,
    /// [`audit_direct`] over the session's Clash connections; `None` = unavailable.
    pub direct: Option<DirectAudit>,
}

/// Overall deadline of the card's measurements (B-LC-4).
pub const CHECK_DEADLINE: Duration = Duration::from_secs(15);
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const PROXY_TIMEOUT: Duration = Duration::from_secs(2);

/// Runs the card: public IPv4 / IPv6 over the OS route (what ordinary apps see), the
/// physical adapters' IPv6, foreign tunnels, the OS resolver and the configured upstream, all
/// concurrently within [`CHECK_DEADLINE`]; whatever did not finish is `NotChecked`.
pub async fn leak_check(
    reader: &IpReader,
    input: CheckInput,
    cancel: &CancellationToken,
) -> CheckReport {
    let (v4, v6, physical, foreign, dns, proxy) = tokio::join!(
        bounded(
            reader.wave(&IpRoute::Direct, Family::V4, WAVE_BUDGET, cancel),
            cancel
        ),
        bounded(
            reader.wave(&IpRoute::Direct, Family::V6, WAVE_BUDGET, cancel),
            cancel
        ),
        bounded(blocking(physical_v6), cancel),
        bounded(blocking(foreign_tunnels), cancel),
        bounded(resolves("example.com"), cancel),
        bounded(probe_upstream(&input.mode), cancel),
    );
    let up = input.tunnel_up;
    let first_foreign = foreign.as_ref().and_then(|f| f.first()).map(String::as_str);
    CheckReport::new(vec![
        proxy_item(&input.mode, up, proxy, first_foreign),
        ipv4_item(v4.map(|s| s.ip), &input.evidence, up),
        ipv6_item(v6.map(|s| s.ip), physical.as_deref(), up),
        self_test_item(input.self_test.as_ref()),
        adapters_item(foreign.as_deref(), up),
        dns_item(dns, up),
        engine_log_item(input.engine_log.as_deref(), up),
        direct_out_item(input.direct.as_ref(), up),
    ])
}

async fn bounded<T>(fut: impl Future<Output = Option<T>>, cancel: &CancellationToken) -> Option<T> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => None,
        out = tokio::time::timeout(CHECK_DEADLINE, fut) => out.ok().flatten(),
    }
}

async fn blocking<T: Send + 'static>(f: fn() -> Option<T>) -> Option<T> {
    tokio::task::spawn_blocking(f).await.ok().flatten()
}

/// Global IPv6 addresses of the physical adapters; `None` when they could not be enumerated.
fn physical_v6() -> Option<Vec<Ipv6Addr>> {
    match vpnte_winnet::adapters::physical_adapters() {
        Ok(adapters) => Some(adapters.iter().flat_map(|a| a.global_v6()).collect()),
        Err(err) if err.code() == windows::Win32::Foundation::ERROR_NOT_FOUND.to_hresult() => {
            Some(Vec::new())
        }
        Err(_) => None,
    }
}

/// Labels of other VPNs' tunnels; our own adapter names are not foreign.
fn foreign_tunnels() -> Option<Vec<String>> {
    let own = vpnte_winnet::adapters::alias::all_aliases();
    let own: Vec<&str> = own.iter().map(String::as_str).collect();
    let found = vpnte_winnet::adapters::foreign_tun::detect(None, &own).ok()?;
    Some(found.iter().map(|f| f.label()).collect())
}

async fn resolves(host: &'static str) -> Option<bool> {
    let lookup = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host, 443))).await;
    Some(lookup.is_ok_and(|found| found.is_ok_and(|mut addrs| addrs.next().is_some())))
}

async fn probe_upstream(mode: &Mode) -> Option<bool> {
    let Mode::LocalProxy {
        upstream: Some(addr),
    } = mode
    else {
        return None;
    };
    let connect = tokio::net::TcpStream::connect(addr.to_string());
    Some(matches!(
        tokio::time::timeout(PROXY_TIMEOUT, connect).await,
        Ok(Ok(_))
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_ip::IpSample;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn item(status: CheckStatus) -> CheckItem {
        CheckItem::new("dns", status, Msg::new("x"))
    }

    fn evidence() -> IpEvidence {
        IpEvidence {
            baseline: Some(ip("198.51.100.1")),
            real_ip: Some(ip("203.0.113.7")),
            last: Some(IpSample {
                ip: ip("198.51.100.1"),
                provider: 0,
                at: 1,
            }),
            fresh: true,
            verdict: crate::ip_monitor::IpVerdict::Passed,
        }
    }

    /// B-LC-1 / D-49: `Fail > Warn > NotChecked > Ok`, `Info` ignored, nothing but `Info` is not
    /// a pass; "no leaks" only for a conclusive pass.
    #[test]
    fn summary_precedence() {
        use CheckStatus::*;
        assert_eq!(summarize(&[item(Ok), item(Warn), item(Fail)]), Fail);
        assert_eq!(summarize(&[item(Ok), item(NotChecked), item(Warn)]), Warn);
        assert_eq!(
            summarize(&[item(Ok), item(NotChecked), item(Info)]),
            NotChecked
        );
        assert_eq!(summarize(&[item(Ok), item(Info)]), Ok);
        assert_eq!(summarize(&[item(Info)]), NotChecked);
        assert_eq!(summarize(&[]), NotChecked);
        assert_eq!(
            CheckReport::new(vec![item(Ok)]).headline.key,
            "probes.leak.check.summary.ok"
        );
        assert_eq!(
            CheckReport::new(vec![item(Ok), item(NotChecked)])
                .headline
                .key,
            "probes.leak.check.summary.notChecked"
        );
        assert_eq!(Info.verdict(), None);
        assert_eq!(NotChecked.verdict(), Some(Verdict::NotChecked));
    }

    /// B-LC-3: IPv4 against the monitor evidence; an unreachable service is not a leak.
    #[test]
    fn ipv4_item_uses_the_evidence() {
        let e = evidence();
        assert_eq!(
            ipv4_item(Some(ip("203.0.113.7")), &e, true).status,
            CheckStatus::Fail
        );
        assert_eq!(
            ipv4_item(Some(ip("198.51.100.1")), &e, true).status,
            CheckStatus::Ok
        );
        assert_eq!(
            ipv4_item(Some(ip("13.143.214.3")), &e, true).status,
            CheckStatus::Warn
        );
        assert_eq!(ipv4_item(None, &e, true).status, CheckStatus::NotChecked);
        assert_eq!(
            ipv4_item(Some(ip("13.143.214.3")), &e, false).status,
            CheckStatus::Info
        );
        let fresh = IpEvidence::default();
        assert_eq!(
            ipv4_item(Some(ip("13.143.214.3")), &fresh, true).status,
            CheckStatus::NotChecked
        );
        let item = ipv4_item(Some(ip("198.51.100.1")), &e, true);
        assert_eq!(
            item.value,
            Msg::new("probes.leak.check.value.ip").arg("ip", "198.51.100.1")
        );
    }

    /// B-LC-2: IPv6 judged against the physical prefixes; a failed probe is not "no IPv6".
    #[test]
    fn ipv6_item_cases() {
        let physical: Vec<Ipv6Addr> = vec!["2a02:6b8:1:2::10".parse().unwrap()];
        assert_eq!(ipv6_item(None, Some(&[]), true).status, CheckStatus::Ok);
        assert_eq!(
            ipv6_item(None, Some(&physical), true).status,
            CheckStatus::NotChecked
        );
        assert_eq!(
            ipv6_item(Some(ip("2a02:6b8:1:2::99")), Some(&physical), true).status,
            CheckStatus::Fail
        );
        assert_eq!(
            ipv6_item(Some(ip("2606:4700::5")), Some(&physical), true).status,
            CheckStatus::Ok
        );
        assert_eq!(
            ipv6_item(Some(ip("2606:4700::5")), None, true).status,
            CheckStatus::NotChecked
        );
        assert_eq!(
            ipv6_item(None, Some(&physical), false).status,
            CheckStatus::Info
        );
    }

    /// leakDiagnostics.test.ts: Direct VPN mode never probes a leftover proxy address.
    #[test]
    fn proxy_item_cases() {
        let direct = proxy_item(&Mode::DirectVpn, true, None, None);
        assert_eq!(
            (direct.status, direct.value.key.as_ref()),
            (CheckStatus::Info, "probes.leak.check.proxy.directVpn")
        );
        assert_eq!(direct.details[0].key, "probes.leak.check.proxy.directVpnOn");
        let addr = HostPort::parse("127.0.0.1:10808").unwrap();
        let mode = Mode::LocalProxy {
            upstream: Some(addr),
        };
        assert_eq!(
            proxy_item(&mode, true, Some(true), None).status,
            CheckStatus::Ok
        );
        assert_eq!(
            proxy_item(&mode, true, Some(false), None).status,
            CheckStatus::Fail
        );
        assert_eq!(
            proxy_item(&mode, true, None, None).status,
            CheckStatus::NotChecked
        );
        let none = Mode::LocalProxy { upstream: None };
        assert_eq!(
            proxy_item(&none, false, None, Some("Happ (10.0.0.2)")).status,
            CheckStatus::Info
        );
        assert_eq!(
            proxy_item(&none, true, None, None).status,
            CheckStatus::Warn
        );
    }

    #[test]
    fn self_test_adapters_and_dns_items() {
        assert_eq!(self_test_item(None).status, CheckStatus::NotChecked);
        let clean = super::super::self_test::tests::complete();
        assert_eq!(self_test_item(Some(&clean)).status, CheckStatus::Ok);
        let mut leak = clean.clone();
        leak.probes[0].reach = super::super::Reach::Reached { ip: ip("5.6.7.8") };
        assert_eq!(self_test_item(Some(&leak)).status, CheckStatus::Fail);
        assert_eq!(adapters_item(None, true).status, CheckStatus::NotChecked);
        assert_eq!(adapters_item(Some(&[]), true).status, CheckStatus::Ok);
        let found = vec!["Happ (172.19.0.1)".to_owned()];
        assert_eq!(adapters_item(Some(&found), true).status, CheckStatus::Warn);
        assert_eq!(adapters_item(Some(&found), false).status, CheckStatus::Ok);
        assert_eq!(dns_item(Some(false), true).status, CheckStatus::Warn);
        assert_eq!(dns_item(Some(false), false).status, CheckStatus::Info);
        assert_eq!(dns_item(Some(true), true).status, CheckStatus::Info);
    }

    /// F9 (leakDiagnostics.test.ts): field-proven noise is benign; real failures count.
    #[test]
    fn engine_log_errors() {
        let benign = [
            "+0300 2026-10-17 ERROR [1729147022 0ms] connection: listen packet connection using  using outbound/block[block-out]: operation not permitted",
            "+0300 2026-10-17 INFO [12 0ms] outbound/block[block-out]: blocked packet connection to 74.125.250.129:19302",
            "+0300 ERROR [7 1ms] connection: connection upload closed: wsasend: An existing connection was forcibly closed by the remote host.",
            "+0300 ERROR router: failed to search process: Access is denied.",
            "+0300 ERROR [55 0ms] router: failed to search process: Access is denied.",
            "+0300 INFO health: last timeout was recovered",
            "+0300 INFO route: failed probes from previous session ignored",
        ];
        for line in benign {
            assert!(!is_real_error(line), "{line}");
        }
        let real = "+0300 2026-10-17 ERROR [3 5s] outbound/vless[proxy-out]: connection to server failed: i/o timeout";
        assert!(is_real_error(real));
        assert!(is_real_error(
            "+0300 INFO router: failed to initialize rule-set geoip-ru: file missing"
        ));
        let mut lines = benign.to_vec();
        lines.push(real);
        assert_eq!(summarize_engine_log(lines).errors, vec![real.to_owned()]);
    }

    /// summarizeSingboxLog: any protocol counts as proxy-out.
    #[test]
    fn engine_log_counts() {
        let s = summarize_engine_log([
            "INFO [1] outbound/vless[proxy-out]: outbound connection to a:443",
            "INFO [2] outbound/vless[proxy-out]: outbound connection to b:443",
            "INFO [3] outbound/direct[direct-out]: outbound connection to 77.88.21.24:443",
        ]);
        assert_eq!((s.proxy_out, s.direct_out), (2, 1));
        let s = summarize_engine_log([
            "outbound/socks[proxy-out]: x",
            "outbound/trojan[proxy-out]: x",
            "outbound/hysteria2[proxy-out]: x",
        ]);
        assert_eq!(s.proxy_out, 3);
        assert_eq!(
            summarize_engine_log(["outbound/block[block-out]: blocked"]).proxy_out,
            0
        );
        let lines: Vec<String> =
            vec!["INFO [1] dns: exchanged A example.com. 60 IN A 93.184.216.34".into()];
        let item = engine_log_item(Some(&lines), true);
        assert_eq!(
            (item.status, item.value.key.as_ref()),
            (CheckStatus::Ok, "probes.leak.check.engineLog.clean")
        );
        assert_eq!(engine_log_item(None, true).status, CheckStatus::NotChecked);
        assert_eq!(
            engine_log_item(Some(&[]), true).status,
            CheckStatus::NotChecked
        );
        assert_eq!(engine_log_item(None, false).status, CheckStatus::Info);
        let bad: Vec<String> = vec![
            "ERROR outbound/vless[proxy-out]: connection to server failed: i/o timeout".into(),
        ];
        let item = engine_log_item(Some(&bad), true);
        assert_eq!(item.status, CheckStatus::Warn);
        assert_eq!(
            item.value,
            Msg::new("probes.leak.check.engineLog.errors").arg("count", 1)
        );
    }

    fn conn(
        rule: &str,
        host: Option<&str>,
        dst: Option<&str>,
        process: Option<&str>,
    ) -> ConnRecord {
        ConnRecord {
            chains: vec!["direct-out".into()],
            rule: rule.into(),
            host: host.map(Into::into),
            destination_ip: dst.map(ip),
            process_path: process.map(Into::into),
        }
    }

    fn core(path: &str) -> bool {
        path.to_lowercase().ends_with("\\happ.exe")
    }

    /// B-LC-8 (replaces the log heuristics of F9): Smart RU and other configured rules are
    /// expected, core processes are expected, private destinations are legitimate, `final` to
    /// a public address is a leak.
    #[test]
    fn direct_out_audit() {
        let conns = [
            conn(
                "rule_set=[geoip-ru] => route(direct-out)",
                Some("api.passport.yandex.ru"),
                Some("77.88.21.24"),
                None,
            ),
            conn(
                "rule_set=[geoip-ru] => route(direct-out)",
                None,
                Some("95.213.56.2"),
                None,
            ),
            conn(
                "rule_set=[geosite-category-gov-ru] => route(direct-out)",
                Some("gosuslugi.ru"),
                Some("109.207.1.118"),
                None,
            ),
            conn("final", None, Some("8.8.8.8"), Some("C:\\Apps\\chrome.exe")),
            conn("final", Some("example.com"), None, None),
            conn(
                "final",
                None,
                Some("1.2.3.4"),
                Some("C:\\Program Files\\Happ\\Happ.exe"),
            ),
            conn("final", None, Some("192.168.1.1"), None),
            conn(
                "ip_is_private => route(direct-out)",
                None,
                Some("10.0.0.5"),
                None,
            ),
            ConnRecord {
                chains: vec!["proxy-out".into()],
                rule: "final".into(),
                ..Default::default()
            },
        ];
        let a = audit_direct(&conns, true, &core);
        assert_eq!(
            (a.by_rule, a.smart_ru, a.core, a.leaked_count),
            (3, 2, 1, 2)
        );
        assert_eq!(
            a.leaked,
            vec!["8.8.8.8".to_owned(), "example.com".to_owned()]
        );
        let off = audit_direct(&conns, false, &core);
        assert_eq!((off.by_rule, off.smart_ru), (3, 0));
        assert_eq!(direct_out_item(Some(&a), true).status, CheckStatus::Fail);
        let clean = audit_direct(&conns[..3], true, &core);
        assert_eq!(direct_out_item(Some(&clean), true).status, CheckStatus::Ok);
        assert_eq!(direct_out_item(None, true).status, CheckStatus::NotChecked);
        assert_eq!(
            direct_out_item(Some(&clean), false).status,
            CheckStatus::NotChecked
        );
    }

    /// AT-07-002/012 (B-LC-1): the summary is never "no leaks" while a leak item is unchecked.
    #[test]
    fn no_leaks_needs_every_leak_item() {
        let e = evidence();
        let clean = super::super::self_test::tests::complete();
        let audit = DirectAudit::default();
        let lines: Vec<String> = vec!["INFO started".into()];
        let ok_items = || {
            vec![
                ipv4_item(Some(ip("198.51.100.1")), &e, true),
                ipv6_item(None, Some(&[]), true),
                self_test_item(Some(&clean)),
                engine_log_item(Some(&lines), true),
            ]
        };
        let mut items = ok_items();
        items.push(direct_out_item(Some(&audit), true));
        assert_eq!(summarize(&items), CheckStatus::Ok);
        let mut items = ok_items();
        items.push(direct_out_item(None, true));
        assert_eq!(summarize(&items), CheckStatus::NotChecked);
        let mut items = ok_items();
        items.push(direct_out_item(Some(&audit), false));
        assert_eq!(summarize(&items), CheckStatus::NotChecked);
    }

    /// isRuHostname vectors.
    #[test]
    fn russian_hostnames() {
        for host in [
            "yandex.ru",
            "api.browser.yandex.ru",
            "example.su",
            "пример.xn--p1ai",
            "api.browser.yandex.net",
            "s3.yandex.net",
            "vk.com",
            "cdn.vk.com",
            "YANDEX.RU.",
        ] {
            assert!(is_ru_hostname(host), "{host}");
        }
        for host in [
            "example.com",
            "google.com",
            "youboost.app",
            "",
            "notru",
            "kinopoisk.ru.evil.com",
        ] {
            assert!(!is_ru_hostname(host), "{host}");
        }
    }

    /// A cancelled card measures nothing and therefore claims nothing.
    #[tokio::test]
    async fn cancelled_card_is_not_a_pass() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let input = CheckInput {
            mode: Mode::DirectVpn,
            tunnel_up: true,
            evidence: evidence(),
            self_test: None,
            engine_log: None,
            direct: None,
        };
        let report = leak_check(&IpReader::new(), input, &cancel).await;
        assert_eq!(report.summary, CheckStatus::NotChecked);
        assert_eq!(report.items.len(), 8);
        let ids: Vec<&str> = report.items.iter().map(|i| i.id).collect();
        assert_eq!(
            ids,
            [
                "proxy",
                "ipv4",
                "ipv6",
                "self-test",
                "adapters",
                "dns",
                "engine-log",
                "direct-out"
            ]
        );
    }

    const RU: &str = include_str!("../../locales/probes-ip.ru.json");
    const EN: &str = include_str!("../../locales/probes-ip.en.json");

    fn flatten(prefix: &str, v: &serde_json::Value, out: &mut Vec<(String, String)>) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    let key = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    flatten(&key, v, out);
                }
            }
            other => out.push((
                prefix.to_owned(),
                other.as_str().unwrap_or_default().to_owned(),
            )),
        }
    }

    fn catalog(json: &str) -> Vec<(String, String)> {
        let value: serde_json::Value = serde_json::from_str(json).expect("valid JSON");
        let mut out = Vec::new();
        flatten("", &value, &mut out);
        out
    }

    fn placeholders(text: &str) -> Vec<String> {
        let mut found: Vec<String> = regex::Regex::new(r"\{\{(\w+)\}\}")
            .unwrap()
            .captures_iter(text)
            .map(|c| c[1].to_owned())
            .collect();
        found.sort();
        found
    }

    /// Both fragments are valid JSON under the crate's top-level key, with identical keys and
    /// placeholders, and every key the code returns exists.
    #[test]
    fn locale_fragments_match_the_code() {
        let (ru, en) = (catalog(RU), catalog(EN));
        let ru_keys: Vec<&str> = ru.iter().map(|(k, _)| k.as_str()).collect();
        let en_keys: Vec<&str> = en.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(ru_keys, en_keys);
        for ((key, r), (_, e)) in ru.iter().zip(&en) {
            assert!(key.starts_with("probes."), "{key}");
            assert!(!r.is_empty() && !e.is_empty(), "{key}");
            assert_eq!(placeholders(r), placeholders(e), "{key}");
        }
        let has = |key: &str| {
            ru_keys.contains(&key)
                || ru_keys.iter().any(|k| {
                    k.strip_prefix(key)
                        .is_some_and(|rest| rest.starts_with('_'))
                })
        };
        let sources = [
            include_str!("../ip_monitor.rs"),
            include_str!("probe.rs"),
            include_str!("self_test.rs"),
            include_str!("check.rs"),
        ];
        let literal = regex::Regex::new(r#""(probes\.[A-Za-z0-9_.-]+[A-Za-z0-9])""#).unwrap();
        for source in sources {
            for key in literal.captures_iter(source).map(|c| c[1].to_owned()) {
                assert!(has(&key), "missing locale key {key}");
            }
        }
        let built = [
            (
                "probes.leak.check.label.",
                vec![
                    "proxy",
                    "ipv4",
                    "ipv6",
                    "self-test",
                    "adapters",
                    "dns",
                    "engine-log",
                    "direct-out",
                ],
            ),
            (
                "probes.leak.selfTest.unproven.",
                vec!["incomplete", "noTunIp", "noAddresses", "probes"],
            ),
            (
                "probes.leak.check.proxy.",
                vec![
                    "directVpn",
                    "directVpnOn",
                    "directVpnOff",
                    "open",
                    "closed",
                    "notNeeded",
                    "externalOnly",
                    "missing",
                    "missingDetail",
                ],
            ),
            (
                "probes.leak.check.ipv4.",
                vec![
                    "noAnswer",
                    "tunnelOff",
                    "realIp",
                    "vpnExit",
                    "noBaseline",
                    "otherExit",
                ],
            ),
            (
                "probes.leak.check.ipv6.",
                vec![
                    "none",
                    "adaptersUnknown",
                    "tunnelOff",
                    "absent",
                    "noAnswer",
                    "realIpv6",
                    "viaVpn",
                ],
            ),
            (
                "probes.leak.check.adapters.",
                vec!["unknown", "none", "conflict", "externalRoute"],
            ),
            (
                "probes.leak.check.dns.",
                vec!["notProbed", "answers", "silent"],
            ),
            (
                "probes.leak.check.engineLog.",
                vec!["tunnelOff", "missing", "empty", "counts", "clean", "errors"],
            ),
            (
                "probes.leak.check.directOut.",
                vec![
                    "tunnelOff",
                    "noData",
                    "leaked",
                    "examples",
                    "none",
                    "expected",
                    "counts",
                ],
            ),
        ];
        for (prefix, suffixes) in built {
            for suffix in suffixes {
                assert!(
                    has(&format!("{prefix}{suffix}")),
                    "missing locale key {prefix}{suffix}"
                );
            }
        }
        let text = |key: &str| {
            ru.iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        assert_eq!(text("probes.leak.selfTest.leak"), "Обнаружена утечка");
        assert!(text("probes.leak.selfTest.ok").contains("В IPv4-проверке"));
        assert!(text("probes.leak.selfTest.unproven.incomplete").contains("не полностью"));
        assert!(text("probes.leak.selfTest.unproven.noTunIp").contains("не определён"));
        assert!(text("probes.leak.selfTest.unproven.noAddresses").contains("нет физических IPv4"));
        assert!(text("probes.leak.selfTest.unproven.probes").contains("не все пробы"));
        assert!(text("probes.leak.selfTest.cancelled").contains("Тест отменён"));
        assert!(text("probes.leak.selfTest.disagreement").starts_with("IP-проверки расходятся"));
        assert!(
            text("probes.leak.check.proxy.directVpnOn")
                .to_lowercase()
                .contains("локальный proxy не используется")
        );
    }
}
