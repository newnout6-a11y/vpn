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
mod direct;
mod engine_log;
mod items;

use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::{UnixMs, Verdict, now_ms};
use vpnte_core::net::HostPort;

use crate::ip_monitor::IpEvidence;
use crate::leak::self_test::SelfTestResult;
use crate::public_ip::{Family, IpReader, IpRoute, WAVE_BUDGET};

pub use direct::{ConnRecord, DirectAudit, audit_direct, direct_out_item, is_ru_hostname};
pub use engine_log::{ErrorSummary, engine_log_item, is_real_error, summarize_engine_log};
pub use items::{adapters_item, dns_item, ipv4_item, ipv6_item, proxy_item, self_test_item};

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
mod tests;
