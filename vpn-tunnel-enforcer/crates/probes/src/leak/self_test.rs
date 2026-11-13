//! The leak self-test: a default-route read, one bound probe per physical address (IPv4 and
//! global IPv6, B-LT-5) and an IP-service cross-check, all as `curl.exe` children.
//!
//! Verdict (owner decision D-60): a physical address that reaches the Internet is a leak when
//! the kill switch is on and only a possible leak when it is off (then nothing is supposed to
//! block it); two IP services that see different exits are a possible leak (D-48), never red;
//! anything incomplete is inconclusive, never "no leaks". Leak evidence wins over
//! incompleteness.
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Shared, WeakShared, join, join_all};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::{KillSwitchLevel, UnixMs, Verdict, now_ms};

use super::probe::{self, CurlOutcome, Reach, Why};
use crate::public_ip::Family;

/// Default-route read (goes wherever an ordinary app's traffic goes: the TUN when it works).
const DEFAULT_URL: &str = "https://api.ipify.org";
const DEFAULT_MAX_S: u64 = 6;
/// Bound probes target IP literals: no DNS dependency, and immune to a FakeIP resolver whose
/// TUN-only answer would make a bound connect "fail" and read as blocked (B-LT-2).
const BOUND_URL_V4: &str = "https://1.1.1.1/cdn-cgi/trace";
const BOUND_URL_V6: &str = "https://[2606:4700:4700::1111]/cdn-cgi/trace";
const BOUND_MAX_S: u64 = 4;
/// Cross-check services, tried in order; the first IPv4 answer counts.
const CROSS_URLS: [&str; 3] = [
    "https://cloudflare.com/cdn-cgi/trace",
    "https://one.one.one.one/cdn-cgi/trace",
    "https://icanhazip.com",
];
const CROSS_MAX_S: u64 = 4;

/// A physical adapter address to probe from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalAddr {
    pub alias: String,
    pub ip: IpAddr,
}

/// The outcome of the bound probe from one address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddrProbe {
    pub alias: String,
    pub local: IpAddr,
    pub reach: Reach,
    pub stderr_tail: Option<String>,
}

/// Two IP services saw different exits (D-48: a possible leak, shown with both addresses).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Disagreement {
    pub other_service_ip: IpAddr,
    pub default_ip: IpAddr,
}

/// Evidence of one self-test run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfTestResult {
    pub at: UnixMs,
    /// Kill-switch level the run was judged against.
    pub kill_switch: KillSwitchLevel,
    /// Public IPv4 seen through the default route (the TUN when it works).
    pub default_v4: Option<Ipv4Addr>,
    pub probes: Vec<AddrProbe>,
    /// False when the physical adapters could not be enumerated.
    pub inspection_complete: bool,
    pub services_disagree: Option<Disagreement>,
    pub cancelled: bool,
    /// Only the listed apps use the VPN (p-app-split) and `curl.exe` is not one of them: the
    /// default-route read and the cross-check went around the tunnel. Their address is shown as
    /// what it is, never as the tunnel's, and the run is judged on the bound probes alone. Set
    /// by whoever knows the session's scope (`with_scope`).
    #[serde(default)]
    pub default_direct: bool,
}

impl SelfTestResult {
    /// The run of a session whose VPN carries only the listed apps (`listed_only`).
    pub fn with_scope(mut self, listed_only: bool) -> Self {
        self.default_direct = listed_only;
        if listed_only {
            // Both reads went direct: their agreement says nothing about the tunnel.
            self.services_disagree = None;
        }
        self
    }

    /// The view of a run stopped before it finished (protection stopped, caller gone).
    pub fn cancelled(kill_switch: KillSwitchLevel) -> Self {
        Self {
            at: now_ms(),
            kill_switch,
            default_v4: None,
            probes: Vec::new(),
            inspection_complete: false,
            services_disagree: None,
            cancelled: true,
            default_direct: false,
        }
    }

    /// Probes whose address reached the Internet.
    pub fn reached(&self) -> impl Iterator<Item = &AddrProbe> {
        self.probes
            .iter()
            .filter(|p| matches!(p.reach, Reach::Reached { .. }))
    }
}

/// What the self-test concludes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SelfTestVerdict {
    /// A physical address reached the Internet although the kill switch should block it.
    Leak,
    /// Reach with the kill switch off, or IP services that disagree.
    PossibleLeak,
    /// Every probe measured "no way out" and the tunnel's exit is known.
    Ok,
    /// Not proven either way (also: cancelled).
    Inconclusive,
}

impl SelfTestVerdict {
    /// The app-wide verdict scale.
    pub fn verdict(self) -> Verdict {
        match self {
            SelfTestVerdict::Leak => Verdict::Fail,
            SelfTestVerdict::PossibleLeak => Verdict::Warn,
            SelfTestVerdict::Ok => Verdict::Ok,
            SelfTestVerdict::Inconclusive => Verdict::NotChecked,
        }
    }
}

/// Why a run is inconclusive (first failing condition).
fn unproven(r: &SelfTestResult) -> Option<&'static str> {
    let v4_probes = || r.probes.iter().filter(|p| p.local.is_ipv4());
    if !r.inspection_complete {
        Some("incomplete")
    } else if r.default_v4.is_none() && !r.default_direct {
        Some("noTunIp")
    } else if v4_probes().next().is_none() {
        Some("noAddresses")
    } else if r
        .probes
        .iter()
        .any(|p| !matches!(p.reach, Reach::NotReached { .. }))
    {
        Some("probes")
    } else {
        None
    }
}

/// The verdict of one run (pure).
pub fn verdict(r: &SelfTestResult) -> SelfTestVerdict {
    if r.reached().next().is_some() {
        return match r.kill_switch {
            KillSwitchLevel::Off => SelfTestVerdict::PossibleLeak,
            KillSwitchLevel::Standard | KillSwitchLevel::Strict => SelfTestVerdict::Leak,
        };
    }
    if r.cancelled || unproven(r).is_some() {
        SelfTestVerdict::Inconclusive
    } else if r.services_disagree.is_some() {
        SelfTestVerdict::PossibleLeak
    } else {
        SelfTestVerdict::Ok
    }
}

/// User-facing summary of a run, derived from the evidence (never from a stored text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTestReport {
    pub verdict: SelfTestVerdict,
    pub headline: Msg,
    /// One line per probe, then the tunnel's exit and the services' disagreement when known.
    pub details: Vec<Msg>,
}

/// Builds the report of `r`.
pub fn report(r: &SelfTestResult) -> SelfTestReport {
    let verdict = verdict(r);
    if r.cancelled && verdict == SelfTestVerdict::Inconclusive {
        return SelfTestReport {
            verdict,
            headline: Msg::new("probes.leak.selfTest.cancelled"),
            details: Vec::new(),
        };
    }
    let reached = r.reached().next().is_some();
    let headline = match verdict {
        SelfTestVerdict::Leak => Msg::new("probes.leak.selfTest.leak"),
        SelfTestVerdict::PossibleLeak if reached => {
            Msg::new("probes.leak.selfTest.bypassKillSwitchOff")
        }
        SelfTestVerdict::PossibleLeak => Msg::new("probes.leak.selfTest.servicesDisagree"),
        SelfTestVerdict::Ok if r.probes.iter().any(|p| p.local.is_ipv6()) => {
            Msg::new("probes.leak.selfTest.okDual")
        }
        SelfTestVerdict::Ok => Msg::new("probes.leak.selfTest.ok"),
        SelfTestVerdict::Inconclusive => {
            let reason = unproven(r).unwrap_or("probes");
            Msg::new(format!("probes.leak.selfTest.unproven.{reason}"))
        }
    };
    let mut details: Vec<Msg> = r.probes.iter().map(probe_line).collect();
    details.push(match (r.default_v4, r.default_direct) {
        (Some(ip), true) => Msg::new("probes.leak.selfTest.directIp").arg("ip", ip),
        (None, true) => Msg::new("probes.leak.selfTest.directIpUnknown"),
        (Some(ip), false) => Msg::new("probes.leak.selfTest.tunIp").arg("ip", ip),
        (None, false) => Msg::new("probes.leak.selfTest.tunIpUnknown"),
    });
    if let Some(d) = r.services_disagree {
        details.push(
            Msg::new("probes.leak.selfTest.disagreement")
                .arg("other", d.other_service_ip)
                .arg("default", d.default_ip),
        );
    }
    SelfTestReport {
        verdict,
        headline,
        details,
    }
}

fn probe_line(p: &AddrProbe) -> Msg {
    let msg = match p.reach {
        Reach::Reached { ip } => Msg::new("probes.leak.probe.reached").arg("ip", ip),
        Reach::NotReached { curl_exit } => {
            Msg::new("probes.leak.probe.blocked").arg("code", curl_exit)
        }
        Reach::Inconclusive { why, .. } => Msg::new(match why {
            Why::Launch => "probes.leak.probe.unknown.launch",
            Why::ProcessTimeout => "probes.leak.probe.unknown.processTimeout",
            Why::Bind => "probes.leak.probe.unknown.bind",
            Why::Dns => "probes.leak.probe.unknown.dns",
            Why::Tls => "probes.leak.probe.unknown.tls",
            Why::BadAnswer => "probes.leak.probe.unknown.badAnswer",
            Why::Curl => "probes.leak.probe.unknown.curl",
        }),
    };
    msg.arg("alias", &p.alias).arg("local", p.local)
}

/// What the self-test needs from the system: `curl.exe` children and the physical addresses.
pub trait LeakEnv: Send + Sync + 'static {
    /// One curl run with `args`, killed after `timeout`; dropping the future kills it too.
    fn curl(&self, args: Vec<String>, timeout: Duration) -> BoxFuture<'static, CurlOutcome>;
    /// Usable IPv4 and global IPv6 addresses of the physical adapters; `Err` = the adapters
    /// could not be enumerated (an empty list = nothing to test).
    fn physical_addresses(&self) -> BoxFuture<'static, Result<Vec<PhysicalAddr>, ()>>;
}

/// The real environment: `%SystemRoot%\System32\curl.exe` and the winnet physical-adapter
/// predicate (shared with the kill switch, so both always agree on what "physical" is).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEnv;

impl LeakEnv for SystemEnv {
    fn curl(&self, args: Vec<String>, timeout: Duration) -> BoxFuture<'static, CurlOutcome> {
        probe::run_curl(args, timeout).boxed()
    }

    fn physical_addresses(&self) -> BoxFuture<'static, Result<Vec<PhysicalAddr>, ()>> {
        async {
            let found = tokio::task::spawn_blocking(vpnte_winnet::adapters::physical_adapters)
                .await
                .map_err(|_| ())?;
            let adapters = match found {
                Ok(adapters) => adapters,
                // "No physical adapter is up" is an answer (nothing to test), not a failure.
                Err(err) if err.code() == windows::Win32::Foundation::ERROR_NOT_FOUND.to_hresult() => {
                    return Ok(Vec::new());
                }
                Err(err) => {
                    tracing::warn!(error = %err, "leak self-test: physical adapters not enumerated");
                    return Err(());
                }
            };
            Ok(adapters
                .iter()
                .flat_map(|a| {
                    let v4 = a.source_v4().into_iter().map(IpAddr::V4);
                    let v6 = a.global_v6().into_iter().map(IpAddr::V6);
                    v4.chain(v6).map(|ip| PhysicalAddr {
                        alias: a.alias.clone(),
                        ip,
                    })
                })
                .collect())
        }
        .boxed()
    }
}

/// One run, unshared. Cancelling `cancel` returns the cancelled view at once; the dropped
/// probes kill their children.
pub async fn run_self_test(
    env: &dyn LeakEnv,
    kill_switch: KillSwitchLevel,
    cancel: &CancellationToken,
) -> SelfTestResult {
    let work = async {
        let default = env.curl(
            probe::curl_args(Family::V4, None, DEFAULT_MAX_S, DEFAULT_URL),
            probe::process_timeout(DEFAULT_MAX_S),
        );
        let bound = async {
            match env.physical_addresses().await {
                Ok(addrs) => (
                    true,
                    join_all(addrs.into_iter().map(|a| bound_probe(env, a))).await,
                ),
                Err(()) => (false, Vec::new()),
            }
        };
        let ((default, cross), (inspection_complete, probes)) =
            join(join(default, cross_check(env)), bound).await;
        let default_v4 = match probe::parse_probe_ip(&default.stdout, Family::V4) {
            Some(IpAddr::V4(v4)) => Some(v4),
            _ => None,
        };
        // Not a verdict on its own: anycast, CDN routing or split rules can make services
        // disagree; a red leak still needs a physical-adapter reach.
        let services_disagree = match (cross, default_v4) {
            (Some(other), Some(default)) if other != IpAddr::V4(default) => Some(Disagreement {
                other_service_ip: other,
                default_ip: IpAddr::V4(default),
            }),
            _ => None,
        };
        SelfTestResult {
            at: now_ms(),
            kill_switch,
            default_v4,
            probes,
            inspection_complete,
            services_disagree,
            cancelled: false,
            default_direct: false,
        }
    };
    tokio::select! {
        biased;
        _ = cancel.cancelled() => SelfTestResult::cancelled(kill_switch),
        result = work => if cancel.is_cancelled() {
            SelfTestResult::cancelled(kill_switch)
        } else {
            result
        },
    }
}

async fn bound_probe(env: &dyn LeakEnv, addr: PhysicalAddr) -> AddrProbe {
    let (family, url) = match addr.ip {
        IpAddr::V4(_) => (Family::V4, BOUND_URL_V4),
        IpAddr::V6(_) => (Family::V6, BOUND_URL_V6),
    };
    let args = probe::curl_args(family, Some(addr.ip), BOUND_MAX_S, url);
    let outcome = env.curl(args, probe::process_timeout(BOUND_MAX_S)).await;
    AddrProbe {
        reach: probe::classify(&outcome, family),
        stderr_tail: outcome.stderr_tail(),
        alias: addr.alias,
        local: addr.ip,
    }
}

/// First IPv4 any cross-check service reports, trying them in order.
async fn cross_check(env: &dyn LeakEnv) -> Option<IpAddr> {
    for url in CROSS_URLS {
        let args = probe::curl_args(Family::V4, None, CROSS_MAX_S, url);
        let outcome = env.curl(args, probe::process_timeout(CROSS_MAX_S)).await;
        if let Some(ip) = probe::parse_probe_ip(&outcome.stdout, Family::V4) {
            return Some(ip);
        }
    }
    None
}

type Run = BoxFuture<'static, SelfTestResult>;

/// Single-flight runner: concurrent callers share one run and each keeps its own
/// cancellation; the run stops (children killed) when its last caller leaves or on
/// [`SelfTester::stop_all`].
pub struct SelfTester {
    env: Arc<dyn LeakEnv>,
    slot: Mutex<Slot>,
}

struct Slot {
    run: Option<WeakShared<Run>>,
    stop: CancellationToken,
}

impl SelfTester {
    /// A runner over `env` (production: `Arc::new(SystemEnv)`).
    pub fn new(env: Arc<dyn LeakEnv>) -> Self {
        Self {
            env,
            slot: Mutex::new(Slot {
                run: None,
                stop: CancellationToken::new(),
            }),
        }
    }

    /// Joins the run in flight or starts one judged against `kill_switch`. `cancel` detaches
    /// this caller only (it gets the cancelled view).
    pub async fn run(
        &self,
        kill_switch: KillSwitchLevel,
        cancel: &CancellationToken,
    ) -> SelfTestResult {
        let shared: Shared<Run> = {
            let mut slot = self.slot.lock();
            match slot.run.as_ref().and_then(WeakShared::upgrade) {
                Some(run) => run,
                None => {
                    let env = self.env.clone();
                    let stop = slot.stop.clone();
                    let run: Run =
                        async move { run_self_test(&*env, kill_switch, &stop).await }.boxed();
                    let run = run.shared();
                    slot.run = run.downgrade();
                    run
                }
            }
        };
        tokio::select! {
            biased;
            _ = cancel.cancelled() => SelfTestResult::cancelled(kill_switch),
            result = shared => result,
        }
    }

    /// Stops the run in flight (protection stopped or a transition began): its callers get the
    /// cancelled view; the next `run` starts afresh.
    pub fn stop_all(&self) {
        let mut slot = self.slot.lock();
        slot.stop.cancel();
        slot.stop = CancellationToken::new();
        slot.run = None;
    }
}

#[cfg(test)]
pub(crate) mod tests;
