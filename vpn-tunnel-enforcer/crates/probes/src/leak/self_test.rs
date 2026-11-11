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
}

impl SelfTestResult {
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
    } else if r.default_v4.is_none() {
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
    details.push(match r.default_v4 {
        Some(ip) => Msg::new("probes.leak.selfTest.tunIp").arg("ip", ip),
        None => Msg::new("probes.leak.selfTest.tunIpUnknown"),
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
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    pub(crate) fn exit(code: Option<i32>, stdout: &str) -> CurlOutcome {
        CurlOutcome {
            exit: code,
            stdout: stdout.into(),
            stderr: String::new(),
            launched: true,
        }
    }

    /// Scripted curl answers keyed by URL (cross / default) or bound address.
    #[derive(Default)]
    pub(crate) struct FakeEnv {
        pub(crate) by_url: Mutex<HashMap<&'static str, CurlOutcome>>,
        pub(crate) by_bind: Mutex<HashMap<IpAddr, CurlOutcome>>,
        pub(crate) addrs: Mutex<Option<Vec<PhysicalAddr>>>,
        pub(crate) urls: Mutex<Vec<String>>,
        pub(crate) calls: AtomicUsize,
        pub(crate) delay_ms: u64,
    }

    impl FakeEnv {
        /// Default route 1.2.3.4, Wi-Fi 192.168.1.2 blocked (curl 7), cross-check agrees.
        pub(crate) fn clean() -> FakeEnv {
            let env = FakeEnv::default();
            env.by_url
                .lock()
                .insert(DEFAULT_URL, exit(Some(0), "1.2.3.4"));
            env.by_url
                .lock()
                .insert(CROSS_URLS[0], exit(Some(0), "fl=1\nip=1.2.3.4\n"));
            env.by_bind
                .lock()
                .insert(ip("192.168.1.2"), exit(Some(7), ""));
            *env.addrs.lock() = Some(vec![PhysicalAddr {
                alias: "Wi-Fi".into(),
                ip: ip("192.168.1.2"),
            }]);
            env
        }
    }

    impl LeakEnv for Arc<FakeEnv> {
        fn curl(&self, args: Vec<String>, _timeout: Duration) -> BoxFuture<'static, CurlOutcome> {
            let env = self.clone();
            async move {
                env.calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(env.delay_ms)).await;
                let url = args.last().cloned().unwrap_or_default();
                env.urls.lock().push(url.clone());
                let bind = args
                    .iter()
                    .position(|a| a == "--interface")
                    .map(|i| ip(&args[i + 1]));
                let found = match bind {
                    Some(local) => env.by_bind.lock().get(&local).cloned(),
                    None => env
                        .by_url
                        .lock()
                        .iter()
                        .find(|(u, _)| **u == url)
                        .map(|(_, o)| o.clone()),
                };
                found.unwrap_or_else(|| exit(Some(6), ""))
            }
            .boxed()
        }

        fn physical_addresses(&self) -> BoxFuture<'static, Result<Vec<PhysicalAddr>, ()>> {
            let addrs = self.addrs.lock().clone();
            async move { addrs.ok_or(()) }.boxed()
        }
    }

    pub(crate) fn complete() -> SelfTestResult {
        SelfTestResult {
            at: 1,
            kill_switch: KillSwitchLevel::Standard,
            default_v4: Some(Ipv4Addr::new(1, 2, 3, 4)),
            probes: vec![AddrProbe {
                alias: "Wi-Fi".into(),
                local: ip("192.168.1.2"),
                reach: Reach::NotReached { curl_exit: 7 },
                stderr_tail: None,
            }],
            inspection_complete: true,
            services_disagree: None,
            cancelled: false,
        }
    }

    fn with_reach(reach: Reach) -> SelfTestResult {
        let mut r = complete();
        r.probes[0].reach = reach;
        r
    }

    /// AT-00-008 (leak-self-test.test.ts): complete evidence is `Ok`; every gap is
    /// `Inconclusive`; curl 7 and 28 count as blocked.
    #[test]
    fn verdict_needs_complete_evidence() {
        assert_eq!(verdict(&complete()), SelfTestVerdict::Ok);
        let mut r = complete();
        r.inspection_complete = false;
        assert_eq!(verdict(&r), SelfTestVerdict::Inconclusive);
        let mut r = complete();
        r.default_v4 = None;
        assert_eq!(verdict(&r), SelfTestVerdict::Inconclusive);
        let mut r = complete();
        r.probes.clear();
        assert_eq!(verdict(&r), SelfTestVerdict::Inconclusive);
        for code in [None, Some(-1), Some(0), Some(6), Some(35), Some(60)] {
            let reach = probe::classify(&exit(code, ""), Family::V4);
            assert_eq!(
                verdict(&with_reach(reach)),
                SelfTestVerdict::Inconclusive,
                "{code:?}"
            );
        }
        for code in [7, 28] {
            assert_eq!(
                verdict(&with_reach(Reach::NotReached { curl_exit: code })),
                SelfTestVerdict::Ok
            );
        }
        let mut r = complete();
        r.cancelled = true;
        assert_eq!(verdict(&r), SelfTestVerdict::Inconclusive);
    }

    /// AT-00-008: leak evidence wins over incompleteness; D-60: with the kill switch off a reach
    /// is only a possible leak; D-48: disagreeing services are a possible leak.
    #[test]
    fn verdict_leak_classes() {
        let mut r = with_reach(Reach::Reached { ip: ip("5.6.7.8") });
        r.inspection_complete = false;
        r.default_v4 = None;
        assert_eq!(verdict(&r), SelfTestVerdict::Leak);
        r.kill_switch = KillSwitchLevel::Strict;
        assert_eq!(verdict(&r), SelfTestVerdict::Leak);
        r.kill_switch = KillSwitchLevel::Off;
        assert_eq!(verdict(&r), SelfTestVerdict::PossibleLeak);
        let mut r = complete();
        r.services_disagree = Some(Disagreement {
            other_service_ip: ip("5.6.7.8"),
            default_ip: ip("1.2.3.4"),
        });
        assert_eq!(verdict(&r), SelfTestVerdict::PossibleLeak);
        assert_eq!(SelfTestVerdict::PossibleLeak.verdict(), Verdict::Warn);
        assert_eq!(SelfTestVerdict::Inconclusive.verdict(), Verdict::NotChecked);
    }

    fn keys(r: &SelfTestReport) -> Vec<&str> {
        r.details.iter().map(|m| m.key.as_ref()).collect()
    }

    /// AT-00-008 messages: headline per verdict / reason; details name the reached address,
    /// its public IP and the TUN IP; the services' disagreement is always appended.
    #[test]
    fn report_texts_follow_the_evidence() {
        assert_eq!(report(&complete()).headline.key, "probes.leak.selfTest.ok");
        let mut r = complete();
        r.inspection_complete = false;
        assert_eq!(
            report(&r).headline.key,
            "probes.leak.selfTest.unproven.incomplete"
        );
        let mut r = complete();
        r.default_v4 = None;
        assert_eq!(
            report(&r).headline.key,
            "probes.leak.selfTest.unproven.noTunIp"
        );
        assert!(keys(&report(&r)).contains(&"probes.leak.selfTest.tunIpUnknown"));
        let mut r = complete();
        r.probes.clear();
        assert_eq!(
            report(&r).headline.key,
            "probes.leak.selfTest.unproven.noAddresses"
        );
        let r = with_reach(probe::classify(&exit(Some(-1), ""), Family::V4));
        assert_eq!(
            report(&r).headline.key,
            "probes.leak.selfTest.unproven.probes"
        );

        let reached = report(&with_reach(Reach::Reached { ip: ip("5.6.7.8") }));
        assert_eq!(reached.headline, Msg::new("probes.leak.selfTest.leak"));
        let line = &reached.details[0];
        assert_eq!(line.key, "probes.leak.probe.reached");
        let args: Vec<&str> = line.args.iter().map(|(_, v)| v.as_str()).collect();
        assert!(
            args.contains(&"Wi-Fi") && args.contains(&"5.6.7.8") && args.contains(&"192.168.1.2")
        );
        assert_eq!(
            reached.details[1],
            Msg::new("probes.leak.selfTest.tunIp").arg("ip", "1.2.3.4")
        );

        let mut off = with_reach(Reach::Reached { ip: ip("5.6.7.8") });
        off.kill_switch = KillSwitchLevel::Off;
        assert_eq!(
            report(&off).headline.key,
            "probes.leak.selfTest.bypassKillSwitchOff"
        );

        let mut r = complete();
        r.services_disagree = Some(Disagreement {
            other_service_ip: ip("5.6.7.8"),
            default_ip: ip("1.2.3.4"),
        });
        let rep = report(&r);
        assert_eq!(rep.headline.key, "probes.leak.selfTest.servicesDisagree");
        assert_eq!(
            rep.details.last().unwrap(),
            &Msg::new("probes.leak.selfTest.disagreement")
                .arg("other", "5.6.7.8")
                .arg("default", "1.2.3.4")
        );
        r.probes.clear();
        let rep = report(&r);
        assert_eq!(rep.verdict, SelfTestVerdict::Inconclusive);
        assert!(
            keys(&rep).contains(&"probes.leak.selfTest.disagreement"),
            "details always shown"
        );

        let cancelled = report(&SelfTestResult::cancelled(KillSwitchLevel::Standard));
        assert_eq!(cancelled.headline.key, "probes.leak.selfTest.cancelled");
        assert_eq!(cancelled.verdict, SelfTestVerdict::Inconclusive);

        let mut dual = complete();
        dual.probes.push(AddrProbe {
            alias: "Wi-Fi".into(),
            local: ip("2a00:1450::5"),
            reach: Reach::NotReached { curl_exit: 28 },
            stderr_tail: None,
        });
        assert_eq!(report(&dual).headline.key, "probes.leak.selfTest.okDual");
    }

    /// AT-07-002 / AT-00-003 (leakSelfTest.test.ts): a clean machine is `Ok`; the cross-check
    /// tries the next service after a failure; an IPv6 address gets an IPv6 probe.
    #[tokio::test]
    async fn run_with_a_blocked_adapter_is_ok() {
        let env = Arc::new(FakeEnv::clean());
        env.by_url.lock().remove(CROSS_URLS[0]);
        env.by_url
            .lock()
            .insert(CROSS_URLS[1], exit(Some(0), "ip=1.2.3.4"));
        env.addrs.lock().as_mut().unwrap().push(PhysicalAddr {
            alias: "Wi-Fi".into(),
            ip: ip("2a00:1450::5"),
        });
        env.by_bind
            .lock()
            .insert(ip("2a00:1450::5"), exit(Some(28), ""));
        let r = run_self_test(&env, KillSwitchLevel::Standard, &CancellationToken::new()).await;
        assert_eq!(verdict(&r), SelfTestVerdict::Ok);
        assert_eq!(r.default_v4, Some(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(r.inspection_complete && r.services_disagree.is_none());
        let urls = env.urls.lock().clone();
        assert!(
            urls.contains(&CROSS_URLS[0].to_owned()) && urls.contains(&CROSS_URLS[1].to_owned())
        );
        assert!(!urls.contains(&CROSS_URLS[2].to_owned()));
        assert!(urls.contains(&BOUND_URL_V6.to_owned()) && urls.contains(&BOUND_URL_V4.to_owned()));
    }

    /// leakSelfTest.test.ts: services disagree (5.6.7.8 vs 1.2.3.4) with no adapters →
    /// inconclusive with the disagreement kept; enumeration failure → incomplete; a bound probe
    /// that printed an address before exit 28 → leak; launch failure → inconclusive.
    #[tokio::test]
    async fn run_outcomes() {
        let cancel = CancellationToken::new();
        let env = Arc::new(FakeEnv::clean());
        env.by_url
            .lock()
            .insert(CROSS_URLS[0], exit(Some(0), "ip=5.6.7.8"));
        *env.addrs.lock() = Some(Vec::new());
        let r = run_self_test(&env, KillSwitchLevel::Standard, &cancel).await;
        assert_eq!(verdict(&r), SelfTestVerdict::Inconclusive);
        assert_eq!(r.services_disagree.unwrap().other_service_ip, ip("5.6.7.8"));
        assert!(r.reached().next().is_none());

        let env = Arc::new(FakeEnv::clean());
        *env.addrs.lock() = None;
        let r = run_self_test(&env, KillSwitchLevel::Standard, &cancel).await;
        assert!(!r.inspection_complete);
        assert_eq!(
            report(&r).headline.key,
            "probes.leak.selfTest.unproven.incomplete"
        );

        let env = Arc::new(FakeEnv::clean());
        env.by_bind
            .lock()
            .insert(ip("192.168.1.2"), exit(Some(28), "1.2.3.4"));
        let r = run_self_test(&env, KillSwitchLevel::Standard, &cancel).await;
        assert_eq!(verdict(&r), SelfTestVerdict::Leak);

        let env = Arc::new(FakeEnv::clean());
        env.by_bind
            .lock()
            .insert(ip("192.168.1.2"), CurlOutcome::not_launched());
        let r = run_self_test(&env, KillSwitchLevel::Standard, &cancel).await;
        assert_eq!(verdict(&r), SelfTestVerdict::Inconclusive);
        assert_eq!(
            r.probes[0].reach,
            Reach::Inconclusive {
                curl_exit: None,
                why: Why::Launch
            }
        );
    }

    /// Lifetime: concurrent callers share one run; one caller leaving does not stop it for the
    /// other; `stop_all` gives the cancelled view.
    #[tokio::test]
    async fn shared_runs_and_cancellation() {
        let env = Arc::new(FakeEnv {
            delay_ms: 150,
            ..FakeEnv::clean()
        });
        let tester = Arc::new(SelfTester::new(Arc::new(env.clone())));
        let cancel = CancellationToken::new();
        let (a, b) = tokio::join!(
            tester.run(KillSwitchLevel::Standard, &cancel),
            tester.run(KillSwitchLevel::Standard, &cancel)
        );
        assert_eq!(a, b);
        assert_eq!(
            env.calls.load(Ordering::SeqCst),
            3,
            "default + one cross-check + one bound probe"
        );

        let leaving = CancellationToken::new();
        let t = tester.clone();
        let stayer = tokio::spawn(async move {
            t.run(KillSwitchLevel::Standard, &CancellationToken::new())
                .await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let early = {
            let t = tester.clone();
            let leaving = leaving.clone();
            tokio::spawn(async move { t.run(KillSwitchLevel::Standard, &leaving).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        leaving.cancel();
        assert!(early.await.unwrap().cancelled);
        let kept = stayer.await.unwrap();
        assert!(!kept.cancelled);
        assert_eq!(verdict(&kept), SelfTestVerdict::Ok);

        let t = tester.clone();
        let stopped = tokio::spawn(async move {
            t.run(KillSwitchLevel::Standard, &CancellationToken::new())
                .await
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        tester.stop_all();
        let r = stopped.await.unwrap();
        assert!(r.cancelled);
        assert_eq!(report(&r).headline.key, "probes.leak.selfTest.cancelled");
    }
}
