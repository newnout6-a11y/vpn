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
        default_direct: false,
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
    assert!(args.contains(&"Wi-Fi") && args.contains(&"5.6.7.8") && args.contains(&"192.168.1.2"));
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
    assert!(urls.contains(&CROSS_URLS[0].to_owned()) && urls.contains(&CROSS_URLS[1].to_owned()));
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
