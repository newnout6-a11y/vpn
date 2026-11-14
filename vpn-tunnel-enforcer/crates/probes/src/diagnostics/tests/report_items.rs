//! Report item builders (systemDiagnostics.test.ts, systemDiagnostics.logging.test.ts).
use std::net::IpAddr;

use vpnte_base::Msg;
use vpnte_base::types::Verdict;

use crate::diagnostics::checks::{self, Finding, Hy2Facts, ProfileFacts, ProxyState};
use crate::diagnostics::endpoints::{endpoint_item, parse_write_out};
use crate::diagnostics::sysinfo::{ServiceRow, ServiceStart};
use crate::diagnostics::{Category, CheckItem, summarize};

/// `isBenignSingBoxLogNoise` vectors.
#[test]
fn benign_engine_noise() {
    let benign = [
        "ERROR[0012] connection: connection upload closed: raw-read tcp4: An existing connection was forcibly closed by the remote host.",
        "ERROR[0013] connection: connection download closed: context canceled",
        "INFO[0014] router: failed to search process: Access is denied.",
        "INFO[0014] [3402671] router: failed to search process: Access is denied.",
    ];
    for line in benign {
        assert!(checks::is_benign_engine_noise(line), "{line}");
    }
    let real = [
        "ERROR[0015] outbound/vless[proxy-out]: connection to server failed: i/o timeout",
        "ERROR[0016] router: failed to initialize rule-set geoip-ru: file missing",
    ];
    for line in real {
        assert!(!checks::is_benign_engine_noise(line), "{line}");
    }
    let lines: Vec<&str> = benign
        .iter()
        .chain(real.iter())
        .copied()
        .chain(["INFO started"])
        .collect();
    assert_eq!(checks::engine_errors(lines), real.to_vec());
}

/// The engine log warns only while the TUN runs; with it stopped the lines are history (and
/// the copy says so instead of "not used by the current route" while running).
#[test]
fn tun_log_item() {
    let lines = vec![
        "ERROR[1] outbound/vless[proxy-out]: connection to server failed: i/o timeout".to_owned(),
    ];
    let running = checks::tun_log_item(&lines, true);
    assert_eq!(
        (running.verdict, running.value.key.as_ref()),
        (Some(Verdict::Warn), "probes.diag.tunLog.errors")
    );
    let stopped = checks::tun_log_item(&lines, false);
    assert_eq!(
        (stopped.verdict, stopped.value.key.as_ref()),
        (None, "probes.diag.tunLog.historical")
    );
    let clean = checks::tun_log_item(&[], true);
    assert_eq!(
        (clean.verdict, clean.value.key.as_ref()),
        (Some(Verdict::Ok), "probes.diag.tunLog.clean")
    );
}

#[test]
fn app_log_counts_only_fresh_problems() {
    use vpnte_core::logging::Problem;
    let p = |at, msg: &str| Problem {
        at,
        level: tracing::Level::WARN,
        target: "vpnte_x".into(),
        msg: msg.into(),
    };
    let now = 10_000_000;
    let item = checks::app_log_item(
        &[
            p(now - checks::FRESH_PROBLEM_MS - 1, "old"),
            p(now - 1_000, "token=SECRET-TOKEN-VALUE"),
        ],
        now,
    );
    assert_eq!(
        (item.verdict, item.value.args[0].1.as_str()),
        (Some(Verdict::Warn), "1")
    );
    assert!(!item.details.join(" ").contains("SECRET-TOKEN-VALUE"));
    assert_eq!(checks::app_log_item(&[], now).verdict, Some(Verdict::Ok));
}

fn bulk(n: usize) -> Vec<CheckItem> {
    (0..n)
        .map(|i| {
            CheckItem::new(
                format!("info-{i}"),
                Category::App,
                "probes.diag.app.label",
                None,
                Msg::new("v"),
            )
        })
        .collect()
}

/// AT-00-005 / F-143: only warn / fail items become finding rows, redacted and bounded.
#[test]
fn findings_are_redacted_and_bounded() {
    let mut items = bulk(35);
    items.push(
        CheckItem::new(
            "dns-resolve",
            Category::Network,
            "probes.diag.dns.label",
            Some(Verdict::Warn),
            Msg::new("probes.diag.dns.failed"),
        )
        .details(vec!["token=PRIVATE-TOKEN".into()], 4),
    );
    items.push(
        CheckItem::new(
            "endpoint-google",
            Category::Internet,
            "probes.diag.endpoint.google",
            Some(Verdict::Fail),
            Msg::new("x"),
        )
        .details(
            vec!["vless://3f1c2b7e-0000-4000-8000-0123456789ab@example.test:443".into()],
            4,
        ),
    );
    items.push(
        CheckItem::new("proxy-current", Category::Proxy, "probes.diag.proxy.label", Some(Verdict::Fail), Msg::new("x"))
            .details(vec!["env:ALL_PROXY=socks5h://private-user:PRIVATE-PROXY-PASSWORD@proxy.example.test:1080".into()], 4),
    );
    let rows: Vec<Finding> = checks::findings(&items);
    assert_eq!(
        rows.iter().map(|f| f.check.as_str()).collect::<Vec<_>>(),
        ["dns-resolve", "endpoint-google", "proxy-current"]
    );
    let all = format!("{rows:?}");
    for secret in [
        "PRIVATE-TOKEN",
        "3f1c2b7e",
        "example.test",
        "private-user",
        "PRIVATE-PROXY-PASSWORD",
    ] {
        assert!(!all.contains(secret), "{secret} leaked: {all}");
    }
    let long = CheckItem::new(
        "x",
        Category::Logs,
        "probes.diag.appLog.label",
        Some(Verdict::Warn),
        Msg::new("v"),
    )
    .details(vec!["a".repeat(9_000)], 1);
    assert!(checks::findings(&[long])[0].details.len() < 4_500);
    // Healthy only: summary ok, no rows.
    let mut healthy = bulk(3);
    healthy.push(CheckItem::new(
        "adapters",
        Category::Network,
        "probes.diag.adapters.label",
        Some(Verdict::Ok),
        Msg::new("v"),
    ));
    assert_eq!(summarize(&healthy), Verdict::Ok);
    assert!(checks::findings(&healthy).is_empty());
}

#[test]
fn proxy_rows_never_carry_credentials() {
    assert_eq!(
        checks::strip_userinfo("socks5://user:pa:ss@127.0.0.1:1080"),
        "socks5://127.0.0.1:1080"
    );
    assert_eq!(
        checks::strip_userinfo("http://127.0.0.1:8080"),
        "http://127.0.0.1:8080"
    );
    let sp = crate::local_proxy::SystemProxy {
        wininet: None,
        winhttp: Some(None),
        env: vec![("ALL_PROXY".into(), "socks5://u:p@127.0.0.1:1080".into())],
    };
    let rows = checks::system_proxy_rows(&sp);
    assert_eq!(
        rows,
        [
            "env:ALL_PROXY=socks5://127.0.0.1:1080",
            "winhttp=direct",
            "wininet=unreadable"
        ]
    );
}

/// Direct VPN idle is informational, never a warning; a missing proxy next to another VPN's
/// tunnel is fine; listeners without a selection warn.
#[test]
fn proxy_item_states() {
    let v = |s: ProxyState| {
        let i = checks::proxy_item(&s, Vec::new());
        (i.verdict, i.value.key.into_owned())
    };
    assert_eq!(
        v(ProxyState::DirectVpn(false)),
        (None, "probes.diag.proxy.directVpnIdle".into())
    );
    assert_eq!(
        v(ProxyState::DirectVpn(true)),
        (None, "probes.diag.proxy.directVpnUnused".into())
    );
    assert_eq!(
        v(ProxyState::Missing {
            external_tunnel: true,
            listeners: 0
        })
        .0,
        None
    );
    assert_eq!(
        v(ProxyState::Missing {
            external_tunnel: false,
            listeners: 2
        }),
        (Some(Verdict::Warn), "probes.diag.proxy.notSelected".into())
    );
    assert_eq!(
        v(ProxyState::Missing {
            external_tunnel: false,
            listeners: 0
        })
        .0,
        Some(Verdict::Warn)
    );
    assert_eq!(
        v(ProxyState::Probed {
            addr: "127.0.0.1:7890 (http)".into(),
            open: false
        })
        .0,
        Some(Verdict::Fail)
    );
    assert_eq!(
        v(ProxyState::Probed {
            addr: "127.0.0.1:7890 (http)".into(),
            open: true
        })
        .0,
        Some(Verdict::Ok)
    );
}

/// `buildActiveProfileDiagnosticItems` vectors, over the facts the app takes from the profile.
#[test]
fn profile_item() {
    let none = checks::profile_item(None);
    assert_eq!(
        (none.id.as_str(), none.verdict, none.value.key.as_ref()),
        (
            "active-profile-capabilities",
            None,
            "probes.diag.profile.none"
        )
    );

    let naive = ProfileFacts {
        name: "Naive".into(),
        protocol: "naive".into(),
        stealth: "ech".into(),
        tls: true,
        ech: true,
        ..Default::default()
    };
    let item = checks::profile_item(Some(&naive));
    assert_eq!(item.verdict, None);
    assert!(item.details.contains(&"echConfigured=true".to_owned()));
    assert!(
        item.value
            .args
            .iter()
            .any(|(k, v)| k == "protocol" && v == "naive")
    );

    let hy2 = ProfileFacts {
        name: "HY2".into(),
        protocol: "hysteria2".into(),
        stealth: "tls".into(),
        tls: true,
        hy2: Some(Hy2Facts {
            obfs: None,
            server_ports: Some("8443:8450".into()),
            hop_interval: Some("30s".into()),
        }),
        warnings: vec![Msg::new("profiles.caps.udpOnTcpOnly")],
        ..Default::default()
    };
    let item = checks::profile_item(Some(&hy2));
    assert_eq!(item.verdict, Some(Verdict::Warn));
    for row in [
        "hy2Transport=QUIC/UDP",
        "hy2ServerPorts=8443:8450",
        "hy2HopInterval=30s",
    ] {
        assert!(item.details.contains(&row.to_owned()), "{row}");
    }
    assert_eq!(item.notes, vec![Msg::new("profiles.caps.udpOnTcpOnly")]);
}

fn svc(name: &str, present: bool, running: Option<bool>, start: ServiceStart) -> ServiceRow {
    ServiceRow {
        name: name.into(),
        present,
        running,
        start,
    }
}

/// B-SD-3: BFE / Dnscache down fails the critical Network group; a disabled helper only warns;
/// a stopped demand-start service is normal.
#[test]
fn service_items() {
    let ok = [
        svc("BFE", true, Some(true), ServiceStart::Auto),
        svc("Dnscache", true, Some(true), ServiceStart::Auto),
    ];
    let others = [
        svc(
            "WinHttpAutoProxySvc",
            true,
            Some(false),
            ServiceStart::Manual,
        ),
        svc("Dhcp", true, Some(true), ServiceStart::Auto),
    ];
    let [core, other] = checks::service_items(&ok, &others);
    assert_eq!(
        (core.category, core.verdict, other.verdict),
        (Category::Network, Some(Verdict::Ok), Some(Verdict::Ok))
    );
    let down = [
        svc("BFE", true, Some(false), ServiceStart::Disabled),
        svc("Dnscache", true, Some(true), ServiceStart::Auto),
    ];
    let disabled = [
        svc("Dhcp", true, Some(false), ServiceStart::Disabled),
        svc("iphlpsvc", false, Some(false), ServiceStart::Unknown),
    ];
    let [core, other] = checks::service_items(&down, &disabled);
    assert_eq!(
        (core.verdict, other.verdict, other.category),
        (Some(Verdict::Fail), Some(Verdict::Warn), Category::Windows)
    );
    assert_eq!(summarize(&[core]), Verdict::Fail);
    assert!(
        other
            .details
            .contains(&"iphlpsvc: missing, start=unknown".to_owned())
    );
    let unknown = [svc("BFE", true, None, ServiceStart::Auto)];
    assert_eq!(
        checks::service_items(&unknown, &[])[0].verdict,
        Some(Verdict::NotChecked)
    );
}

/// A and AAAA are independent: an AAAA-only answer is fine; no answer fails.
#[test]
fn dns_item() {
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let v6_only = checks::dns_item(&Ok(vec![ip("2606:2800:21f:cb07:6820:80da:af6b:8b2c")]));
    assert_eq!(v6_only.verdict, Some(Verdict::Ok));
    assert!(v6_only.details[0].starts_with("AAAA "));
    assert_eq!(
        checks::dns_item(&Ok(Vec::new())).verdict,
        Some(Verdict::Fail)
    );
    assert_eq!(
        checks::dns_item(&Err("timeout".into())).verdict,
        Some(Verdict::Fail)
    );
}

#[test]
fn binaries_item() {
    let item = checks::binaries_item(
        &[
            ("sing-box.exe", Some(82_074_624)),
            ("xray.exe", None),
            ("wintun.dll", Some(427_552)),
            ("libcronet.dll", Some(1)),
        ],
        &[("sing-box.exe", Some("1.14.4".into())), ("xray.exe", None)],
    );
    assert_eq!(item.verdict, Some(Verdict::Fail));
    assert!(
        item.value
            .args
            .iter()
            .any(|(k, v)| k == "files" && v == "xray.exe")
    );
    assert!(item.details.contains(&"sing-box.exe: 80151 KB".to_owned()));
    assert!(
        item.details
            .contains(&"sing-box.exe version: 1.14.4".to_owned())
    );
    assert!(
        item.details
            .contains(&"xray.exe version: not run".to_owned())
    );
}

/// Both versions come through the engine crate's pinned one-shot runs (bundled binaries; skips
/// quietly without them); a missing folder runs nothing.
#[tokio::test]
async fn binaries_read_versions_through_the_engine_crate() {
    let resources = crate::test_support::resources();
    let bundled = ["sing-box.exe", "xray.exe"]
        .iter()
        .all(|exe| resources.join(exe).is_file());
    if bundled {
        let item = crate::diagnostics::report::binaries(&resources).await;
        let row = |name: &str| {
            item.details
                .iter()
                .find_map(|d| d.strip_prefix(&format!("{name} version: ")))
                .map(str::to_owned)
        };
        assert!(
            row("sing-box.exe").is_some_and(|v| v.starts_with("1.14.")),
            "{:?}",
            item.details
        );
        assert!(
            row("xray.exe").is_some_and(|v| v.starts_with("26.")),
            "{:?}",
            item.details
        );
    }
    let none = std::env::temp_dir().join("vpnte-probes-no-resources");
    let item = crate::diagnostics::report::binaries(&none).await;
    assert_eq!(item.verdict, Some(Verdict::Fail));
    assert!(
        item.details
            .contains(&"sing-box.exe version: not run".to_owned())
    );
    assert!(
        item.details
            .contains(&"xray.exe version: not run".to_owned())
    );
}

/// curl output: any HTTP answer is reachable (5xx warns), a non-zero exit fails, a curl that
/// could not run is "not checked".
#[test]
fn endpoint_items() {
    let o = parse_write_out(Some(0), "204|142.250.74.4|0.153201|");
    assert_eq!(
        (o.http_code, o.remote_ip, o.time_s),
        (204, Some("142.250.74.4".parse().unwrap()), Some(0.153201))
    );
    let item = endpoint_item(
        "endpoint-google",
        "probes.diag.endpoint.google",
        "https://www.google.com/generate_204",
        Ok(o),
    );
    assert_eq!(
        (item.verdict, item.value.key.as_ref()),
        (Some(Verdict::Ok), "probes.diag.endpoint.http")
    );
    let busy = endpoint_item(
        "e",
        "probes.diag.endpoint.store",
        "u",
        Ok(parse_write_out(Some(0), "503|1.2.3.4|1.0|")),
    );
    assert_eq!(busy.verdict, Some(Verdict::Warn));
    let dns = parse_write_out(Some(6), "000||0.012|Could not resolve host: www.google.com");
    let item = endpoint_item("e", "probes.diag.endpoint.google", "u", Ok(dns));
    assert_eq!(
        (item.verdict, item.value.key.as_ref()),
        (Some(Verdict::Fail), "probes.diag.endpoint.noConnection")
    );
    assert!(
        item.details
            .iter()
            .any(|d| d.starts_with("curl exit=6 Could not resolve host"))
    );
    let missing = endpoint_item(
        "e",
        "probes.diag.endpoint.google",
        "u",
        Err("curl.exe not found".into()),
    );
    assert_eq!(missing.verdict, Some(Verdict::NotChecked));
}

/// The whole report on this machine (DNS, curl.exe, `sing-box version`, native reads). Read-only;
/// Direct VPN mode and no proxy, so no local proxy port is ever dialled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "touches the network and runs curl.exe / sing-box.exe"]
async fn real_report_runs() {
    use crate::diagnostics::{ReportInputs, TunnelFacts, system_report};
    let mut settings = vpnte_core::settings::Settings::default();
    settings.connection_mode = vpnte_core::settings::ConnectionMode::DirectVpn;
    let resources = crate::test_support::resources();
    let tmp = std::env::temp_dir().join("vpnte-probes-report");
    let dirs = vpnte_core::paths::DataDirs::new(tmp.clone(), tmp.join("legacy"), resources);
    let inputs = ReportInputs {
        app_version: "2.0.0".into(),
        dirs,
        settings,
        tunnel: TunnelFacts::default(),
        proxy: None,
        engine_log: Vec::new(),
        profile: None,
        routing: Vec::new(),
        extra: Vec::new(),
        own_pids: Vec::new(),
    };
    let started = std::time::Instant::now();
    let report = system_report(inputs, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();
    for i in &report.items {
        println!(
            "{:<28} {:<16} {} {:?}",
            i.id,
            format!("{:?}", i.verdict),
            i.value.key,
            i.value.args
        );
    }
    println!("summary {:?} in {:?}", report.summary, started.elapsed());
    assert!(report.items.len() >= 20);
}

/// Cancelled before it starts: `Cancelled`, nothing read or run.
#[tokio::test]
async fn cancelled_report_does_nothing() {
    use crate::diagnostics::{ReportInputs, TunnelFacts, system_report};
    let tmp = std::env::temp_dir().join("vpnte-probes-report-cancel");
    let inputs = ReportInputs {
        app_version: "2.0.0".into(),
        dirs: vpnte_core::paths::DataDirs::new(
            tmp.clone(),
            tmp.join("legacy"),
            tmp.join("resources"),
        ),
        settings: vpnte_core::settings::Settings::default(),
        tunnel: TunnelFacts::default(),
        proxy: None,
        engine_log: Vec::new(),
        profile: None,
        routing: Vec::new(),
        extra: Vec::new(),
        own_pids: Vec::new(),
    };
    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel();
    let err = system_report(inputs, cancel).await.unwrap_err();
    assert_eq!(err.kind, vpnte_base::ErrorKind::Cancelled);
}
