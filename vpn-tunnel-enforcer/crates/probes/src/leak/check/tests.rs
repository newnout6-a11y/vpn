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
    let bad: Vec<String> =
        vec!["ERROR outbound/vless[proxy-out]: connection to server failed: i/o timeout".into()];
    let item = engine_log_item(Some(&bad), true);
    assert_eq!(item.status, CheckStatus::Warn);
    assert_eq!(
        item.value,
        Msg::new("probes.leak.check.engineLog.errors").arg("count", 1)
    );
}

fn conn(rule: &str, host: Option<&str>, dst: Option<&str>, process: Option<&str>) -> ConnRecord {
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

const RU: &str = include_str!("../../../locales/probes-ip.ru.json");
const EN: &str = include_str!("../../../locales/probes-ip.en.json");

/// Both fragments are valid JSON under the crate's top-level key, with identical keys and
/// placeholders, and every key the code returns exists.
#[test]
fn locale_fragments_match_the_code() {
    use crate::test_support::{flatten, placeholders};
    let (ru, en) = (flatten(RU), flatten(EN));
    let ru_keys: Vec<&str> = ru.keys().map(String::as_str).collect();
    let en_keys: Vec<&str> = en.keys().map(String::as_str).collect();
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
        include_str!("../../ip_monitor/mod.rs"),
        include_str!("../../ip_monitor/monitor.rs"),
        include_str!("../probe.rs"),
        include_str!("../self_test.rs"),
        include_str!("mod.rs"),
        include_str!("items.rs"),
        include_str!("engine_log.rs"),
        include_str!("direct.rs"),
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
    let text = |key: &str| ru[key].clone();
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
