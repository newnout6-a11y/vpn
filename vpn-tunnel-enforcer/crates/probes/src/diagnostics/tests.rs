use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Loopback, Verdict};
use vpnte_base::{ErrorKind, Msg};

use super::routing::{
    EchoFn, EchoPath, RU_ECHOES, RoutingInputs, RoutingVerdict, TUNNEL_ECHOES,
    derive_routing_verdict, first_ipv4, parse_echo, routing_test_with,
};
use super::*;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn item(category: Category, verdict: Option<Verdict>) -> CheckItem {
    CheckItem::new("x", category, "probes.diag.x.label", verdict, Msg::new("v"))
}

/// AT-07-002: leak-check rows keep their verdict in the report (`NotChecked` is never `Ok`,
/// `Info` stays informational) and land in the Routing group.
#[test]
fn leak_items_become_routing_rows() {
    use crate::leak::{CheckItem as LeakItem, CheckStatus};
    let leak = |status| LeakItem {
        id: "dns",
        label: Msg::new("t.label"),
        status,
        value: Msg::new("t.value"),
        details: vec![Msg::new("t.detail")],
    };
    let row = CheckItem::from(&leak(CheckStatus::NotChecked));
    assert_eq!(row.id, "dns");
    assert_eq!(row.category, Category::Routing);
    assert_eq!(row.verdict, Some(Verdict::NotChecked));
    assert_eq!(
        (row.label, row.value),
        (Msg::new("t.label"), Msg::new("t.value"))
    );
    assert_eq!(row.notes, vec![Msg::new("t.detail")]);
    assert!(row.details.is_empty());
    assert_eq!(CheckItem::from(&leak(CheckStatus::Info)).verdict, None);
    assert_eq!(
        CheckItem::from(&leak(CheckStatus::Fail)).verdict,
        Some(Verdict::Fail)
    );
}

#[test]
fn summary_rule() {
    use Category::*;
    assert_eq!(
        summarize(&[item(Network, Some(Verdict::Ok)), item(App, None)]),
        Verdict::Ok
    );
    assert_eq!(
        summarize(&[
            item(Internet, Some(Verdict::Fail)),
            item(Logs, Some(Verdict::Warn))
        ]),
        Verdict::Fail
    );
    // A failure outside the critical groups degrades to a warning.
    assert_eq!(
        summarize(&[
            item(Windows, Some(Verdict::Fail)),
            item(Tun, Some(Verdict::Ok))
        ]),
        Verdict::Warn
    );
    assert_eq!(
        summarize(&[item(Profile, Some(Verdict::Warn))]),
        Verdict::Warn
    );
    // B-SD-2: not-checked rows count like information, never as "fine".
    assert_eq!(
        summarize(&[item(Routing, Some(Verdict::NotChecked)), item(App, None)]),
        Verdict::NotChecked
    );
    assert_eq!(
        summarize(&[
            item(Routing, Some(Verdict::NotChecked)),
            item(Proxy, Some(Verdict::Ok))
        ]),
        Verdict::Ok
    );
}

#[test]
fn rows_are_capped_with_a_tail() {
    let rows: Vec<String> = (0..20).map(|i| i.to_string()).collect();
    let capped = cap_rows(rows, 18);
    assert_eq!(capped.len(), 19);
    assert_eq!(capped.last().unwrap(), "... +2 more");
    assert_eq!(cap_rows(vec!["a".into()], 18), vec!["a".to_string()]);
}

/// AT-00-003/004/005 (routingSelfTest.test.ts): the verdict table.
#[test]
fn routing_verdicts() {
    let v = |t, vpn: Option<&str>, direct: Option<&str>, smart, ru: Option<&str>| {
        let (verdict, msg, split, ru_direct) =
            derive_routing_verdict(t, vpn.map(ip), direct.map(ip), smart, ru.map(ip));
        (verdict, msg.key.into_owned(), split, ru_direct)
    };
    assert_eq!(
        v(false, None, None, false, None).0,
        RoutingVerdict::TunnelOff
    );
    assert_eq!(
        v(true, Some("1.2.3.4"), None, false, None).0,
        RoutingVerdict::Inconclusive
    );
    assert_eq!(
        v(true, Some("5.5.5.5"), Some("5.5.5.5"), false, None),
        (
            RoutingVerdict::Leak,
            "probes.routing.leak".into(),
            false,
            None
        )
    );
    assert_eq!(
        v(true, Some("9.9.9.9"), Some("5.5.5.5"), false, None),
        (RoutingVerdict::Ok, "probes.routing.ok".into(), true, None)
    );
    assert_eq!(
        v(
            true,
            Some("9.9.9.9"),
            Some("5.5.5.5"),
            true,
            Some("5.5.5.5")
        ),
        (
            RoutingVerdict::Ok,
            "probes.routing.smartOk".into(),
            true,
            Some(true)
        )
    );
    assert_eq!(
        v(
            true,
            Some("9.9.9.9"),
            Some("5.5.5.5"),
            true,
            Some("9.9.9.9")
        ),
        (
            RoutingVerdict::Partial,
            "probes.routing.ruViaVpn".into(),
            true,
            Some(false)
        )
    );
    assert_eq!(
        v(true, Some("9.9.9.9"), Some("5.5.5.5"), true, None),
        (
            RoutingVerdict::Partial,
            "probes.routing.smartUnverified".into(),
            true,
            None
        )
    );
    let (_, msg, _, _) = derive_routing_verdict(
        true,
        Some(ip("9.9.9.9")),
        Some(ip("5.5.5.5")),
        true,
        Some(ip("9.9.9.9")),
    );
    assert_eq!(
        msg.args
            .iter()
            .map(|(k, v)| (k.as_ref(), v.as_str()))
            .collect::<Vec<_>>(),
        vec![("vpn", "9.9.9.9"), ("direct", "5.5.5.5"), ("ru", "9.9.9.9")]
    );
}

/// Echo bodies: strict for egress, octet-checked first quad for the RU page (junk skipped).
#[test]
fn echo_parsing() {
    assert_eq!(parse_echo("203.0.113.9\n"), Some(ip("203.0.113.9")));
    assert_eq!(parse_echo("\"203.0.113.9\""), Some(ip("203.0.113.9")));
    assert_eq!(
        parse_echo("fl=1\nh=1.1.1.1\nip=2001:db8::5\nts=1"),
        Some(ip("2001:db8::5"))
    );
    assert_eq!(parse_echo("<html>Your IP 203.0.113.9</html>"), None);
    assert_eq!(
        first_ipv4("Ваш IP: 5.5.5.5").map(IpAddr::V4),
        Some(ip("5.5.5.5"))
    );
    let page = "<script>var layout=\"384.518.844.978\";</script>\nIP address: 62.118.134.108";
    assert_eq!(first_ipv4(page).map(IpAddr::V4), Some(ip("62.118.134.108")));
    assert_eq!(
        first_ipv4("build 1.2.3.4.5, mask 10.0.0.256, id a1.2.3.4"),
        None
    );
    assert!(
        RU_ECHOES
            .iter()
            .chain(TUNNEL_ECHOES.iter())
            .all(|u| !u.contains("2ip.ru") && u.starts_with("https://"))
    );
}

/// A fake echo answering per path and counting calls.
fn echo(
    tunnel: &'static str,
    direct: &'static str,
    ru: &'static str,
) -> (EchoFn, Arc<Mutex<Vec<String>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let log = calls.clone();
    let f: EchoFn = Arc::new(move |path, url| {
        log.lock().push(url.to_owned());
        let body = match path {
            EchoPath::Direct => direct,
            EchoPath::Tunnel if RU_ECHOES.contains(&url) => ru,
            EchoPath::Tunnel => tunnel,
        };
        Box::pin(async move { (!body.is_empty()).then(|| body.to_owned()) })
    });
    (f, calls)
}

fn inputs(smart_ru: bool, disable_geo_lookup: bool, direct: bool) -> RoutingInputs {
    RoutingInputs {
        tunnel_active: true,
        direct: direct.then_some(Loopback {
            port: 1,
            creds: None,
        }),
        tun_source: None,
        smart_ru,
        disable_geo_lookup,
    }
}

#[tokio::test]
async fn routing_test_runs_the_paths() {
    let (f, calls) = echo("9.9.9.9", "fl=1\nip=5.5.5.5", "\"5.5.5.5\"");
    let r = routing_test_with(&inputs(true, false, true), &f, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        (r.verdict, r.vpn_ip, r.direct_ip),
        (RoutingVerdict::Ok, Some(ip("9.9.9.9")), Some(ip("5.5.5.5")))
    );
    assert_eq!(r.smart_ru.ru_goes_direct, Some(true));
    assert_eq!(calls.lock().len(), 3);

    // Smart RU with geo lookups off: one call, the VPN echo; RU unknown.
    let (f, calls) = echo("9.9.9.9", "", "");
    let r = routing_test_with(&inputs(true, true, false), &f, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!((r.smart_ru.enabled, r.smart_ru.ru_host_ip), (true, None));
    assert_eq!(*calls.lock(), vec![TUNNEL_ECHOES[0].to_string()]);
    assert_eq!(r.verdict, RoutingVerdict::Inconclusive);
}

#[tokio::test]
async fn routing_test_tunnel_off_and_cancel() {
    let (f, calls) = echo("9.9.9.9", "5.5.5.5", "");
    let mut off = inputs(false, false, true);
    off.tunnel_active = false;
    let r = routing_test_with(&off, &f, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(r.verdict, RoutingVerdict::TunnelOff);
    assert!(calls.lock().is_empty());

    let cancel = CancellationToken::new();
    cancel.cancel();
    let err = routing_test_with(&inputs(false, false, true), &f, cancel)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled);
    assert!(calls.lock().is_empty());
}

/// Client listeners for the report: loopback / wildcard only, by process name or client port,
/// unique by (process, port), the app's own processes left out.
mod listeners {
    use crate::diagnostics::proxy_listeners;

    #[test]
    fn listener_list_for_display() {
        use crate::local_proxy::ListenerRow;
        let row = |a: &str, pid, p: &str| ListenerRow {
            local: a.parse().unwrap(),
            pid,
            process: Some(p.into()),
        };
        let rows = vec![
            row("127.0.0.1:10808", 10, "xray.exe"),
            row("[::1]:10808", 10, "xray.exe"),
            row("127.0.0.1:7890", 11, "node.exe"),
            row("127.0.0.1:3000", 12, "node.exe"),
            row("0.0.0.0:17995", 13, "unknown.exe"),
            row("192.168.1.2:1080", 14, "clash.exe"),
            row("127.0.0.1:2080", 99, "sing-box.exe"),
        ];
        let got: Vec<(String, u16)> = proxy_listeners(&rows, &[99])
            .into_iter()
            .map(|l| (l.process, l.addr.port()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("xray.exe".into(), 10808),
                ("node.exe".into(), 7890),
                ("unknown.exe".into(), 17995)
            ]
        );
    }
}

mod locales;
mod report_items;
mod snapshots;
