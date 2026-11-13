//! «VPN только для выбранных приложений» (re-check item 16): the scope rule's place against
//! owner answer 4, what each app's connection meets, and the real config through sing-box.
use std::net::Ipv4Addr;
use std::path::Path;

use serde_json::{Value, json};

use super::*;
use crate::routing::domain::DomainPattern;
use crate::routing::process::AppPath;

/// The network's own resolver (Yandex), read at the start.
const PHYS: &[Ipv4Addr] = &[Ipv4Addr::new(77, 88, 8, 7)];
const ON: SmartRu = SmartRu {
    enabled: true,
    maps_direct: false,
};

fn rules() -> Vec<DomainRule> {
    let rule = |p: &str, a| DomainRule::new(DomainPattern::parse(p).unwrap(), a);
    vec![
        rule("ads.example", DomainAction::Block),
        rule("*.example.org", DomainAction::Vpn),
        rule("corp.example", DomainAction::Direct),
    ]
}

fn split() -> ResolvedSplit {
    ResolvedSplit {
        direct: vec!["games".into()],
        vpn: vec!["browser".into()],
        inactive: Vec::new(),
    }
}

fn inputs<'a>(
    dir: Option<&'a Path>,
    rules: &'a [DomainRule],
    split: &'a ResolvedSplit,
) -> RoutingInputs<'a> {
    RoutingInputs {
        smart: ON,
        rule_set_dir: dir,
        domain_rules: rules,
        split,
        engine_paths: &[],
        third_party_cores: false,
        dns: None,
        physical_dns: PHYS,
        endpoint_is_hostname: false,
    }
}

fn strs(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// sing-box's first match over process then domain rules for `process` (plain names stand
/// for the regexes) opening `host`: `ru_ip` = the address is in `geoip-ru`; `gosuslugi.ru` is
/// on the gov list, `rutracker.org` on the blocked one. Returns the outbound or `reject`.
fn walk(f: &RoutingFragments, process: &str, host: &str, ru_ip: bool) -> String {
    let rules = f.parts.process_rules.iter().chain(&f.parts.domain_rules);
    for r in rules {
        let hit = if let Some(list) = r.get("process_path_regex") {
            let named = strs(r, "process_path_regex").iter().any(|p| p == process);
            assert!(list.is_array());
            named != r.get("invert").and_then(Value::as_bool).unwrap_or(false)
        } else if r.get("network").is_some() {
            true
        } else {
            let sets = strs(r, "rule_set");
            strs(r, "domain").iter().any(|d| d == host)
                || strs(r, "domain_suffix")
                    .iter()
                    .any(|s| host.ends_with(s.as_str()))
                || sets.iter().any(|s| {
                    (s == smart_ru::GOV_RU && host == "gosuslugi.ru")
                        || (s == GEOIP_RU && ru_ip)
                        || (s == smart_ru::RU_BLOCKED_SITES && host == "rutracker.org")
                })
        };
        if hit {
            let out = r.get("outbound").or_else(|| r.get("action"));
            return out.and_then(Value::as_str).unwrap_or("?").to_owned();
        }
    }
    PROXY_OUT.to_owned()
}

fn position(rules: &[Value], pred: impl Fn(&Value) -> bool) -> usize {
    rules.iter().position(pred).expect("rule present")
}

/// Answer 4: the user's own rules (block, VPN, direct) come first for every app, then the
/// blocked-in-Russia step, then the scope; Smart RU's pins, gov and RU rules see the scope only.
#[test]
fn the_scope_sits_after_the_users_rules_and_the_blocked_step() {
    let (rules, split) = (rules(), split());
    let own = vec!["own".to_owned()];
    let i = inputs(Some(Path::new(r"C:\dir")), &rules, &split);
    let f = build_scoped(&i, Scope::OnlyListed { own: &own });
    let d = &f.parts.domain_rules;
    let scope = position(d, |r| r.get("invert").is_some());
    assert_eq!(
        d[scope],
        json!({ "process_path_regex": ["browser", "own"], "invert": true, "outbound": DIRECT_OUT })
    );
    let user_direct = position(d, |r| strs(r, "domain") == ["corp.example"]);
    let blocked = position(d, |r| {
        strs(r, "rule_set").contains(&smart_ru::RU_BLOCKED_SITES.into())
    });
    let gov = position(d, |r| strs(r, "rule_set") == [GOV_RU]);
    let geoip = position(d, |r| strs(r, "rule_set") == [GEOIP_RU]);
    assert!(user_direct < blocked && blocked < scope, "{d:#?}");
    assert!(scope < gov && gov < geoip, "{d:#?}");
    // No P4: the listed apps meet the user's rules and Smart RU; «Мимо VPN» keeps its rule.
    let p = &f.parts.process_rules;
    assert_eq!(
        p,
        &vec![json!({ "process_path_regex": ["games"], "outbound": DIRECT_OUT })]
    );
    // DNS is the same as for every app: the queries come from the DNS Client service.
    assert_eq!(f.parts.dns_rules, build(&i).parts.dns_rules);
    assert_eq!(f.parts.dns_servers, build(&i).parts.dns_servers);
}

/// What each kind of app meets in each scope (the module's order, walked like sing-box).
#[test]
fn every_app_meets_the_users_rules_and_only_listed_ones_the_tunnel() {
    let (rules, split) = (rules(), split());
    let own = vec!["own".to_owned()];
    let i = inputs(Some(Path::new(r"C:\dir")), &rules, &split);
    let only = build_scoped(&i, Scope::OnlyListed { own: &own });
    let all = build_scoped(&i, Scope::All);
    assert_eq!(all, build(&i));
    let cases = [
        // (process, host, ru_ip, OnlyListed, All)
        ("player", "video.example.com", false, DIRECT_OUT, PROXY_OUT),
        ("player", "ads.example", false, "reject", "reject"),
        ("player", "www.example.org", false, PROXY_OUT, PROXY_OUT),
        ("player", "corp.example", false, DIRECT_OUT, DIRECT_OUT),
        ("player", "rutracker.org", true, PROXY_OUT, PROXY_OUT),
        ("player", "gosuslugi.ru", true, DIRECT_OUT, DIRECT_OUT),
        ("browser", "video.example.com", false, PROXY_OUT, PROXY_OUT),
        ("browser", "corp.example", false, DIRECT_OUT, PROXY_OUT),
        ("browser", "gosuslugi.ru", true, DIRECT_OUT, PROXY_OUT),
        ("browser", "shop.ru", true, DIRECT_OUT, PROXY_OUT),
        ("browser", "ads.example", false, "reject", PROXY_OUT),
        ("own", "video.example.com", false, PROXY_OUT, PROXY_OUT),
        ("own", "shop.ru", true, DIRECT_OUT, DIRECT_OUT),
        ("games", "www.example.org", false, DIRECT_OUT, DIRECT_OUT),
    ];
    for (process, host, ru_ip, want_only, want_all) in cases {
        assert_eq!(
            walk(&only, process, host, ru_ip),
            want_only,
            "only: {process} {host}"
        );
        assert_eq!(
            walk(&all, process, host, ru_ip),
            want_all,
            "all: {process} {host}"
        );
    }
}

/// Nothing in scope (no listed app, the own exe unknown): every connection leaves directly. The
/// list keeps one spelling per regex (they are case-insensitive).
#[test]
fn the_scope_list_is_never_empty_and_has_no_duplicates() {
    let rules = rules();
    let none = ResolvedSplit::default();
    let f = build_scoped(&inputs(None, &rules, &none), Scope::OnlyListed { own: &[] });
    let last = f.parts.domain_rules.last().expect("the scope rule");
    assert_eq!(
        last,
        &json!({ "network": ["tcp", "udp"], "outbound": DIRECT_OUT })
    );
    assert_eq!(walk(&f, "player", "corp.example", false), DIRECT_OUT);
    assert_eq!(walk(&f, "player", "www.example.org", false), PROXY_OUT);
    let split = ResolvedSplit {
        vpn: vec![r"(?i)^C:\A\b\.exe$".into()],
        ..ResolvedSplit::default()
    };
    let own = vec![r"(?i)^c:\a\B\.EXE$".into(), "own".into()];
    let f = build_scoped(
        &inputs(None, &rules, &split),
        Scope::OnlyListed { own: &own },
    );
    let last = f.parts.domain_rules.last().expect("the scope rule");
    assert_eq!(
        strs(last, "process_path_regex"),
        [r"(?i)^C:\A\b\.exe$", "own"]
    );
}

/// An app whose file is gone gets no rule: outside the scope its traffic leaves directly, and
/// the warning says so (inside All it stays in the tunnel, as before).
#[test]
fn an_inactive_app_is_reported_as_direct_outside_the_scope() {
    let rules = rules();
    let split = ResolvedSplit {
        inactive: vec![InactiveApp {
            name: "Old".into(),
            path: r"C:\Old\old.exe".into(),
            reason: InactiveReason::FileMissing,
        }],
        ..ResolvedSplit::default()
    };
    let i = inputs(None, &rules, &split);
    let only = build_scoped(&i, Scope::OnlyListed { own: &[] });
    let keys = |f: &RoutingFragments| -> Vec<String> {
        let apps = f
            .warnings
            .iter()
            .filter(|w| !matches!(w, RoutingWarning::SmartRuDisabled));
        apps.map(|w| w.msg().key.into_owned()).collect()
    };
    assert_eq!(keys(&only), ["engine.routing.warn.appMissingDirect"]);
    assert_eq!(keys(&build(&i)), ["engine.routing.warn.appMissing"]);
}

/// The whole config through `sing-box check` for both captures (TUN, the no-admin loopback
/// proxy), both scopes and both upstream kinds (a local SOCKS proxy; Xray chained behind
/// sing-box, which keeps the routing): the scope rule is in `route.rules`, `final` stays
/// `proxy-out` and the DNS final `dns-remote`. Skipped quietly without the engine.
#[test]
fn both_captures_and_scopes_pass_sing_box_check() {
    if crate::test_support::singbox_exe().is_none() {
        return;
    }
    let dir = crate::test_support::resources();
    let rules = rules();
    let app = |p: &str| AppPath::parse(p).unwrap().regex();
    let split = ResolvedSplit {
        direct: vec![app(r"C:\Games\game.exe")],
        vpn: vec![app(r"C:\Program Files\Browser\browser.exe")],
        inactive: Vec::new(),
    };
    let own = vec![app(
        r"C:\Program Files\VPN Tunnel Enforcer\vpn-tunnel-enforcer.exe",
    )];
    let i = inputs(Some(&dir), &rules, &split);
    for scope in [Scope::All, Scope::OnlyListed { own: &own }] {
        let f = build_scoped(&i, scope);
        for tun in [true, false] {
            for slots in [false, true] {
                let config = config(&f, tun, slots);
                let what = format!("{scope:?} tun={tun} slots={slots}");
                assert_eq!(
                    crate::test_support::singbox_check(&config),
                    Ok(true),
                    "{what}"
                );
                let route = &config["route"];
                assert_eq!(route["final"], PROXY_OUT, "{what}");
                assert_eq!(config["dns"]["final"], DNS_REMOTE, "{what}");
                let scoped = route["rules"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r.get("invert") == Some(&json!(true)));
                assert_eq!(scoped, scope != Scope::All, "{what}");
            }
        }
    }
}

/// The generated config around `f`: TUN or the loopback proxy, a local SOCKS upstream or the
/// Xray slots (with their `dns-bootstrap-in`).
fn config(f: &RoutingFragments, tun: bool, slots: bool) -> Value {
    use crate::singbox_config::{
        Capture, ConfigInputs, Listeners, TunParams, TunStack, UdpPolicy, Upstream,
    };
    use crate::slot::{Slot, SlotEndpoint};
    use vpnte_base::types::{Creds, Loopback, ProxyKind};
    let creds = |user: &str| Creds {
        user: user.into(),
        pass: format!("{user}-SYNTHETIC"),
    };
    let upstream = if slots {
        let ep = |port, user| SlotEndpoint::new(port, creds(user)).unwrap();
        Upstream::XraySlots {
            slots: [ep(25551, "slot-a"), ep(25552, "slot-b")],
            active: Slot::A,
            udp: UdpPolicy {
                udp: true,
                block_quic: true,
            },
        }
    } else {
        Upstream::LocalProxy {
            addr: vpnte_core::net::HostPort::parse("127.0.0.1:1080").unwrap(),
            kind: ProxyKind::Socks5,
            creds: None,
        }
    };
    let capture = if tun {
        Capture::Tun(TunParams {
            alias: "Ethernet 5".into(),
            mtu: 1500,
            ipv6: false,
            dns_hijack: true,
            stack: TunStack::Mixed,
        })
    } else {
        Capture::Proxy { port: 25557 }
    };
    crate::singbox_config::build(&ConfigInputs {
        upstream,
        capture,
        listeners: Listeners {
            clash_port: 25553,
            clash_secret: "0123456789abcdef0123456789abcdef".into(),
            direct: Loopback {
                port: 25554,
                creds: Some(creds("direct-user")),
            },
            probe: None,
            dns_bootstrap: slots.then_some(25556),
        },
        routing: f.parts.clone(),
        phys_dns: vec![Ipv4Addr::new(77, 88, 8, 7)],
    })
    .unwrap()
}
