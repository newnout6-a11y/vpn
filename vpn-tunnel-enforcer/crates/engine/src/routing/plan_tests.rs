use std::net::Ipv4Addr;
use std::path::Path;

use serde_json::{Value, json};

use super::*;
use crate::routing::domain::DomainPattern;
use crate::routing::process::AppPath;
use crate::routing::smart_ru::{GOOGLE_AND_GEMINI_PINNED_SUFFIXES, KIMI_MOONSHOT_DOMAIN_SUFFIXES};

const DIR: &str = r"C:\runtime\dir";
const ON: SmartRu = SmartRu {
    enabled: true,
    maps_direct: false,
};
const ON_MAPS: SmartRu = SmartRu {
    enabled: true,
    maps_direct: true,
};

fn rule(pattern: &str, action: DomainAction) -> DomainRule {
    DomainRule::new(DomainPattern::parse(pattern).unwrap(), action)
}

/// Runs `build` with everything empty except the given parts.
fn frag(
    smart: SmartRu,
    dir: Option<&str>,
    rules: &[DomainRule],
    phys: &[Ipv4Addr],
) -> RoutingFragments {
    let split = ResolvedSplit::default();
    build(&RoutingInputs {
        smart,
        rule_set_dir: dir.map(Path::new),
        domain_rules: rules,
        split: &split,
        engine_paths: &[],
        third_party_cores: false,
        dns: None,
        physical_dns: phys,
        endpoint_is_hostname: false,
    })
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

/// Walks rules like sing-box's first match: `gov` = members of the gov geosite, `ru_ip` =
/// the host resolves into `geoip-ru`. Returns the outbound / server, or `reject`.
fn first<'a>(
    rules: &'a [Value],
    host: &str,
    gov: &[&str],
    ru_ip: bool,
    key: &str,
) -> Option<&'a str> {
    rules.iter().find_map(|r| {
        let sets = strs(r, "rule_set");
        let hit = if sets.is_empty() {
            strs(r, "domain").iter().any(|d| d == host)
                || strs(r, "domain_suffix")
                    .iter()
                    .any(|s| host.ends_with(s.as_str()))
                || strs(r, "domain_keyword")
                    .iter()
                    .any(|k| host.contains(k.as_str()))
        } else {
            sets.iter().any(|s| {
                (s == "geosite-category-gov-ru" && gov.contains(&host))
                    || (s == "geoip-ru" && ru_ip)
            })
        };
        hit.then(|| {
            r.get(key)
                .or_else(|| r.get("action"))
                .and_then(Value::as_str)
                .unwrap_or("?")
        })
    })
}

fn route<'a>(f: &'a RoutingFragments, host: &str, ru_ip: bool) -> &'a str {
    first(
        &f.parts.domain_rules,
        host,
        &["gosuslugi.ru"],
        ru_ip,
        "outbound",
    )
    .unwrap_or("proxy-out")
}

fn dns<'a>(f: &'a RoutingFragments, host: &str) -> &'a str {
    first(&f.parts.dns_rules, host, &["gosuslugi.ru"], false, "server").unwrap_or("dns-remote")
}

fn index_of(rules: &[Value], pred: impl Fn(&Value) -> bool) -> usize {
    rules.iter().position(pred).expect("rule present")
}

/// smartRouteRules / smartRouteDnsRules / smartRouteRuleSets: nothing when Smart RU is off.
#[test]
fn smart_ru_off_emits_nothing() {
    let f = frag(SmartRu::default(), Some(DIR), &[], &[]);
    assert!(
        f.parts.domain_rules.is_empty()
            && f.parts.dns_rules.is_empty()
            && f.parts.rule_sets.is_empty()
    );
    assert_eq!(
        f.parts.dns_servers.len(),
        1,
        "only dns-remote, no dns-direct"
    );
    assert_eq!(f.parts.dns_servers[0]["tag"], "dns-remote");
    assert!(f.warnings.is_empty());
}

/// §7.6: Smart RU on without rule sets is forced off, visibly (B-SR-2).
#[test]
fn smart_ru_without_rule_sets_is_disabled_with_warning() {
    let f = frag(ON, None, &[], &[]);
    assert!(
        f.parts.domain_rules.is_empty()
            && f.parts.dns_rules.is_empty()
            && f.parts.rule_sets.is_empty()
    );
    assert_eq!(f.warnings, vec![RoutingWarning::SmartRuDisabled]);
    assert_eq!(f.parts.dns_servers.len(), 1);
}

/// smartRouteRules vectors: IP checkers first (apex too), Google before the gov / geoip sets,
/// maps direct only when asked, Kimi direct, rule sets always as arrays (B-SR-7).
#[test]
fn smart_ru_route_rules() {
    let f = frag(ON, Some(DIR), &[], &[]);
    let r = &f.parts.domain_rules;
    assert_eq!(r[0]["outbound"], "proxy-out");
    assert!(strs(&r[0], "domain_suffix").contains(&".2ip.ru".to_owned()));
    assert!(strs(&r[0], "domain").contains(&"2ip.ru".to_owned()));
    assert!(strs(&r[0], "domain").contains(&"ipify.org".to_owned()));
    let gov = index_of(r, |x| x["rule_set"] == json!(["geosite-category-gov-ru"]));
    let geoip = index_of(r, |x| x["rule_set"] == json!(["geoip-ru"]));
    assert_eq!(r[gov]["outbound"], "direct-out");
    assert_eq!(r[geoip]["outbound"], "direct-out");
    let google = index_of(r, |x| {
        strs(x, "domain_suffix").contains(&".gemini.google.com".into())
    });
    assert_eq!(r[google]["outbound"], "proxy-out");
    assert!(google < gov && gov < geoip && 0 < google);
    for s in GOOGLE_AND_GEMINI_PINNED_SUFFIXES {
        assert!(
            strs(&r[google], "domain_suffix").contains(&(*s).to_owned()),
            "{s}"
        );
    }
    let kimi = index_of(r, |x| {
        strs(x, "domain_suffix").contains(&".kimi.com".into())
    });
    assert_eq!(r[kimi]["outbound"], "direct-out");
    assert!(kimi > geoip);
    for s in KIMI_MOONSHOT_DOMAIN_SUFFIXES {
        assert!(
            strs(&r[kimi], "domain_suffix").contains(&(*s).to_owned()),
            "{s}"
        );
    }
    let maps_to = |f: &RoutingFragments| {
        let i = index_of(&f.parts.domain_rules, |x| {
            strs(x, "domain_suffix").contains(&".2gis.com".into())
        });
        f.parts.domain_rules[i]["outbound"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(maps_to(&f), "proxy-out");
    assert!(!r.iter().any(|x| {
        x["outbound"] == "direct-out"
            && strs(x, "domain_suffix")
                .iter()
                .any(|s| s.contains("2gis") || s.contains("yandex"))
    }));
    let on_maps = frag(ON_MAPS, Some(DIR), &[], &[]);
    assert_eq!(maps_to(&on_maps), "direct-out");
    let first_direct = on_maps
        .parts
        .domain_rules
        .iter()
        .find(|x| x["outbound"] == "direct-out" && x.get("domain_suffix").is_some())
        .unwrap();
    assert!(
        strs(first_direct, "domain_suffix")
            .iter()
            .any(|s| s.contains("yandex"))
    );
    let tags: Vec<&str> = f
        .parts
        .rule_sets
        .iter()
        .map(|s| s["tag"].as_str().unwrap())
        .collect();
    assert_eq!(tags, ["geoip-ru", "geosite-category-gov-ru"]);
    assert_eq!(f.parts.rule_sets[0]["path"], "C:/runtime/dir/geoip-ru.srs");
}

/// smartRouteDnsRules vectors + the `dns-direct` server (tunControllerConfig.test.ts:763).
#[test]
fn smart_ru_dns_rules_and_direct_server() {
    let phys = [Ipv4Addr::new(77, 88, 8, 7), Ipv4Addr::new(77, 88, 8, 3)];
    let f = frag(ON, Some(DIR), &[], &phys);
    let d = &f.parts.dns_rules;
    assert_eq!(d[0]["server"], "dns-remote");
    assert!(strs(&d[0], "domain_suffix").contains(&".2ip.ru".into()));
    let gemini = index_of(d, |x| {
        strs(x, "domain_suffix").contains(&".gemini.google.com".into())
    });
    assert_eq!(d[gemini]["server"], "dns-remote");
    let kimi = index_of(d, |x| {
        strs(x, "domain_suffix").contains(&".kimi.com".into())
    });
    assert_eq!(d[kimi]["server"], "dns-direct");
    let gov = index_of(d, |x| x["rule_set"] == json!(["geosite-category-gov-ru"]));
    assert_eq!(d[gov]["server"], "dns-direct");
    let ru = index_of(d, |x| {
        strs(x, "domain_suffix").contains(&".xn--p1ai".into())
    });
    for s in [".ru", ".su", ".xn--p1ai", ".vk.com", ".yandex.net"] {
        assert!(strs(&d[ru], "domain_suffix").contains(&s.into()), "{s}");
    }
    assert_eq!(d[ru]["server"], "dns-direct");
    let maps = index_of(d, |x| {
        strs(x, "domain_suffix").contains(&".2gis.com".into())
    });
    assert_eq!(d[maps]["server"], "dns-remote");
    assert!(
        maps < gov,
        "maps pin before the gov set in DNS too (B-SR-3)"
    );
    let on_maps = frag(ON_MAPS, Some(DIR), &[], &phys);
    let maps = index_of(&on_maps.parts.dns_rules, |x| {
        strs(x, "domain_suffix").contains(&".2gis.com".into())
    });
    assert_eq!(on_maps.parts.dns_rules[maps]["server"], "dns-direct");
    assert_eq!(
        f.parts.dns_servers[1],
        json!({ "type": "udp", "tag": "dns-direct", "server": "77.88.8.7" })
    );
    let none = frag(ON, Some(DIR), &[], &[]);
    assert_eq!(
        none.parts.dns_servers[1],
        json!({ "type": "dhcp", "tag": "dns-direct" })
    );
    let tun_only = frag(
        ON,
        Some(DIR),
        &[],
        &[Ipv4Addr::new(192, 168, 250, 254), Ipv4Addr::LOCALHOST],
    );
    assert_eq!(tun_only.parts.dns_servers[1]["type"], "dhcp");
}

/// Owner answer 4 (12.11.2026): block → user direct / VPN in user order → pins → gov (+maps) →
/// geoip-ru + Kimi; DNS mirrors it.
#[test]
fn owner_rule_order() {
    let rules = [
        rule("ads.example", DomainAction::Block),
        rule("cdn.example.com", DomainAction::Vpn),
        rule("example.com", DomainAction::Direct),
        rule("gosuslugi.ru", DomainAction::Vpn),
    ];
    let f = frag(ON, Some(DIR), &rules, &[]);
    let r = &f.parts.domain_rules;
    assert_eq!(r.len(), 11);
    assert_eq!(r[0]["action"], "reject");
    assert_eq!(strs(&r[0], "domain"), ["ads.example"]);
    assert_eq!(
        (strs(&r[1], "domain"), r[1]["outbound"].as_str()),
        (vec!["cdn.example.com".to_owned()], Some("proxy-out"))
    );
    assert_eq!(
        (strs(&r[2], "domain"), r[2]["outbound"].as_str()),
        (vec!["example.com".to_owned()], Some("direct-out"))
    );
    assert_eq!(
        (strs(&r[3], "domain"), r[3]["outbound"].as_str()),
        (vec!["gosuslugi.ru".to_owned()], Some("proxy-out"))
    );
    assert!(strs(&r[4], "domain").contains(&"2ip.ru".into()));
    assert!(strs(&r[5], "domain_suffix").contains(&".google.com".into()));
    assert!(strs(&r[6], "domain_suffix").contains(&".youtube.com".into()));
    assert_eq!(
        (
            r[7]["outbound"].as_str(),
            strs(&r[7], "domain_suffix")[2].as_str()
        ),
        (Some("proxy-out"), ".2gis.com")
    );
    assert_eq!(r[8]["rule_set"], json!(["geosite-category-gov-ru"]));
    assert_eq!(r[9]["rule_set"], json!(["geoip-ru"]));
    assert!(strs(&r[10], "domain_suffix").contains(&".moonshot.cn".into()));
    assert_eq!(route(&f, "cdn.example.com", false), "proxy-out");
    assert_eq!(route(&f, "www.example.com", false), "direct-out");
    assert_eq!(route(&f, "ads.example", false), "reject");
    assert_eq!(dns(&f, "cdn.example.com"), "dns-remote");
    assert_eq!(dns(&f, "www.example.com"), "dns-direct");
    assert_eq!(dns(&f, "ads.example"), "reject");
    assert_eq!(
        f.parts.dns_rules[0],
        json!({ "domain": ["ads.example"], "domain_suffix": [".ads.example"],
        "action": "reject", "method": "default", "no_drop": true })
    );
    let user_dns: Vec<&str> = f.parts.dns_rules[1..4]
        .iter()
        .map(|d| d["server"].as_str().unwrap())
        .collect();
    assert_eq!(user_dns, ["dns-remote", "dns-direct", "dns-remote"]);
}

/// Owner answer 4: a user VPN rule beats Smart RU's direct choice (gov set, RU TLD + `geoip-ru`)
/// for the route and its DNS; removing the rule brings Smart RU's choice back.
#[test]
fn user_vpn_rule_beats_smart_ru_direct() {
    let without = frag(ON, Some(DIR), &[], &[]);
    assert_eq!(route(&without, "gosuslugi.ru", true), "direct-out");
    assert_eq!(dns(&without, "gosuslugi.ru"), "dns-direct");
    assert_eq!(route(&without, "yandex.ru", true), "direct-out");
    assert_eq!(dns(&without, "yandex.ru"), "dns-direct");
    let rules = [
        rule("gosuslugi.ru", DomainAction::Vpn),
        rule("yandex.ru", DomainAction::Vpn),
    ];
    let with = frag(ON, Some(DIR), &rules, &[]);
    for host in ["gosuslugi.ru", "yandex.ru", "music.yandex.ru"] {
        assert_eq!(route(&with, host, true), "proxy-out", "{host}");
        assert_eq!(dns(&with, host), "dns-remote", "{host}");
    }
    assert_eq!(route(&with, "bar.example.ru", true), "direct-out");
    assert_eq!(dns(&with, "bar.example.ru"), "dns-direct");
}

/// Owner answer 4, the reverse: a user direct rule beats a Smart RU pin (Google, YouTube, maps)
/// for the route and its DNS; removing the rule brings the pin back.
#[test]
fn user_direct_rule_beats_smart_ru_pin() {
    let without = frag(ON, Some(DIR), &[], &[]);
    for host in ["www.google.com", "youtube.com", "api.2gis.com"] {
        assert_eq!(route(&without, host, true), "proxy-out", "{host}");
        assert_eq!(dns(&without, host), "dns-remote", "{host}");
    }
    let rules = [
        rule("google.com", DomainAction::Direct),
        rule("*.youtube.com", DomainAction::Direct),
        rule("2gis.com", DomainAction::Direct),
    ];
    let with = frag(ON, Some(DIR), &rules, &[]);
    for host in [
        "www.google.com",
        "google.com",
        "m.youtube.com",
        "api.2gis.com",
    ] {
        assert_eq!(route(&with, host, false), "direct-out", "{host}");
        assert_eq!(dns(&with, host), "dns-direct", "{host}");
    }
    assert_eq!(route(&with, "mail.googleapis.com", false), "proxy-out");
    assert_eq!(dns(&with, "mail.googleapis.com"), "dns-remote");
}

/// domainRulesToSingboxRules vectors (Smart RU off) with the Rust changes: block hoisted
/// first, keywords explicit, adjacent same-action rules merged without changing match order.
#[test]
fn user_domain_rules() {
    assert!(
        frag(SmartRu::default(), None, &[], &[])
            .parts
            .domain_rules
            .is_empty()
    );
    let f = frag(
        SmartRu::default(),
        None,
        &[
            rule("a.com", DomainAction::Vpn),
            rule("b.com", DomainAction::Direct),
            rule("c.com", DomainAction::Block),
        ],
        &[],
    );
    let heads: Vec<&str> = f
        .parts
        .domain_rules
        .iter()
        .map(|r| {
            r.get("outbound")
                .or_else(|| r.get("action"))
                .and_then(Value::as_str)
                .unwrap()
        })
        .collect();
    assert_eq!(heads, ["reject", "proxy-out", "direct-out"]);
    assert_eq!(f.parts.domain_rules[0]["no_drop"], true);
    assert_eq!(
        f.parts.dns_servers[1]["tag"], "dns-direct",
        "a direct rule resolves directly"
    );
    let wild = frag(
        SmartRu::default(),
        None,
        &[rule("*.example.com", DomainAction::Vpn)],
        &[],
    );
    assert_eq!(
        wild.parts.domain_rules[0],
        json!({ "domain_suffix": [".example.com"], "outbound": "proxy-out" })
    );
    let exact = frag(
        SmartRu::default(),
        None,
        &[rule("example.com", DomainAction::Vpn)],
        &[],
    );
    assert_eq!(
        exact.parts.domain_rules[0],
        json!({ "domain": ["example.com"], "domain_suffix": [".example.com"], "outbound": "proxy-out" })
    );
    let kw = frag(
        SmartRu::default(),
        None,
        &[rule("~telegram", DomainAction::Block)],
        &[],
    );
    assert_eq!(
        strs(&kw.parts.domain_rules[0], "domain_keyword"),
        ["telegram"]
    );
    let merged = frag(
        SmartRu::default(),
        None,
        &[
            rule("high.com", DomainAction::Vpn),
            rule("low.com", DomainAction::Vpn),
            rule("c.com", DomainAction::Direct),
            rule("d.com", DomainAction::Vpn),
        ],
        &[],
    );
    assert_eq!(merged.parts.domain_rules.len(), 3);
    assert_eq!(
        strs(&merged.parts.domain_rules[0], "domain"),
        ["high.com", "low.com"]
    );
    assert_eq!(merged.parts.dns_rules.len(), 3);
    for f in [&f, &wild, &exact, &kw, &merged] {
        for r in f.parts.domain_rules.iter().chain(&f.parts.dns_rules) {
            assert!(
                strs(r, "domain_keyword").iter().all(|k| !k.is_empty()),
                "B-DR-9"
            );
        }
    }
}

fn inputs_with<'a>(
    split: &'a ResolvedSplit,
    engines: &'a [AppPath],
    cores: bool,
) -> RoutingInputs<'a> {
    RoutingInputs {
        smart: SmartRu::default(),
        rule_set_dir: None,
        domain_rules: &[],
        split,
        engine_paths: engines,
        third_party_cores: cores,
        dns: None,
        physical_dns: &[],
        endpoint_is_hostname: false,
    }
}

/// AT-06-008 / B-ST-2 / B-ST-4: one rule per class in the order engines, third-party cores,
/// user direct, user VPN; an app path is one exact regex (tunControllerConfig.test.ts:1095).
#[test]
fn process_rules_per_class() {
    let app = AppPath::parse(r"C:\Program Files (x86)\App+1\app.exe").unwrap();
    let split = ResolvedSplit {
        direct: vec![app.regex()],
        vpn: Vec::new(),
        inactive: Vec::new(),
    };
    let f = build(&inputs_with(&split, &[], false));
    assert_eq!(
        f.parts.process_rules,
        vec![json!({ "process_path_regex": [app.regex()], "outbound": "direct-out" })]
    );
    assert!(
        build(&inputs_with(&ResolvedSplit::default(), &[], false))
            .parts
            .process_rules
            .is_empty()
    );
    let xray =
        AppPath::parse(r"C:\Program Files\VPN Tunnel Enforcer\resources\vpnte-xray.exe").unwrap();
    let split = ResolvedSplit {
        direct: vec!["d".into()],
        vpn: vec!["v".into()],
        inactive: Vec::new(),
    };
    let f = build(&inputs_with(&split, &[xray.clone(), xray.clone()], true));
    assert_eq!(f.parts.process_rules.len(), 4);
    assert_eq!(
        f.parts.process_rules[0]["process_path_regex"],
        json!([xray.regex()])
    );
    assert_eq!(
        f.parts.process_rules[1]["process_path_regex"]
            .as_array()
            .unwrap()
            .len(),
        30
    );
    assert_eq!(
        f.parts.process_rules[2],
        json!({ "process_path_regex": ["d"], "outbound": "direct-out" })
    );
    assert_eq!(
        f.parts.process_rules[3],
        json!({ "process_path_regex": ["v"], "outbound": "proxy-out" })
    );
}

/// B-DNS-8 and inactive apps: every fallback is reported.
#[test]
fn warnings() {
    let split = ResolvedSplit::default();
    let mut i = inputs_with(&split, &[], false);
    i.endpoint_is_hostname = true;
    assert_eq!(
        build(&i).warnings,
        vec![RoutingWarning::BootstrapDnsFallback]
    );
    let tun = [Ipv4Addr::new(192, 168, 250, 254)];
    i.physical_dns = &tun;
    assert_eq!(
        build(&i).warnings,
        vec![RoutingWarning::BootstrapDnsFallback]
    );
    let lan = [Ipv4Addr::new(192, 168, 1, 1)];
    i.physical_dns = &lan;
    assert!(build(&i).warnings.is_empty());
    let gone = InactiveApp {
        name: "Gone".into(),
        path: r"C:\Apps\Gone\gone.exe".into(),
        reason: InactiveReason::FileMissing,
    };
    let split = ResolvedSplit {
        inactive: vec![gone.clone()],
        ..ResolvedSplit::default()
    };
    let w = build(&inputs_with(&split, &[], false)).warnings;
    assert_eq!(w, vec![RoutingWarning::InactiveApp(gone)]);
    assert_eq!(w[0].msg().key, "engine.routing.warn.appMissing");
    assert_eq!(w[0].msg().args[0].1, "Gone");
}

/// Same inputs, same fragments (the tunnel compares them to skip needless restarts).
#[test]
fn deterministic() {
    let rules = [
        rule("a.com", DomainAction::Direct),
        rule("~kw", DomainAction::Vpn),
    ];
    let a = frag(ON_MAPS, Some(DIR), &rules, &[Ipv4Addr::new(10, 0, 0, 1)]);
    let b = frag(ON_MAPS, Some(DIR), &rules, &[Ipv4Addr::new(10, 0, 0, 1)]);
    assert_eq!(a, b);
}

/// The fragments inside the real generated config (IPv4 TUN): a local SOCKS upstream, or the
/// Xray slots whose `dns-bootstrap-in` puts the `evaluate` bootstrap order first in
/// `dns.rules` (sing-box then leaves legacy DNS mode and refuses legacy address filters).
fn config(f: &RoutingFragments, slot_mode: bool) -> Value {
    use crate::singbox_config::{
        Capture, ConfigInputs, Listeners, TunParams, TunStack, UdpPolicy, Upstream,
    };
    use crate::slot::{Slot, SlotEndpoint};
    use vpnte_base::types::{Creds, Loopback, ProxyKind};
    let creds = |user: &str| Creds {
        user: user.into(),
        pass: format!("{user}-SYNTHETIC"),
    };
    let direct = Loopback {
        port: 25554,
        creds: Some(creds("direct-user")),
    };
    let upstream = if slot_mode {
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
    crate::singbox_config::build(&ConfigInputs {
        upstream,
        capture: Capture::Tun(TunParams {
            alias: "Ethernet 5".into(),
            mtu: 1500,
            ipv6: false,
            dns_hijack: true,
            stack: TunStack::Mixed,
        }),
        listeners: Listeners {
            clash_port: 25553,
            clash_secret: "0123456789abcdef0123456789abcdef".into(),
            direct,
            probe: None,
            dns_bootstrap: slot_mode.then_some(25556),
        },
        routing: f.parts.clone(),
        phys_dns: vec![Ipv4Addr::new(77, 88, 8, 7)],
    })
    .unwrap()
}

/// §7.1 integration: the fragments (Smart RU with the bundled `.srs`, user rules of every
/// kind, process rules, each DNS mapping) inside the generated config pass `sing-box check -c
/// stdin`, also next to the slot mode's `evaluate` bootstrap order. Skipped quietly when the
/// engine is not in `resources/`.
#[test]
fn fragments_pass_sing_box_check() {
    if crate::test_support::singbox_exe().is_none() {
        return;
    }
    let dir = crate::test_support::resources();
    let rules = [
        rule("ads.example", DomainAction::Block),
        rule("*.example.org", DomainAction::Vpn),
        rule("~kw", DomainAction::Direct),
    ];
    let app = AppPath::parse(r"C:\Program Files (x86)\App+1\app.exe").unwrap();
    let split = ResolvedSplit {
        direct: vec![app.regex()],
        vpn: vec![app.regex()],
        inactive: Vec::new(),
    };
    let addrs: Vec<Option<DnsAddr>> = [
        None,
        Some("9.9.9.9"),
        Some("https://dns.google/dns-query"),
        Some("https://dns.example:8443/abc123/dns-query"),
        Some("https://[2606:4700::1111]/dns-query"),
        Some("tls://dns.example:443"),
    ]
    .into_iter()
    .map(|a| a.map(|s| s.parse().unwrap()))
    .collect();
    for addr in &addrs {
        let f = build(&RoutingInputs {
            smart: ON_MAPS,
            rule_set_dir: Some(&dir),
            domain_rules: &rules,
            split: &split,
            engine_paths: std::slice::from_ref(&app),
            third_party_cores: true,
            dns: addr.as_ref(),
            physical_dns: &[Ipv4Addr::new(77, 88, 8, 7)],
            endpoint_is_hostname: true,
        });
        let checked = crate::test_support::singbox_check(&config(&f, false));
        assert_eq!(checked, Ok(true), "{addr:?}");
        let checked = crate::test_support::singbox_check(&config(&f, true));
        assert_eq!(checked, Ok(true), "slot mode, {addr:?}");
    }
}

/// Routing's DNS rules match by domain only (domain lists and the domain-only gov geosite):
/// next to the slot mode's `evaluate` order sing-box refuses legacy address filters
/// (`ip_cidr`, `ip_is_private`, ... without `match_response`), and an IP rule set would be one.
#[test]
fn dns_rules_match_by_domain_only() {
    let rules = [
        rule("ads.example", DomainAction::Block),
        rule("*.example.org", DomainAction::Vpn),
        rule("~kw", DomainAction::Direct),
    ];
    let f = frag(ON_MAPS, Some(DIR), &rules, &[]);
    assert!(f.parts.dns_rules.len() >= 5, "{:?}", f.parts.dns_rules);
    let matchers = ["domain", "domain_suffix", "domain_keyword", "rule_set"];
    let effects = ["server", "action", "method", "no_drop"];
    for r in &f.parts.dns_rules {
        let keys: Vec<&str> = r.as_object().unwrap().keys().map(String::as_str).collect();
        assert!(
            keys.iter()
                .all(|k| matchers.contains(k) || effects.contains(k)),
            "{r}"
        );
        assert!(keys.iter().any(|k| matchers.contains(k)), "{r}");
        assert!(strs(r, "rule_set").iter().all(|s| s != GEOIP_RU), "{r}");
    }
}
