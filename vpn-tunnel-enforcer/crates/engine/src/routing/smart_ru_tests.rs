use std::path::Path;

use serde_json::{Value, json};

use super::*;

/// smartRouteRuleSets: local binary sets with forward-slash paths, never `remote`, never
/// `geosite-category-ru` (finding F8, the IP-leak fix).
#[test]
fn rule_sets_are_local_files() {
    let sets = rule_sets(Path::new(r"C:\runtime\dir\"));
    let tags: Vec<&str> = sets.iter().map(|s| s["tag"].as_str().unwrap()).collect();
    assert_eq!(
        tags,
        [
            "geoip-ru",
            "geosite-category-gov-ru",
            "geosite-ru-blocked",
            "geoip-ru-blocked"
        ]
    );
    for (s, (_, file, _)) in sets.iter().zip(RULE_SETS) {
        assert_eq!(s["type"], "local");
        assert_eq!(s["format"], "binary");
        assert!(s.get("url").is_none() && s.get("download_detour").is_none());
        assert!(s.get("update_interval").is_none());
        assert_eq!(s["path"], format!("C:/runtime/dir/{file}"));
    }
    let files: Vec<&str> = RULE_SETS.iter().map(|(_, f, _)| *f).collect();
    assert_eq!(
        files,
        [
            "geoip-ru.srs",
            "geosite-category-gov-ru.srs",
            "geosite-ru-blocked.srs",
            "geoip-ru-blocked.srs"
        ]
    );
    assert!(
        RULE_SETS
            .iter()
            .all(|(tag, _, _)| *tag != "geosite-category-ru")
    );
    assert!(
        RULE_SETS
            .iter()
            .all(|(_, _, url)| url.starts_with("https://"))
    );
}

/// suffixListToMatcher vectors: apex as `domain`, dotted form as `domain_suffix`, blanks skipped.
#[test]
fn suffix_matcher_vectors() {
    let fields = |list: &[&str]| Value::Object(suffixes(&[list]).into_fields());
    assert_eq!(
        fields(&[".2ip.ru", ".ipify.org"]),
        json!({ "domain": ["2ip.ru", "ipify.org"], "domain_suffix": [".2ip.ru", ".ipify.org"] })
    );
    assert_eq!(
        fields(&["2ip.ru"]),
        json!({ "domain": ["2ip.ru"], "domain_suffix": [".2ip.ru"] })
    );
    assert_eq!(
        fields(&["", "   ", ".x.com"]),
        json!({ "domain": ["x.com"], "domain_suffix": [".x.com"] })
    );
}

/// Pins: IP checkers first (with the apex of 2ip.ru), then Google / Gemini, media, and maps
/// only while maps are not direct; `.googlevideo.com` appears once.
#[test]
fn pin_order_and_dedup() {
    let on = pins(false);
    assert_eq!(on.len(), 4);
    let first = Value::Object(on[0].clone().into_fields());
    assert!(
        first["domain"]
            .as_array()
            .unwrap()
            .contains(&json!("2ip.ru"))
    );
    assert!(
        first["domain"]
            .as_array()
            .unwrap()
            .contains(&json!("ipify.org"))
    );
    assert!(
        first["domain_suffix"]
            .as_array()
            .unwrap()
            .contains(&json!(".2ip.ru"))
    );
    let google = Value::Object(on[1].clone().into_fields());
    for s in GOOGLE_AND_GEMINI_PINNED_SUFFIXES {
        assert!(
            google["domain_suffix"]
                .as_array()
                .unwrap()
                .contains(&json!(s)),
            "{s}"
        );
    }
    let media = Value::Object(on[2].clone().into_fields());
    assert!(
        !media["domain_suffix"]
            .as_array()
            .unwrap()
            .contains(&json!(".googlevideo.com"))
    );
    assert!(
        media["domain_suffix"]
            .as_array()
            .unwrap()
            .contains(&json!(".youtube.com"))
    );
    let maps = Value::Object(on[3].clone().into_fields());
    assert!(
        maps["domain_suffix"]
            .as_array()
            .unwrap()
            .contains(&json!(".2gis.com"))
    );
    assert_eq!(pins(true).len(), 3);
}

/// The monitoring self-test's RU probe hosts must not be pinned to the tunnel, and no
/// pinned list may contain an RU commercial service.
#[test]
fn ru_probe_hosts_match_no_pin() {
    let pinned = [
        IP_CHECKER_SUFFIXES,
        GOOGLE_AND_GEMINI_PINNED_SUFFIXES,
        VPN_PINNED_MEDIA_SUFFIXES,
        MAPS_DOMAIN_SUFFIXES,
    ];
    for host in ["yandex.ru", "internet.yandex.ru"] {
        for list in pinned {
            assert!(
                !list.iter().any(|s| host == &s[1..] || host.ends_with(s)),
                "{host} is pinned by {s:?}",
                s = list
            );
        }
    }
}

/// Lists stay verbatim: sizes as in smartRoute.ts, plus the two RU services of the November
/// 2026 study (T7).
#[test]
fn list_sizes_are_verbatim() {
    assert_eq!(RU_TLD_SUFFIXES.len(), 3);
    assert_eq!(RU_COMMERCIAL_SERVICE_SUFFIXES.len(), 22);
    assert_eq!(MAPS_DOMAIN_SUFFIXES.len(), 4);
    assert_eq!(GOOGLE_AND_GEMINI_PINNED_SUFFIXES.len(), 15);
    assert_eq!(KIMI_MOONSHOT_DOMAIN_SUFFIXES.len(), 6);
    assert_eq!(VPN_PINNED_MEDIA_SUFFIXES.len(), 8);
    assert_eq!(IP_CHECKER_SUFFIXES.len(), 26);
}

const ON: SmartRu = SmartRu {
    enabled: true,
    maps_direct: false,
};

fn rule(pattern: &str, action: DomainAction) -> DomainRule {
    DomainRule::new(DomainPattern::parse(pattern).unwrap(), action)
}

/// Smart RU's own route by name, in its rule order: pins first (the IP checker under `.ru`,
/// Google's `.ru`-free names), maps by the switch, RU names and Kimi direct, the rest undecided.
#[test]
fn route_of_follows_the_lists_in_rule_order() {
    let cases = [
        ("yandex.ru", Some(SmartRoute::Direct)),
        ("music.yandex.ru", Some(SmartRoute::Direct)),
        ("vk.com", Some(SmartRoute::Direct)),
        ("api.kimi.com", Some(SmartRoute::Direct)),
        ("2ip.ru", Some(SmartRoute::Vpn)),
        ("www.google.com", Some(SmartRoute::Vpn)),
        ("youtube.com", Some(SmartRoute::Vpn)),
        ("maps.yandex.ru", Some(SmartRoute::Vpn)),
        ("example.com", None),
        ("my2ip.ru", Some(SmartRoute::Direct)),
        ("cdn1.ozonusercontent.com", Some(SmartRoute::Direct)),
        ("bitrix.info", Some(SmartRoute::Direct)),
        ("ozonusercontent.com.example", None),
    ];
    for (host, want) in cases {
        assert_eq!(ON.route_of(host, None), want, "{host}");
    }
    let maps = SmartRu {
        maps_direct: true,
        ..ON
    };
    assert_eq!(
        maps.route_of("maps.yandex.ru", None),
        Some(SmartRoute::Direct)
    );
    assert_eq!(maps.route_of("2gis.com", None), Some(SmartRoute::Direct));
    assert_eq!(SmartRu::default().route_of("yandex.ru", None), None);
}

/// Owner answer 4: a note only where the user's rule sends a site the other way.
#[test]
fn overridden_by_names_only_real_conflicts() {
    let vpn_ru = rule("yandex.ru", DomainAction::Vpn);
    let direct_pin = rule("*.youtube.com", DomainAction::Direct);
    assert_eq!(ON.overridden_by(&vpn_ru, None), Some(SmartRoute::Direct));
    assert_eq!(ON.overridden_by(&direct_pin, None), Some(SmartRoute::Vpn));
    for agree in [
        rule("yandex.ru", DomainAction::Direct),
        rule("youtube.com", DomainAction::Vpn),
        rule("example.com", DomainAction::Direct),
        rule("yandex.ru", DomainAction::Block),
        rule("~yandex", DomainAction::Vpn),
    ] {
        assert_eq!(ON.overridden_by(&agree, None), None, "{}", agree.pattern);
    }
    assert_eq!(SmartRu::default().overridden_by(&vpn_ru, None), None);
}

/// psmart-b1: with the blocked-in-Russia list read back, a name on it is Smart RU's VPN route,
/// before the RU-TLD direct rule: a user's VPN rule for it agrees (no note), a Direct rule
/// overrides it (the note names the VPN).
#[test]
fn a_blocked_name_is_smart_rus_vpn_route() {
    let gov = r#"{"rules":[{"domain_suffix":["gosuslugi.ru"]}]}"#;
    let blocked = r#"{"rules":[{"domain_suffix":["tvrain.ru","linkedin.com"]}]}"#;
    let lists = crate::routing::bypass::SmartLists::parse(gov, blocked).unwrap();
    let l = Some(&lists);
    assert_eq!(ON.route_of("tvrain.ru", l), Some(SmartRoute::Vpn));
    assert_eq!(ON.route_of("www.tvrain.ru", l), Some(SmartRoute::Vpn));
    assert_eq!(ON.route_of("www.linkedin.com", l), Some(SmartRoute::Vpn));
    assert_eq!(ON.route_of("yandex.ru", l), Some(SmartRoute::Direct));
    assert_eq!(ON.route_of("ntvrain.ru", l), Some(SmartRoute::Direct));
    assert_eq!(
        ON.overridden_by(&rule("tvrain.ru", DomainAction::Vpn), l),
        None
    );
    assert_eq!(
        ON.overridden_by(&rule("tvrain.ru", DomainAction::Direct), l),
        Some(SmartRoute::Vpn)
    );
    assert_eq!(
        ON.overridden_by(&rule("*.linkedin.com", DomainAction::Direct), l),
        Some(SmartRoute::Vpn)
    );
    assert_eq!(SmartRu::default().route_of("tvrain.ru", l), None);
}
