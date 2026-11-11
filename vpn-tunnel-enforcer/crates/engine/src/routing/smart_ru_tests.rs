use std::path::Path;

use serde_json::{Value, json};

use super::*;

/// smartRouteRuleSets: local binary sets with forward-slash paths, never `remote`, never
/// `geosite-category-ru` (finding F8, the IP-leak fix).
#[test]
fn rule_sets_are_local_files() {
    let sets = rule_sets(Path::new(r"C:\runtime\dir\"));
    let tags: Vec<&str> = sets.iter().map(|s| s["tag"].as_str().unwrap()).collect();
    assert_eq!(tags, ["geoip-ru", "geosite-category-gov-ru"]);
    for s in &sets {
        assert_eq!(s["type"], "local");
        assert_eq!(s["format"], "binary");
        assert!(s.get("url").is_none() && s.get("download_detour").is_none());
        assert!(s.get("update_interval").is_none());
        let path = s["path"].as_str().unwrap();
        assert!(
            path == "C:/runtime/dir/geoip-ru.srs"
                || path == "C:/runtime/dir/geosite-category-gov-ru.srs"
        );
    }
    let files: Vec<&str> = RULE_SETS.iter().map(|(_, f, _)| *f).collect();
    assert_eq!(files, ["geoip-ru.srs", "geosite-category-gov-ru.srs"]);
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

/// Lists stay verbatim: sizes as in smartRoute.ts.
#[test]
fn list_sizes_are_verbatim() {
    assert_eq!(RU_TLD_SUFFIXES.len(), 3);
    assert_eq!(RU_COMMERCIAL_SERVICE_SUFFIXES.len(), 20);
    assert_eq!(MAPS_DOMAIN_SUFFIXES.len(), 4);
    assert_eq!(GOOGLE_AND_GEMINI_PINNED_SUFFIXES.len(), 15);
    assert_eq!(KIMI_MOONSHOT_DOMAIN_SUFFIXES.len(), 6);
    assert_eq!(VPN_PINNED_MEDIA_SUFFIXES.len(), 8);
    assert_eq!(IP_CHECKER_SUFFIXES.len(), 26);
}
