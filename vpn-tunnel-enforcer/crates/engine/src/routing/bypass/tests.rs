//! Tests of the bypass list (RU-2026 item 14 a-b): the user's list, the automatic entries
//! against owner answer 4, and the read-back of the bundled rule sets.
use uuid::Uuid;

use super::*;
use crate::routing::domain::{DomainAction, DomainPattern, DomainRule};
use crate::routing::process::{AppRule, ProcessName, SplitApp, SplitTarget};
use crate::routing::smart_ru::SmartRu;

fn entry(raw: &str) -> BypassEntry {
    BypassEntry::parse(raw).unwrap()
}

fn shown(entries: &[BypassEntry]) -> Vec<String> {
    entries.iter().map(ToString::to_string).collect()
}

#[test]
fn entries_parse_to_their_stored_form() {
    for (raw, stored) in [
        ("Example.COM", "example.com"),
        ("https://www.example.com/path?q=1", "www.example.com"),
        ("*.corp.example", "*.corp.example"),
        ("пример.рф", "xn--e1afmkfd.xn--p1ai"),
        ("intranet", "intranet"),
        ("10.0.0.5", "10.0.0.5"),
        ("10.*", "10.*"),
        ("192.168.*", "192.168.*"),
        ("172.16.*.*", "172.16.*"),
        ("[fd00::1]", "fd00::1"),
        ("fd00::1", "fd00::1"),
    ] {
        assert_eq!(entry(raw).to_string(), stored, "{raw}");
    }
}

#[test]
fn bad_entries_are_refused_by_name() {
    for raw in [
        "~ads",
        "*",
        "10.*.5.*",
        "256.*",
        "1.2.3.4.*",
        "a..b",
        "x.com:8080",
        "*.*.com",
    ] {
        assert_eq!(
            BypassEntry::parse(raw),
            Err(BypassError::Invalid(raw.to_owned())),
            "{raw}"
        );
    }
    let msg = BypassError::Invalid("a..b".into()).msg();
    assert_eq!(msg.key, "engine.routing.bypass.invalid");
}

#[test]
fn a_pasted_windows_list_keeps_order_and_drops_local_and_repeats() {
    let list = parse_list("<local>;intranet.corp; 10.*,\n*.lan  intranet.corp").unwrap();
    assert_eq!(shown(&list), ["intranet.corp", "10.*", "*.lan"]);
    assert_eq!(parse_list(" \n ; ").unwrap(), Vec::<BypassEntry>::new());
}

#[test]
fn the_list_has_limits() {
    let many: Vec<String> = (0..=MAX_ENTRIES).map(|n| format!("h{n}.example")).collect();
    assert_eq!(parse_list(&many.join("\n")), Err(BypassError::TooMany));
    let long = format!("{}.example", "a".repeat(60));
    let wide: Vec<String> = (0..100).map(|n| format!("{n}{long}.{long}")).collect();
    assert_eq!(parse_list(&wide.join(";")), Err(BypassError::TooLong));
}

#[test]
fn each_reader_gets_its_own_syntax() {
    let site = entry("example.com");
    assert_eq!(site.override_items(), ["example.com", "*.example.com"]);
    assert_eq!(site.no_proxy_items(), ["example.com", ".example.com"]);
    let subs = entry("*.example.com");
    assert_eq!(subs.override_items(), ["*.example.com"]);
    assert_eq!(subs.no_proxy_items(), [".example.com"]);
    assert_eq!(entry("192.168.*").no_proxy_items(), ["192.168.0.0/16"]);
    assert_eq!(entry("10.*").no_proxy_items(), ["10.0.0.0/8"]);
    assert_eq!(entry("172.16.5.*").no_proxy_items(), ["172.16.5.0/24"]);
    assert_eq!(entry("fd00::1").override_items(), ["[fd00::1]"]);
    assert_eq!(entry("fd00::1").no_proxy_items(), ["fd00::1"]);
}

#[test]
fn render_puts_the_user_first_and_keeps_automatic_subdomains_out_of_no_proxy() {
    let user = vec![entry("corp.example"), entry("10.*")];
    let auto = vec![
        entry("corp.example"),
        entry("bank.example"),
        entry("*.gov.example"),
    ];
    let lists = render(&user, &auto);
    assert_eq!(
        lists.proxy_override,
        [
            "corp.example",
            "*.corp.example",
            "10.*",
            "bank.example",
            "*.bank.example",
            "*.gov.example",
        ]
    );
    assert_eq!(
        lists.no_proxy,
        [
            "corp.example",
            ".corp.example",
            "10.0.0.0/8",
            "bank.example",
            ".bank.example"
        ]
    );
}

#[test]
fn render_leaves_out_automatic_entries_over_the_budget_never_the_users() {
    let long = "a".repeat(60);
    let user: Vec<BypassEntry> = (0..20)
        .map(|n| entry(&format!("u{n}.{long}.example")))
        .collect();
    let auto: Vec<BypassEntry> = (0..400)
        .map(|n| entry(&format!("a{n}.{long}.example")))
        .collect();
    let lists = render(&user, &auto);
    let text = lists.proxy_override.join(";");
    assert!(text.len() < MAX_TEXT, "{}", text.len());
    assert!(lists.no_proxy.join(",").len() < MAX_TEXT);
    for u in &user {
        assert!(lists.proxy_override.contains(&u.to_string()));
    }
    assert!(lists.proxy_override.len() < 2 * (user.len() + auto.len()));
}

fn rule(pattern: &str, action: DomainAction) -> DomainRule {
    DomainRule::new(DomainPattern::parse(pattern).unwrap(), action)
}

fn app(rule: AppRule) -> SplitApp {
    SplitApp {
        id: Uuid::new_v4(),
        name: "Chrome".into(),
        target: SplitTarget::Command(ProcessName::parse("chrome").unwrap()),
        rule,
    }
}

const SMART: SmartRu = SmartRu {
    enabled: true,
    maps_direct: false,
};

/// A gov list with a zone, a subdomains-only entry and a conditional rule, and a blocked list
/// with a name inside the zone (as the November 2026 lists hold for `spb.ru`).
fn lists() -> SmartLists {
    let gov = r#"{"version":1,"rules":[
        {"domain_suffix":["gosuslugi.ru","spb.ru",".psk","cbr.ru"]},
        {"domain_suffix":["portonly.ru"],"port":[443]}]}"#;
    let blocked = r#"{"version":1,"rules":[{"domain_suffix":["echomsk.spb.ru","rutracker.org"]}]}"#;
    SmartLists::parse(gov, blocked).unwrap()
}

fn auto(
    rules: &[DomainRule],
    apps: &[SplitApp],
    smart: SmartRu,
    l: Option<&SmartLists>,
) -> Vec<String> {
    shown(&automatic(&AutoInputs {
        domain_rules: rules,
        apps,
        smart,
        lists: l,
    }))
}

#[test]
fn user_direct_rules_become_entries_in_their_order() {
    let rules = [
        rule("bank.example", DomainAction::Direct),
        rule("~kw", DomainAction::Direct),
        rule("*.corp.example", DomainAction::Direct),
        rule("other.example", DomainAction::Vpn),
    ];
    let off = SmartRu::default();
    assert_eq!(
        auto(&rules, &[], off, None),
        ["bank.example", "*.corp.example"]
    );
}

/// Answer 4: a user rule that sends any host under an entry elsewhere drops the entry, in
/// either order and in either direction of the name tree.
#[test]
fn a_block_or_vpn_rule_near_an_entry_drops_it() {
    let off = SmartRu::default();
    for near in [
        "pay.bank.example",
        "bank.example",
        "*.example",
        "*.bank.example",
    ] {
        for action in [DomainAction::Vpn, DomainAction::Block] {
            let rules = [
                rule(near, action),
                rule("bank.example", DomainAction::Direct),
                rule("shop.test", DomainAction::Direct),
            ];
            assert_eq!(
                auto(&rules, &[], off, None),
                ["shop.test"],
                "{near} {action:?}"
            );
        }
    }
    let rules = [
        rule("~ads", DomainAction::Block),
        rule("bank.example", DomainAction::Direct),
    ];
    assert!(
        auto(&rules, &[], off, None).is_empty(),
        "a keyword can match any subdomain"
    );
}

#[test]
fn an_app_through_the_vpn_stops_every_automatic_entry() {
    let rules = [rule("bank.example", DomainAction::Direct)];
    let off = SmartRu::default();
    assert!(auto(&rules, &[app(AppRule::Vpn)], off, None).is_empty());
    assert!(auto(&rules, &[app(AppRule::Vpn)], SMART, Some(&lists())).is_empty());
    let direct = auto(
        &rules,
        &[app(AppRule::Direct), app(AppRule::None)],
        off,
        None,
    );
    assert_eq!(direct, ["bank.example"]);
}

#[test]
fn smart_ru_adds_its_gov_list_minus_blocked_and_pinned_names() {
    let rules = [
        rule("bank.example", DomainAction::Direct),
        rule("google.com", DomainAction::Direct),
        rule("*.2gis.ru", DomainAction::Direct),
        rule("cbr.ru", DomainAction::Vpn),
    ];
    // spb.ru holds a blocked name, cbr.ru has a user VPN rule, portonly.ru a port condition;
    // google.com and 2gis.ru are pinned (maps go through the tunnel by default).
    let got = auto(&rules, &[], SMART, Some(&lists()));
    assert_eq!(got, ["bank.example", "gosuslugi.ru", "*.psk"]);
    let maps = SmartRu {
        maps_direct: true,
        ..SMART
    };
    let got = auto(&rules, &[], maps, Some(&lists()));
    assert_eq!(got, ["bank.example", "*.2gis.ru", "gosuslugi.ru", "*.psk"]);
}

#[test]
fn smart_ru_off_or_unreadable_adds_no_gov_entry() {
    let rules = [rule("google.com", DomainAction::Direct)];
    // Off: the engine has no pins and no gov rule, the user's rule alone decides.
    assert_eq!(
        auto(&rules, &[], SmartRu::default(), Some(&lists())),
        ["google.com"]
    );
    assert!(auto(&rules, &[], SMART, None).is_empty());
}

#[test]
fn a_blocked_keyword_or_inverted_rule_clears_every_name() {
    let gov = r#"{"rules":[{"domain_suffix":["gosuslugi.ru"]}]}"#;
    for blocked in [
        r#"{"rules":[{"domain_keyword":["casino"]}]}"#,
        r#"{"rules":[{"domain_regex":["^x"]}]}"#,
        r#"{"rules":[{"type":"logical","mode":"and","rules":[{"domain":["a.b"],"invert":true}]}]}"#,
    ] {
        let l = SmartLists::parse(gov, blocked).unwrap();
        assert!(l.blocked_near("gosuslugi.ru"), "{blocked}");
        assert!(auto(&[], &[], SMART, Some(&l)).is_empty(), "{blocked}");
    }
    let plain = SmartLists::parse(gov, r#"{"rules":[{"domain":["x.gosuslugi.ru"]}]}"#).unwrap();
    assert!(plain.blocked_near("gosuslugi.ru"));
    assert!(!plain.blocked_near("other.ru"));
}

/// The re-check's binding conclusion: no RU TLD ever goes into the list on its own.
#[test]
fn ru_tlds_are_never_automatic() {
    let got = auto(&[], &[], SMART, Some(&lists()));
    for tld in ["ru", "su", "xn--p1ai"] {
        assert!(
            !got.iter().any(|e| e == tld || e == &format!("*.{tld}")),
            "{tld}"
        );
    }
}

#[tokio::test]
async fn the_bundled_rule_sets_read_back_through_the_engine() {
    let Some(exe) = crate::test_support::singbox_exe() else {
        return;
    };
    let dir = crate::test_support::resources();
    let l = read_smart_lists(&exe, &dir).await.unwrap();
    assert!(l.gov().contains(&entry("gosuslugi.ru")));
    assert!(l.blocked_near("rutracker.org") && l.blocked_near("www.linkedin.com"));
    assert!(!l.blocked_near("gosuslugi.ru"));
    let got = auto(&[], &[], SMART, Some(&l));
    assert!(got.contains(&"gosuslugi.ru".to_owned()));
    assert!(
        got.iter()
            .all(|e| !l.blocked_near(e.trim_start_matches("*.")))
    );
    for tld in ["ru", "su", "xn--p1ai"] {
        assert!(
            !got.iter().any(|e| e.trim_start_matches("*.") == tld),
            "{tld}"
        );
    }
}
