use serde_json::json;

use super::*;
use crate::apps::InstalledApp;

fn pat(s: &str) -> DomainPattern {
    DomainPattern::parse(s).unwrap()
}

fn path(s: &str) -> AppPath {
    AppPath::parse(s).unwrap()
}

/// Domain-rule CRUD: duplicates refused, unknown ids harmless, reorder ignores repeats
/// (the old code stored a repeated id twice), imports dedup and cap (B-DR-5).
#[test]
fn domain_rule_crud() {
    let mut d = RulesDoc::default();
    let a = d.add_domain_rule(pat("a.com"), DomainAction::Vpn).unwrap();
    let b = d
        .add_domain_rule(pat("b.com"), DomainAction::Direct)
        .unwrap();
    let c = d
        .add_domain_rule(pat("c.com"), DomainAction::Block)
        .unwrap();
    let dup = d
        .add_domain_rule(pat("A.COM"), DomainAction::Direct)
        .unwrap_err();
    assert_eq!(dup.user_msg().key, "engine.routing.domain.duplicate");
    d.update_domain_rule(b, None, Some(DomainAction::Vpn))
        .unwrap();
    assert_eq!(d.domain_rules[1].action, DomainAction::Vpn);
    assert!(d.update_domain_rule(b, Some(pat("a.com")), None).is_err());
    let missing = d
        .update_domain_rule(Uuid::new_v4(), None, None)
        .unwrap_err();
    assert_eq!(missing.user_msg().key, "engine.routing.domain.notFound");
    d.reorder_domain_rules(&[c, a, c, Uuid::new_v4()]);
    let order: Vec<Uuid> = d.domain_rules.iter().map(|r| r.id).collect();
    assert_eq!(order, [c, a, b]);
    assert!(d.delete_domain_rule(a));
    assert!(!d.delete_domain_rule(a));
    let report = d.import_domains(
        &[pat("b.com"), pat("new.com"), pat("x.org")],
        DomainAction::Direct,
    );
    assert_eq!(
        report,
        ImportReport {
            added: 2,
            duplicates: 1,
            over_limit: 0
        }
    );
    assert_eq!(d.domain_rules.last().unwrap().action, DomainAction::Direct);
    let mut full = RulesDoc::default();
    let many: Vec<DomainPattern> = (0..MAX_RULES + 2)
        .map(|i| pat(&format!("h{i}.example")))
        .collect();
    let report = full.import_domains(&many, DomainAction::Vpn);
    assert_eq!((report.added, report.over_limit), (MAX_RULES, 2));
    let limit = full
        .add_domain_rule(pat("one.more"), DomainAction::Vpn)
        .unwrap_err();
    assert_eq!(limit.user_msg().key, "engine.routing.domain.limit");
}

/// Hit counters survive the rule's deletion; past the cap only live rules keep theirs.
#[test]
fn hit_counters() {
    let mut d = RulesDoc::default();
    let a = d.add_domain_rule(pat("a.com"), DomainAction::Vpn).unwrap();
    d.add_hits(&BTreeMap::from([(a, 2)]));
    d.add_hits(&BTreeMap::from([(a, 3)]));
    assert_eq!(d.hit_count(a), 5);
    d.delete_domain_rule(a);
    assert_eq!(d.hit_count(a), 5);
    let b = d.add_domain_rule(pat("b.com"), DomainAction::Vpn).unwrap();
    let flood: BTreeMap<Uuid, u64> = (0..MAX_HIT_ENTRIES)
        .map(|_| (Uuid::new_v4(), 1))
        .chain([(b, 1)])
        .collect();
    d.add_hits(&flood);
    assert_eq!(d.rule_hits.len(), 1);
    assert_eq!(d.hit_count(b), 1);
}

/// DNS (dnsProfilesSelection.test.ts + B-DNS-2/5): automatic is selectable, built-ins are
/// read-only, deleting the active profile falls back to automatic, dangling ids read as auto.
#[test]
fn dns_profiles() {
    let mut d = RulesDoc::default();
    assert!(d.dns_profiles().len() >= 4);
    assert!(d.active_dns().is_none());
    d.select_dns(Some("builtin-quad9")).unwrap();
    assert_eq!(d.active_dns().unwrap().name, "Quad9");
    assert!(d.select_dns(Some("nope")).is_err());
    let id = d
        .add_dns_profile("  Mine  ", "https://dns.example/q".parse().unwrap(), None)
        .unwrap();
    assert!(id.starts_with("dns-") && id.len() > 12);
    assert_eq!(d.dns.custom[0].name, "Mine");
    assert_eq!(
        d.add_dns_profile(" ", "1.1.1.1".parse().unwrap(), None)
            .unwrap_err()
            .user_msg()
            .key,
        "engine.routing.dns.nameEmpty"
    );
    assert!(
        d.add_dns_profile(&"n".repeat(121), "1.1.1.1".parse().unwrap(), None)
            .is_err()
    );
    d.select_dns(Some(&id)).unwrap();
    d.update_dns_profile(
        &id,
        Some("Renamed"),
        None,
        Some(Some("8.8.8.8".parse().unwrap())),
    )
    .unwrap();
    assert_eq!(d.active_dns().unwrap().name, "Renamed");
    assert_eq!(
        d.update_dns_profile("builtin-google", Some("x"), None, None)
            .unwrap_err()
            .user_msg()
            .key,
        "engine.routing.dns.builtinReadOnly"
    );
    assert!(d.delete_dns_profile("builtin-google").is_err());
    assert!(
        d.update_dns_profile("dns-0-missing", None, None, None)
            .is_err()
    );
    assert!(d.delete_dns_profile(&id).unwrap());
    assert!(d.dns.active_id.is_none());
    d.dns.active_id = Some("dns-gone".into());
    assert!(d.active_dns().is_none());
    d.select_dns(None).unwrap();
    assert!(d.dns.active_id.is_none());
}

/// Split tunnel (splitTunnelProcess / splitTunneling tests): command dedup is case-insensitive
/// and re-arms `direct`, app dedup by path, tombstones for removed apps only, a manual add
/// clears the tombstone, re-scans skip tombstoned and known paths.
#[test]
fn split_tunnel_entries() {
    let mut d = RulesDoc::default();
    let curl = d.add_command(ProcessName::parse("curl").unwrap());
    let entry = &d.split_tunnel.apps[0];
    assert_eq!(
        (entry.name.as_str(), entry.rule),
        ("curl.exe", AppRule::Direct)
    );
    assert!(d.set_app_rule(curl, AppRule::None));
    assert_eq!(d.add_command(ProcessName::parse("CURL.EXE").unwrap()), curl);
    assert_eq!(d.split_tunnel.apps.len(), 1);
    assert_eq!(d.split_tunnel.apps[0].rule, AppRule::Direct);
    assert!(!d.set_app_rule(Uuid::new_v4(), AppRule::Vpn));
    let gone = d.add_app(path(r"C:\Apps\Gone\gone.exe"), "");
    assert_eq!(d.split_tunnel.apps[1].name, "Gone");
    assert_eq!(d.split_tunnel.apps[1].rule, AppRule::None);
    assert_eq!(d.add_app(path(r"c:\apps\gone\GONE.exe"), "Other"), gone);
    assert!(d.remove_app(gone));
    assert!(
        d.split_tunnel
            .removed_paths
            .contains(r"c:\apps\gone\gone.exe")
    );
    assert!(d.remove_app(curl));
    assert_eq!(
        d.split_tunnel.removed_paths.len(),
        1,
        "commands leave no tombstone"
    );
    assert!(!d.remove_app(curl));
    let scan = [
        InstalledApp {
            name: "Gone".into(),
            path: path(r"C:\Apps\Gone\gone.exe"),
        },
        InstalledApp {
            name: "Back".into(),
            path: path(r"C:\Apps\Back\back.exe"),
        },
    ];
    assert_eq!(d.merge_discovered(&scan), 1);
    assert_eq!(d.merge_discovered(&scan), 0);
    d.add_app(path(r"C:\Apps\Gone\gone.exe"), "Gone");
    assert!(d.split_tunnel.removed_paths.is_empty());
}

/// The whole document round-trips through JSON; invalid entries are dropped on load instead
/// of making the file unreadable (B-DR-2 / B-DR-9 / B-DNS-5).
#[test]
fn document_serde() {
    let mut d = RulesDoc::default();
    d.add_domain_rule(pat("*.example.com"), DomainAction::Block)
        .unwrap();
    d.add_command(ProcessName::parse("git").unwrap());
    d.add_dns_profile("Mine", "tls://dns.example:853".parse().unwrap(), None)
        .unwrap();
    let json = serde_json::to_value(&d).unwrap();
    assert!(json.get("splitTunnel").is_some() && json.get("domainRules").is_some());
    assert_eq!(serde_json::from_value::<RulesDoc>(json).unwrap(), d);
    let raw = json!({
        "domainRules": [
            { "id": Uuid::nil(), "pattern": "/", "action": "direct" },
            { "id": Uuid::nil(), "pattern": "ok.com", "action": "teleport" },
            { "id": Uuid::nil(), "pattern": "ok.com", "action": "vpn" }
        ],
        "dns": { "custom": [ { "id": "dns-1", "name": "Bad", "primary": "0.0.0.0" } ], "activeId": "dns-1" },
        "splitTunnel": { "apps": [ { "id": Uuid::nil(), "name": "x", "kind": "app", "target": "x.exe", "rule": "direct" } ] },
        "futureKey": 1
    });
    let d: RulesDoc = serde_json::from_value(raw).unwrap();
    assert_eq!(d.domain_rules.len(), 1);
    assert!(d.dns.custom.is_empty() && d.split_tunnel.apps.is_empty());
    assert!(d.active_dns().is_none());
    assert_eq!(d.extra["futureKey"], 1);
}

/// §7.6 restart suppression, routing half: edits that change nothing routing-relevant leave
/// the generated fragments equal, so the tunnel can skip its restart; `set_app_rule` on an
/// unknown id or to the current rule leaves even the document equal (no store write).
#[test]
fn neutral_edits_keep_fragments() {
    use crate::routing::plan::{RoutingInputs, build};
    use crate::routing::smart_ru::SmartRu;
    let fragments = |d: &RulesDoc| {
        let split = d.resolve_split(|_| Probe::File { canonical: None });
        build(&RoutingInputs {
            smart: SmartRu::default(),
            rule_set_dir: None,
            domain_rules: &d.domain_rules,
            split: &split,
            engine_paths: &[],
            third_party_cores: false,
            dns: None,
            physical_dns: &[],
            endpoint_is_hostname: false,
        })
    };
    let mut d = RulesDoc::default();
    let git = d.add_command(ProcessName::parse("git").unwrap());
    let off = d.add_app(path(r"C:\Apps\Off\off.exe"), "Off");
    d.add_domain_rule(pat("a.com"), DomainAction::Direct)
        .unwrap();
    let before_doc = d.clone();
    let before = fragments(&d);
    assert!(!d.set_app_rule(Uuid::new_v4(), AppRule::Vpn));
    assert!(d.set_app_rule(git, AppRule::Direct));
    assert_eq!(d, before_doc);
    assert!(d.remove_app(off));
    assert_eq!(fragments(&d), before);
    assert_eq!(d.add_command(ProcessName::parse("GIT.exe").unwrap()), git);
    assert_eq!(fragments(&d), before);
    d.set_app_rule(git, AppRule::Vpn);
    assert_ne!(fragments(&d), before);
}

/// One-time import from the Electron stores (routing-dns §6.6): priority order, dotless
/// patterns as keywords, match-all / invalid entries dropped and counted (B-DR-9, B-DNS-5),
/// a dangling active id → automatic, split entries typed by `kind`. A string priority ("5",
/// stored uncoerced by the old app) sorts as its number, so `low.com` wins over `LOW.com`.
#[test]
fn legacy_import() {
    let rule_id = "3f2a1c4e-0000-4000-8000-000000000001";
    let domain = json!({ "domainRules": [
        { "id": "rule-5", "pattern": "low.com", "action": "direct", "priority": "5", "hitCount": 9 },
        { "id": rule_id, "pattern": "https://High.com/", "action": "vpn", "priority": 0, "hitCount": 0 },
        { "id": "x", "pattern": "telegram", "action": "block", "priority": 1 },
        { "id": "y", "pattern": "/", "action": "direct", "priority": 2 },
        { "id": "z", "pattern": "*.", "action": "direct", "priority": 3 },
        { "id": "w", "pattern": "ok.org", "action": "teleport", "priority": 4 },
        { "id": "v", "pattern": "LOW.com", "action": "vpn", "priority": 6 }
    ]});
    let dns = json!({
        "customProfiles": [
            { "id": "dns-1-abc", "name": " Home ", "primary": "https://dns.example/dns-query",
              "secondary": "", "type": "doh", "isBuiltin": false },
            { "id": "dns-2-bad", "name": "Bad", "primary": "0.0.0.0", "secondary": "", "type": "plain" },
            { "id": "builtin-google", "name": "Fake", "primary": "8.8.8.8", "secondary": "" },
            { "id": "dns-3-sec", "name": "Sec", "primary": "9.9.9.9", "secondary": "not an address" }
        ],
        "activeProfileId": "dns-2-bad"
    });
    let split = json!({
        "splitTunnelApps": [
            { "id": "a1", "name": "App", "path": "C:/Apps/App/app.exe", "icon": null, "rule": "direct" },
            { "id": "a2", "name": "curl.exe", "path": "curl.exe", "icon": null, "rule": "direct", "kind": "process" },
            { "id": "a3", "name": "Rel", "path": "relative.exe", "icon": null, "rule": "vpn", "kind": "app" },
            { "id": "a4", "name": "", "path": "C:\\Apps\\Odd\\odd.exe", "icon": null, "rule": "sideways" }
        ],
        "splitTunnelRemovedPaths": ["C:\\Apps\\Gone\\gone.exe"],
        "splitTunnelEnabled": true
    });
    let (d, warnings) = RulesDoc::from_legacy(Some(&domain), Some(&dns), Some(&split));
    let rules: Vec<(String, DomainAction)> = d
        .domain_rules
        .iter()
        .map(|r| (r.pattern.to_string(), r.action))
        .collect();
    assert_eq!(
        rules,
        [
            ("high.com".to_owned(), DomainAction::Vpn),
            ("~telegram".to_owned(), DomainAction::Block),
            ("low.com".to_owned(), DomainAction::Direct),
        ]
    );
    assert_eq!(d.domain_rules[0].id.to_string(), rule_id);
    assert!(d.rule_hits.is_empty(), "old hitCount is not imported");
    let ids: Vec<&str> = d.dns.custom.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["dns-1-abc", "dns-3-sec"]);
    assert_eq!(d.dns.custom[0].name, "Home");
    assert!(d.dns.custom[1].secondary.is_none());
    assert!(d.dns.active_id.is_none());
    assert_eq!(d.split_tunnel.apps.len(), 3);
    assert_eq!(
        d.split_tunnel.apps[0].target,
        SplitTarget::App(path(r"C:\Apps\App\app.exe"))
    );
    assert_eq!(
        d.split_tunnel.apps[1].target,
        SplitTarget::parse("curl").unwrap()
    );
    assert_eq!(d.split_tunnel.apps[2].rule, AppRule::None);
    assert_eq!(d.split_tunnel.apps[2].name, "Odd");
    assert!(
        d.split_tunnel
            .removed_paths
            .contains(r"c:\apps\gone\gone.exe")
    );
    let keys: Vec<(&str, &str)> = warnings
        .iter()
        .map(|m| (m.key.as_ref(), m.args[0].1.as_str()))
        .collect();
    assert_eq!(
        keys,
        [
            ("engine.routing.legacy.domainDropped", "4"),
            ("engine.routing.legacy.dnsDropped", "2"),
            ("engine.routing.legacy.splitDropped", "1"),
        ]
    );
    let (empty, none) = RulesDoc::from_legacy(None, None, None);
    assert_eq!((empty, none.len()), (RulesDoc::default(), 0));
    let active = json!({ "customProfiles": [], "activeProfileId": "builtin-adguard" });
    assert_eq!(
        RulesDoc::from_legacy(None, Some(&active), None)
            .0
            .dns
            .active_id
            .as_deref(),
        Some("builtin-adguard")
    );
}
