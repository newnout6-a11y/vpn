//! The import of Happ routing profiles: the planner over recorded and synthetic profiles, and
//! the service flow (offer, preview, import on the click, stale token) over a temp backend.
use vpnte_base::ErrorKind;
use vpnte_base::types::ClientDevice;
use vpnte_engine::routing::domain::{DomainAction, DomainPattern, DomainRule};
use vpnte_engine::routing::process::ProcessName;
use vpnte_profiles::model::SubscriptionMeta;
use vpnte_profiles::text::{Controls, RoutingValue, parse_routing};
use vpnte_servers::store::{AddTarget, NewSubscription};
use vpnte_ui::split_tunnel::{
    EntryNote, Kept, PreviewEntry, RouteKind, RoutingSource, SplitTunnelApi,
};

use super::plan::{Plan, plan};
use crate::api_lists::SplitService;
use crate::api_settings::test_support::{FakeTunnel, TempDir, backend};

/// frayZV/simple-ru-routing `JSON-EXAMPLE` (public), as a provider sends it.
const SIMPLE_RU: &str = r#"{"Name":"Simple-RU-routing","GlobalProxy":"true","RemoteDNSType":"DoU","RemoteDNSDomain":"https://dns.adguard-dns.com/dns-query","RemoteDNSIP":"94.140.14.14","DomesticDNSType":"DoU","DomesticDNSDomain":"https://dns.adguard-dns.com/dns-query","DomesticDNSIP":"94.140.15.15","Geoipurl":"https://github.com/frayZV/simple-ru-geoip/releases/latest/download/geoip.dat","Geositeurl":"https://github.com/frayZV/simple-ru-geosite/releases/latest/download/geosite.dat","LastUpdated":"4070905200","DnsHosts":{},"DirectSites":["geosite:private","geosite:category-ru","geosite:apple","geosite:twitch"],"DirectIp":["geoip:ru","geoip:private"],"ProxySites":["geosite:youtube","geosite:category-ban-ru"],"ProxyIp":[],"BlockSites":[],"BlockIp":[],"DomainStrategy":"IPIfNonMatch","FakeDNS":"false","UseChunkFiles":"true"}"#;

/// Every kind of entry a profile can hold, against the user's own rules for two of the sites.
const MIXED: &str = r#"{
  "Name": "Mixed", "GlobalProxy": "false", "FakeDNS": "true", "DnsHosts": {"a.example": "192.0.2.1"},
  "BlockSites": ["domain:ads.example"],
  "ProxySites": ["domain:connectivitycheck.gstatic.com", "full:www.gstatic.com", "keyword:tracker",
                 "regexp:.*\\.example$", "Example.ORG", "1.2.3.4", "geosite:category-ru"],
  "ProxyIp": ["192.168.0.0/16"],
  "DirectSites": ["domain:bank.example", "domain:connectivitycheck.gstatic.com", "ext:my.dat:x"],
  "DirectIp": ["10.0.0.0/8", "203.0.113.0/24", "255.255.255.255", 7]
}"#;

fn value(text: &str) -> RoutingValue {
    parse_routing(text).expect("a routing profile")
}

fn rule(pattern: &str, action: DomainAction) -> DomainRule {
    DomainRule::new(DomainPattern::parse(pattern).expect("pattern"), action)
}

fn entry(text: &str, route: RouteKind, note: EntryNote) -> PreviewEntry {
    PreviewEntry {
        text: text.into(),
        route,
        note,
    }
}

/// A Russian provider's profile: category-ru and geoip:ru turn Smart RU on, the local network is
/// in place already, the lists the app does not ship are listed, the DNS stays the user's.
#[test]
fn russian_profile_turns_smart_ru_on() {
    let (plan_off, preview) = plan(&value(SIMPLE_RU), &[], false);
    assert_eq!(
        plan_off,
        Plan {
            rules: Vec::new(),
            smart_ru: true
        }
    );
    let step = preview.smart_ru.clone().expect("Smart RU step");
    assert!(step.turn_on);
    assert_eq!(step.from, ["geosite:category-ru", "geoip:ru"]);
    assert_eq!(
        preview.covered,
        [
            entry("geosite:private", RouteKind::Direct, EntryNote::Local),
            entry("geoip:private", RouteKind::Direct, EntryNote::Local),
        ]
    );
    assert_eq!(
        preview.skipped,
        [
            entry("geosite:youtube", RouteKind::Vpn, EntryNote::NotShipped),
            entry(
                "geosite:category-ban-ru",
                RouteKind::Vpn,
                EntryNote::NotShipped
            ),
            entry("geosite:apple", RouteKind::Direct, EntryNote::NotShipped),
            entry("geosite:twitch", RouteKind::Direct, EntryNote::NotShipped),
        ]
    );
    assert_eq!(
        preview.kept,
        [Kept::Dns("94.140.14.14, 94.140.15.15".into())]
    );
    assert!(preview.add.is_empty() && preview.changes());

    // Smart RU on already: nothing to change.
    let (plan_on, preview) = plan(&value(SIMPLE_RU), &[], true);
    assert!(!plan_on.smart_ru);
    assert!(!preview.smart_ru.as_ref().expect("step").turn_on);
    assert!(!preview.changes());
}

/// Sites become the user's rules in the profile's order (block, proxy, direct); the user's own
/// rule for a site stays; a repeat, a regexp, an address, a provider file and an unknown item
/// are listed with their reason; Russian sites outside a «direct» list never touch Smart RU.
#[test]
fn sites_join_the_users_rules_and_the_users_rules_win() {
    let mine = [
        rule("ads.example", DomainAction::Block),
        rule("bank.example", DomainAction::Vpn),
    ];
    let (plan, preview) = plan(&value(MIXED), &mine, false);
    let want = [
        ("connectivitycheck.gstatic.com", DomainAction::Vpn),
        ("www.gstatic.com", DomainAction::Vpn),
        ("~tracker", DomainAction::Vpn),
        ("example.org", DomainAction::Vpn),
    ];
    let planned: Vec<(String, DomainAction)> = plan
        .rules
        .iter()
        .map(|(p, a)| (p.to_string(), *a))
        .collect();
    assert_eq!(planned, want.map(|(p, a)| (p.to_owned(), a)));
    assert!(!plan.smart_ru, "category-ru in a proxy list");
    let shown: Vec<(&str, RouteKind)> = preview
        .add
        .iter()
        .map(|r| (r.pattern.as_str(), r.route))
        .collect();
    assert_eq!(shown.len(), 4);
    assert!(shown.iter().all(|(_, route)| *route == RouteKind::Vpn));
    assert_eq!(
        preview.covered,
        [
            entry("domain:ads.example", RouteKind::Block, EntryNote::Present),
            entry("10.0.0.0/8", RouteKind::Direct, EntryNote::Local),
        ]
    );
    assert_eq!(
        preview.skipped,
        [
            entry(r"regexp:.*\.example$", RouteKind::Vpn, EntryNote::Regexp),
            entry("1.2.3.4", RouteKind::Vpn, EntryNote::IpRule),
            entry(
                "geosite:category-ru",
                RouteKind::Vpn,
                EntryNote::RussianSites
            ),
            entry("192.168.0.0/16", RouteKind::Vpn, EntryNote::Local),
            entry(
                "domain:bank.example",
                RouteKind::Direct,
                EntryNote::YourRule(RouteKind::Vpn)
            ),
            entry(
                "domain:connectivitycheck.gstatic.com",
                RouteKind::Direct,
                EntryNote::Repeated
            ),
            entry("ext:my.dat:x", RouteKind::Direct, EntryNote::NotShipped),
            entry("203.0.113.0/24", RouteKind::Direct, EntryNote::IpRule),
            entry("255.255.255.255", RouteKind::Direct, EntryNote::IpRule),
            entry("7", RouteKind::Direct, EntryNote::Invalid),
        ]
    );
    assert_eq!(
        preview.kept,
        [Kept::RestDirect, Kept::DnsHosts(1), Kept::FakeDns]
    );
    assert_eq!(preview.smart_ru, None);
}

/// `happ://routing/off` changes nothing.
#[test]
fn off_changes_nothing() {
    let (plan, preview) = plan(&value("happ://routing/off"), &[], false);
    assert_eq!(plan, Plan::default());
    assert!(preview.off && !preview.changes());
}

/// Only ranges wholly inside a local block count as the local network.
#[test]
fn local_ranges() {
    use super::plan::is_local;
    let local = |text: &str| {
        let (addr, prefix) = text.split_once('/').expect("cidr");
        is_local(addr.parse().expect("addr"), prefix.parse().expect("prefix"))
    };
    for yes in [
        "10.1.2.0/24",
        "172.16.0.0/12",
        "192.168.1.1/32",
        "127.0.0.1/32",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "fc00::/7",
        "fd12::/16",
        "fe80::/64",
        "ff02::1/128",
        "::1/128",
    ] {
        assert!(local(yes), "{yes}");
    }
    for no in [
        "10.0.0.0/7",
        "172.32.0.0/12",
        "100.64.0.0/10",
        "255.255.255.255/32",
        "8.8.8.8/32",
        "2001:db8::/32",
        "::/0",
    ] {
        assert!(!local(no), "{no}");
    }
}

/// Adds a subscription whose provider sent `routing` (one fake key in it).
fn add_subscription(backend: &crate::services::Backend, routing: &str) -> String {
    let key = "vless://11111111-2222-3333-4444-555555555555@r.example.net:443?security=tls#R";
    let profiles = vpnte_servers::parse::parse_text(key)
        .expect("parse")
        .profiles;
    let target = AddTarget::Subscription(Box::new(NewSubscription {
        url: vpnte_servers::subscription::canonical_source("https://sub.example.net/feed/token")
            .expect("url"),
        device: ClientDevice::Pc,
        info: SubscriptionMeta::default(),
        partial: false,
        send_hwid: false,
        headers: None,
        controls: Controls {
            routing: Some(routing.to_owned()),
            ..Controls::default()
        },
        fallback: None,
        moved_at: None,
    }));
    backend
        .servers
        .add(profiles, target)
        .expect("add")
        .group
        .to_string()
}

/// The provider's profile is offered, nothing changes until the import of the previewed plan;
/// the rules land in the user's list after the user's own, Smart RU goes on, and the spent
/// preview is refused as stale. A pasted link previews the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_preview_import() {
    let dir = TempDir::new("lists-routing-import");
    let tunnel = FakeTunnel::new(false);
    let backend = backend(&dir, tunnel.clone());
    backend
        .rules
        .update(|doc| {
            doc.add_domain_rule(
                DomainPattern::parse("bank.example").expect("p"),
                DomainAction::Vpn,
            )
        })
        .expect("own rule")
        .expect("added");
    backend
        .settings
        .update(|s| s.smart_ru_split = false)
        .expect("smart off");
    // An app entry first, so the page's first look runs no app discovery.
    let curl = ProcessName::parse("curl").expect("name");
    backend
        .rules
        .update(|doc| doc.add_command(curl))
        .expect("command");
    let profile = r#"{"Name":"P","DirectSites":["geosite:category-ru","domain:bank.example"],"ProxySites":["domain:one.example","keyword:two"]}"#;
    let group = add_subscription(&backend, profile);
    let api = SplitService::start(backend.clone());

    let offers = {
        let mut rx = api.state();
        let snapshot = rx
            .wait_for(|s| !s.offers.is_empty())
            .await
            .expect("offers")
            .clone();
        snapshot.offers
    };
    assert_eq!(offers.len(), 1);
    assert_eq!(
        (offers[0].group_id.as_str(), offers[0].profile.as_deref()),
        (group.as_str(), Some("P"))
    );

    let preview = api
        .preview_routing(RoutingSource::Subscription(group.clone()))
        .await
        .expect("preview");
    assert_eq!(preview.add.len(), 2);
    assert_eq!(
        preview.skipped,
        [entry(
            "domain:bank.example",
            RouteKind::Direct,
            EntryNote::YourRule(RouteKind::Vpn)
        )]
    );
    let untouched = backend.rules.read(|doc| doc.domain_rules.len());
    assert_eq!(untouched, 1, "a preview changes nothing");
    assert!(!backend.settings.read(|s| s.smart_ru_split));

    let done = api.import_routing(preview.token).await.expect("import");
    assert_eq!(
        (done.added, done.over_limit, done.smart_ru_on),
        (2, 0, true)
    );
    let rules: Vec<(String, DomainAction)> = backend.rules.read(|doc| {
        doc.domain_rules
            .iter()
            .map(|r| (r.pattern.to_string(), r.action))
            .collect()
    });
    assert_eq!(
        rules,
        [
            ("bank.example".to_owned(), DomainAction::Vpn),
            ("one.example".to_owned(), DomainAction::Vpn),
            ("~two".to_owned(), DomainAction::Vpn),
        ]
    );
    assert!(backend.settings.read(|s| s.smart_ru_split));
    // PR #137 review: the tunnel is told, as by the Settings page (Smart RU applies at the next
    // connect; fixfollow-b2).
    let told = tunnel.applied.lock().clone();
    assert!(
        matches!(told.as_slice(), [(old, new)] if !old.smart_ru_split && new.smart_ru_split),
        "{} changes told",
        told.len()
    );

    let err = api.import_routing(preview.token).await.expect_err("spent");
    assert_eq!(err.kind, ErrorKind::Conflict);
    assert_eq!(err.user_msg().key, "app.lists.routing.stale");

    let link = format!(
        "happ://routing/onadd/{}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, profile)
    );
    let again = api
        .preview_routing(RoutingSource::Pasted(link))
        .await
        .expect("pasted");
    assert!(!again.changes(), "everything is in place now");
    let older = preview.token;
    assert!(again.token > older);
    let err = api.import_routing(older).await.expect_err("older token");
    assert_eq!(err.kind, ErrorKind::Conflict);

    let err = api
        .preview_routing(RoutingSource::Pasted("hello".into()))
        .await
        .expect_err("not a profile");
    assert_eq!(
        (err.kind, err.user_msg().key.as_ref()),
        (ErrorKind::Validation, "profiles.routing.notRouting")
    );
    let err = api
        .preview_routing(RoutingSource::Subscription("no-such-group".into()))
        .await
        .expect_err("gone");
    assert_eq!(err.user_msg().key, "app.lists.routing.gone");
}
