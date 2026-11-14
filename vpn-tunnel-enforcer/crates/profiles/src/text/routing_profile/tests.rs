//! Recorded routing profiles from public sources: Happ's docs (`happ.su/main/dev-docs/routing`,
//! the "China" example and the header sample link) and providers' published profiles
//! (frayZV/simple-ru-routing, KazZzeL/allow-domains-happ-routing, legiz-ru/my-remnawave).
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use super::*;

/// Happ's header / body sample, verbatim.
const DOC_SAMPLE_LINK: &str = "happ://routing/onadd/ewogICAgIk5hbWUiOiAidGVzdCIsCiAgICAiR2xvYmFsUHJveHkiOiAidHJ1ZSIsCiAgICAiUmVtb3RlRG5zIjogIiIsCiAgICAiRG9tZXN0aWNEbnMiOiAiIiwKICAgICJHZW9pcHVybCI6ICIiLAogICAgIkdlb3NpdGV1cmwiOiAiIiwKICAgICJEbnNIb3N0cyI6IHt9LAogICAgIkRpcmVjdFNpdGVzIjogW10sCiAgICAiRGlyZWN0SXAiOiBbXSwKICAgICJQcm94eVNpdGVzIjogW10sCiAgICAiUHJveHlJcCI6IFtdLAogICAgIkJsb2NrU2l0ZXMiOiBbXSwKICAgICJCbG9ja0lwIjogW10sCiAgICAiRG9tYWluU3RyYXRlZ3kiOiAiQXNJcyIKfQ==";

/// Happ's "Example Custom Profile", verbatim.
const DOC_CHINA: &str = r#"{
    "Name": "China",
    "GlobalProxy": "true",
    "RemoteDNSType": "DoH",
    "RemoteDNSDomain": "https://cloudflare-dns.com/dns-query",
    "RemoteDNSIP": "1.1.1.1",
    "DomesticDNSType": "DoU",
    "DomesticDNSDomain": "",
    "DomesticDNSIP": "8.8.8.8",
    "Geoipurl": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
    "Geositeurl": "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
    "LastUpdated": "",
    "DnsHosts": {
        "cloudflare-dns.com": "1.1.1.1"
    },
  "DirectSites": ["geosite:cn", "geosite:geolocation-cn"],
    "DirectIp": [
        "geoip:cn",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "255.255.255.255"
    ],
  "ProxySites": ["geosite:cn"],
  "ProxyIp": ["geoip:amazon"],
  "BlockSites": ["geosite:ads"],
  "BlockIp": ["geoip:ads"],
    "DomainStrategy": "IPIfNonMatch",
    "FakeDNS": "false"
}"#;

/// frayZV/simple-ru-routing `JSON-EXAMPLE`, verbatim.
const SIMPLE_RU: &str = r#"{
  "Name": "Simple-RU-routing",
  "GlobalProxy": "true",
  "RemoteDNSType": "DoU",
  "RemoteDNSDomain": "https://dns.adguard-dns.com/dns-query",
  "RemoteDNSIP": "94.140.14.14",
  "DomesticDNSType": "DoU",
  "DomesticDNSDomain": "https://dns.adguard-dns.com/dns-query",
  "DomesticDNSIP": "94.140.15.15",
  "Geoipurl": "https://github.com/frayZV/simple-ru-geoip/releases/latest/download/geoip.dat",
  "Geositeurl": "https://github.com/frayZV/simple-ru-geosite/releases/latest/download/geosite.dat",
  "LastUpdated": "4070905200",
  "DnsHosts": {},
  "DirectSites": [
    "geosite:private",
    "geosite:category-ru",
    "geosite:apple",
    "geosite:twitch"
  ],
  "DirectIp": [
    "geoip:ru",
    "geoip:private"
  ],
  "ProxySites": [
    "geosite:youtube",
    "geosite:category-ban-ru"
  ],
  "ProxyIp": [],
  "BlockSites": [],
  "BlockIp": [],
  "DomainStrategy": "IPIfNonMatch",
  "FakeDNS": "false",
  "UseChunkFiles": "true"
}"#;

/// KazZzeL `russia-inside.deeplink`, decoded, verbatim (the release ships it as an onadd link).
const RUSSIA_INSIDE: &str = r#"{
    "Name": "RussiaInside",
    "GlobalProxy": "false",
    "UseChunkFiles": "true",
    "RemoteDNSType": "DoU",
    "RemoteDNSDomain": "https://cloudflare-dns.com/dns-query",
    "RemoteDNSIP": "1.1.1.1",
    "DomesticDNSType": "DoU",
    "DomesticDNSDomain": "https://dns.google/dns-query",
    "DomesticDNSIP": "8.8.8.8",
    "Geoipurl": "https://github.com/KazZzeL/allow-domains-dat/releases/latest/download/allow-subnets.dat",
    "Geositeurl": "https://github.com/KazZzeL/allow-domains-dat/releases/latest/download/russia-inside.dat",
    "LastUpdated": "1794275574",
    "DnsHosts": {
        "cloudflare-dns.com": "1.1.1.1",
        "dns.google": "8.8.8.8"
    },
    "RouteOrder": "block-direct-proxy",
    "DirectSites": [],
    "DirectIp": [
        "geoip:private-fakedns"
    ],
    "ProxySites": [
        "domain:connectivitycheck.gstatic.com",
        "domain:www.gstatic.com",
        "geosite:list"
    ],
    "ProxyIp": [
        "geoip:cloudflare",
        "geoip:cloudfront",
        "geoip:digitalocean",
        "geoip:discord",
        "geoip:google-meet",
        "geoip:hetzner",
        "geoip:meta",
        "geoip:ovh",
        "geoip:roblox",
        "geoip:telegram",
        "geoip:twitter"
    ],
    "BlockSites": [],
    "BlockIp": [],
    "DomainStrategy": "IPIfNonMatch",
    "FakeDNS": "true"
}"#;

/// legiz-ru/my-remnawave README, the Re:filter link, verbatim.
const REFILTER_LINK: &str = "happ://routing/onadd/eyJOYW1lIjoiUmU6ZmlsdGVyIiwiR2xvYmFsUHJveHkiOiJmYWxzZSIsIlJvdXRlT3JkZXIiOiJibG9jay1kaXJlY3QtcHJveHkiLCJSZW1vdGVETlNUeXBlIjoiRG9VIiwiUmVtb3RlRE5TRG9tYWluIjoiaHR0cHM6Ly9jbG91ZGZsYXJlLWRucy5jb20vZG5zLXF1ZXJ5IiwiUmVtb3RlRE5TSVAiOiIxLjEuMS4xIiwiRG9tZXN0aWNETlNUeXBlIjoiRG9VIiwiRG9tZXN0aWNETlNEb21haW4iOiJodHRwczovL2NvbW1vbi5kb3QuZG5zLnlhbmRleC5uZXQvZG5zLXF1ZXJ5IiwiRG9tZXN0aWNETlNJUCI6Ijc3Ljg4LjguOCIsIkdlb2lwdXJsIjoiaHR0cHM6Ly9naXRodWIuY29tLzFhbmRyZXZpY2gvUmUtZmlsdGVyLWxpc3RzL3JlbGVhc2VzL2xhdGVzdC9kb3dubG9hZC9nZW9pcC5kYXQiLCJHZW9zaXRldXJsIjoiaHR0cHM6Ly9naXRodWIuY29tLzFhbmRyZXZpY2gvUmUtZmlsdGVyLWxpc3RzL3JlbGVhc2VzL2xhdGVzdC9kb3dubG9hZC9nZW9zaXRlLmRhdCIsIkxhc3RVcGRhdGVkIjoiIiwiRG5zSG9zdHMiOnt9LCJEaXJlY3RTaXRlcyI6W10sIkRpcmVjdElwIjpbIjEwLjAuMC4wLzgiLCIxNzIuMTYuMC4wLzEyIiwiMTkyLjE2OC4wLjAvMTYiLCIxNjkuMjU0LjAuMC8xNiIsIjIyNC4wLjAuMC80IiwiMjU1LjI1NS4yNTUuMjU1Il0sIlByb3h5U2l0ZXMiOlsiZ2Vvc2l0ZTpyZWZpbHRlciJdLCJQcm94eUlwIjpbImdlb2lwOnJlZmlsdGVyIl0sIkJsb2NrU2l0ZXMiOltdLCJCbG9ja0lwIjpbXSwiRG9tYWluU3RyYXRlZ3kiOiJJUE9uRGVtYW5kIiwiRmFrZUROUyI6ImZhbHNlIiwiVXNlQ2h1bmtGaWxlcyI6InRydWUifQ==";

fn profile_of(value: &str) -> RoutingProfile {
    match parse_routing(value) {
        Ok(RoutingValue::Profile(profile)) => profile,
        other => panic!("not a profile: {other:?}"),
    }
}

/// `(route, raw)` of every entry, in order.
fn listed(profile: &RoutingProfile) -> Vec<(Route, &str)> {
    profile
        .entries
        .iter()
        .map(|e| (e.route, e.raw.as_str()))
        .collect()
}

fn net(text: &str) -> Entry {
    Entry::Ip(text.parse().expect("test CIDR"))
}

/// The docs' sample link: a profile with nothing in it.
#[test]
fn doc_sample_link() {
    let profile = profile_of(DOC_SAMPLE_LINK);
    assert_eq!(profile.name.as_deref(), Some("test"));
    assert!(profile.global_proxy);
    assert!(profile.entries.is_empty());
    assert!(profile.dns.is_empty(), "blank RemoteDns / DomesticDns");
    assert_eq!((profile.dns_hosts, profile.fake_dns), (0, false));
}

/// The docs' China profile: no RouteOrder, so block, proxy, direct; sites before IPs.
#[test]
fn doc_china_profile_in_default_order() {
    let profile = profile_of(DOC_CHINA);
    assert_eq!(profile.name.as_deref(), Some("China"));
    assert_eq!(
        listed(&profile),
        [
            (Route::Block, "geosite:ads"),
            (Route::Block, "geoip:ads"),
            (Route::Proxy, "geosite:cn"),
            (Route::Proxy, "geoip:amazon"),
            (Route::Direct, "geosite:cn"),
            (Route::Direct, "geosite:geolocation-cn"),
            (Route::Direct, "geoip:cn"),
            (Route::Direct, "10.0.0.0/8"),
            (Route::Direct, "172.16.0.0/12"),
            (Route::Direct, "192.168.0.0/16"),
            (Route::Direct, "169.254.0.0/16"),
            (Route::Direct, "224.0.0.0/4"),
            (Route::Direct, "255.255.255.255"),
        ]
    );
    assert_eq!(profile.entries[0].entry, Entry::Geosite("ads".into()));
    assert_eq!(profile.entries[12].entry, net("255.255.255.255/32"));
    // Remote: DoH, so its URL; domestic: DoU with a blank domain, so its address.
    assert_eq!(
        profile.dns,
        ["https://cloudflare-dns.com/dns-query", "8.8.8.8"]
    );
    assert_eq!(profile.dns_hosts, 1);
}

/// A Russian provider's profile as JSON: category-ru and geoip:ru direct, the rest proxied.
#[test]
fn simple_ru_routing_json() {
    let profile = profile_of(SIMPLE_RU);
    assert!(profile.global_proxy);
    assert_eq!(
        listed(&profile),
        [
            (Route::Proxy, "geosite:youtube"),
            (Route::Proxy, "geosite:category-ban-ru"),
            (Route::Direct, "geosite:private"),
            (Route::Direct, "geosite:category-ru"),
            (Route::Direct, "geosite:apple"),
            (Route::Direct, "geosite:twitch"),
            (Route::Direct, "geoip:ru"),
            (Route::Direct, "geoip:private"),
        ]
    );
    assert_eq!(profile.entries[6].entry, Entry::Geoip("ru".into()));
    // Both sides DoU: the addresses, not the URLs.
    assert_eq!(profile.dns, ["94.140.14.14", "94.140.15.15"]);
}

/// An onadd link with RouteOrder, `domain:` entries, GlobalProxy off and FakeDNS on.
#[test]
fn russia_inside_link() {
    let link = format!("happ://routing/onadd/{}", STANDARD.encode(RUSSIA_INSIDE));
    let profile = profile_of(&link);
    assert!(!profile.global_proxy);
    assert!(profile.fake_dns);
    assert_eq!(profile.dns_hosts, 2);
    let routes: Vec<Route> = profile.entries.iter().map(|e| e.route).collect();
    assert_eq!(
        routes[0],
        Route::Direct,
        "block-direct-proxy: no block entries"
    );
    assert_eq!(
        profile.entries[0].entry,
        Entry::Geoip("private-fakedns".into())
    );
    assert_eq!(
        profile.entries[1].entry,
        Entry::Domain("connectivitycheck.gstatic.com".into())
    );
    assert_eq!(profile.entries[3].entry, Entry::Geosite("list".into()));
    assert_eq!(profile.entries.len(), 15);
    assert!(profile.entries[1..].iter().all(|e| e.route == Route::Proxy));
}

/// A published link, verbatim: proxy only the listed sets, block-direct-proxy.
#[test]
fn refilter_link_verbatim() {
    let profile = profile_of(REFILTER_LINK);
    assert_eq!(profile.name.as_deref(), Some("Re:filter"));
    assert!(!profile.global_proxy);
    let tail: Vec<(Route, &str)> = listed(&profile).split_off(6);
    assert_eq!(
        tail,
        [
            (Route::Proxy, "geosite:refilter"),
            (Route::Proxy, "geoip:refilter")
        ]
    );
    assert_eq!(
        profile.dns,
        ["1.1.1.1", "77.88.8.8"],
        "DoU sides show their addresses"
    );
}

/// `happ://routing/off`, in any case; the routing host with an unknown verb is not a profile.
#[test]
fn off_and_unknown_verbs() {
    assert_eq!(parse_routing("happ://routing/off"), Ok(RoutingValue::Off));
    assert_eq!(parse_routing(" HAPP://Routing/OFF "), Ok(RoutingValue::Off));
    assert_eq!(
        parse_routing("happ://routing/delete/abc"),
        Err(RoutingError::NotRouting)
    );
}

/// A provider's `routing` value may be the link, its base64 (either alphabet, padded or not,
/// `%3D` for the padding) or the JSON itself.
#[test]
fn payload_forms() {
    let json = r#"{"Name":"n","DirectSites":["domain:example.ru"]}"#;
    let padded = STANDARD.encode(json);
    let forms = [
        json.to_owned(),
        padded.clone(),
        URL_SAFE_NO_PAD.encode(json),
        format!("happ://routing/add/{padded}"),
        format!("happ://routing/add/{}", padded.replace('=', "%3D")),
        format!("happ://routing/onadd/{}", json.replace('"', "%22")),
        format!("\u{feff}  happ://routing/onadd/{padded}\r\n"),
    ];
    for form in forms {
        let profile = profile_of(&form);
        assert_eq!(profile.name.as_deref(), Some("n"), "{form}");
        assert_eq!(profile.entries[0].entry, Entry::Domain("example.ru".into()));
    }
}

/// What is not a routing profile says so; a damaged link says it is damaged.
#[test]
fn refusals() {
    let cases = [
        ("hello", RoutingError::NotRouting),
        ("", RoutingError::NotRouting),
        (r#"{"outbounds":[]}"#, RoutingError::NotRouting),
        ("[1,2]", RoutingError::NotRouting),
        ("vless://u@h.example:443", RoutingError::NotRouting),
        ("happ://routing/onadd/", RoutingError::Damaged),
        ("happ://routing/onadd/%%%", RoutingError::Damaged),
        ("happ://routing/add/bm90IGpzb24=", RoutingError::Damaged),
        ("happ://routing/add/eyJOYW1lIjo=", RoutingError::Damaged),
    ];
    for (value, want) in cases {
        assert_eq!(parse_routing(value), Err(want), "{value}");
    }
    let huge = format!("happ://routing/add/{}", "A".repeat(MAX_PROFILE_BYTES));
    assert_eq!(parse_routing(&huge), Err(RoutingError::TooLarge));
    assert_eq!(RoutingError::Damaged.msg().key, "profiles.routing.damaged");
}

/// Xray's site syntax, prefixes in any case; any other text is a plain site.
#[test]
fn site_entries() {
    let cases = [
        ("domain:Example.COM", Entry::Domain("example.com".into())),
        (
            "full:www.example.com",
            Entry::Full("www.example.com".into()),
        ),
        ("keyword:Goo", Entry::Keyword("goo".into())),
        (r"regexp:^a\.b$", Entry::Regexp(r"^a\.b$".into())),
        ("GEOSITE:Category-RU", Entry::Geosite("category-ru".into())),
        ("geosite:google@cn", Entry::Geosite("google@cn".into())),
        (
            "ext:custom.dat:tag",
            Entry::External("custom.dat:tag".into()),
        ),
        ("Example.com", Entry::Plain("example.com".into())),
        (
            "https://x.example/p",
            Entry::Plain("https://x.example/p".into()),
        ),
        ("пример.рф", Entry::Plain("пример.рф".into())),
    ];
    for (raw, want) in cases {
        assert_eq!(site(raw), want, "{raw}");
    }
}

/// IP entries: `geoip:`, `ext:`, addresses and ranges (host bits dropped), anything else unknown.
#[test]
fn ip_entries() {
    let cases = [
        ("geoip:RU", Entry::Geoip("ru".into())),
        ("geoip:!cn", Entry::Geoip("!cn".into())),
        ("ext:ip.dat:tag", Entry::External("ip.dat:tag".into())),
        ("10.0.0.1/8", net("10.0.0.0/8")),
        ("8.8.8.8", net("8.8.8.8/32")),
        ("2001:db8::/32", net("2001:db8::/32")),
        ("::1", net("::1/128")),
        ("example.com", Entry::Unknown("example.com".into())),
    ];
    for (raw, want) in cases {
        assert_eq!(ip(raw), want, "{raw}");
    }
}

/// Every non-blank item is listed: numbers and objects as unknown entries, a list sent as one
/// string as one entry, an overlong entry cut for the preview.
#[test]
fn odd_lists_stay_visible() {
    let long = "a".repeat(MAX_ENTRY_BYTES + 10);
    let json = serde_json::json!({
        "BlockSites": ["", "  ", 7, {"x": 1}, long],
        "ProxySites": "domain:one.example",
        "DirectSites": null,
    })
    .to_string();
    let profile = profile_of(&json);
    let kinds: Vec<&Entry> = profile.entries.iter().map(|e| &e.entry).collect();
    assert_eq!(kinds.len(), 4);
    assert_eq!(kinds[0], &Entry::Unknown("7".into()));
    assert_eq!(kinds[1], &Entry::Unknown(r#"{"x":1}"#.into()));
    assert!(matches!(kinds[2], Entry::Unknown(cut) if cut.ends_with('…')));
    assert!(profile.entries[2].raw.len() <= MAX_ENTRY_BYTES + '…'.len_utf8());
    assert_eq!(kinds[3], &Entry::Domain("one.example".into()));
}

/// RouteOrder: any order of the three words; anything else is block, proxy, direct.
#[test]
fn route_orders() {
    use Route::{Block, Direct, Proxy};
    assert_eq!(
        route_order(Some("direct-proxy-block")),
        [Direct, Proxy, Block]
    );
    assert_eq!(
        route_order(Some(" Block-Direct-Proxy ")),
        [Block, Direct, Proxy]
    );
    for odd in [
        None,
        Some("block-block-proxy"),
        Some("block-proxy"),
        Some("x"),
        Some(""),
    ] {
        assert_eq!(route_order(odd), [Block, Proxy, Direct], "{odd:?}");
    }
}

/// Switches written as JSON bools read like Happ's strings; unknown words keep the default.
#[test]
fn switches() {
    let profile = profile_of(r#"{"GlobalProxy": false, "FakeDNS": true, "DirectIp": []}"#);
    assert!(!profile.global_proxy && profile.fake_dns);
    let profile = profile_of(r#"{"GlobalProxy": "maybe", "FakeDNS": "1"}"#);
    assert!(profile.global_proxy && profile.fake_dns);
}

/// A routing link is no subscription (the add flow names the Apps page), and this reader takes
/// the same link.
#[test]
fn deeplink_refers_routing_links_here() {
    use crate::deeplink::{DeepLinkError, unwrap_deeplink};
    for link in [DOC_SAMPLE_LINK, REFILTER_LINK, "happ://routing/off"] {
        assert_eq!(unwrap_deeplink(link), Err(DeepLinkError::RoutingProfile));
        assert!(parse_routing(link).is_ok(), "{link}");
    }
    crate::test_locales::assert_localized(&DeepLinkError::RoutingProfile.msg().key);
    for err in [
        RoutingError::NotRouting,
        RoutingError::Damaged,
        RoutingError::TooLarge,
    ] {
        crate::test_locales::assert_localized(&err.msg().key);
    }
}
