use std::sync::atomic::{AtomicU32, Ordering};

use super::*;
use crate::live_stages::CANCELLED;

const IPAPI_OK: &str = r#"{"ip":"198.51.100.10","asn":"AS64500","org":"Example Hosting","network":"198.51.100.0/24","country":"DE","country_name":"Germany","country_code":"DE"}"#;
const IPWHO_OK: &str = r#"{"success":true,"country":"Netherlands","country_code":"NL","connection":{"asn":64501,"org":"Org","isp":"Example ISP"}}"#;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn parses_providers() {
    let Outcome::Found(info) = parse_ipapi(Fetch::Http(200, IPAPI_OK.into())) else {
        panic!("ipapi answer not parsed")
    };
    assert_eq!(
        (
            info.asn.as_str(),
            info.country.as_str(),
            info.country_code.as_deref()
        ),
        ("AS64500", "Germany", Some("DE"))
    );
    assert_eq!(info.network, "198.51.100.0/24");
    assert!(matches!(
        parse_ipapi(Fetch::Http(429, String::new())),
        Outcome::Retry(_)
    ));
    assert!(matches!(
        parse_ipapi(Fetch::Http(503, String::new())),
        Outcome::Retry(_)
    ));
    assert!(matches!(parse_ipapi(Fetch::Timeout), Outcome::Retry(_)));
    assert!(matches!(
        parse_ipapi(Fetch::Network("dns error".into())),
        Outcome::Retry(_)
    ));
    assert_eq!(
        parse_ipapi(Fetch::Http(404, String::new())),
        Outcome::Fail("HTTP 404".into())
    );
    let reserved = r#"{"error":true,"reason":"Reserved IP Address"}"#;
    assert_eq!(
        parse_ipapi(Fetch::Http(200, reserved.into())),
        Outcome::Fail("Reserved IP Address".into())
    );
    let limited = r#"{"error":true,"reason":"RateLimited"}"#;
    assert!(matches!(
        parse_ipapi(Fetch::Http(200, limited.into())),
        Outcome::Retry(_)
    ));
    let Outcome::Found(info) = parse_ipwho(Fetch::Http(200, IPWHO_OK.into())) else {
        panic!("ipwho answer not parsed")
    };
    assert_eq!(
        (
            info.asn.as_str(),
            info.org.as_str(),
            info.country_code.as_deref()
        ),
        ("AS64501", "Example ISP", Some("NL"))
    );
    let failed = r#"{"success":false,"message":"Invalid IP address"}"#;
    assert_eq!(
        parse_ipwho(Fetch::Http(200, failed.into())),
        Outcome::Fail("Invalid IP address".into())
    );
}

/// AT-05-001 / B-28: fallback after a rate limit, answers cached, a 429 backs the provider off.
#[tokio::test]
async fn falls_back_caches_and_backs_off() {
    let cache = GeoCache::new().unwrap();
    let calls = AtomicU32::new(0);
    let cancel = CancellationToken::new();
    let fetch = |p: Provider, _ip: IpAddr| {
        calls.fetch_add(1, Ordering::Relaxed);
        async move {
            match p {
                Provider::IpApi => Fetch::Http(429, "Too Many Requests".into()),
                Provider::IpWhoIs => Fetch::Http(200, IPWHO_OK.into()),
            }
        }
    };
    let info = lookup_with(&cache, ip("198.51.100.10"), &cancel, fetch)
        .await
        .unwrap();
    assert_eq!(info.asn, "AS64501");
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    lookup_with(&cache, ip("198.51.100.10"), &cancel, fetch)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 2, "cached");
    lookup_with(&cache, ip("198.51.100.11"), &cancel, fetch)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::Relaxed),
        3,
        "ipapi skipped while backing off"
    );
}

/// B-28: a definite ipapi failure is final; a cancelled lookup is never cached.
#[tokio::test]
async fn final_failures_and_cancel() {
    let cache = GeoCache::new().unwrap();
    let calls = AtomicU32::new(0);
    let cancel = CancellationToken::new();
    let err = lookup_with(&cache, ip("198.51.100.10"), &cancel, |_, _| {
        calls.fetch_add(1, Ordering::Relaxed);
        async { Fetch::Http(404, String::new()) }
    })
    .await
    .unwrap_err();
    assert_eq!(
        (err.as_str(), calls.load(Ordering::Relaxed)),
        ("HTTP 404", 1)
    );
    cancel.cancel();
    let ok = |_, _| async { Fetch::Http(200, IPAPI_OK.into()) };
    let err = lookup_with(&cache, ip("198.51.100.10"), &cancel, ok)
        .await
        .unwrap_err();
    assert_eq!(err, CANCELLED);
    assert!(cache.cached(ip("198.51.100.10")).is_none());
}

/// formatInfrastructureError vectors, as message keys (§7.12).
#[test]
fn geo_error_messages() {
    let key = |e: &str| geo_error_msg(e).key.into_owned();
    assert_eq!(
        key("Request failed with status code 429"),
        "probes.liveStages.geo.rateLimited"
    );
    assert_eq!(key("RateLimited"), "probes.liveStages.geo.rateLimited");
    assert_eq!(
        key("getaddrinfo ENOTFOUND ipapi.co"),
        "probes.liveStages.geo.unreachable"
    );
    assert_eq!(key("User aborted probe"), "probes.liveStages.geo.cancelled");
    let other = geo_error_msg("Reserved IP Address");
    assert_eq!(other.key, "probes.liveStages.geo.failed");
    assert_eq!(other.args[0].1, "Reserved IP Address");
}

/// The /24 hint skips the same host and IPv6 and names an unnamed profile by its server.
#[test]
fn shared_cidr_hint() {
    let other = |name: &str, server: &str, addr: &str| OtherProfile {
        name: name.into(),
        server: server.into(),
        resolved_ip: Some(ip(addr)),
    };
    let others = [
        other("Frankfurt 2", "fra2.example", "198.51.100.20"),
        other("", "fra3.example", "198.51.100.30"),
        other("Same host", "fra1.example", "198.51.100.10"),
        other("Elsewhere", "ams.example", "203.0.113.5"),
    ];
    let hint = shared_cidr(ip("198.51.100.10"), "fra1.example", &others);
    assert_eq!(hint, ["Frankfurt 2", "fra3.example"]);
    assert!(shared_cidr(ip("2001:db8::1"), "fra1.example", &others).is_empty());
}

#[test]
fn assembles_the_section() {
    let addr = Some(ip("198.51.100.10"));
    let off = assemble(false, None, addr, "h", Some("DE".into()), &[]);
    assert_eq!(
        (off.status, off.reason),
        (TimedStatus::NotChecked, Some(NotCheckedReason::GeoDisabled))
    );
    assert_eq!(off.endpoint_country.as_deref(), Some("DE"));
    let asn = AsnInfo {
        country: "Germany".into(),
        ..AsnInfo::default()
    };
    let ok = assemble(
        true,
        Some(Ok(asn)),
        addr,
        "h",
        Some("Deutschland".into()),
        &[],
    );
    assert_eq!(
        (ok.status, ok.endpoint_country.as_deref()),
        (TimedStatus::Ok, Some("Germany"))
    );
    let failed = assemble(true, Some(Err("timeout".into())), None, "h", None, &[]);
    assert_eq!(failed.status, TimedStatus::Error);
    assert!(
        matches!(failed.error, Some(Text::Msg(ref m)) if m.key == "probes.liveStages.geo.unreachable")
    );
    let cancelled = assemble(true, Some(Err(CANCELLED.into())), None, "h", None, &[]);
    assert_eq!(cancelled.status, TimedStatus::Skipped);
}

/// Imported rows: the dropped profile-cache egress fields are ignored.
#[test]
fn reads_legacy_infrastructure() {
    let row = r#"{"status":"ok","asn":{"asn":"AS1","org":"o","network":"","country":"Germany"},
            "egressSource":"profile-cache","egressObservedAt":null,"egressIp":"198.51.100.1",
            "activeTunnelMatchesProfile":true,"sharedCidrWithProfiles":["x"],
            "changesFromPrevious":{"ipChanged":true,"pmtuChanged":false}}"#;
    let infra: Infrastructure = serde_json::from_str(row).unwrap();
    assert_eq!(infra.asn.unwrap().country_code, None);
    assert_eq!(infra.changes_from_previous.unwrap().ip_changed, Some(true));
    assert_eq!(infra.shared_cidr_with_profiles, ["x"]);
}
