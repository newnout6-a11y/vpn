//! Geo tests with a scripted fetcher (servers §7 vectors 25-29; serverPickerGeoLifecycle.test.ts,
//! serverPickerGeoTransport.test.ts; AT-07-007, AT-00-003).
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::future::BoxFuture;
use serde_json::{Value, json};
use tokio::time::Instant;
use vpnte_core::net::Route;
use vpnte_core::settings::{BootstrapRouteMode, ProxyOverride, Settings};

use super::providers::{
    Fault, JsonGet, Provider, backoff, is_https_geo_url, parse_retry_after, vote,
};
use super::*;

const FAST: Timing = Timing {
    deadline: Duration::from_millis(300),
    poll: Duration::from_millis(5),
    found_ttl: Duration::from_millis(250),
    empty_ttl: Duration::from_millis(60),
};

type Script = dyn Fn(usize, &str) -> (Duration, Result<Value, Fault>) + Send + Sync;

/// Answers by URL (and call number) after a delay; counts calls and abandoned requests.
struct Fake {
    calls: AtomicUsize,
    dropped: Arc<AtomicUsize>,
    script: Box<Script>,
}

struct Unfinished(Arc<AtomicUsize>, bool);

impl Drop for Unfinished {
    fn drop(&mut self) {
        if !self.1 {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl JsonGet for Fake {
    fn get<'a>(
        &'a self,
        url: String,
        _: &'a [Route],
        deadline: Instant,
    ) -> BoxFuture<'a, Result<Value, Fault>> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        let (delay, answer) = (self.script)(n, &url);
        let dropped = self.dropped.clone();
        Box::pin(async move {
            let mut guard = Unfinished(dropped, false);
            let done_at = Instant::now() + delay;
            if done_at > deadline {
                // Cut at the deadline (as the HTTP timeout would): counted as abandoned.
                tokio::time::sleep_until(deadline).await;
                return Err(Fault::Failed);
            }
            tokio::time::sleep_until(done_at).await;
            guard.1 = true;
            answer
        })
    }
}

fn scripted(
    script: impl Fn(usize, &str) -> (Duration, Result<Value, Fault>) + Send + Sync + 'static,
) -> (Geo, Arc<Fake>) {
    let fake = Arc::new(Fake {
        calls: AtomicUsize::new(0),
        dropped: Arc::new(AtomicUsize::new(0)),
        script: Box::new(script),
    });
    (Geo::build(true, fake.clone(), FAST), fake)
}

/// Every provider says `code` (geojs in its array form).
fn all_say(
    code: &'static str,
    delay: Duration,
) -> impl Fn(usize, &str) -> (Duration, Result<Value, Fault>) {
    move |_, url| (delay, Ok(body_for(url, code)))
}

fn body_for(url: &str, code: &str) -> Value {
    let ip = url
        .split(['=', '/'])
        .find_map(|p| p.parse::<IpAddr>().ok())
        .unwrap();
    if url.contains("geojs") {
        json!([{ "ip": ip.to_string(), "country": code, "name": "x" }])
    } else if url.contains("ipwho.is") {
        json!({ "success": true, "country_code": code })
    } else {
        json!({ "country": code })
    }
}

struct Owner {
    current: AtomicBool,
    switching: bool,
    active: bool,
}

fn owner() -> Arc<Owner> {
    Arc::new(Owner {
        current: AtomicBool::new(true),
        switching: false,
        active: true,
    })
}

impl LookupOwner for Owner {
    fn is_current(&self) -> bool {
        self.current.load(Ordering::SeqCst)
    }
    fn switching(&self) -> bool {
        self.switching
    }
    fn has_active(&self) -> bool {
        self.active
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn iso(code: &str) -> Option<Iso2> {
    Iso2::new(code)
}

/// Vector 29: majority vote, ties by the fixed priority geojs > ipinfo.io > ipwho.is.
#[test]
fn vote_vectors() {
    let (g, i, w) = (Provider::GeoJs, Provider::IpInfoIo, Provider::IpWhoIs);
    assert_eq!(
        vote(&[(g, iso("NL")), (i, iso("NL")), (w, iso("DE"))]),
        iso("NL")
    );
    assert_eq!(
        vote(&[(g, iso("NL")), (i, iso("DE")), (w, None)]),
        iso("NL")
    );
    assert_eq!(
        vote(&[(g, None), (i, iso("DE")), (w, iso("FR"))]),
        iso("DE")
    );
    assert_eq!(
        vote(&[(g, iso("DE")), (i, iso("FR")), (w, iso("FR"))]),
        iso("FR")
    );
    assert_eq!(vote(&[(g, None), (i, None), (w, None)]), None);
}

/// Vector 26 body plus the other providers' shapes.
#[test]
fn provider_answers() {
    let doc = ip("198.51.100.20");
    let geojs = json!([{ "ip": "198.51.100.20", "country": "NO", "name": "Norway" }]);
    assert_eq!(Provider::GeoJs.country(doc, &geojs), iso("NO"));
    assert_eq!(
        Provider::GeoJs.country(ip("8.8.8.8"), &geojs),
        None,
        "row of another IP"
    );
    let single = json!({ "ip": "8.8.8.8", "country": "US" });
    assert_eq!(Provider::GeoJs.country(ip("8.8.8.8"), &single), iso("US"));
    assert_eq!(
        Provider::GeoJs.country(doc, &json!([{ "ip": "198.51.100.20", "country": "" }])),
        None
    );
    assert_eq!(
        Provider::IpInfoIo.country(doc, &json!({ "country": "de" })),
        iso("DE")
    );
    assert_eq!(
        Provider::IpWhoIs.country(doc, &json!({ "success": false, "country_code": "DE" })),
        None
    );
    assert_eq!(
        Provider::IpWhoIs.country(doc, &json!({ "success": true, "country_code": "NL" })),
        iso("NL")
    );
    assert_eq!(
        Provider::IpInfoIo.country(doc, &json!({ "country": "XX" })),
        None
    );
    for p in [
        Provider::GeoJs,
        Provider::IpInfoIo,
        Provider::IpWhoIs,
        Provider::IpApiCo,
    ] {
        assert!(is_https_geo_url(&p.url(doc)));
    }
}

/// Vector 25: HTTPS gate of lookup URLs.
#[test]
fn https_gate() {
    assert!(is_https_geo_url(
        "https://get.geojs.io/v1/ip/country.json?ip=8.8.8.8"
    ));
    assert!(is_https_geo_url("https://ipwho.is/8.8.8.8"));
    for bad in [
        "http://ip-api.com/batch?fields=status,country",
        "http://get.geojs.io/v1/ip/country.json",
        "ftp://example.com/x",
        "file:///c:/windows/win.ini",
        "//get.geojs.io/v1/ip/country.json",
        "get.geojs.io/v1/ip/country.json",
        "",
        "http://evil.example/?u=https://get.geojs.io",
        "http://https.example.com/lookup",
    ] {
        assert!(!is_https_geo_url(bad), "{bad}");
    }
}

/// Vector 28: 429 backoff and `Retry-After`.
#[test]
fn backoff_vectors() {
    let now = jiff::Timestamp::now();
    assert_eq!(
        backoff(1, parse_retry_after("120", now)),
        Duration::from_secs(120)
    );
    assert_eq!(
        backoff(1, parse_retry_after("invalid", now)),
        Duration::from_secs(60)
    );
    let in_two_minutes = (now + jiff::SignedDuration::from_secs(120))
        .strftime("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    let parsed = parse_retry_after(&in_two_minutes, now).unwrap();
    assert!(
        parsed <= Duration::from_secs(120) && parsed >= Duration::from_secs(118),
        "{parsed:?}"
    );
    assert_eq!(backoff(1, Some(parsed)).as_secs().div_ceil(10), 12);
    assert!(backoff(2, None) >= Duration::from_secs(120));
    assert_eq!(backoff(9, None), Duration::from_secs(15 * 60));
    assert_eq!(
        backoff(1, Some(Duration::from_secs(86_400))),
        Duration::from_secs(3600)
    );
    let past = (now - jiff::SignedDuration::from_secs(60))
        .strftime("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    assert_eq!(
        backoff(1, parse_retry_after(&past, now)),
        Duration::from_secs(60)
    );
}

/// Vector 26: 50 concurrent lookups of one IP share one wave (3 requests) and the cache; after
/// the cache life a new wave runs.
#[tokio::test]
async fn one_wave_for_concurrent_callers() {
    let (geo, fake) = scripted(all_say("NO", Duration::from_millis(30)));
    let lookups = (0..50).map(|_| geo.country(ip("8.8.8.8"), vec![Route::Direct], owner()));
    let answers = join_all(lookups).await;
    assert!(answers.iter().all(|a| *a == iso("NO")));
    assert_eq!(fake.calls.load(Ordering::SeqCst), 3);
    assert_eq!(geo.country(ip("8.8.8.8"), vec![], owner()).await, iso("NO"));
    assert_eq!(fake.calls.load(Ordering::SeqCst), 3, "cached");
    tokio::time::sleep(FAST.found_ttl).await;
    assert_eq!(geo.country(ip("8.8.8.8"), vec![], owner()).await, iso("NO"));
    assert_eq!(fake.calls.load(Ordering::SeqCst), 6);
}

/// Disabled: no request even with a cached answer; non-public input: no request at all.
#[tokio::test]
async fn disabled_or_private_makes_no_request() {
    let (geo, fake) = scripted(all_say("NO", Duration::ZERO));
    assert_eq!(geo.country(ip("1.1.1.1"), vec![], owner()).await, iso("NO"));
    geo.set_enabled(false);
    assert_eq!(geo.country(ip("1.1.1.1"), vec![], owner()).await, None);
    assert_eq!(
        geo.verify_exit(ip("1.1.1.1"), vec![], owner()).await,
        Err(VerifyReject::GeoDisabled)
    );
    geo.set_enabled(true);
    let before = fake.calls.load(Ordering::SeqCst);
    for private in ["10.0.0.1", "127.0.0.1", "192.0.2.1", "fd00::1"] {
        assert_eq!(geo.country(ip(private), vec![], owner()).await, None);
        assert_eq!(
            geo.verify_exit(ip(private), vec![], owner()).await,
            Err(VerifyReject::InvalidIp)
        );
    }
    assert_eq!(fake.calls.load(Ordering::SeqCst), before);
}

/// A completed read without a country is cached briefly; failures are not cached at all.
#[tokio::test]
async fn empty_and_failed_reads() {
    let (geo, fake) = scripted(|_, _| (Duration::ZERO, Ok(json!({ "success": false }))));
    assert_eq!(geo.country(ip("8.8.4.4"), vec![], owner()).await, None);
    assert_eq!(geo.country(ip("8.8.4.4"), vec![], owner()).await, None);
    assert_eq!(
        fake.calls.load(Ordering::SeqCst),
        3,
        "completed-empty cached briefly"
    );
    tokio::time::sleep(FAST.empty_ttl).await;
    assert_eq!(geo.country(ip("8.8.4.4"), vec![], owner()).await, None);
    assert_eq!(
        fake.calls.load(Ordering::SeqCst),
        6,
        "retried after the short life"
    );

    let (geo, fake) = scripted(|_, _| (Duration::ZERO, Err(Fault::Failed)));
    assert_eq!(geo.country(ip("9.9.9.9"), vec![], owner()).await, None);
    assert_eq!(geo.country(ip("9.9.9.9"), vec![], owner()).await, None);
    assert_eq!(
        fake.calls.load(Ordering::SeqCst),
        6,
        "failures are never cached"
    );
}

/// Hung providers: `None` at the deadline, every request abandoned; providers run in parallel.
#[tokio::test]
async fn deadline_and_parallel_providers() {
    let (geo, fake) = scripted(all_say("NO", Duration::from_secs(10)));
    let started = Instant::now();
    assert_eq!(geo.country(ip("8.8.8.8"), vec![], owner()).await, None);
    let took = started.elapsed();
    assert!(
        took >= FAST.deadline && took < FAST.deadline * 3,
        "{took:?}"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(fake.dropped.load(Ordering::SeqCst), 3);

    let (geo, _) = scripted(|_, url| {
        let delay = if url.contains("geojs") {
            150
        } else if url.contains("ipinfo") {
            200
        } else {
            0
        };
        (Duration::from_millis(delay), Ok(body_for(url, "SE")))
    });
    let started = Instant::now();
    assert_eq!(geo.country(ip("8.8.8.8"), vec![], owner()).await, iso("SE"));
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(195) && took < Duration::from_millis(290),
        "{took:?}"
    );
}

/// An obsolete owner gets `None` within a poll tick and the read is abandoned; a still-current
/// caller keeps the shared read alive.
#[tokio::test]
async fn owners_decide_the_shared_read() {
    let (geo, fake) = scripted(all_say("NO", Duration::from_millis(120)));
    let stale = owner();
    let flag = stale.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        flag.current.store(false, Ordering::SeqCst);
    });
    let started = Instant::now();
    assert_eq!(
        geo.country(ip("8.8.8.8"), vec![], stale.clone()).await,
        None
    );
    assert!(started.elapsed() < Duration::from_millis(80));
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(fake.dropped.load(Ordering::SeqCst), 3, "abandoned read");

    let (geo, fake) = scripted(all_say("NO", Duration::from_millis(120)));
    let stale = owner();
    let flag = stale.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        flag.current.store(false, Ordering::SeqCst);
    });
    let (a, b) = tokio::join!(
        geo.country(ip("8.8.8.8"), vec![], stale),
        geo.country(ip("8.8.8.8"), vec![], owner())
    );
    assert_eq!((a, b), (None, iso("NO")));
    assert_eq!(fake.calls.load(Ordering::SeqCst), 3);
}

/// A late, abandoned wave cannot overwrite a newer read of the same IP.
#[tokio::test]
async fn abandoned_wave_never_writes() {
    let (geo, _) = scripted(|n, url| {
        if n < 3 {
            (Duration::from_millis(150), Ok(body_for(url, "DE")))
        } else {
            (Duration::ZERO, Ok(body_for(url, "NL")))
        }
    });
    let stale = owner();
    let flag = stale.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        flag.current.store(false, Ordering::SeqCst);
    });
    assert_eq!(geo.country(ip("8.8.8.8"), vec![], stale).await, None);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(geo.country(ip("8.8.8.8"), vec![], owner()).await, iso("NL"));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(geo.country(ip("8.8.8.8"), vec![], owner()).await, iso("NL"));
}

/// Exit verification guard order (serverPicker.ts:1517-1542; serverPickerSwitch.test.ts).
#[tokio::test]
async fn exit_verification_guards() {
    let (geo, _) = scripted(all_say("FI", Duration::from_millis(40)));
    let exit = ip("95.216.1.1");
    assert_eq!(
        geo.verify_exit(exit, vec![], owner()).await,
        Ok(iso("FI").unwrap())
    );
    let switching = Arc::new(Owner {
        current: AtomicBool::new(true),
        switching: true,
        active: true,
    });
    assert_eq!(
        geo.verify_exit(exit, vec![], switching).await,
        Err(VerifyReject::SwitchInProgress)
    );
    let none = Arc::new(Owner {
        current: AtomicBool::new(true),
        switching: false,
        active: false,
    });
    assert_eq!(
        geo.verify_exit(exit, vec![], none).await,
        Err(VerifyReject::NoActiveProfile)
    );
    let stale = owner();
    stale.current.store(false, Ordering::SeqCst);
    assert_eq!(
        geo.verify_exit(exit, vec![], stale).await,
        Err(VerifyReject::Superseded)
    );

    let late = owner();
    let flag = late.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(15)).await;
        flag.current.store(false, Ordering::SeqCst);
    });
    assert_eq!(
        geo.verify_exit(ip("95.216.2.2"), vec![], late).await,
        Err(VerifyReject::Superseded)
    );
    let off = geo.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(15)).await;
        off.set_enabled(false);
    });
    assert_eq!(
        geo.verify_exit(ip("95.216.3.3"), vec![], owner()).await,
        Err(VerifyReject::GeoDisabled)
    );
    geo.set_enabled(true);
    let (empty, _) = scripted(|_, _| (Duration::ZERO, Ok(json!({}))));
    assert_eq!(
        empty.verify_exit(exit, vec![], owner()).await,
        Err(VerifyReject::LookupFailed)
    );
}

/// A 429 puts the provider into backoff: the next wave skips it, the others still vote.
#[tokio::test]
async fn rate_limited_provider_is_skipped() {
    let geojs = Arc::new(AtomicUsize::new(0));
    let seen = geojs.clone();
    let (geo, _) = scripted(move |_, url| {
        if url.contains("geojs") {
            seen.fetch_add(1, Ordering::SeqCst);
            (
                Duration::ZERO,
                Err(Fault::RateLimited(Some(Duration::from_secs(120)))),
            )
        } else {
            (Duration::ZERO, Ok(body_for(url, "PL")))
        }
    });
    assert_eq!(geo.country(ip("8.8.8.8"), vec![], owner()).await, iso("PL"));
    assert_eq!(geo.country(ip("1.0.0.1"), vec![], owner()).await, iso("PL"));
    assert_eq!(geojs.load(Ordering::SeqCst), 1);
}

/// Routes: TUN running + auto → direct only; otherwise direct, the own proxy, 10808, 10809
/// (deduplicated); `localProxy` drops direct, `direct` drops proxies.
#[test]
fn routes_by_mode() {
    let labels = |routes: Vec<Route>| routes.iter().map(Route::label).collect::<Vec<_>>();
    let mut s = Settings::default();
    assert_eq!(labels(geo_routes(&s, true)), ["direct"]);
    assert_eq!(
        labels(geo_routes(&s, false)),
        [
            "direct",
            "socks5h://127.0.0.1:10808",
            "http://127.0.0.1:10809"
        ]
    );
    s.proxy_override = Some(ProxyOverride::parse("127.0.0.1:10808").unwrap().0);
    s.bootstrap_route_mode = BootstrapRouteMode::LocalProxy;
    assert_eq!(
        labels(geo_routes(&s, true)),
        ["socks5h://127.0.0.1:10808", "http://127.0.0.1:10809"]
    );
    s.proxy_override = Some(ProxyOverride::parse("127.0.0.1:2080").unwrap().0);
    assert_eq!(
        labels(geo_routes(&s, false)),
        [
            "socks5h://127.0.0.1:2080",
            "socks5h://127.0.0.1:10808",
            "http://127.0.0.1:10809"
        ]
    );
    s.bootstrap_route_mode = BootstrapRouteMode::Direct;
    assert_eq!(labels(geo_routes(&s, false)), ["direct"]);
}

/// ASN answers: ipapi.co first, ipwho.is as fallback (servers §2.11).
#[tokio::test]
async fn asn_lookups() {
    let (geo, _) = scripted(|_, url| {
        if url.contains("ipapi.co") {
            (
                Duration::ZERO,
                Ok(
                    json!({ "asn": "AS13335", "org": "Cloudflare", "network": "1.1.1.0/24", "country_name": "Australia" }),
                ),
            )
        } else {
            (Duration::ZERO, Err(Fault::Failed))
        }
    });
    let cancel = CancellationToken::new();
    let info = geo.asn(ip("1.1.1.1"), &[], &cancel).await.unwrap();
    assert_eq!(info.asn.as_deref(), Some("AS13335"));
    assert_eq!(info.network.as_deref(), Some("1.1.1.0/24"));
    let (geo, _) = scripted(|_, url| {
        if url.contains("ipapi.co") {
            (
                Duration::ZERO,
                Ok(json!({ "error": true, "reason": "RateLimited" })),
            )
        } else {
            (
                Duration::ZERO,
                Ok(
                    json!({ "success": true, "country": "Germany", "connection": { "asn": 24940, "isp": "Hetzner" } }),
                ),
            )
        }
    });
    let info = geo.asn(ip("95.216.1.1"), &[], &cancel).await.unwrap();
    assert_eq!(
        (info.asn.as_deref(), info.org.as_deref(), info.network),
        (Some("AS24940"), Some("Hetzner"), None)
    );
    assert_eq!(info.country.as_deref(), Some("Germany"));
    let (geo, fake) = scripted(|_, _| (Duration::ZERO, Ok(json!({ "success": false }))));
    assert_eq!(geo.asn(ip("95.216.1.1"), &[], &cancel).await, None);
    geo.set_enabled(false);
    let before = fake.calls.load(Ordering::SeqCst);
    assert_eq!(geo.asn(ip("95.216.1.1"), &[], &cancel).await, None);
    assert_eq!(
        fake.calls.load(Ordering::SeqCst),
        before,
        "disabled: no ASN request"
    );
}
