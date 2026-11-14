use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vpnte_core::settings::ProxyOverride;

use super::fetch::{FetchError, fetch_body, fetch_https};
use super::*;
use vpnte_base::types::Engine;

use crate::routing::smart_ru::{GEOIP_RU, GOV_RU, RU_BLOCKED_IPS, RU_BLOCKED_SITES};
use crate::singbox_process::child::run_once;
use crate::test_support::{TempDir, resources, singbox_exe};

fn service(t: &TempDir) -> RuleSetService {
    let store = Arc::new(Store::<RuleSetsDoc>::open(t.path()));
    RuleSetService::with_paths(store, t.path().join("rulesets"), resources())
}

fn bundled(file: &str) -> Vec<u8> {
    std::fs::read(resources().join(file)).unwrap()
}

/// §2.2 route attempts per `bootstrapRouteMode` (the verifier's correction: `localProxy`
/// never tries direct, `useProxy = false` forces direct), user proxy first, duplicates out;
/// managed updates every 24 h by default (re-check item 12a).
#[test]
fn download_routes() {
    let mut cfg = RefreshSettings::from_settings(&Settings::default());
    assert_eq!(
        (cfg.managed, cfg.auto_update, cfg.use_proxy, cfg.interval_h),
        (true, true, true, 24)
    );
    assert_eq!(cfg.session, None);
    let kinds = |c: &RefreshSettings| c.routes().into_iter().map(|(k, _)| k).collect::<Vec<_>>();
    assert_eq!(
        kinds(&cfg),
        [RouteKind::Direct, RouteKind::HappSocks, RouteKind::HappHttp]
    );
    assert_eq!(cfg.routes()[1].1.label(), "socks5h://127.0.0.1:10808");
    assert_eq!(cfg.routes()[2].1.label(), "http://127.0.0.1:10809");
    let (proxy, _) = ProxyOverride::parse("127.0.0.1:2080").unwrap();
    cfg.user_proxy = Some(proxy.route(ProxyKind::Socks5));
    assert_eq!(
        kinds(&cfg),
        [
            RouteKind::Direct,
            RouteKind::UserProxy,
            RouteKind::HappSocks,
            RouteKind::HappHttp
        ]
    );
    cfg.bootstrap = BootstrapRouteMode::LocalProxy;
    assert_eq!(
        kinds(&cfg),
        [
            RouteKind::UserProxy,
            RouteKind::HappSocks,
            RouteKind::HappHttp
        ]
    );
    cfg.bootstrap = BootstrapRouteMode::Direct;
    assert_eq!(kinds(&cfg), [RouteKind::Direct]);
    cfg.bootstrap = BootstrapRouteMode::Auto;
    cfg.use_proxy = false;
    assert_eq!(kinds(&cfg), [RouteKind::Direct]);
    cfg.use_proxy = true;
    let (happ, _) = ProxyOverride::parse("socks5://127.0.0.1:10808").unwrap();
    cfg.user_proxy = Some(happ.route(ProxyKind::Socks5));
    assert_eq!(
        kinds(&cfg),
        [RouteKind::Direct, RouteKind::UserProxy, RouteKind::HappHttp]
    );
    cfg.managed = false;
    assert!(
        !cfg.auto_refresh(true),
        "bundled mode never refreshes by itself"
    );
    cfg.managed = true;
    assert!(cfg.auto_refresh(true) && !cfg.auto_refresh(false));
    // bootstrapRoute.ts:21-30 vectors, now enforced by the settings' proxy grammar.
    assert!(ProxyOverride::parse("socks5://127.0.0.1:1080").is_ok());
    assert!(ProxyOverride::parse("host").is_err());
    assert!(ProxyOverride::parse("h:70000").is_err());
}

/// Re-check item 12c: the running session's own route comes first in every mode (proxy
/// capture: its loopback inbound), then the mode's own order; "direct only" stays direct.
#[test]
fn the_session_route_is_tried_first() {
    let mut cfg = RefreshSettings::from_settings(&Settings::default());
    let inbound = HostPort::new("127.0.0.1", 20808).unwrap();
    cfg.session = Some(Route::proxy(ProxyKind::Socks5, &inbound, None));
    let kinds = |c: &RefreshSettings| c.routes().into_iter().map(|(k, _)| k).collect::<Vec<_>>();
    assert_eq!(
        kinds(&cfg),
        [
            RouteKind::Session,
            RouteKind::Direct,
            RouteKind::HappSocks,
            RouteKind::HappHttp
        ]
    );
    assert_eq!(cfg.routes()[0].1.label(), "socks5h://127.0.0.1:20808");
    cfg.use_proxy = false;
    assert_eq!(
        kinds(&cfg),
        [RouteKind::Direct],
        "the user's direct-only choice"
    );
    cfg.use_proxy = true;
    // psmart-a2/b5: «Только напрямую» / «Только через локальный proxy» are kept exactly while
    // a session runs, as for subscriptions.
    cfg.bootstrap = BootstrapRouteMode::Direct;
    assert_eq!(
        kinds(&cfg),
        [RouteKind::Direct],
        "the user's direct-only choice"
    );
    cfg.bootstrap = BootstrapRouteMode::LocalProxy;
    assert_eq!(kinds(&cfg), [RouteKind::HappSocks, RouteKind::HappHttp]);
    assert_eq!(
        RouteKind::Session.label().key.as_ref(),
        "engine.routing.ruleSets.route.session"
    );
}

/// ruleSetManager.test.ts: managed only when selected AND complete; bundled otherwise; no
/// directory at all when the bundled files are missing too (B-SR-2: Smart RU off, visibly).
#[test]
fn source_selection() {
    let t = TempDir::new("rulesets");
    let s = service(&t);
    // The unelevated selection, whatever this test process is (CI runners are elevated; the
    // elevated selection has its own test below).
    let active = |managed| s.select(managed, false).unwrap();
    assert_eq!(active(true), (ActiveSource::Bundled, resources()));
    let generation = format!("{GEN_PREFIX}1700000000000");
    let dir = t.path().join("rulesets").join(&generation);
    std::fs::create_dir_all(&dir).unwrap();
    // A generation of the old two-file layout is incomplete: the bundled set is used until the
    // next refresh brings all four.
    std::fs::write(dir.join("geoip-ru.srs"), b"x").unwrap();
    std::fs::write(dir.join("geosite-category-gov-ru.srs"), b"x").unwrap();
    s.store
        .update(|d| {
            d.current = Some(generation.clone());
            d.checks = CHECKS;
        })
        .unwrap();
    assert_eq!(
        active(true).0,
        ActiveSource::Bundled,
        "incomplete generation"
    );
    std::fs::write(dir.join("geosite-ru-blocked.srs"), b"x").unwrap();
    std::fs::write(dir.join("geoip-ru-blocked.srs"), b"x").unwrap();
    assert_eq!(
        active(false).0,
        ActiveSource::Bundled,
        "bundled mode ignores a complete cache"
    );
    let (source, path) = active(true);
    assert_eq!(
        source,
        ActiveSource::Managed {
            generation,
            since: 1_700_000_000_000
        }
    );
    assert_eq!(path, dir);
    let store = Arc::new(Store::<RuleSetsDoc>::open(t.path()));
    let no_bundle = t.path().join("none");
    let empty = RuleSetService::with_paths(store, t.path().join("rulesets"), no_bundle);
    assert_eq!(empty.select(false, false), None);
    let (source, path) = empty.select(true, false).unwrap();
    assert!(matches!(source, ActiveSource::Managed { .. }) && path == dir);
}

/// PR review 4533368399: elevated, sing-box parses the files with administrator rights from
/// user-writable folders, so only pinned bundled files are used: a complete managed generation
/// is passed over and a changed bundled file turns Smart RU off for the run (refused before it
/// is held, so nothing stays open).
#[test]
fn an_elevated_run_uses_only_pinned_bundled_rule_sets() {
    let t = TempDir::new("rulesets-pin");
    let generation = format!("{GEN_PREFIX}1700000000000");
    let managed = t.path().join("rulesets").join(&generation);
    let changed = t.path().join("bundle");
    std::fs::create_dir_all(&managed).unwrap();
    std::fs::create_dir_all(&changed).unwrap();
    for (_, file, _) in RULE_SETS {
        std::fs::write(managed.join(file), bundled(file)).unwrap();
        std::fs::write(changed.join(file), b"changed").unwrap();
    }
    let store = Arc::new(Store::<RuleSetsDoc>::open(t.path()));
    store
        .update(|d| {
            d.current = Some(generation);
            d.checks = CHECKS;
        })
        .unwrap();
    let s = RuleSetService::with_paths(store, t.path().join("rulesets"), changed);
    assert!(matches!(
        s.select(true, false),
        Some((ActiveSource::Managed { .. }, _))
    ));
    assert_eq!(s.select(true, true), None);
    assert_eq!(s.select(false, true), None);
}

/// §7.6 canaries on the bundled files, and B-SR-1 vectors: an empty file, an HTML error page,
/// an unsupported SRS version, a truncated stream and a swapped set are all rejected.
#[tokio::test]
async fn engine_validation() {
    let Some(exe) = singbox_exe() else { return };
    let t = TempDir::new("rulesets");
    let geoip = resources().join("geoip-ru.srs");
    let gov = resources().join("geosite-category-gov-ru.srs");
    assert_eq!(
        validate(&exe, &geoip, GEOIP_RU, &resources()).await,
        Some(true)
    );
    assert_eq!(validate(&exe, &gov, GOV_RU, &resources()).await, Some(true));
    assert_eq!(
        validate(&exe, &geoip, GOV_RU, &resources()).await,
        Some(false)
    );
    // Re-check item 12b: the blocked-in-Russia pair, and swapped sets refused.
    let sites = resources().join("geosite-ru-blocked.srs");
    let ips = resources().join("geoip-ru-blocked.srs");
    assert_eq!(
        validate(&exe, &sites, RU_BLOCKED_SITES, &resources()).await,
        Some(true)
    );
    assert_eq!(
        validate(&exe, &ips, RU_BLOCKED_IPS, &resources()).await,
        Some(true)
    );
    assert_eq!(
        validate(&exe, &ips, RU_BLOCKED_SITES, &resources()).await,
        Some(false)
    );
    assert_eq!(
        validate(&exe, &gov, RU_BLOCKED_SITES, &resources()).await,
        Some(false)
    );
    assert_eq!(
        validate(&exe, &geoip, RU_BLOCKED_IPS, &resources()).await,
        Some(false)
    );
    assert_eq!(
        validate(&exe, &sites, "unknown", &resources()).await,
        Some(false)
    );
    let truncated = bundled("geoip-ru.srs")[..2000].to_vec();
    for (name, bytes) in [
        ("empty.srs", Vec::new()),
        ("html.srs", b"<html>404</html>".to_vec()),
        ("v9.srs", b"SRS\x09abc".to_vec()),
        ("truncated.srs", truncated),
    ] {
        let p = t.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        assert_eq!(
            validate(&exe, &p, GEOIP_RU, &resources()).await,
            Some(false),
            "{name}"
        );
    }
    assert_eq!(
        validate(
            &t.path().join("no-engine.exe"),
            &geoip,
            GEOIP_RU,
            &resources()
        )
        .await,
        None
    );
}

/// Serves the bundled bytes, or `bad` for the file named in `broken`.
fn fake(
    broken: Option<&'static str>,
    bad: Option<Vec<u8>>,
) -> impl AsyncFn(&'static str) -> Option<(Vec<u8>, RouteKind)> {
    async move |url: &'static str| {
        let file = url.rsplit('/').next().unwrap();
        if broken.is_some_and(|b| b == file) {
            return bad.clone().map(|b| (b, RouteKind::HappSocks));
        }
        Some((bundled(file), RouteKind::Direct))
    }
}

/// The whole refresh: promote both files as one generation, stay fresh within the interval,
/// re-run when forced, and on a bad or missing file keep the active generation, record the
/// fault and leave no staging behind (B-SR-1 / B-SR-2).
#[tokio::test]
async fn refresh_promotes_or_keeps() {
    if singbox_exe().is_none() {
        return;
    }
    let t = TempDir::new("rulesets");
    let s = service(&t);
    let cancel = CancellationToken::new();
    let first = s.refresh_with(false, 24, &cancel, fake(None, None)).await;
    let RefreshOutcome::Updated { generation } = first else {
        panic!("{first:?}")
    };
    let (source, dir) = s.select(true, false).unwrap();
    assert!(matches!(source, ActiveSource::Managed { .. }));
    assert_eq!(
        std::fs::read(dir.join("geoip-ru.srs")).unwrap(),
        bundled("geoip-ru.srs")
    );
    let doc = s.store.snapshot();
    assert_eq!(
        doc.files["geoip-ru.srs"].size,
        bundled("geoip-ru.srs").len() as u64
    );
    assert_eq!(
        doc.files["geoip-ru.srs"].sha256,
        "133d045108290b7e1ea929e3021807ad1842876d959bfc5ae347fdc7db4b5865"
    );
    assert_eq!(
        doc.files["geosite-category-gov-ru.srs"].route,
        RouteKind::Direct
    );
    assert_eq!(
        s.refresh_with(false, 24, &cancel, fake(None, None)).await,
        RefreshOutcome::Fresh
    );
    tokio::time::sleep(Duration::from_millis(5)).await;
    let forced = s.refresh_with(true, 24, &cancel, fake(None, None)).await;
    assert!(matches!(&forced, RefreshOutcome::Updated { generation: g } if *g != generation));
    let current = s.store.read(|d| d.current.clone());
    let html = Some(b"<html>rate limited</html>".to_vec());
    let failed = s
        .refresh_with(
            true,
            24,
            &cancel,
            fake(Some("geosite-category-gov-ru.srs"), html),
        )
        .await;
    assert_eq!(
        failed,
        RefreshOutcome::Failed(RefreshFault::Invalid {
            file: "geosite-category-gov-ru.srs".into()
        })
    );
    assert_eq!(
        s.store.read(|d| d.current.clone()),
        current,
        "the active generation stays"
    );
    assert!(s.store.read(|d| d.last_error.is_some()));
    assert!(!t.path().join("rulesets").join(STAGING).exists());
    let missing = s
        .refresh_with(true, 24, &cancel, fake(Some("geoip-ru.srs"), None))
        .await;
    assert_eq!(
        missing,
        RefreshOutcome::Failed(RefreshFault::Download {
            file: "geoip-ru.srs".into()
        })
    );
    let notice = missing.notice().unwrap();
    assert_eq!(
        (notice.level, notice.title.key.as_ref()),
        (Level::Warn, "engine.routing.ruleSets.notUpdated")
    );
    assert!(RefreshOutcome::Fresh.notice().is_none());
    let ok = s.refresh_with(true, 24, &cancel, fake(None, None)).await;
    assert!(matches!(ok, RefreshOutcome::Updated { .. }));
    assert!(s.store.read(|d| d.last_error.is_none()));
    cancel.cancel();
    assert_eq!(
        s.refresh_with(true, 24, &cancel, fake(None, None)).await,
        RefreshOutcome::Cancelled
    );
}

/// `fake` that counts its downloads in `n`.
fn counted(
    n: &std::sync::atomic::AtomicUsize,
    broken: Option<&'static str>,
    bad: Option<Vec<u8>>,
) -> impl AsyncFn(&'static str) -> Option<(Vec<u8>, RouteKind)> {
    let inner = fake(broken, bad);
    async move |url: &'static str| {
        n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        inner(url).await
    }
}

/// ops4 / conn6: a refused file is not fetched again by every session start for an hour (the
/// same fault comes back, so the caller's one-notice-per-streak rule holds); a forced refresh
/// and a download failure still try at once. Lab before: 4 downloads + checks per start.
#[tokio::test]
async fn a_refused_file_is_not_fetched_again_within_the_hour() {
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    if singbox_exe().is_none() {
        return;
    }
    let t = TempDir::new("rulesets-backoff");
    let s = service(&t);
    let cancel = CancellationToken::new();
    let n = AtomicUsize::new(0);
    let gov = "geosite-category-gov-ru.srs";
    let html = || Some(b"<html>rate limited</html>".to_vec());
    let refused = RefreshOutcome::Failed(RefreshFault::Invalid { file: gov.into() });
    let first = s
        .refresh_with(false, 24, &cancel, counted(&n, Some(gov), html()))
        .await;
    assert_eq!(first, refused);
    let downloads = n.load(SeqCst);
    assert!(downloads > 0);
    for _ in 0..3 {
        let again = s
            .refresh_with(false, 24, &cancel, counted(&n, Some(gov), html()))
            .await;
        assert_eq!(again, refused, "the recorded fault, not Fresh");
    }
    assert_eq!(n.load(SeqCst), downloads, "no download within the hour");
    s.store
        .update(|d| d.last_check = d.last_check.map(|t| t - INVALID_BACKOFF_MS - 1))
        .unwrap();
    let later = s
        .refresh_with(false, 24, &cancel, counted(&n, None, None))
        .await;
    assert!(matches!(later, RefreshOutcome::Updated { .. }), "{later:?}");
    let forced = s
        .refresh_with(true, 24, &cancel, counted(&n, Some(gov), html()))
        .await;
    assert_eq!(forced, refused);
    let before = n.load(SeqCst);
    let forced = s
        .refresh_with(true, 24, &cancel, counted(&n, Some(gov), html()))
        .await;
    assert_eq!(forced, refused);
    assert!(n.load(SeqCst) > before, "a forced refresh downloads");
    let missing = s
        .refresh_with(true, 24, &cancel, counted(&n, Some("geoip-ru.srs"), None))
        .await;
    assert!(matches!(
        missing,
        RefreshOutcome::Failed(RefreshFault::Download { .. })
    ));
    let before = n.load(SeqCst);
    s.store.update(|d| d.last_ok = None).unwrap();
    let retry = s
        .refresh_with(false, 24, &cancel, counted(&n, None, None))
        .await;
    assert!(matches!(retry, RefreshOutcome::Updated { .. }), "{retry:?}");
    assert!(
        n.load(SeqCst) > before,
        "a download failure is retried at once"
    );
}

/// `json` compiled by the bundled engine (`sing-box rule-set compile`).
async fn compiled(exe: &Path, t: &TempDir, json: &str) -> Vec<u8> {
    let (src, out) = (t.path().join("hostile.json"), t.path().join("hostile.srs"));
    std::fs::write(&src, json).unwrap();
    let args = [
        "rule-set".as_ref(),
        "compile".as_ref(),
        src.as_os_str(),
        "-o".as_ref(),
        out.as_os_str(),
    ];
    let run = run_once(Engine::SingBox, exe, &args, None, Duration::from_secs(20)).await;
    assert!(run.unwrap().status.success());
    std::fs::read(out).unwrap()
}

/// psmart-b3: a crafted geoip-ru that keeps the release's networks and canaries but adds three
/// quarters of IPv4 passes every canary; its content bounds refuse it, and the active
/// generation stays.
#[tokio::test]
async fn a_set_that_passes_its_canaries_but_not_its_bounds_is_refused() {
    let Some(exe) = singbox_exe() else { return };
    let t = TempDir::new("rulesets-hostile");
    let s = service(&t);
    let cancel = CancellationToken::new();
    let first = s.refresh_with(false, 24, &cancel, fake(None, None)).await;
    assert!(matches!(first, RefreshOutcome::Updated { .. }), "{first:?}");
    let current = s.store.read(|d| d.current.clone());
    let release = decompile(&exe, &resources().join("geoip-ru.srs"))
        .await
        .unwrap();
    let mut json: serde_json::Value = serde_json::from_str(&release).unwrap();
    let cidrs = json["rules"][0]["ip_cidr"].as_array_mut().unwrap();
    cidrs.extend(["64.0.0.0/2", "128.0.0.0/1"].map(serde_json::Value::from));
    let hostile = compiled(&exe, &t, &json.to_string()).await;
    let path = t.path().join("geoip-ru.srs");
    std::fs::write(&path, &hostile).unwrap();
    for (probe, want) in [
        ("77.88.8.8", true),
        ("8.8.8.8", false),
        ("1.1.1.1", false),
        ("95.0.0.1", true),
    ] {
        let file = path.as_os_str();
        let args = [
            "rule-set".as_ref(),
            "match".as_ref(),
            "-f".as_ref(),
            "binary".as_ref(),
            file,
            probe.as_ref(),
        ];
        let out = run_once(Engine::SingBox, &exe, &args, None, Duration::from_secs(20))
            .await
            .unwrap();
        let hit = String::from_utf8_lossy(&out.stderr).contains("match rules.[");
        assert_eq!(hit, want, "{probe}: the canaries alone would pass it");
    }
    let refused = s
        .refresh_with(true, 24, &cancel, fake(Some("geoip-ru.srs"), Some(hostile)))
        .await;
    assert_eq!(
        refused,
        RefreshOutcome::Failed(RefreshFault::Invalid {
            file: "geoip-ru.srs".into()
        })
    );
    assert_eq!(
        s.store.read(|d| d.current.clone()),
        current,
        "the active generation stays"
    );
}

/// Pruning keeps the current generation and the newest older one.
#[test]
fn prune_generations() {
    let t = TempDir::new("rulesets");
    let s = service(&t);
    let root = t.path().join("rulesets");
    for ms in [100, 200, 300, 400] {
        std::fs::create_dir_all(root.join(format!("{GEN_PREFIX}{ms}"))).unwrap();
    }
    std::fs::create_dir_all(root.join(STAGING)).unwrap();
    s.store
        .update(|d| d.current = Some(format!("{GEN_PREFIX}400")))
        .unwrap();
    assert_eq!(s.prune(), 2);
    let mut left: Vec<String> = std::fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(left, ["gen-300", "gen-400"]);
}

/// A one-shot HTTP/1.1 server on loopback answering every request with `response`.
async fn serve(response: Vec<u8>) -> reqwest::Url {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(&response).await;
            let _ = sock.shutdown().await;
        }
    });
    reqwest::Url::parse(&format!("http://127.0.0.1:{port}/x.srs")).unwrap()
}

/// Body cap, status and empty-body handling (plain HTTP on loopback: the transport is
/// reqwest's; the scheme rule is tested separately).
#[tokio::test]
async fn fetch_limits() {
    let client = vpnte_core::net::client_for(&Route::Direct, Duration::from_secs(5)).unwrap();
    let ok =
        serve(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nSRS".to_vec())
            .await;
    assert_eq!(fetch_body(&client, ok, 16).await.unwrap(), b"SRS");
    let missing =
        serve(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec())
            .await;
    assert!(matches!(
        fetch_body(&client, missing, 16).await,
        Err(FetchError::Status(404))
    ));
    let declared =
        serve(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n".to_vec())
            .await;
    assert!(matches!(
        fetch_body(&client, declared, 16).await,
        Err(FetchError::TooLarge)
    ));
    let streamed = serve(
        format!(
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{}",
            "x".repeat(64)
        )
        .into_bytes(),
    )
    .await;
    assert!(matches!(
        fetch_body(&client, streamed, 16).await,
        Err(FetchError::TooLarge)
    ));
    let empty =
        serve(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()).await;
    assert!(matches!(
        fetch_body(&client, empty, 16).await,
        Err(FetchError::Empty)
    ));
    assert!(matches!(
        fetch_https("http://example.com/x.srs", &Route::Direct).await,
        Err(FetchError::NotHttps)
    ));
}

/// fixlists-a7: a generation promoted under older checks is passed over until it is checked
/// once under today's; it stays when it passes and gives way to the bundled files when not.
#[tokio::test]
async fn a_generation_from_older_checks_is_checked_once() {
    let Some(exe) = singbox_exe() else { return };
    let t = TempDir::new("rulesets-recheck");
    let s = service(&t);
    let generation = format!("{GEN_PREFIX}1700000000000");
    let dir = t.path().join("rulesets").join(&generation);
    std::fs::create_dir_all(&dir).unwrap();
    for (_, file, _) in RULE_SETS {
        std::fs::write(dir.join(file), bundled(file)).unwrap();
    }
    s.store
        .update(|d| d.current = Some(generation.clone()))
        .unwrap();
    assert_eq!(s.select(true, false).unwrap().0, ActiveSource::Bundled);
    s.recheck().await;
    assert_eq!(s.store.read(|d| d.checks), CHECKS);
    let managed = s.select(true, false).unwrap().0;
    assert!(
        matches!(managed, ActiveSource::Managed { .. }),
        "{managed:?}"
    );
    // A crafted set of an older build: today's bounds refuse it.
    let release = decompile(&exe, &resources().join("geoip-ru.srs"))
        .await
        .unwrap();
    let mut json: serde_json::Value = serde_json::from_str(&release).unwrap();
    let cidrs = json["rules"][0]["ip_cidr"].as_array_mut().unwrap();
    cidrs.push("74.125.0.0/16".into());
    std::fs::write(
        dir.join("geoip-ru.srs"),
        compiled(&exe, &t, &json.to_string()).await,
    )
    .unwrap();
    s.store.update(|d| d.checks = 0).unwrap();
    s.recheck().await;
    assert_eq!(s.store.read(|d| d.current.clone()), None);
    assert_eq!(s.select(true, false).unwrap().0, ActiveSource::Bundled);
}
