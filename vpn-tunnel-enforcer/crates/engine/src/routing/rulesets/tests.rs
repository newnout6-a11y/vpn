use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vpnte_core::settings::ProxyOverride;

use super::fetch::{FetchError, fetch_body, fetch_https};
use super::*;
use crate::routing::smart_ru::GOV_RU;
use crate::test_support::{TempDir, resources, singbox_exe};

fn service(t: &TempDir) -> RuleSetService {
    let store = Arc::new(Store::<RuleSetsDoc>::open(t.path()));
    RuleSetService::with_paths(store, t.path().join("rulesets"), resources())
}

fn bundled(file: &str) -> Vec<u8> {
    std::fs::read(resources().join(file)).unwrap()
}

/// §2.2 route attempts per `bootstrapRouteMode` (the verifier's correction: `localProxy`
/// never tries direct, `useProxy = false` forces direct), user proxy first, duplicates out.
#[test]
fn download_routes() {
    let mut cfg = RefreshSettings::from_settings(&Settings::default());
    assert_eq!(
        (cfg.managed, cfg.auto_update, cfg.use_proxy, cfg.interval_h),
        (false, true, true, 24)
    );
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

/// ruleSetManager.test.ts: managed only when selected AND complete; bundled otherwise; no
/// directory at all when the bundled files are missing too (B-SR-2: Smart RU off, visibly).
#[test]
fn source_selection() {
    let t = TempDir::new("rulesets");
    let s = service(&t);
    let active = |managed| s.active(managed).unwrap();
    assert_eq!(active(true), (ActiveSource::Bundled, resources()));
    let generation = format!("{GEN_PREFIX}1700000000000");
    let dir = t.path().join("rulesets").join(&generation);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("geoip-ru.srs"), b"x").unwrap();
    s.store
        .update(|d| d.current = Some(generation.clone()))
        .unwrap();
    assert_eq!(
        active(true).0,
        ActiveSource::Bundled,
        "incomplete generation"
    );
    std::fs::write(dir.join("geosite-category-gov-ru.srs"), b"x").unwrap();
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
    assert_eq!(empty.active(false), None);
    let (source, path) = empty.active(true).unwrap();
    assert!(matches!(source, ActiveSource::Managed { .. }) && path == dir);
}

/// §7.6 canaries on the bundled files, and B-SR-1 vectors: an empty file, an HTML error page,
/// an unsupported SRS version, a truncated stream and a swapped set are all rejected.
#[tokio::test]
async fn engine_validation() {
    let Some(exe) = singbox_exe() else { return };
    let t = TempDir::new("rulesets");
    let geoip = resources().join("geoip-ru.srs");
    let gov = resources().join("geosite-category-gov-ru.srs");
    assert_eq!(validate(&exe, &geoip, GEOIP_RU).await, Some(true));
    assert_eq!(validate(&exe, &gov, GOV_RU).await, Some(true));
    assert_eq!(validate(&exe, &geoip, GOV_RU).await, Some(false));
    let truncated = bundled("geoip-ru.srs")[..2000].to_vec();
    for (name, bytes) in [
        ("empty.srs", Vec::new()),
        ("html.srs", b"<html>404</html>".to_vec()),
        ("v9.srs", b"SRS\x09abc".to_vec()),
        ("truncated.srs", truncated),
    ] {
        let p = t.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        assert_eq!(validate(&exe, &p, GEOIP_RU).await, Some(false), "{name}");
    }
    assert_eq!(
        validate(&t.path().join("no-engine.exe"), &geoip, GEOIP_RU).await,
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
    let (source, dir) = s.active(true).unwrap();
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
