use std::net::IpAddr;
use std::sync::Arc;

use serde_json::json;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::now_ms;
use vpnte_core::net;
use vpnte_core::store::Store;

use super::fetch::{LookupError, all_public, inspect, vetted};
use super::page::{PageMeta, clean_text, decode_entities, sanitize, scan_head};
use super::*;
use crate::domains::{DomainsDoc, HistoryService};
use crate::test_support::{TempDir, eventually};

/// domainEnrichment.test.ts normalizeEnrichmentDomain / registrableEnrichmentDomain.
#[test]
fn normalize_and_registrable_vectors() {
    assert_eq!(
        normalize_domain("WWW.Example.com.").as_deref(),
        Some("www.example.com")
    );
    for bad in [
        "localhost",
        "127.0.0.1",
        "printer.local",
        "",
        "a/b.com",
        "u@b.com",
        "single",
        "[::1]",
    ] {
        assert_eq!(normalize_domain(bad), None, "{bad}");
    }
    assert_eq!(
        registrable("contacts.google.com").as_deref(),
        Some("google.com")
    );
    assert_eq!(
        registrable("browser-resources.s3.yandex.net").as_deref(),
        Some("yandex.net")
    );
    assert_eq!(
        registrable("www.example.co.uk").as_deref(),
        Some("example.co.uk")
    );
    assert_eq!(
        registrable("пример.рф").as_deref(),
        Some("xn--e1afmkfd.xn--p1ai")
    );
    assert_eq!(registrable("printer.local"), None);
}

/// isAllowedMetadataUrl.
#[test]
fn allowed_url_vectors() {
    let ok = |s: &str| allowed_url_str(s);
    assert!(ok("https://example.com"));
    assert!(ok("https://example.com:443/path?q=1"));
    for bad in [
        "http://example.com",
        "https://127.0.0.1",
        "https://example.com:8443",
        "https://user@example.com",
        "https://localhost/",
        "not a url",
    ] {
        assert!(!ok(bad), "{bad}");
    }
}

/// buildEnrichmentProxyRules. SOCKS goes as `socks5h` (core `Route::proxy`): names are resolved
/// by the proxy.
#[test]
fn proxy_route_vectors() {
    let label = |addr: &str, kind| proxy_route(addr, kind).map(|r| r.label());
    assert_eq!(
        label("127.0.0.1:1080", ProxyKind::Socks5).as_deref(),
        Some("socks5h://127.0.0.1:1080")
    );
    assert_eq!(
        label("http://127.0.0.1:8080/", ProxyKind::Http).as_deref(),
        Some("http://127.0.0.1:8080")
    );
    assert_eq!(
        label("https://proxy.example.com:443", ProxyKind::Http),
        None
    );
    assert_eq!(label("proxy.example.com:8080/path", ProxyKind::Http), None);
    assert_eq!(
        label("socks5://u:p@127.0.0.1:1080", ProxyKind::Socks5),
        None
    );
    assert_eq!(label("http://127.0.0.1", ProxyKind::Http), None);
    assert_eq!(label("  ", ProxyKind::Socks5), None);
}

/// sanitizePageMetadata.
#[test]
fn sanitize_vectors() {
    let final_url = Url::parse("https://example.com/").unwrap();
    let meta = PageMeta {
        site_name: Some(" Example  Site ".into()),
        title: Some("Title".into()),
        description: None,
        canonical: Some("https://example.com/canonical".into()),
        icon: Some("http://example.com/favicon.ico".into()),
    };
    let e = sanitize(meta, &final_url, 5);
    assert_eq!(e.status, EnrichStatus::Ready);
    assert_eq!(e.site_name.as_deref(), Some("Example Site"));
    assert_eq!(
        e.canonical_url.as_deref(),
        Some("https://example.com/canonical")
    );
    assert_eq!((e.favicon_url, e.fetched_at), (None, 5));
    // The site name falls back to the title, the canonical URL to the final one.
    let meta = PageMeta {
        title: Some("x".repeat(500)),
        ..PageMeta::default()
    };
    let e = sanitize(meta, &final_url, 5);
    assert_eq!(e.site_name.as_ref().map(|s| s.chars().count()), Some(180));
    assert_eq!(e.canonical_url.as_deref(), Some("https://example.com/"));
    // No text at all: unavailable, every field empty.
    let e = sanitize(PageMeta::default(), &final_url, 5);
    assert_eq!(e, DomainEnrichment::empty(EnrichStatus::Unavailable, 5));
    assert_eq!(clean_text(Some("caf\u{FFFD} menu".into()), 120), None);
    assert_eq!(
        clean_text(Some(decode_entities("a&#0;b\u{1b}[1mc")), 120).as_deref(),
        Some("a b [1mc")
    );
}

/// isPrivateOrReservedAddress (judged by the one core predicate) and the safe-domain rule.
#[test]
fn private_and_safe_domain_vectors() {
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    for private in [
        "127.0.0.1",
        "127.255.255.254",
        "::1",
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.0.1",
        "192.168.254.254",
        "169.254.169.254",
        "169.254.1.1",
        "fe80::1",
        "100.64.0.1",
        "100.127.255.254",
        "224.0.0.1",
        "255.255.255.255",
        "ff02::1",
        "fc00::1",
        "fd12:3456:789a::1",
        "::ffff:127.0.0.1",
        "::ffff:192.168.1.10",
        "::ffff:169.254.169.254",
    ] {
        assert!(!net::is_public_ip(ip(private)), "{private}");
    }
    for public in [
        "1.1.1.1",
        "8.8.8.8",
        "93.184.216.34",
        "172.32.0.1",
        "100.128.0.1",
        "2606:4700:4700::1111",
        "::ffff:1.1.1.1",
    ] {
        assert!(net::is_public_ip(ip(public)), "{public}");
    }
    assert!(all_public(&[ip("93.184.216.34")]));
    for unsafe_set in [
        vec![ip("127.0.0.1")],
        vec![ip("192.168.1.1")],
        vec![ip("169.254.169.254")],
        vec![ip("93.184.216.34"), ip("127.0.0.1")],
        vec![],
    ] {
        assert!(!all_public(&unsafe_set), "{unsafe_set:?}");
    }
}

/// A resolver answer for a local name is refused before any request.
#[tokio::test]
async fn local_names_are_refused_before_any_request() {
    assert!(matches!(
        vetted("localhost").await,
        Err(LookupError::NotPublic)
    ));
    let err = inspect("localhost", &Route::Direct).await.unwrap_err();
    assert!(matches!(err, LookupError::Refused), "{err:?}");
}

const PAGE: &str = r#"<!doctype html><html><head>
<meta charset="utf-8"><title>
  Fallback &amp; title </title>
<META property="og:site_name" content="Example &quot;Shop&quot;">
<meta name="description" content='Plain description'>
<meta property="og:description" content="">
<link rel="apple-touch-icon" href="/apple.png">
<link rel="shortcut icon" href="/favicon.ico">
<link href="canonical/page" rel="canonical">
</head><body><meta property="og:title" content="Body title"></body></html>"#;

/// The head scanner reads what the old in-browser script read; links resolve against the page.
#[test]
fn head_scanner_reads_the_page_head() {
    let base = Url::parse("https://www.example.com/start/").unwrap();
    let meta = scan_head(PAGE, &base);
    assert_eq!(meta.site_name.as_deref(), Some("Example \"Shop\""));
    assert_eq!(meta.title.as_deref(), Some("\n  Fallback & title "));
    assert_eq!(meta.description.as_deref(), Some("Plain description"));
    assert_eq!(
        meta.canonical.as_deref(),
        Some("https://www.example.com/start/canonical/page")
    );
    assert_eq!(
        meta.icon.as_deref(),
        Some("https://www.example.com/favicon.ico")
    );
    let e = sanitize(meta, &base, 1);
    assert_eq!(e.title.as_deref(), Some("Fallback & title"));
}

#[test]
fn entities_are_decoded() {
    assert_eq!(
        decode_entities("&amp;&lt;&gt;&#39;&#x41;&#66;&nbsp;&unknown; & x &"),
        "&<>'AB\u{a0}&unknown; & x &"
    );
}

/// Storage H6: old cache entries keep their results; pending ones and bad URLs are dropped.
#[test]
fn legacy_cache_is_converted() {
    let old = json!({"entries": {
        "example.com": {"status": "ready", "source": "website", "siteName": "Example",
            "title": "Example", "description": null, "canonicalUrl": "https://example.com/",
            "faviconUrl": "http://example.com/i.ico", "fetchedAt": 100},
        "sub.example.org": {"status": "unavailable", "source": "website", "siteName": null,
            "title": null, "description": null, "canonicalUrl": null, "faviconUrl": null,
            "fetchedAt": 50},
        "queued.example": {"status": "pending", "siteName": null, "title": null,
            "description": null, "canonicalUrl": null, "faviconUrl": null, "fetchedAt": 1},
        "localhost": {"status": "ready", "fetchedAt": 1}
    }});
    let doc = EnrichmentDoc::from_legacy(&old);
    assert_eq!(doc.entries.len(), 2);
    let e = &doc.entries["example.com"];
    assert_eq!(
        (e.status, e.favicon_url.as_deref()),
        (EnrichStatus::Ready, None)
    );
    assert_eq!(doc.entries["example.org"].status, EnrichStatus::Unavailable);
}

fn record(domain: &str) -> DomainRecord {
    DomainRecord {
        domain: domain.into(),
        first_seen: 1,
        last_seen: 1,
        connections: 1,
        lookups: 0,
        bytes_up: 0,
        bytes_down: 0,
        outbound: None,
    }
}

/// Queue bounds, `pending` reads, disable before any job ran (no request leaves), attach rules.
#[tokio::test]
async fn queue_pending_disable_and_attach() {
    let root = TempDir::new("enrich-queue");
    let enricher = Enricher::open(Arc::new(Store::open(root.path())));
    let domains: Vec<String> = (0..10).map(|i| format!("www.site{i}.example")).collect();
    enricher.queue(&domains, &Route::Direct);
    assert_eq!(enricher.inner.state.lock().pending.len(), MAX_PENDING);
    assert_eq!(
        enricher.get("site0.example").unwrap().status,
        EnrichStatus::Pending
    );
    assert_eq!(enricher.get("www.site9.example"), None);
    enricher.queue(&domains, &Route::Direct); // full: nothing added
    assert_eq!(enricher.inner.state.lock().pending.len(), MAX_PENDING);
    enricher.disable();
    assert_eq!(enricher.get("site0.example"), None);
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert!(enricher.inner.state.lock().cache.is_empty());

    let now = now_ms();
    let ready = DomainEnrichment {
        site_name: Some("Example".into()),
        ..DomainEnrichment::empty(EnrichStatus::Ready, now)
    };
    let stale = DomainEnrichment::empty(EnrichStatus::Unavailable, now - FAILURE_TTL_MS - 1);
    {
        let mut state = enricher.inner.state.lock();
        state.cache.insert("example.com".into(), ready.clone());
        state.cache.insert("example.org".into(), stale);
    }
    assert_eq!(enricher.get("www.example.com"), Some(ready.clone()));
    assert_eq!(enricher.get("example.org"), None);
    let rows = vec![record("www.example.com")];
    let on = EnrichInputs {
        enabled: true,
        route: Some(Route::Direct),
    };
    assert_eq!(
        enricher.entries(rows.clone(), &on)[0].enrichment,
        Some(ready)
    );
    let no_route = EnrichInputs {
        enabled: true,
        route: None,
    };
    assert_eq!(
        enricher.entries(rows.clone(), &no_route)[0].enrichment,
        None
    );
    assert_eq!(
        enricher.entries(rows, &EnrichInputs::default())[0].enrichment,
        None
    );

    enricher.clear().await.unwrap();
    assert_eq!(enricher.get("www.example.com"), None);
    assert!(
        Store::<EnrichmentDoc>::open(root.path())
            .snapshot()
            .entries
            .is_empty()
    );
}

/// Review fix: a route change (the TUN stopped, another local proxy) aborts lookups queued for
/// the old egress before they send anything; their results are never stored.
#[tokio::test]
async fn route_change_aborts_queued_lookups() {
    let root = TempDir::new("enrich-route");
    let enricher = Enricher::open(Arc::new(Store::open(root.path())));
    let domains = Store::<DomainsDoc>::open(root.path());
    let mut doc = DomainsDoc::default();
    doc.domains
        .insert("www.site.example".into(), record("www.site.example"));
    domains.replace(doc).unwrap();
    let history = Arc::new(HistoryService::open(Arc::new(domains), None));
    // Both lookup slots taken: a queued job waits and sends nothing.
    let slots = enricher.inner.slots.acquire_many(2).await.unwrap();
    let (inputs_tx, inputs) = watch::channel(EnrichInputs {
        enabled: true,
        route: Some(Route::Direct),
    });
    let cancel = CancellationToken::new();
    enricher.spawn_tick(history, inputs, cancel.clone());
    eventually(|| enricher.get("site.example").is_some()).await; // the first tick queued it
    inputs_tx.send_replace(EnrichInputs {
        enabled: true,
        route: proxy_route("127.0.0.1:1080", ProxyKind::Socks5),
    });
    eventually(|| enricher.get("site.example").is_none()).await;
    drop(slots);
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    let state = enricher.inner.state.lock();
    assert!(state.pending.is_empty() && state.cache.is_empty());
    drop(state);
    cancel.cancel();
}

/// End-to-end lookup over the real internet (resolver, TLS, redirects, head scan).
#[tokio::test]
#[ignore = "needs internet"]
async fn live_lookup_of_example_com() {
    let (meta, url) = inspect("example.com", &Route::Direct).await.unwrap();
    let e = sanitize(meta, &url, now_ms());
    assert_eq!(e.status, EnrichStatus::Ready, "{e:?}");
    assert!(e.title.is_some());
}
