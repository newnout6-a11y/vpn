use std::path::PathBuf;

use serde_json::json;
use vpnte_tunnel::api::{ProxyEndpoint, SessionEndpoints, TunStatus};
use vpnte_update::feed::Feed;
use vpnte_update::net::Via;
use vpnte_update::store::EngineStore;
use vpnte_update::version::Version;

use super::doc::UpdatesDoc;
use super::view::{app_offer, engine_offers, rollback};
use super::ways::ways;

/// A feed with app `app` (severity, `warn_below`) and sing-box `engine`.
fn feed(app: &str, severity: &str, warn_below: Option<&str>, engine: &str) -> Feed {
    serde_json::from_value(json!({
        "schema": 1, "seq": 3, "issued": "2026-11-12T10:00:00Z",
        "app": {
            "stable": { "version": app, "severity": severity, "notes": { "ru": "Что нового" },
                "file": { "name": "VPN-Tunnel-Enforcer-Setup.exe", "size": 10, "sha256": "00",
                          "urls": ["https://example.invalid/setup.exe"] },
                "rollback_to": "2.0.0",
                "rollback_file": { "name": "old.exe", "size": 10, "sha256": "00",
                                   "urls": ["https://example.invalid/old.exe"] } },
            "beta": null, "warn_below": warn_below },
        "engines": [{ "id": "sing-box", "version": engine, "app": ">=2.0.0 <2.1.0",
            "tested_on": "2026-11-12",
            "archive": { "url": "https://example.invalid/sb.zip", "size": 1, "sha256": "00" },
            "files": [] }]
    }))
    .unwrap()
}

const RUNNING: Version = Version(2, 0, 0);

/// «Пропустить» hides a normal release; a security release or a build below `warn_below` stays
/// visible and loses «Пропустить» (never forced: «Позже» is the UI's).
#[test]
fn skipping_respects_security_and_warn_below() {
    let mut doc = UpdatesDoc::default();
    assert!(
        doc.auto_check && !doc.download_ahead,
        "defaults: check on, ahead off"
    );
    let normal = feed("2.0.1", "normal", None, "1.14.5");
    let offer = app_offer(&normal, &doc, RUNNING).unwrap();
    assert!(offer.can_skip && !offer.security);
    doc.skipped.push("2.0.1".into());
    assert!(app_offer(&normal, &doc, RUNNING).is_none());
    let security = feed("2.0.1", "security", None, "1.14.5");
    let offer = app_offer(&security, &doc, RUNNING).unwrap();
    assert!(offer.security && !offer.can_skip);
    let below = feed("2.0.1", "normal", Some("2.0.1"), "1.14.5");
    assert!(!app_offer(&below, &doc, RUNNING).unwrap().can_skip);
    assert!(app_offer(&normal, &UpdatesDoc::default(), Version(2, 0, 1)).is_none());
}

/// The rollback offer exists only on the newest release with a listed rollback installer.
#[test]
fn rollback_only_from_the_newest_release() {
    let f = feed("2.0.1", "normal", None, "1.14.5");
    assert_eq!(rollback(&f, Version(2, 0, 1)), Some(Version(2, 0, 0)));
    assert_eq!(rollback(&f, RUNNING), None);
}

/// Engine offers: a tested version newer than the bundled one inside this build's range (the
/// bundled version is read from the manifest: an engine bump keeps this valid).
#[test]
fn engine_offers_follow_the_compiled_range() {
    let none = PathBuf::from(r"C:\nonexistent-vpnte-updates");
    let store = EngineStore::new(none.join("engines"), none.join("resources"));
    let bundled = vpnte_update::policy::bundled_version("sing-box").unwrap();
    let next = Version(bundled.0, bundled.1, bundled.2 + 1).to_string();
    let offers = engine_offers(&feed("2.0.1", "normal", None, &next), &store, RUNNING);
    assert_eq!(offers.len(), 1);
    assert_eq!(
        (offers[0].from.clone(), offers[0].to.clone()),
        (bundled.to_string(), next.clone())
    );
    let older = Version(bundled.0, bundled.1, bundled.2.saturating_sub(1)).to_string();
    for outside in ["1.15.0".to_owned(), bundled.to_string(), older] {
        let f = feed("2.0.1", "normal", None, &outside);
        assert!(engine_offers(&f, &store, RUNNING).is_empty(), "{outside}");
    }
    let f = feed("2.0.1", "normal", None, &next);
    assert!(
        engine_offers(&f, &store, Version(2, 1, 0)).is_empty(),
        "outside the entry's app range"
    );
}

/// research §4.6: the session's authenticated probe inbound first, then mixed-direct-in; no
/// session = the plain direct route.
#[test]
fn ways_go_through_the_session_first() {
    let idle = TunStatus::default();
    let direct = ways(&idle);
    assert_eq!(direct.len(), 1);
    assert_eq!(direct[0].via, Via::Direct);
    assert_eq!(direct[0].route.label(), "direct");
    let endpoint = |port| ProxyEndpoint {
        port,
        user: "u".into(),
        pass: "p".into(),
    };
    let running = TunStatus {
        running: true,
        session: Some(SessionEndpoints {
            clash_port: 1,
            clash_secret: "s".into(),
            direct: endpoint(20001),
            probe: Some(endpoint(20002)),
            tun_luid: None,
            tun_alias: None,
            proxy_port: None,
            logs: Vec::new(),
        }),
        ..TunStatus::default()
    };
    let got = ways(&running);
    assert_eq!(
        got.iter().map(|w| w.via).collect::<Vec<_>>(),
        [Via::Session, Via::Direct]
    );
    assert_eq!(got[0].route.label(), "socks5h://127.0.0.1:20002");
    assert_eq!(got[1].route.label(), "socks5h://127.0.0.1:20001");
}
