//! The whole service built over a throw-away backend that is NOT elevated (forced, also on an
//! elevated runner): the NOADMIN §0 refusals and the kill-switch bookkeeping. Nothing here
//! starts an engine, scans for local proxies or touches the system proxy: every connect is a
//! Hard one, refused before anything runs.
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;
use vpnte_automation::coordinator::Coordinator;
use vpnte_base::ErrorKind;
use vpnte_base::types::KillSwitchLevel;
use vpnte_core::ops::{OperationRegistry, Source};
use vpnte_core::paths::DataDirs;
use vpnte_core::settings::{RoutingMode, Settings};
use vpnte_core::store::Store;
use vpnte_engine::routing::RulesDoc;
use vpnte_engine::routing::rulesets::{RuleSetService, RuleSetsDoc};
use vpnte_probes::geo::Geo;
use vpnte_probes::ip_monitor::IpVerdict;
use vpnte_servers::model::ProfileId;
use vpnte_servers::refresh::RefreshCtx;
use vpnte_servers::store::Servers;
use vpnte_servers::subscription::{Hwids, SubscriptionFetcher};
use vpnte_tunnel::history::History;
use vpnte_winnet::wfp::{ExceptionKind, Toggles};

use crate::services::{Backend, Engines};
use crate::svc_core::docs::{ProtectionDoc, SoftDoc, ThemesDoc};
use crate::svc_core::notify::Notifier;

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn backend(root: &TempDir) -> Arc<Backend> {
    let resources = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources"));
    let dirs = DataDirs::new(
        root.0.join("data"),
        root.0.join("legacy"),
        resources.clone(),
    );
    dirs.ensure().unwrap();
    let settings = Arc::new(Store::<Settings>::open(&dirs.root));
    // No toast may reach this desktop, whatever happens below.
    settings
        .update(|s| s.desktop_notifications = false)
        .unwrap();
    let ops = OperationRegistry::new();
    let fetcher = Arc::new(SubscriptionFetcher::new(Hwids::current(), settings.clone()));
    let rule_sets = Arc::new(Store::<RuleSetsDoc>::open(&dirs.root));
    Arc::new(Backend {
        lock: dirs.lock().unwrap(),
        log: Mutex::new(None),
        elevated: false,
        engines: Engines {
            singbox: resources.join("sing-box.exe"),
            xray: resources.join("xray.exe"),
        },
        protection: Arc::new(Store::<ProtectionDoc>::open(&dirs.root)),
        themes: Arc::new(Store::<ThemesDoc>::open(&dirs.root)),
        soft: Arc::new(Store::<SoftDoc>::open(&dirs.root)),
        cleanup: Arc::new(Store::open(&dirs.root)),
        rules: Arc::new(Store::<RulesDoc>::open(&dirs.root)),
        rule_sets: Arc::new(RuleSetService::new(rule_sets, &dirs)),
        history: History::open(&dirs.root),
        servers: Arc::new(Servers::open(&dirs.root)),
        refresh: RefreshCtx::new(fetcher, ops.clone()),
        ops,
        geo: Geo::new(false),
        notifier: Arc::new(Notifier::new(settings.clone()).unwrap()),
        settings,
        import: None,
        shutdown: CancellationToken::new(),
        clipboard: OnceLock::new(),
        tunnel: OnceLock::new(),
        dirs,
    })
}

fn level(b: &Backend) -> (KillSwitchLevel, KillSwitchLevel) {
    (
        b.settings.read(|s| s.kill_switch),
        b.protection.read(|d| d.settings.level),
    )
}

/// NOADMIN §0 / §2 (AT-02-007 new): unelevated there is no TUN and no WFP. A Hard connect is
/// refused up front with the offer of Soft; strict and every WFP-only operation answer
/// `Permission`; off / standard are kept in both stores; a refused level is put back into the
/// settings the caller already wrote.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unelevated_service_refuses_privileged_operations() {
    let root =
        TempDir(std::env::temp_dir().join(format!("vpnte-app-tunnel-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&root.0);
    let b = backend(&root);
    b.settings
        .update(|s| s.routing_mode = RoutingMode::Hard)
        .unwrap();
    let built = super::build(&b).unwrap();
    let t = built.tunnel.clone();
    // The domain history is hosted here: «clear» works (it was "not available" before), and no
    // engine ran yet, so the export has no engine config to pack.
    t.clear_traffic_history()
        .await
        .expect("traffic history cleared");
    assert!(built.domains.history.list().is_empty());
    assert!(built.feed.last_config().is_none());
    // NOADMIN §0: browser policies (HKLM) only from an elevated process, refused before anything
    // is read or written (also on an elevated runner: the backend says unelevated).
    let browsers = built.automation.browser_policies(true).await.unwrap_err();
    assert_eq!(
        (browsers.kind, browsers.user_msg().key.as_ref()),
        (ErrorKind::Permission, "automation.hardening.needsAdmin")
    );
    assert!(built.automation.coord.session().is_none());

    assert!(!t.tun_available());
    assert!(t.kill_switch().await.wfp.is_none());
    assert!(!t.runtime_status().borrow().running);
    assert!(!t.traffic().borrow().running);
    assert_eq!(t.ip_evidence().borrow().verdict, IpVerdict::NotChecked);

    let err = t.connect(Source::Ui).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Permission);
    assert_eq!(err.user_msg().key, "tunnel.runtime.tunUnavailable");

    let permission = |e: vpnte_base::AppError| {
        assert_eq!(e.kind, ErrorKind::Permission);
        assert_eq!(e.user_msg().key, "app.base.needsAdmin");
    };
    // ks-a: "Always" is refused with one calm line until the helper service keeps it safe.
    let always = t
        .set_kill_switch_level(KillSwitchLevel::Strict)
        .await
        .unwrap_err();
    assert_eq!(always.kind, ErrorKind::Permission);
    assert_eq!(always.user_msg().key, "app.tunnel.alwaysNeedsService");
    assert!(!t.always_available());
    assert_eq!(level(&b), (KillSwitchLevel::Off, KillSwitchLevel::Off));
    t.set_kill_switch_level(KillSwitchLevel::Standard)
        .await
        .unwrap();
    assert_eq!(
        level(&b),
        (KillSwitchLevel::Standard, KillSwitchLevel::Standard)
    );

    // The settings page saved strict, then hands the change over: refused and put back.
    let old = b.settings.snapshot();
    b.settings
        .update(|s| s.kill_switch = KillSwitchLevel::Strict)
        .unwrap();
    let new = b.settings.snapshot();
    let err = t.apply_settings_change(old, new).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Permission);
    assert_eq!(
        level(&b),
        (KillSwitchLevel::Standard, KillSwitchLevel::Standard)
    );

    permission(t.release_kill_switch().await.unwrap_err());
    permission(t.remove_exception("e1".into()).await.unwrap_err());
    permission(
        t.add_exception(ExceptionKind::Ip, "10.0.0.0/8".into(), "lan".into())
            .await
            .unwrap_err(),
    );
    let toggles = Toggles {
        leak_protection: false,
        public_wifi_compat: true,
        allow_lan: true,
    };
    permission(t.set_protection_toggles(toggles).await.unwrap_err());

    // An unknown server cannot be selected; nothing runs, so nothing is switched.
    let err = t
        .switch_server(ProfileId::from("missing"), Source::Ui)
        .await;
    assert!(err.is_err());

    let report = t.shutdown(Duration::from_secs(5)).await;
    assert!(
        report.soft_restored,
        "nothing applied, nothing left: {report:?}"
    );
    b.shutdown.cancel();
}

/// Elevated only (CI: `-- --ignored elevated_`): the guard drives the real WFP protection. Off
/// -> standard is armed (no session, so no filter yet) and both stores follow; back to off; the
/// dynamic session closes. Leaves nothing behind.
#[test]
#[ignore = "needs elevation"]
fn elevated_guard_levels_follow_the_protection() {
    let root = TempDir(
        std::env::temp_dir().join(format!("vpnte-app-tunnel-elevated-{}", std::process::id())),
    );
    let _ = std::fs::remove_dir_all(&root.0);
    let b = backend(&root);
    let remote = super::remote::Remote::absent(b.protection.clone());
    let guard = super::guard::Guard::new(
        true,
        &b.engines,
        b.settings.clone(),
        b.protection.clone(),
        remote,
    );
    guard.startup().unwrap();
    guard.set_level(KillSwitchLevel::Standard).unwrap();
    assert_eq!(
        level(&b),
        (KillSwitchLevel::Standard, KillSwitchLevel::Standard)
    );
    let wfp = guard.status().wfp.expect("elevated: a read-back");
    assert_eq!(wfp.level, KillSwitchLevel::Standard);
    guard.set_level(KillSwitchLevel::Off).unwrap();
    assert_eq!(level(&b), (KillSwitchLevel::Off, KillSwitchLevel::Off));
    guard.shutdown();
}
