//! Re-check item 16 on the backend side: the scope switch saves `Settings::app_scope`, the page
//! follows a change made elsewhere and the running session's scope, says which mode its hint
//! describes, and the older-service line appears only where it applies.
use std::time::Duration;

use tokio::sync::watch;
use vpnte_core::settings::{self, RoutingMode};
use vpnte_engine::routing::process::ProcessName;
use vpnte_tunnel::api::{CaptureKind, TunStatus};
use vpnte_ui::split_tunnel::{AppScope, SplitSnapshot, SplitTunnelApi};

use super::{SplitService, older_service};
use crate::api_settings::test_support::{FakeTunnel, TempDir, backend};

/// Waits (at most 10 s) until the pushed state satisfies `what`.
async fn until(rx: &mut watch::Receiver<SplitSnapshot>, what: impl Fn(&SplitSnapshot) -> bool) {
    let reached = {
        let wait = rx.wait_for(|s| what(s));
        tokio::time::timeout(Duration::from_secs(10), wait)
            .await
            .is_ok()
    };
    if !reached {
        let now = rx.borrow();
        panic!(
            "not in time: scope {:?}, pending {}, proxy {}",
            now.scope, now.pending, now.proxy
        );
    }
}

/// The switch saves the scope and the page shows it; a change made elsewhere (another page, an
/// import of the settings) reaches the page too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_scope_is_saved_and_followed() {
    let dir = TempDir::new("lists-split-scope");
    let backend = backend(&dir, FakeTunnel::new(false));
    // A stored entry, so the page's first look runs no discovery.
    backend
        .rules
        .update(|doc| doc.add_command(ProcessName::parse("curl").expect("name")))
        .expect("entry");
    let api = SplitService::start(backend.clone());
    let mut state = api.state();
    assert_eq!(state.borrow().scope, AppScope::All);
    assert!(!state.borrow().older_service, "no service linked");

    api.set_scope(AppScope::OnlyListed).await.expect("saved");
    assert_eq!(
        state.borrow().scope,
        AppScope::OnlyListed,
        "published first"
    );
    let stored = backend.settings.read(|s| s.app_scope);
    assert_eq!(stored, settings::AppScope::OnlyListed);

    backend
        .settings
        .update(|s| s.app_scope = settings::AppScope::All)
        .expect("saved elsewhere");
    until(&mut state, |s| s.scope == AppScope::All).await;
}

/// appsplit-a2: the line needs a linked service older than the scope's protocol, whatever the
/// saved mode (a schedule starts Tunnel sessions of its own).
#[test]
fn the_older_service_line_needs_an_older_link() {
    assert!(older_service(Some(3)));
    assert!(!older_service(Some(4)));
    assert!(!older_service(None), "no link: nothing is claimed");
}

/// appsplit-b5/b6: a running session keeps the scope it started with, so a flip of the switch
/// reads as pending until the next connection; the hint describes the running session's mode,
/// else the saved one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_switch_follows_the_running_session() {
    let dir = TempDir::new("lists-split-run");
    let tunnel = FakeTunnel::new(false);
    let backend = backend(&dir, tunnel.clone());
    backend
        .rules
        .update(|doc| doc.add_command(ProcessName::parse("curl").expect("name")))
        .expect("entry");
    backend
        .settings
        .update(|s| s.routing_mode = RoutingMode::Hard)
        .expect("Tunnel mode");
    let api = SplitService::start(backend.clone());
    let mut state = api.state();
    until(&mut state, |s| !s.proxy && !s.pending).await;

    tunnel.status.send_replace(TunStatus {
        running: true,
        started_at: Some(1_000),
        capture: Some(CaptureKind::Proxy),
        ..TunStatus::default()
    });
    until(&mut state, |s| s.proxy && !s.pending).await;
    api.set_scope(AppScope::OnlyListed).await.expect("saved");
    until(&mut state, |s| s.scope == AppScope::OnlyListed && s.pending).await;
    api.set_scope(AppScope::All).await.expect("saved");
    until(&mut state, |s| s.scope == AppScope::All && !s.pending).await;
    api.set_scope(AppScope::OnlyListed).await.expect("saved");
    until(&mut state, |s| s.pending).await;

    // The next run starts with the saved scope; nothing runs: nothing waits.
    tunnel.status.send_replace(TunStatus {
        running: true,
        started_at: Some(2_000),
        capture: Some(CaptureKind::Tun),
        ..TunStatus::default()
    });
    until(&mut state, |s| !s.pending && !s.proxy).await;
    tunnel.status.send_replace(TunStatus::default());
    api.set_scope(AppScope::All).await.expect("saved");
    until(&mut state, |s| s.scope == AppScope::All && !s.pending).await;
}
