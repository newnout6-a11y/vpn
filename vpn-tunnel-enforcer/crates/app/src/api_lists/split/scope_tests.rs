//! Re-check item 16 on the backend side: the scope switch saves `Settings::app_scope`, the page
//! follows a change made elsewhere, and the older-service line appears only where it applies.
use std::time::Duration;

use tokio::sync::watch;
use vpnte_core::settings::{self, RoutingMode, Settings};
use vpnte_engine::routing::process::ProcessName;
use vpnte_ui::split_tunnel::{AppScope, SplitSnapshot, SplitTunnelApi};

use super::{SplitService, older_service};
use crate::api_settings::test_support::{FakeTunnel, TempDir, backend};

/// Waits (at most 10 s) until the pushed state satisfies `what`.
async fn until(rx: &mut watch::Receiver<SplitSnapshot>, what: impl Fn(&SplitSnapshot) -> bool) {
    let wait = rx.wait_for(|s| what(s));
    tokio::time::timeout(Duration::from_secs(10), wait)
        .await
        .expect("in time")
        .expect("open");
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

/// The line needs Tunnel mode through a linked service older than the scope's protocol.
#[test]
fn the_older_service_line_needs_tunnel_mode_and_an_older_link() {
    let tunnel = Settings {
        routing_mode: RoutingMode::Hard,
        ..Settings::default()
    };
    let proxy = Settings {
        routing_mode: RoutingMode::Soft,
        ..Settings::default()
    };
    assert!(older_service(&tunnel, Some(3)));
    assert!(!older_service(&tunnel, Some(4)));
    assert!(!older_service(&tunnel, None), "no link: nothing is claimed");
    assert!(!older_service(&proxy, Some(3)), "Proxy mode runs here");
}
