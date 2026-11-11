//! The projection task: re-reads every section whenever a store, the tunnel or a local fact
//! changes, and publishes only what differs (the page re-renders per changed snapshot).
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use vpnte_core::settings::RuleSetMode;
use vpnte_engine::routing::rulesets::ActiveSource;
use vpnte_tunnel::fsm::{TunnelSnapshot, TunnelState};
use vpnte_tunnel::history::SessionMode;
use vpnte_tunnel::lifecycle::SessionView;
use vpnte_ui::settings as ui;

use super::project::{self, dns_view, domains_view, kill_switch_view, notifications_view};
use super::{Shared, actions, wizard};
use crate::services::{Backend, KillSwitchStatus, TunnelOps};

/// Coalesces bursts of store events (a save writes several documents) into one projection.
const DEBOUNCE: Duration = Duration::from_millis(40);

/// Publishes the store-backed sections at once (no flash of defaults) and starts the task
/// that keeps every section current until `backend.shutdown`.
pub fn spawn(shared: &Arc<Shared>) {
    let tunnel = shared.backend.tunnel().ok().cloned();
    let (snapshot, session) = tunnel_now(tunnel.as_deref());
    publish_stores(shared, &snapshot, session.as_ref());
    let status = KillSwitchStatus {
        settings: shared.backend.protection.read(|d| d.settings.clone()),
        wfp: None,
    };
    publish(&shared.kill, kill_switch_view(&status, &snapshot));
    tokio::spawn(run(shared.clone(), tunnel));
}

async fn run(shared: Arc<Shared>, tunnel: Option<Arc<dyn TunnelOps>>) {
    let backend = shared.backend.clone();
    let mut settings = backend.settings.subscribe();
    let mut protection = backend.protection.subscribe();
    let mut rules = backend.rules.subscribe();
    let mut soft = backend.soft.subscribe();
    let mut themes = backend.themes.subscribe();
    let mut snapshot = tunnel.as_ref().map(|t| t.snapshot());
    let mut session = tunnel.as_ref().map(|t| t.session());

    // Facts read from Windows once at start; the actions refresh them later.
    let autostart = actions::read_autostart(&shared).await;
    shared.touch(|l| l.autostart = autostart);
    let _ = actions::check_os_notifications(&shared).await;
    if !backend.settings.read(|s| s.first_run_complete) {
        wizard::open(&shared).await;
    }

    let mut kill_dirty = true;
    loop {
        let (snap, sess) = tunnel_now(tunnel.as_deref());
        publish_stores(&shared, &snap, sess.as_ref());
        if kill_dirty && let Some(tunnel) = &tunnel {
            let status = tunnel.kill_switch().await;
            publish(&shared.kill, kill_switch_view(&status, &snap));
        }
        kill_dirty = tokio::select! {
            () = backend.shutdown.cancelled() => break,
            () = changed(&mut settings) => false,
            () = changed(&mut rules) => false,
            () = changed(&mut soft) => false,
            () = changed(&mut themes) => false,
            () = changed(&mut protection) => true,
            () = changed_opt(&mut snapshot) => true,
            () = changed_opt(&mut session) => true,
            () = shared.dirty.notified() => true,
        };
        tokio::time::sleep(DEBOUNCE).await;
    }
}

/// The tunnel's published state now (idle defaults without a tunnel).
fn tunnel_now(tunnel: Option<&dyn TunnelOps>) -> (TunnelSnapshot, Option<SessionView>) {
    match tunnel {
        Some(t) => (t.snapshot().borrow().clone(), t.session().borrow().clone()),
        None => (TunnelSnapshot::default(), None),
    }
}

/// Every section that comes from stores and local facts.
fn publish_stores(shared: &Shared, snap: &TunnelSnapshot, session: Option<&SessionView>) {
    let backend = &shared.backend;
    let settings = backend.settings.snapshot();
    let (autostart, os, refreshing, last_error) = {
        let l = shared.local.lock();
        let os = l.os_notifications.clone();
        (
            l.autostart,
            os,
            l.rule_sets_refreshing,
            l.rule_sets_error.clone(),
        )
    };
    let soft = backend.soft.read(|d| d.dev_targets);
    let leak = backend.protection.read(|d| d.settings.leak_protection);
    let state = ui::SettingsState {
        settings: project::settings_view(&settings, &soft, leak),
        locale: settings.locale,
        active_theme_id: settings.active_theme_id.clone(),
        themes: backend.themes.read(project::themes),
        autostart: autostart.unwrap_or(false),
        // Location privacy is not wired in this build: never shown as active.
        location_privacy: false,
        proxy_credentials_saved: settings
            .proxy_override
            .as_ref()
            .is_some_and(|p| p.credentials.is_some()),
        capture_consent_given: false,
        capture_used_bytes: None,
        connected: snap.state == TunnelState::Connected,
        direct_session: session.is_some_and(|s| s.mode == SessionMode::Direct),
        // `message: None` = adaptive status unavailable (not exposed by the tunnel here).
        adaptive: ui::AdaptiveView::default(),
        rule_sets: rule_set_view(backend, &settings, refreshing, last_error),
        browser: ui::BrowserView::default(),
        diagnostics_export_running: false,
    };
    publish(&shared.state, state);
    let doc = backend.rules.snapshot();
    publish(&shared.dns, dns_view(&doc));
    publish(&shared.domains, domains_view(&doc, settings.smart_ru_split));
    publish(&shared.notifications, notifications_view(&settings, os));
}

/// Which Smart RU lists the next engine start uses (the service's own choice rule).
fn rule_set_view(
    backend: &Backend,
    settings: &vpnte_core::settings::Settings,
    refreshing: bool,
    last_error: Option<vpnte_base::Msg>,
) -> ui::RuleSetView {
    let managed = settings.smart_ru_rule_set_mode == RuleSetMode::Managed;
    let (active_source, managed_at) = match backend.rule_sets.active(managed) {
        Some((ActiveSource::Managed { since, .. }, _)) => (ui::RuleSource::Managed, Some(since)),
        _ => (ui::RuleSource::Bundled, None),
    };
    ui::RuleSetView {
        active_source,
        managed_at,
        refreshing,
        last_error,
    }
}

/// Sends `value` only when it differs from the published one.
pub fn publish<T: PartialEq>(tx: &watch::Sender<T>, value: T) {
    tx.send_if_modified(|current| {
        let differs = *current != value;
        if differs {
            *current = value;
        }
        differs
    });
}

/// Waits for the next change; a closed channel never wakes the loop again.
async fn changed<T>(rx: &mut watch::Receiver<T>) {
    if rx.changed().await.is_err() {
        std::future::pending::<()>().await;
    }
}

async fn changed_opt<T>(rx: &mut Option<watch::Receiver<T>>) {
    match rx {
        Some(rx) => changed(rx).await,
        None => std::future::pending().await,
    }
}
