//! What the app lends the subscription fetcher (ru-2026 item 3): the session's route by capture,
//! and the server a spare slot runs on. Projection of the provider facts and of hide-settings.
use std::collections::HashMap;

use vpnte_base::types::ProxyKind;
use vpnte_core::net::{HostPort, Route};
use vpnte_profiles::text::Controls;
use vpnte_servers::model::{
    ArchiveReason, Archived, HealthRecord, ProfileId, ServerReaction, ServerVerdict, VerdictRecord,
};
use vpnte_tunnel::api::{CaptureKind, ProxyEndpoint, SessionEndpoints, TunStatus};

use super::super::relays::{pick_healthy, session_route};
use super::*;

fn endpoints(proxy_port: Option<u16>) -> SessionEndpoints {
    SessionEndpoints {
        clash_port: 9,
        clash_secret: "0".repeat(32),
        direct: ProxyEndpoint {
            port: 9,
            user: "fake-user".into(),
            pass: "fake-pass".into(),
        },
        probe: None,
        tun_luid: None,
        tun_alias: None,
        proxy_port,
        logs: Vec::new(),
    }
}

/// Proxy capture: the mixed inbound (SOCKS, remote DNS); TUN: nothing (a direct request rides the
/// tunnel); no session or no inbound: nothing.
#[test]
fn session_route_by_capture() {
    let mut status = TunStatus::default();
    assert_eq!(session_route(&status), None);
    status.capture = Some(CaptureKind::Proxy);
    status.session = Some(endpoints(Some(20555)));
    let inbound = HostPort::parse("127.0.0.1:20555").unwrap();
    let want = Route::proxy(ProxyKind::Socks5, &inbound, None);
    assert_eq!(session_route(&status), Some(want));
    status.session = Some(endpoints(None));
    assert_eq!(session_route(&status), None);
    status.capture = Some(CaptureKind::Tun);
    status.session = Some(endpoints(Some(20555)));
    assert_eq!(session_route(&status), None);
}

fn health(online: bool, at: i64) -> Option<HealthRecord> {
    Some(HealthRecord {
        online,
        at,
        rtt_ms: None,
        reason: None,
        egress_ip: None,
    })
}

fn verdict(verdict: ServerVerdict, at: i64) -> VerdictRecord {
    VerdictRecord {
        verdict,
        reaction: ServerReaction::None,
        at,
    }
}

/// The newest positive evidence wins; a newer failure cancels an older success; archived, locked
/// and the main VPN's server are never borrowed.
#[test]
fn spare_slot_takes_the_newest_working_server() {
    let mut rows: Vec<ServerSummary> = ["a", "b", "c", "d", "e", "f"]
        .iter()
        .map(|id| row(id, "g"))
        .collect();
    rows[0].health = health(true, 10);
    rows[1].health = health(true, 20);
    rows[2].health = health(false, 30); // c: newer healthy verdict below
    rows[3].health = health(true, 50); // d: archived
    rows[3].archived = Some(Archived {
        at: 1,
        reason: ArchiveReason::Provider,
    });
    rows[4].health = health(true, 60); // e: locked
    rows[4].locked = true;
    rows[5].health = health(true, 70); // f: the main VPN's server
    let mut verdicts = HashMap::new();
    verdicts.insert(ProfileId::from("c"), verdict(ServerVerdict::Healthy, 40));
    verdicts.insert(ProfileId::from("b"), verdict(ServerVerdict::Frozen, 25));
    let avoid = ProfileId::from("f");
    let got = pick_healthy(&rows, &verdicts, Some(&avoid));
    assert_eq!(got, Some(ProfileId::from("c")));
    verdicts.insert(ProfileId::from("c"), verdict(ServerVerdict::Stalled, 45));
    let got = pick_healthy(&rows, &verdicts, Some(&avoid));
    assert_eq!(
        got,
        Some(ProfileId::from("a")),
        "b's newer verdict is a freeze"
    );
    assert_eq!(pick_healthy(&rows[2..3], &verdicts, None), None);
}

/// ru-2026 items 2 and 22: the provider's facts reach the page; hide-settings marks the group and
/// its rows, a manual group never.
#[test]
fn provider_facts_and_hidden_rows_are_projected() {
    let mut sub = group("sub", false);
    sub.info = SubscriptionMeta {
        support_url: Some("https://t.me/support_example".into()),
        announce: Some("Maintenance tonight".into()),
        refresh_hours: Some(6),
        ..SubscriptionMeta::default()
    };
    sub.send_hwid = true;
    sub.header_names = vec!["X-Panel-Client".into()];
    sub.moved_at = Some(5);
    sub.host = Some("new.example.net".into());
    sub.controls = Controls {
        hide_settings: Some(true),
        ..Controls::default()
    };
    let mut keys = group("keys", true);
    keys.controls.hide_settings = Some(true);
    let list = sm::ServersView {
        groups: vec![sub, keys],
        servers: vec![row("a", "sub"), row("b", "keys")],
        ..sm::ServersView::default()
    };
    let view = project(&Inputs {
        list: &list,
        extras: &HashMap::new(),
        ips: &HashMap::new(),
        tunnel: None,
        session: None,
        switching: None,
        geo_disabled: false,
        lang: Lang::En,
    });
    let g = &view.groups[0];
    assert_eq!(
        g.support_url.as_deref(),
        Some("https://t.me/support_example")
    );
    assert_eq!(g.announce.as_deref(), Some("Maintenance tonight"));
    assert_eq!(g.provider_refresh_hours, Some(6));
    assert!(g.send_hwid && g.settings_hidden);
    assert_eq!(g.header_names, ["X-Panel-Client"]);
    assert_eq!(g.moved_at, Some(5));
    assert_eq!(
        g.host.as_deref(),
        Some("new.example.net"),
        "the move note names it"
    );
    assert!(!view.groups[1].settings_hidden);
    let hidden: Vec<bool> = view.servers.iter().map(|s| s.config_hidden).collect();
    assert_eq!(hidden, [true, false]);
    // Security state is never hidden: protocol and engine plan stay.
    assert_eq!(view.servers[0].protocol, "vless");
}

/// ru-2026 item 22: copy, save and the bulk export refuse the servers of a group whose provider
/// sent `hide-settings`, before any Save dialog opens; other servers export as before.
#[tokio::test]
async fn hidden_servers_never_leave_the_app() {
    locales();
    let env = super::backend::Env::new("hidden");
    let added = add_hidden(&env);
    assert_hidden(&env, &added.added[0].to_string()).await;
}

/// subs-a4 / subs-b9: the keys stay hidden when their group is deleted with "keep the servers"
/// (they move to the manual keys, which never hide by themselves).
#[tokio::test]
async fn hidden_keys_stay_hidden_in_the_manual_group() {
    locales();
    let env = super::backend::Env::new("hidden-kept");
    let added = add_hidden(&env);
    env.backend
        .servers
        .delete_group(&added.group, false)
        .unwrap();
    let row = env.backend.servers.get(&added.added[0]).unwrap();
    assert_ne!(row.group_id, added.group, "moved to the manual keys");
    assert_hidden(&env, &added.added[0].to_string()).await;
}

/// The keys of the reports' paste, imported as a subscription that sent `hide-settings`.
pub(super) fn add_hidden(env: &super::backend::Env) -> vpnte_servers::store::AddReport {
    use vpnte_servers::store::{AddTarget as StoreTarget, NewSubscription};

    let profiles = vpnte_servers::parse::parse_text(super::reports::PASTE)
        .unwrap()
        .profiles;
    let target = StoreTarget::Subscription(Box::new(NewSubscription {
        url: vpnte_servers::subscription::canonical_source("https://sub.example.net/feed/token")
            .unwrap(),
        device: ClientDevice::Pc,
        info: SubscriptionMeta::default(),
        partial: false,
        send_hwid: false,
        headers: None,
        controls: Controls {
            hide_settings: Some(true),
            ..Controls::default()
        },
        fallback: None,
        moved_at: None,
    }));
    env.backend.servers.add(profiles, target).unwrap()
}

/// Copy, save and both bulk exports refuse `id` before any Save dialog; the page hides it.
async fn assert_hidden(env: &super::backend::Env, id: &str) {
    use vpnte_ui::servers::ServersApi;

    let api = super::super::ServersBackend::start(env.backend.clone());
    let key = |err: vpnte_base::AppError| err.user_msg().key.into_owned();
    assert_eq!(
        key(api.copy_key(id).await.unwrap_err()),
        "servers.hidden.refused"
    );
    assert_eq!(
        key(api.save_key(id).await.unwrap_err()),
        "servers.hidden.refused"
    );
    let all = api.export_all_keys().await.unwrap_err();
    assert_eq!(key(all), "servers.hidden.refused");
    let proxies = api.export_proxy_list().await.unwrap_err();
    assert_eq!(key(proxies), "servers.hidden.refused");
    assert!(api.state().borrow().servers.iter().all(|s| s.config_hidden));
}

/// A slot start that takes `ms` and records when its spare is dropped (the slot's stop).
fn slow_start(
    ms: u64,
    stopped: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> impl std::future::Future<Output = Option<vpnte_servers::subscription::Spare>> + Send + 'static
{
    let stopped = stopped.clone();
    async move {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        let addr = HostPort::new("127.0.0.1", 1080).unwrap();
        let route = Route::proxy(ProxyKind::Socks5, &addr, None);
        let stop = move || stopped.store(true, std::sync::atomic::Ordering::SeqCst);
        Some(vpnte_servers::subscription::Spare::new(route, stop))
    }
}

/// subs-a1: a fetch that gives up while the spare slot is still starting (its future dropped by
/// the deadline, or its token cancelled) leaves no slot behind: the start finishes in its own
/// task and the slot is stopped. A fetch that waits gets the spare, and its drop stops the slot.
#[tokio::test]
async fn a_spare_given_up_mid_start_is_stopped() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio_util::sync::CancellationToken;

    use super::super::relays::lend;

    let wait = |ms| tokio::time::sleep(std::time::Duration::from_millis(ms));
    let dropped = Arc::new(AtomicBool::new(false));
    let start = slow_start(100, &dropped);
    let gave_up = tokio::time::timeout(
        std::time::Duration::from_millis(10),
        lend(start, CancellationToken::new()),
    )
    .await;
    assert!(gave_up.is_err(), "the fetch gave up mid-start");
    wait(300).await;
    assert!(dropped.load(Ordering::SeqCst), "the late slot was stopped");

    let cancelled = Arc::new(AtomicBool::new(false));
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        token.cancel();
    });
    assert!(lend(slow_start(100, &cancelled), cancel).await.is_none());
    wait(50).await;
    assert!(cancelled.load(Ordering::SeqCst));

    let kept = Arc::new(AtomicBool::new(false));
    let spare = lend(slow_start(10, &kept), CancellationToken::new()).await;
    assert!(spare.is_some());
    assert!(!kept.load(Ordering::SeqCst), "in use");
    drop(spare);
    assert!(kept.load(Ordering::SeqCst), "handed back");
}
