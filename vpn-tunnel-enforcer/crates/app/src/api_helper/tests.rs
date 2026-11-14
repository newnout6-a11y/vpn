//! The capability view (p-noadmin-ui): the derivation for each state of the service and of the
//! process's rights, and the view following the tunnel's facts. No test reaches a real service
//! (the fake tunnel stands for it) and none asks Windows for the install.
use std::sync::atomic::Ordering;
use std::time::Duration;

use vpnte_service::proto::PROTOCOL;
use vpnte_ui::helper::{Ability, HelperApi, Lack, Service};

use super::*;
use crate::api_settings::test_support::{FakeTunnel, TempDir, backend};

fn facts(installed: bool, protocol: Option<u32>, elevated: bool, tun: bool) -> Facts {
    Facts {
        installed,
        protocol,
        elevated,
        tun,
        starting: false,
        scm: None,
    }
}

/// p-live2 (lab, p-live-fix): an installed service that Windows is starting, or that is
/// stopped, is said as such; Tunnel mode still belongs to it (it comes back by itself).
#[test]
fn a_service_that_is_down_is_said_as_such() {
    let installed = facts(true, Some(PROTOCOL), false, true);
    for (scm, starting, expected) in [
        (Some(Presence::Starting), false, Service::Starting),
        (Some(Presence::Running), true, Service::Starting),
        (None, true, Service::Starting),
        (Some(Presence::Stopped), false, Service::Stopped),
        (Some(Presence::Stopping), false, Service::Stopped),
        (Some(Presence::Running), false, Service::Installed),
        (Some(Presence::Missing), false, Service::Installed),
    ] {
        let cap = derive(Facts {
            scm,
            starting,
            ..installed
        });
        assert_eq!(cap.service, expected, "{scm:?} {starting}");
        assert_eq!(cap.tunnel, Ability::Service);
    }
    assert_eq!(Service::Starting.pause_key(), Some("ui.helper.starting"));
    assert_eq!(Service::Stopped.pause_key(), Some("ui.helper.stopped"));
    assert_eq!(Service::Installed.pause_key(), None);
}

/// The prompt was declined: proxy mode; Tunnel mode and the kill switch wait for the service,
/// browser policies and packet capture are not in this version for an unelevated app.
#[test]
fn without_the_service_tunnel_and_kill_switch_wait_for_it() {
    let cap = derive(facts(false, None, false, false));
    assert_eq!(cap.service, Service::Missing);
    assert!(!cap.elevated);
    assert_eq!(cap.tunnel, Ability::NeedsService);
    assert_eq!(cap.kill_switch, Ability::NeedsService);
    assert_eq!(cap.policies, Ability::NotInVersion);
    assert_eq!(cap.capture, Ability::NotInVersion);
}

/// Installed: Tunnel mode and the kill switch go through it, before its first link too.
#[test]
fn an_installed_service_carries_tunnel_and_kill_switch() {
    for protocol in [None, Some(PROTOCOL)] {
        let cap = derive(facts(true, protocol, false, true));
        assert_eq!(cap.service, Service::Installed, "{protocol:?}");
        assert_eq!(cap.tunnel, Ability::Service);
        assert_eq!(cap.kill_switch, Ability::Service);
        assert_eq!(cap.policies, Ability::NotInVersion);
    }
}

/// One version behind (the oldest the app still links to): it runs Tunnel mode without the
/// apps page's scope until it updates itself.
#[test]
fn an_older_service_says_what_it_lacks() {
    let cap = derive(facts(true, Some(PROTOCOL - 1), false, true));
    assert_eq!(
        cap.service,
        Service::Older {
            lacks: vec![Lack::AppScope]
        }
    );
    assert_eq!(cap.tunnel, Ability::Service);
    assert_eq!(lacks(SCOPE_PROTOCOL), Vec::new());
}

/// Elevated without the service (development, CI): everything privileged it can host runs
/// in-process, as before; capture is still not built.
#[test]
fn an_elevated_app_without_the_service_works_in_process() {
    let cap = derive(facts(false, None, true, true));
    assert_eq!(cap.service, Service::Missing);
    assert!(cap.elevated);
    assert_eq!(cap.tunnel, Ability::InProcess);
    assert_eq!(cap.kill_switch, Ability::InProcess);
    assert_eq!(cap.policies, Ability::InProcess);
    assert_eq!(cap.capture, Ability::NotInVersion);
    // Its own exe unusable for WFP: no TUN here either, so the service is what helps.
    let cap = derive(facts(false, None, true, false));
    assert_eq!(cap.tunnel, Ability::NeedsService);
}

/// Elevated with the service installed: the service owns the TUN and our filters (the guard's
/// rule); the browser policies stay in-process.
#[test]
fn an_elevated_app_leaves_tunnel_and_filters_to_an_installed_service() {
    let cap = derive(facts(true, Some(PROTOCOL), true, true));
    assert_eq!(cap.tunnel, Ability::Service);
    assert_eq!(cap.kill_switch, Ability::Service);
    assert_eq!(cap.policies, Ability::InProcess);
}

/// Waits (bounded) until the published view satisfies `pred`.
async fn until(rx: &watch::Receiver<Capability>, pred: impl Fn(&Capability) -> bool) -> Capability {
    let mut rx = rx.clone();
    let wait = async {
        loop {
            {
                let now = rx.borrow_and_update();
                if pred(&now) {
                    return now.clone();
                }
            }
            rx.changed().await.expect("view open");
        }
    };
    tokio::time::timeout(Duration::from_secs(10), wait)
        .await
        .expect("view in time")
}

/// The view at start, after the service's first link (its version comes with the next change
/// of the session), and after a lost link whose re-link brings the updated service's version
/// with no event of its own (the window's re-reads find it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_view_follows_the_service() {
    let dir = TempDir::new("helper-follow");
    let fake = FakeTunnel::new(false);
    let backend = backend(&dir, fake.clone());
    let helper = HelperService::start(backend.clone());
    let rx = helper.capability();
    assert_eq!(rx.borrow().service, Service::Missing);
    assert_eq!(rx.borrow().tunnel, Ability::NeedsService);

    fake.service.store(true, Ordering::Relaxed);
    fake.protocol.store(PROTOCOL - 1, Ordering::Relaxed);
    fake.snapshot.send_modify(|_| {});
    let cap = until(&rx, |c| matches!(c.service, Service::Older { .. })).await;
    assert_eq!(cap.tunnel, Ability::Service);

    fake.losses.send_modify(|n| *n += 1);
    tokio::time::sleep(Duration::from_millis(200)).await;
    fake.protocol.store(PROTOCOL, Ordering::Relaxed);
    until(&rx, |c| c.service == Service::Installed).await;
    backend.shutdown.cancel();
}
