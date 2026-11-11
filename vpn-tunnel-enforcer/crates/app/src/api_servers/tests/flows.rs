//! Flows of the page over a real list: import, select, live switch with cancel, pings, archive,
//! groups, persisted UI state, and the honest answers of what this build does not wire.
use std::num::NonZeroU32;
use std::rc::Rc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vpnte_base::ErrorKind;
use vpnte_base::types::ClientDevice;
use vpnte_ui::servers::{
    AddTarget, ArchiveReason, CountryCheck, LiveMode, SelectOutcome, ServersApi,
};

use super::super::ServersBackend;
use super::backend::{Env, until};
use super::locales;
use super::reports::PASTE;

#[tokio::test]
async fn the_page_works_over_a_real_list() {
    locales();
    let env = Env::new("flow");
    let api = ServersBackend::start(env.backend.clone());
    let state = api.state();
    assert!(state.borrow().loaded && state.borrow().servers.is_empty());

    let report = api
        .add(PASTE.to_owned(), AddTarget::Auto, ClientDevice::Pc)
        .await
        .unwrap();
    assert_eq!((report.added, report.subscription), (2, false));
    assert_eq!(report.group_name, "Manual keys");
    let lines: Vec<u32> = report.skipped.iter().map(|s| s.line).collect();
    assert_eq!(lines, [3, 5]);
    // Published before the call answered.
    let view = state.borrow().clone();
    assert_eq!(view.servers.len(), 2);
    let (first, second) = (view.servers[0].id.clone(), view.servers[1].id.clone());
    assert_eq!(
        view.active_id.as_deref(),
        Some(first.as_str()),
        "first key selected"
    );
    assert_eq!(view.groups[0].name, "Manual keys");
    assert_eq!(view.servers[0].protocol, "vless");

    assert_eq!(api.select(&second).await.unwrap(), SelectOutcome::Switched);
    assert_eq!(state.borrow().active_id.as_deref(), Some(second.as_str()));

    assert_eq!(api.ping_one(&second).await.unwrap(), Some(33));
    assert_eq!(state.borrow().servers[1].ping_ms, Some(33));
    let (tx, mut rx) = mpsc::unbounded_channel();
    api.ping_many(vec![first.clone(), second.clone()], tx)
        .await
        .unwrap();
    let mut answers = Vec::new();
    while let Ok(answer) = rx.try_recv() {
        answers.push(answer);
    }
    answers.sort();
    let mut expected = vec![(first.clone(), Some(33)), (second.clone(), Some(33))];
    expected.sort();
    assert_eq!(answers, expected, "every answer, as it landed");
    let err = api.ping_one("gone").await.unwrap_err();
    assert_eq!(err.user_msg().key, "servers.notFound");

    api.remove(&first).await.unwrap();
    let archive = state.borrow().servers[0].archived.expect("archived");
    assert_eq!(archive.reason, ArchiveReason::User);
    api.restore(&first).await.unwrap();
    assert!(state.borrow().servers[0].archived.is_none());
    api.purge(&first).await.unwrap();
    assert_eq!(state.borrow().servers.len(), 1);

    let group = state.borrow().groups[0].id.clone();
    api.rename_group(&group, "  My   keys ".into())
        .await
        .unwrap();
    assert_eq!(state.borrow().groups[0].name, "My keys");
    let err = api
        .set_refresh_interval(&group, NonZeroU32::new(30))
        .await
        .unwrap_err();
    assert_eq!(err.user_msg().key, "servers.group.manualNoRefresh");
    api.save_expanded_groups(vec![group.clone()]).await.unwrap();
    assert_eq!(api.expanded_groups(), std::slice::from_ref(&group));

    // Geo lookups are off in this data dir: no request, an honest answer.
    let check = api.verify_country(&second).await.unwrap();
    assert_eq!(check, CountryCheck::GeoDisabled);
    assert_eq!(api.geo(&second).await.unwrap(), None);
    assert!(state.borrow().geo_lookup_disabled);

    let (progress, _keep) = mpsc::unbounded_channel();
    let err = api
        .live_check(&second, LiveMode::Basic, progress)
        .await
        .unwrap_err();
    assert_eq!(
        (err.kind, err.user_msg().key.as_ref()),
        (ErrorKind::Conflict, "app.servers.liveUnavailable")
    );
    let err = api.live_history(&second).await.unwrap_err();
    assert_eq!(err.user_msg().key, "app.servers.liveUnavailable");
    let (progress, _keep) = mpsc::unbounded_channel();
    let stop = CancellationToken::new();
    let err = api
        .live_batch(vec![second.clone()], stop, progress)
        .await
        .unwrap_err();
    assert_eq!(err.user_msg().key, "app.servers.liveUnavailable");
    let err = api.start_proxies(vec![second.clone()]).await.unwrap_err();
    assert_eq!(err.user_msg().key, "app.servers.proxiesUnavailable");

    // Every key the user removed: nothing left to check in the group.
    api.remove(&second).await.unwrap();
    let err = api.check_group_health(&group).await.unwrap_err();
    assert_eq!(err.user_msg().key, "probes.keyHealth.groupEmpty");
    let err = api.check_group_health("gone").await.unwrap_err();
    assert_eq!(err.user_msg().key, "servers.group.notFound");
}

/// AT-00-003 / AT-00-007 (selection owns its cleanup): a live switch publishes its target, the
/// cancel ends it silently, and the marker stays on the server the tunnel still runs on.
#[tokio::test]
async fn a_live_switch_shows_its_target_and_can_be_cancelled() {
    locales();
    let env = Env::new("switch");
    let api = Rc::new(ServersBackend::start(env.backend.clone()));
    let mut state = api.state();
    api.add(PASTE.to_owned(), AddTarget::Auto, ClientDevice::Pc)
        .await
        .unwrap();
    let view = state.borrow().clone();
    let (first, second) = (view.servers[0].id.clone(), view.servers[1].id.clone());
    env.tunnel.connect_to(&first);
    until(&mut state, |v| v.tunnel_running).await;

    let target = second.clone();
    let (outcome, ()) = tokio::join!(api.select(&second), async {
        let mut watch = api.state();
        until(&mut watch, |v| {
            v.switching_to.as_deref() == Some(target.as_str())
        })
        .await;
        api.cancel_switch().await.unwrap();
    });
    assert_eq!(outcome.unwrap(), SelectOutcome::Cancelled);
    let view = state.borrow().clone();
    assert_eq!(view.switching_to, None);
    assert!(view.tunnel_running);
    assert_eq!(
        view.active_id.as_deref(),
        Some(first.as_str()),
        "the tunnel did not move"
    );
}
