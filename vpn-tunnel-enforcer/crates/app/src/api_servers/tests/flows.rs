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
    SubscriptionRequest,
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
        .add(
            PASTE.to_owned(),
            AddTarget::Auto,
            ClientDevice::Pc,
            SubscriptionRequest::default(),
        )
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

    // p-small (RU-2026 item 6), psmall-a4: the list-wide check runs through the probes; no
    // engine can start here, so nothing could be checked: the answer says why (as a group check
    // does), nothing streams and nothing is stored. The engine's own refusal is the reason: an
    // unelevated process cannot spawn the missing exe, an elevated one (CI's runner) refuses it
    // first at the release pin check (`vpnte_engine::pin`).
    let (results, mut landed) = mpsc::unbounded_channel();
    let err = api.check_all_health(results).await.unwrap_err();
    let key = err.user_msg().key;
    assert!(
        [
            "engine.process.spawnFailed",
            "engine.process.notPinned",
            "engine.process.fileMissing",
        ]
        .contains(&key.as_ref()),
        "the engine's refusal, got {key}"
    );
    assert!(landed.try_recv().is_err());
    assert!(state.borrow().servers.iter().all(|s| s.health.is_none()));

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
    // p-small (RU-2026 item 6): the list-wide check has nothing left either.
    let (results, _keep) = mpsc::unbounded_channel();
    let err = api.check_all_health(results).await.unwrap_err();
    assert_eq!(err.user_msg().key, "app.servers.nothingToCheck");
}

/// AT-00-003 / AT-00-007 (selection owns its cleanup): a live switch publishes its target, the
/// cancel ends it silently, and the marker stays on the server the tunnel still runs on.
#[tokio::test]
async fn a_live_switch_shows_its_target_and_can_be_cancelled() {
    locales();
    let env = Env::new("switch");
    let api = Rc::new(ServersBackend::start(env.backend.clone()));
    let mut state = api.state();
    api.add(
        PASTE.to_owned(),
        AddTarget::Auto,
        ClientDevice::Pc,
        SubscriptionRequest::default(),
    )
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

/// ENGINE-GAPS decisions 2 and 3: every row says which engine a connect would use and why; the
/// row's own engine is stored and shown; a forced engine that cannot run the key is refused with
/// the selection's own sentence and nothing is stored.
#[tokio::test]
async fn per_server_engine_is_visible_and_never_impossible() {
    use vpnte_base::types::{Engine, EnginePref};
    use vpnte_ui::servers::EnginePlan;
    locales();
    let env = Env::new("engine");
    let api = ServersBackend::start(env.backend.clone());
    let mut state = api.state();
    let paste = "vless://11111111-2222-3333-4444-555555555555@good.example.net:443?security=tls&sni=good.example.net#ok\n\
        tuic://00000000-0000-4000-8000-000000000003:fake-password@203.0.113.13:443?sni=example.com#t\n";
    api.add(
        paste.to_owned(),
        AddTarget::Auto,
        ClientDevice::Pc,
        SubscriptionRequest::default(),
    )
    .await
    .unwrap();
    let view = state.borrow().clone();
    let (vless, tuic) = (view.servers[0].clone(), view.servers[1].clone());
    let plan = |engine, key: &str| EnginePlan::Runs {
        engine,
        reason: vpnte_base::Msg::new(key.to_owned()),
    };
    assert_eq!(vless.engine, EnginePref::Auto);
    let default = plan(Engine::SingBox, "engine.xray.reason.default");
    assert_eq!(vless.engine_plan, Some(default));
    let protocol = plan(Engine::SingBox, "engine.xray.reason.protocol");
    assert_eq!(tuic.engine_plan, Some(protocol));

    api.set_engine(&vless.id, EnginePref::Xray).await.unwrap();
    let id = vless.id.clone();
    until(&mut state, |v| {
        v.servers
            .iter()
            .any(|s| s.id == id && s.engine == EnginePref::Xray)
    })
    .await;
    let row = state.borrow().servers[0].clone();
    let chosen = plan(Engine::Xray, "engine.xray.reason.preference");
    assert_eq!(row.engine_plan, Some(chosen));

    let err = api
        .set_engine(&tuic.id, EnginePref::Xray)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Validation);
    assert_eq!(err.user_msg().key, "engine.xray.reject.noXrayClient");
    let stored = env.backend.servers.get(&tuic.id.as_str().into()).unwrap();
    assert_eq!(stored.engine, EnginePref::Auto, "nothing stored");
}

/// p-uiperf: the results of a ping-all (20 in a second) reach the page paced: pushes at least
/// 500 ms apart, the last one with the last result.
#[tokio::test(start_paused = true)]
async fn ping_results_reach_the_page_paced() {
    use std::time::Duration;
    locales();
    let env = Env::new("pace");
    let api = ServersBackend::start(env.backend.clone());
    api.add(
        PASTE.to_owned(),
        AddTarget::Auto,
        ClientDevice::Pc,
        SubscriptionRequest::default(),
    )
    .await
    .unwrap();
    let mut state = api.state();
    let id = until(&mut state, |v| !v.servers.is_empty()).await.servers[0]
        .id
        .clone();
    // the import's own pushes go out first
    tokio::time::sleep(Duration::from_secs(2)).await;
    state.mark_unchanged();
    let watched = id.clone();
    let recorder = tokio::spawn(async move {
        let mut pushes = Vec::new();
        while let Ok(Ok(())) = tokio::time::timeout(Duration::from_secs(3), state.changed()).await {
            let view = state.borrow_and_update();
            let ping = view
                .servers
                .iter()
                .find(|s| s.id == watched)
                .and_then(|s| s.ping_ms);
            pushes.push((tokio::time::Instant::now(), ping));
        }
        pushes
    });
    for rtt in 1..=20 {
        env.backend
            .servers
            .record_ping(&id.as_str().into(), Some(rtt));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let pushes = recorder.await.expect("recorder");
    assert!((2..=4).contains(&pushes.len()), "{pushes:?}");
    for pair in pushes.windows(2) {
        assert!(
            pair[1].0 - pair[0].0 >= Duration::from_millis(500),
            "{pushes:?}"
        );
    }
    assert_eq!(pushes.last().map(|p| p.1), Some(Some(20)), "{pushes:?}");
}
