//! Connecting at launch (RU item 7): off by default, the user's choice or the provider's word,
//! the lowest delay measured one check at a time, never against the user.
use vpnte_base::types::{Owner, now_ms};

use super::*;
use crate::coordinator::testing::Call;
use crate::coordinator::{OpError, SessionKind};

fn direct(id: &str) -> ConnectRequest {
    ConnectRequest::Direct {
        profile_id: id.to_owned(),
    }
}

fn three() -> Rig {
    let rig = rig(vec![server("a", "g"), server("b", "g"), server("c", "h")]);
    *rig.host.last_used.lock() = Some("a".into());
    rig
}

#[tokio::test(start_paused = true)]
async fn nothing_connects_at_launch_by_default() {
    let rig = three();
    let done = rig.pick.launch(CancellationToken::new()).await;
    assert_eq!(done, Launched::Skipped);
    assert_eq!(rig.coord.connects(), 0);
    assert_eq!(rig.pick.launch_rule(), (None, LaunchSource::Default));
}

/// Review fix a13: an explicit Off is stored and wins over a provider's later word.
#[tokio::test(start_paused = true)]
async fn an_explicit_off_wins_over_the_providers_word() {
    let rig = three();
    rig.pick.set_choice(LaunchChoice::Off).unwrap();
    *rig.host.provider.lock() = Some(ProviderWord::On(LaunchPick::LastUsed));
    assert_eq!(rig.pick.launch_rule(), (None, LaunchSource::User));
    assert_eq!(
        rig.pick.launch(CancellationToken::new()).await,
        Launched::Skipped
    );
    assert_eq!(rig.coord.connects(), 0);
}

#[tokio::test(start_paused = true)]
async fn the_last_used_server_connects_at_launch_as_its_own_low_owner() {
    let rig = three();
    rig.pick.set_choice(LaunchChoice::LastUsed).unwrap();
    rig.pick.launch(CancellationToken::new()).await;
    assert_eq!(
        rig.coord.calls(),
        [Call::Connect(Owner::Autopilot, direct("a"))]
    );
    assert!(rig.host.checks.lock().is_empty(), "no handshake spent");
}

/// The provider's `subscription-autoconnect` with `-type: lowestdelay`: at most three servers
/// are checked, one after another, and the alive one with the lowest delay connects.
#[tokio::test(start_paused = true)]
async fn the_provider_word_connects_the_lowest_delay_measured_one_by_one() {
    let rig = rig(["a", "b", "c", "d"]
        .iter()
        .map(|id| server(id, "g"))
        .collect());
    *rig.host.last_used.lock() = Some("d".into());
    *rig.host.provider.lock() = Some(ProviderWord::On(LaunchPick::LowestDelay));
    let alive = |ms| {
        Some(Checked {
            alive: true,
            latency_ms: Some(ms),
        })
    };
    rig.host.check_results.lock().extend([
        ("a".to_owned(), alive(300)),
        ("b".to_owned(), alive(120)),
        (
            "c".to_owned(),
            Some(Checked {
                alive: false,
                latency_ms: None,
            }),
        ),
    ]);
    rig.pick.launch(CancellationToken::new()).await;
    assert_eq!(*rig.host.checks.lock(), ["a", "b", "c"]);
    assert_eq!(
        rig.coord.calls(),
        [Call::Connect(Owner::Autopilot, direct("b"))]
    );
}

/// The provider's word covers its own subscription only: the measuring stays in its group.
#[tokio::test(start_paused = true)]
async fn the_providers_lowest_delay_stays_in_its_group() {
    let rig = rig(vec![
        server("a", "g"),
        server("x", "other"),
        server("b", "g"),
    ]);
    *rig.host.last_used.lock() = Some("a".into());
    *rig.host.provider.lock() = Some(ProviderWord::On(LaunchPick::LowestDelay));
    let alive = |ms| {
        Some(Checked {
            alive: true,
            latency_ms: Some(ms),
        })
    };
    rig.host.check_results.lock().extend([
        ("a".to_owned(), alive(200)),
        ("b".to_owned(), alive(90)),
        ("x".to_owned(), alive(10)),
    ]);
    rig.pick.launch(CancellationToken::new()).await;
    assert_eq!(*rig.host.checks.lock(), ["a", "b"]);
    assert_eq!(
        rig.coord.calls(),
        [Call::Connect(Owner::Autopilot, direct("b"))]
    );
}

#[tokio::test(start_paused = true)]
async fn fresh_stored_delays_spend_no_handshake() {
    let mut servers = vec![server("a", "g"), server("b", "g")];
    for (s, ms) in servers.iter_mut().zip([90, 40]) {
        (s.alive, s.latency_ms, s.checked_at) = (Some(true), Some(ms), Some(now_ms()));
    }
    let rig = rig(servers);
    rig.pick.set_choice(LaunchChoice::LowestDelay).unwrap();
    rig.pick.launch(CancellationToken::new()).await;
    assert!(rig.host.checks.lock().is_empty());
    assert_eq!(
        rig.coord.calls(),
        [Call::Connect(Owner::Autopilot, direct("b"))]
    );
}

/// The automatic paths never act against the user: a Connect / Disconnect before the launch
/// run, a session that already runs, a lane left blocked, a local-proxy upstream.
#[tokio::test(start_paused = true)]
async fn a_launch_never_overrides_what_is_already_there() {
    let rig = three();
    rig.pick.set_choice(LaunchChoice::LastUsed).unwrap();
    rig.host.user_acts_now();
    let done = rig.pick.launch(CancellationToken::new()).await;
    assert_eq!(done, Launched::UserFirst);

    let rig = three();
    rig.pick.set_choice(LaunchChoice::LastUsed).unwrap();
    rig.coord
        .set_session(SessionKind::SoftDirect, Owner::Manual, Some("b"));
    rig.pick.launch(CancellationToken::new()).await;

    let left = three();
    left.pick.set_choice(LaunchChoice::LastUsed).unwrap();
    *left.coord.left_by.lock() = Some(Owner::Manual);
    left.pick.launch(CancellationToken::new()).await;

    let proxy = three();
    proxy.pick.set_choice(LaunchChoice::LastUsed).unwrap();
    *proxy.host.local_proxy.lock() = true;
    proxy.pick.launch(CancellationToken::new()).await;
    for coord in [&rig.coord, &left.coord, &proxy.coord] {
        assert_eq!(coord.connects(), 0);
    }
}

/// A refusal by the coordinator (a higher owner holds the lane) is quiet: no notice, no retries.
#[tokio::test(start_paused = true)]
async fn a_refused_launch_is_quiet() {
    let rig = three();
    rig.pick.set_choice(LaunchChoice::LastUsed).unwrap();
    rig.coord
        .connect_results
        .lock()
        .push_back(Err(OpError::Conflict));
    rig.pick.launch(CancellationToken::new()).await;
    assert!(rig.coord.notices.lock().is_empty());
    assert!(rig.host.refreshes.lock().is_empty());
}

/// TUN capture needs rights this process lacks: the refusal is shown once, no server is
/// measured or dialled for a connect that cannot run (review fix a12/b9), no retries.
#[tokio::test(start_paused = true)]
async fn a_permission_refusal_is_shown_once_without_measuring() {
    let rig = three();
    rig.pick.set_choice(LaunchChoice::LowestDelay).unwrap();
    *rig.host.refused.lock() = Some(vpnte_base::Msg::new("tunnel.runtime.tunUnavailable"));
    let done = rig.pick.launch(CancellationToken::new()).await;
    assert_eq!(
        done,
        Launched::Failed {
            profile_id: "a".into()
        }
    );
    assert!(rig.host.checks.lock().is_empty(), "nothing measured");
    assert_eq!(rig.coord.connects(), 0);
    assert!(rig.host.refreshes.lock().is_empty());
    assert_eq!(
        super::rescue::notices(&rig),
        [super::rescue::notice(
            vpnte_base::types::Level::Warn,
            "launch.failed",
            Some("tunnel.runtime.tunUnavailable")
        )]
    );

    // A local-proxy upstream: not ours, nothing measured, nothing said.
    let proxy = three();
    proxy.pick.set_choice(LaunchChoice::LowestDelay).unwrap();
    *proxy.host.local_proxy.lock() = true;
    assert_eq!(
        proxy.pick.launch(CancellationToken::new()).await,
        Launched::Skipped
    );
    assert!(proxy.host.checks.lock().is_empty());
    assert!(proxy.coord.notices.lock().is_empty());
}

/// Review fix a12: the lowest-delay measuring stops the moment the user acts.
#[tokio::test(start_paused = true)]
async fn the_measuring_stops_the_moment_the_user_acts() {
    let rig = three();
    rig.pick.set_choice(LaunchChoice::LowestDelay).unwrap();
    *rig.host.act_at.lock() = Some(("a".into(), false));
    let done = rig.pick.launch(CancellationToken::new()).await;
    assert_eq!(done, Launched::UserFirst);
    assert_eq!(
        *rig.host.checks.lock(),
        ["a"],
        "no second check after the user acted"
    );
    assert_eq!(rig.coord.connects(), 0);
}

/// With «Restart the engine after a crash» off the failed launch is told and nothing retries.
#[tokio::test(start_paused = true)]
async fn without_reconnects_a_failed_launch_is_told_once() {
    let rig = three();
    rig.pick.set_choice(LaunchChoice::LastUsed).unwrap();
    rig.host.allowed.lock().reconnect = false;
    rig.coord
        .connect_results
        .lock()
        .push_back(super::rescue::failed());
    rig.pick.launch(CancellationToken::new()).await;
    assert_eq!(rig.coord.connects(), 1);
    assert!(rig.host.refreshes.lock().is_empty());
    assert_eq!(
        rig.coord.notice_keys().first().map(String::as_str),
        Some("automation.autopick.launch.failed")
    );
}
