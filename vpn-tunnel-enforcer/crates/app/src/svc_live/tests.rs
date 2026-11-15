//! The live check's app side: our tunnel as the check sees it, the split-tunnel snapshot, the
//! history opened and pruned at start, and a check through the real runner that needs no
//! network (an unknown server).
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::json;
use tokio::sync::watch;
use vpnte_base::types::{ClientDevice, EnginePref, Owner, now_ms};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_engine::routing::RulesDoc;
use vpnte_engine::routing::process::{AppRule, SplitApp, SplitTarget};
use vpnte_probes::live::{
    CheckMode, CheckRequest, CheckTarget, HistoryStore, JobOutcome, JobRequest, LiveCheck,
    LiveHistory, TunnelState,
};
use vpnte_servers::store::{AddTarget, Servers};
use vpnte_tunnel::api::{ProxyEndpoint, SessionEndpoints, TunStatus};
use vpnte_tunnel::fsm::{Transition, TunnelSnapshot};
use vpnte_tunnel::history::SessionMode;
use vpnte_tunnel::lifecycle::SessionView;
use vpnte_tunnel::runtime::EngineExes;

use super::env::{split_rules, tunnel_view};
use super::*;

const KEY: &str = "vless://00000000-0000-4000-8000-00000000000a@203.0.113.20:443?security=tls&sni=example.com&type=tcp#Fake%20A";

/// A throw-away data dir under %TEMP%, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("vpnte-wire-live-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn endpoint(port: u16) -> ProxyEndpoint {
    ProxyEndpoint {
        port,
        user: "u".into(),
        pass: "p".into(),
    }
}

fn running(probe: Option<ProxyEndpoint>, luid: Option<u64>) -> TunStatus {
    TunStatus {
        running: true,
        session: Some(SessionEndpoints {
            clash_port: 1,
            clash_secret: "0".repeat(32),
            direct: endpoint(20001),
            probe,
            tun_luid: luid,
            tun_alias: None,
            proxy_port: None,
            logs: Vec::new(),
        }),
        ..TunStatus::default()
    }
}

fn session(id: &str) -> SessionView {
    SessionView {
        owner: Owner::Manual,
        profile_id: id.into(),
        profile_name: id.into(),
        mode: SessionMode::Hard,
        generation: Some(1),
        adaptive: Default::default(),
        started_at: 1,
        engine: None,
    }
}

/// A running engine lends both inbounds (live-check-in for the self-probe, mixed-direct-in for
/// the detour) and the TUN's LUID; a transition in flight lends nothing; idle is down.
#[test]
fn the_tunnel_as_the_check_sees_it() {
    let idle = TunnelSnapshot::default();
    let up = tunnel_view(
        &idle,
        &running(Some(endpoint(20002)), Some(42)),
        Some(&session("srv-1")),
    );
    assert_eq!(up.state, TunnelState::Up);
    assert_eq!(up.active_profile_id.as_deref(), Some("srv-1"));
    assert_eq!(up.live_check_in.as_ref().map(|l| l.port), Some(20002));
    let direct = up.mixed_direct_in.expect("mixed-direct-in");
    assert_eq!(direct.port, 20001);
    assert!(direct.creds.is_some(), "the inbound needs its credentials");
    assert_eq!(up.tun_luid, Some(42));

    // Soft session of a local proxy: no probe inbound, no TUN, still up.
    let soft = tunnel_view(&idle, &running(None, None), None);
    assert_eq!(soft.state, TunnelState::Up);
    assert!(soft.live_check_in.is_none() && soft.mixed_direct_in.is_some());

    let moving = TunnelSnapshot {
        transition: Some(Transition::Connecting),
        ..TunnelSnapshot::default()
    };
    let transition = tunnel_view(&moving, &running(None, Some(42)), None);
    assert_eq!(transition.state, TunnelState::Transition);
    assert!(transition.mixed_direct_in.is_none() && transition.tun_luid.is_none());

    let down = tunnel_view(&idle, &TunStatus::default(), None);
    assert_eq!(down.state, TunnelState::Down);
}

/// Routed entries only; a VPN-forced app counts by its file name; nothing routed = off.
#[test]
fn split_tunnel_snapshot_of_the_stored_rules() {
    let app = |target: &str, rule: AppRule| SplitApp {
        id: uuid::Uuid::new_v4(),
        name: target.into(),
        target: SplitTarget::parse(target).unwrap(),
        rule,
    };
    let rules = split_rules(&[
        app("curl.exe", AppRule::Direct),
        app(r"C:\Tools\git.exe", AppRule::Direct),
        app(r"C:\Games\game.exe", AppRule::Vpn),
        app("ssh.exe", AppRule::Vpn),
        app("listed.exe", AppRule::None),
    ]);
    assert!(rules.enabled);
    assert_eq!(rules.direct_names, ["curl.exe"]);
    assert_eq!(rules.direct_paths.len(), 1);
    assert_eq!(rules.vpn_names, ["game.exe", "ssh.exe"]);
    assert!(!split_rules(&[app("listed.exe", AppRule::None)]).enabled);
}
/// A stored row of `profile` (else of the plain host) for `host`, measured a moment ago (rows
/// past 180 days are capped away; a row stored under another target is dropped on load).
fn row(n: u32, profile: Option<&str>, host: &str) -> LiveCheck {
    let at = now_ms() - 1_000;
    serde_json::from_value(json!({
        "id": format!("lc_{n:032x}"),
        "profileId": profile,
        "host": host,
        "port": 443,
        "startedAt": at,
        "finishedAt": at + 500,
        "dns": {"status": "ok", "durationMs": 5, "a": [host]},
        "reachability": {"status": "ok", "durationMs": 7, "tcpReachable": true, "port": 443},
    }))
    .unwrap()
}

fn env(dir: &TempDir, servers: &Arc<Servers>) -> Arc<AppLiveEnv> {
    let resources = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources"));
    Arc::new(AppLiveEnv {
        servers: servers.clone(),
        settings: Arc::new(Store::<Settings>::open(&dir.0)),
        rules: Arc::new(Store::<RulesDoc>::open(&dir.0)),
        exes: watch::channel(EngineExes {
            singbox: resources.join("sing-box.exe"),
            xray: resources.join("xray.exe"),
        })
        .1,
        status: watch::channel(TunStatus::default()).1,
        snapshot: watch::channel(TunnelSnapshot::default()).1,
        session: watch::channel(None).1,
    })
}

/// The history lives at the data root; at start the rows of servers no longer in the list go,
/// rows of kept servers and of plain hosts stay. A check of an unknown server ends without a
/// row and without touching the network.
#[tokio::test]
async fn the_history_is_pruned_at_start_and_the_runner_answers() {
    let dir = TempDir::new("start");
    let servers = Arc::new(Servers::open(&dir.0));
    let profile = vpnte_profiles::uri::parse_uri(KEY).unwrap();
    let target = AddTarget::Keys {
        group: None,
        device: ClientDevice::default(),
    };
    let kept = servers.add(vec![profile], target).unwrap().added[0].clone();
    let targets = BTreeMap::from([
        (
            format!("profile:{}", kept.as_str()),
            vec![row(1, Some(kept.as_str()), "203.0.113.20")],
        ),
        (
            "profile:gone".to_owned(),
            vec![row(2, Some("gone"), "203.0.113.30")],
        ),
        (
            "host:example.org".to_owned(),
            vec![row(3, None, "example.org")],
        ),
    ]);
    HistoryStore::open(&dir.0)
        .store()
        .replace(LiveHistory { targets })
        .unwrap();

    let service = start(env(&dir, &servers), &dir.0, &servers).expect("runner");
    let left: Vec<String> = service
        .history()
        .list(None, None)
        .into_iter()
        .map(|c| c.host)
        .collect();
    assert_eq!(left.len(), 2, "{left:?}");
    assert!(!left.contains(&"203.0.113.30".to_owned()), "{left:?}");

    let job = service
        .submit(JobRequest::Single(CheckRequest {
            target: CheckTarget::Profile("no-such-server".into()),
            mode: CheckMode::Basic,
            throughput: false,
        }))
        .unwrap();
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), job.done)
        .await
        .expect("answered")
        .expect("runner alive");
    let JobOutcome::Single(Err(err)) = outcome else {
        panic!("an unknown server cannot be checked");
    };
    assert_eq!(err.user_msg().key, "probes.live.profileNotFound");
    service.shutdown().await;
    assert_eq!(
        service.history().list(None, None).len(),
        2,
        "nothing stored"
    );
}

/// The probes' live-check texts are registered (they showed as raw keys before).
#[test]
fn live_check_texts_are_registered() {
    let layers = crate::svc_core::locale_layers();
    let (ru, en) = vpnte_probes::LOCALES
        .iter()
        .find(|(_, en)| en.contains("\"profileNotFound\""))
        .expect("probes-live fragment");
    assert!(layers.contains(&(*ru, *en)));
}

/// The check runs a server on the engine the row chose (an Xray-only server must not be probed
/// with sing-box); a row without a choice, or one gone since, follows the setting (`Auto`).
#[test]
fn the_check_uses_the_rows_engine() {
    use vpnte_probes::live::LiveEnv;
    let dir = TempDir::new("engine");
    let servers = Arc::new(Servers::open(&dir.0));
    let profile = vpnte_profiles::uri::parse_uri(KEY).unwrap();
    let target = AddTarget::Keys {
        group: None,
        device: ClientDevice::default(),
    };
    let id = servers.add(vec![profile], target).unwrap().added[0].clone();
    let env = env(&dir, &servers);
    assert_eq!(env.server_engine(id.as_str()), EnginePref::Auto);
    servers.set_profile_engine(&id, EnginePref::Xray).unwrap();
    assert_eq!(env.server_engine(id.as_str()), EnginePref::Xray);
    assert_eq!(env.server_engine("gone"), EnginePref::Auto);
}
