//! speed3-a1 and lab L12-5 in Tunnel mode: a request carries the app's hint for every name the
//! server's graph dials, and any request that carried hints and failed drops them (a protected
//! restart, an in-place switch that failed where it dialled), not only a failed start.
use std::net::IpAddr;

use vpnte_tunnel::api::{SwitchFailure, SwitchPhase};

use super::*;
use crate::svc_tunnel::warm::Ahead;

const KEY: &str = "vless://00000000-0000-4000-8000-000000000008@Hint.Example:443?security=tls&sni=example.com&type=tcp#Hinted";
const NAME: &str = "hint.example";

fn hinted_start() -> StartRequest {
    let profile = VpnProfile {
        id: "hinted".into(),
        profile: Arc::new(vpnte_profiles::uri::parse_uri(KEY).expect("fake key parses")),
        device: None,
        engine: EnginePref::Auto,
    };
    StartRequest {
        mode: Mode::DirectVpn { profile },
        ..tun_request()
    }
}

/// The names of the hints the fake runtime's last start or switch found.
fn carried(runtime: &FakeRuntime) -> Vec<String> {
    let facts = runtime.facts.lock();
    let last = facts.last().expect("a start or switch read its facts");
    last.hints.iter().map(|h| h.name.clone()).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_restart_or_switch_drops_the_hints_it_carried() {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let pipe = pipe_name(n);
    let dir = TempDir::new(&format!("remote-hints-{n}"));
    let listener = Listener::bind(&pipe_config(&pipe)).expect("private pipe");
    let inputs = Arc::new(SharedInputs::new(None));
    let runtime = FakeRuntime::new();
    let _ = runtime.inputs.set(inputs.clone());
    let host = Host::new(HostDeps {
        runtime: runtime.clone(),
        kill_switch: kill_switch(),
        inputs,
        users: Arc::new(Users::open(&dir.0.join("users.json"))),
        check: admit_all(),
        on_last_user: Arc::new(|| {}),
        service_version: "2.0.0-test".into(),
        refuse_tunnel: None,
    });
    let cancel = CancellationToken::new();
    tokio::spawn(host.serve(listener, cancel.clone()));
    let protection = Arc::new(Store::<ProtectionDoc>::open(&dir.0));
    let r = Remote::on_pipe(&pipe, Arc::new(NoInputs), protection);
    let ahead = Arc::new(Ahead::default());
    r.resolve_ahead_with(ahead.clone());
    let addr: IpAddr = "203.0.113.40".parse().expect("ip");

    runtime.fail.store(true, Ordering::SeqCst);
    ahead.hold(NAME, vec![addr]);
    let restart = r.restart_protected("test".into(), hinted_start(), RestartOptions::default());
    assert!(restart.await.is_err());
    assert_eq!(carried(&runtime), [NAME]);
    assert!(
        ahead.hint(NAME).is_none(),
        "a failed protected restart drops it"
    );

    ahead.hold(NAME, vec![addr]);
    *runtime.switch.lock() = Some(SwitchReceipt {
        failures: vec![SwitchFailure {
            phase: SwitchPhase::Probe,
            message: "silent".into(),
        }],
        ..SwitchReceipt::default()
    });
    let owner: OwnerCheck = Arc::new(|| true);
    let receipt = r
        .switch_upstream(hinted_start(), CancellationToken::new(), owner)
        .await;
    assert!(receipt.is_some_and(|r| !r.committed));
    assert_eq!(carried(&runtime), [NAME]);
    assert!(
        ahead.hint(NAME).is_none(),
        "a switch failed at its probe drops it"
    );
    cancel.cancel();
}
