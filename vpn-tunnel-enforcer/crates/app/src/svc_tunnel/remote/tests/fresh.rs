//! speed3 S3-07 in Tunnel mode (p-wire5): a user's own switch carries the list's fresh evidence
//! to the service, as the in-process runtime reads it through `Failover::fresh`; an automatic
//! switch never does.
use vpnte_base::types::{ClientDevice, now_ms};
use vpnte_servers::model::{HealthRecord, ProfileId};
use vpnte_servers::store::{AddTarget, HealthUpdate, Servers};

use super::*;

const KEY: &str = "vless://00000000-0000-4000-8000-000000000007@198.51.100.7:443?security=tls&sni=example.com&type=tcp#Fresh";

/// A list whose one server a full key check found online a minute ago, first answer in 300 ms.
fn fresh_list(dir: &Path) -> (Arc<Servers>, ProfileId) {
    let servers = Arc::new(Servers::open(dir));
    let key = vpnte_profiles::uri::parse_uri(KEY).expect("fake key parses");
    let target = AddTarget::Keys {
        group: None,
        device: ClientDevice::Pc,
    };
    let id = servers.add(vec![key], target).expect("added").added[0].clone();
    let row = servers.get(&id).expect("row");
    let update = HealthUpdate {
        id: id.clone(),
        identity: row.identity().expect("identity"),
        record: HealthRecord {
            online: true,
            at: now_ms() - 60_000,
            rtt_ms: Some(300),
            reason: None,
            egress_ip: None,
        },
        country: None,
    };
    assert_eq!(servers.record_health(vec![update]).expect("stored"), 1);
    (servers, id)
}

/// A switch to server `id` asked for by `origin`.
fn switch_to(id: &ProfileId, origin: Origin) -> StartRequest {
    let profile = VpnProfile {
        id: id.0.clone(),
        profile: Arc::new(vpnte_profiles::uri::parse_uri(KEY).expect("fake key parses")),
        device: None,
        engine: EnginePref::Auto,
    };
    StartRequest {
        mode: Mode::DirectVpn { profile },
        origin,
        ..tun_request()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_users_switch_carries_the_fresh_evidence() {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let pipe = pipe_name(n);
    let dir = TempDir::new(&format!("remote-fresh-{n}"));
    let listener = Listener::bind(&pipe_config(&pipe)).expect("private pipe");
    let inputs = Arc::new(SharedInputs::new(None));
    let host = Host::new(HostDeps {
        runtime: FakeRuntime::new(),
        kill_switch: kill_switch(),
        inputs: inputs.clone(),
        users: Arc::new(Users::open(&dir.0.join("users.json"))),
        check: admit_all(),
        on_last_user: Arc::new(|| {}),
        service_version: "2.0.0-test".into(),
        refuse_tunnel: None,
    });
    let cancel = CancellationToken::new();
    tokio::spawn(host.serve(listener, cancel.clone()));
    let protection = Arc::new(Store::<ProtectionDoc>::open(&dir.0));
    let (servers, id) = fresh_list(&dir.0);
    let r = Remote::on_pipe(&pipe, Arc::new(NoInputs), protection);
    r.fresh_from(servers);
    let owner: OwnerCheck = Arc::new(|| true);
    for (origin, fresh) in [
        (Origin::User, true),
        (Origin::Rotation, false),
        (Origin::Schedule, false),
        (Origin::Recovery, false),
    ] {
        let next = switch_to(&id, origin);
        // The fake runtime cannot switch in place; the service took the request's facts first.
        let receipt = r
            .switch_upstream(next, CancellationToken::new(), owner.clone())
            .await;
        assert!(receipt.is_none());
        assert_eq!(inputs.server_facts(&id.0).fresh, fresh, "{origin:?}");
    }
    cancel.cancel();
}
