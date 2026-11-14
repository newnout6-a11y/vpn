//! The runtime failover's rounds over the server list.
use std::sync::Arc;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_automation::adaptive::reaction::Verdicts;
use vpnte_base::types::{ClientDevice, Owner};
use vpnte_servers::store::AddTarget;
use vpnte_tunnel::history::SessionMode;
use vpnte_tunnel::runtime::Failover;

use super::coord::rig;
use super::pure::view;
use crate::svc_auto::ServerFailover;
use crate::svc_auto::host::Fingerprints;

/// a3/b3: a round starts from the server that runs (the lifecycle moved the session to the
/// sibling the last failover started) and never goes back to a server that crashed out of a
/// session inside its freeze window: A crashed, B took over and crashed too, so C is next.
#[tokio::test]
async fn failover_rounds_start_from_the_running_server() {
    let r = rig("failover");
    let key = "vless://00000000-0000-4000-8000-000000000003@198.51.100.3:443?security=tls&sni=c.test&type=tcp#c";
    let c = vpnte_profiles::uri::parse_uri(key).expect("fake key parses");
    let target = AddTarget::Keys {
        group: None,
        device: ClientDevice::Pc,
    };
    let c = r.servers.add(vec![c], target).expect("servers").added[0]
        .0
        .clone();
    let a = r.ids[0].clone();
    let session = watch::Sender::new(Some(view(SessionMode::Direct, &a, Owner::Manual, 1)));
    let failover = ServerFailover::new(r.servers.clone(), Fingerprints::default());
    failover.attach(session.subscribe(), Arc::new(Verdicts::new()));
    let cancel = CancellationToken::new();
    let b = failover
        .next_live_sibling(&cancel)
        .await
        .expect("a sibling");
    assert_eq!(b.id, r.ids[1], "store order among unknown servers");
    failover.commit(&b.id);
    session.send_replace(Some(view(SessionMode::Direct, &b.id, Owner::Manual, 2)));
    let next = failover
        .next_live_sibling(&cancel)
        .await
        .expect("the third server");
    assert_eq!(
        next.id, c,
        "neither the running server nor the one that crashed before it"
    );
}

/// speed3 S3-07 (owner default 1): a user's switch may select first only on a full key check
/// younger than 10 min that found the server online with a first answer within 1 s, and no
/// later verdict against it. An old check, an offline one, a slow first answer, a session's
/// credit (no latency) and a row with pings only keep the probe.
#[test]
fn only_a_young_fast_full_check_lets_a_switch_select_first() {
    use vpnte_servers::model::{
        HealthRecord, ProfileId, ServerReaction, ServerVerdict, VerdictRecord,
    };

    use crate::svc_auto::failover::fresh;

    let r = rig("fresh-evidence");
    let row = r
        .servers
        .get(&ProfileId::from(r.ids[0].as_str()))
        .expect("row");
    let now = 1_800_000_000_000;
    let checked = |online, ago: i64, rtt_ms| {
        let mut row = row.clone();
        row.health = Some(HealthRecord {
            online,
            at: now - ago,
            rtt_ms,
            reason: None,
            egress_ip: None,
        });
        row
    };
    assert!(
        fresh(&checked(true, 60_000, Some(420)), now),
        "young, fast, online"
    );
    assert!(
        fresh(&checked(true, 599_000, Some(1_000)), now),
        "at the edges"
    );
    assert!(
        !fresh(&checked(true, 600_000, Some(420)), now),
        "10 min old"
    );
    assert!(!fresh(&checked(false, 60_000, Some(420)), now), "offline");
    assert!(
        !fresh(&checked(true, 60_000, Some(1_001)), now),
        "a slow first answer"
    );
    assert!(
        !fresh(&checked(true, 60_000, None), now),
        "a session's credit alone"
    );
    let mut no_check = row.clone();
    no_check.health = None;
    assert!(!fresh(&no_check, now), "pings never write a check");
    let mut frozen = checked(true, 60_000, Some(420));
    frozen.verdict = Some(VerdictRecord {
        verdict: ServerVerdict::Frozen,
        reaction: ServerReaction::SwitchServer,
        at: now - 30_000,
    });
    assert!(!fresh(&frozen, now), "a later verdict rules it out");
}
