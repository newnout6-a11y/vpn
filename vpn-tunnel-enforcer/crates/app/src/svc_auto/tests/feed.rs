//! The verdict feed end to end: a verdict a server check records reaches the reactions' memory
//! of this network, which rotation and the adaptive bypass read.
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_automation::adaptive::reaction::Reactions;
use vpnte_base::types::now_ms;
use vpnte_probes::public_ip::IpReader;
use vpnte_servers::model::{ProfileId, ServerReaction, ServerVerdict, VerdictRecord};
use vpnte_servers::store::VerdictUpdate;
use vpnte_tunnel::api::TunStatus;

use super::coord::{Rig, rig};
use crate::svc_auto::AppReactions;
use crate::svc_auto::feed;
use crate::svc_auto::host::{Fingerprints, ServerHost};

/// The reactions task and the feed over the rig's server list.
async fn reactions(r: &Rig, cancel: &CancellationToken) -> Arc<AppReactions> {
    let status = watch::channel(TunStatus::default()).1;
    let host = Arc::new(ServerHost::new(
        r.servers.clone(),
        r.settings.clone(),
        status,
        Arc::new(IpReader::new()),
        Fingerprints::default(),
        r.lane.clone(),
    ));
    let reactions = Arc::new(Reactions::new(r.coord.clone(), host, r.settings.clone()));
    tokio::spawn({
        let (reactions, cancel) = (reactions.clone(), cancel.clone());
        async move { reactions.run(cancel).await }
    });
    let feed = feed::run(reactions.clone(), r.servers.clone(), None, cancel.clone());
    tokio::spawn(feed);
    tokio::time::sleep(Duration::from_millis(50)).await;
    reactions
}

fn verdict(r: &Rig, id: &ProfileId, verdict: ServerVerdict, at: i64) -> VerdictUpdate {
    let identity = r.servers.get(id).and_then(|row| row.identity());
    VerdictUpdate {
        id: id.clone(),
        identity: identity.expect("row identity"),
        record: VerdictRecord {
            verdict,
            reaction: ServerReaction::SwitchServer,
            at,
        },
    }
}

async fn until(what: &str, done: impl Fn() -> bool) {
    let waited = tokio::time::timeout(Duration::from_secs(5), async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    assert!(waited.await.is_ok(), "{what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recorded_verdicts_reach_the_reactions() {
    let r = rig("feed");
    let cancel = CancellationToken::new();
    let reactions = reactions(&r, &cancel).await;

    let a = ProfileId::from(r.ids[0].as_str());
    let identity = r.servers.get(&a).and_then(|row| row.identity());
    let update = VerdictUpdate {
        id: a.clone(),
        identity: identity.expect("row identity"),
        record: VerdictRecord {
            verdict: ServerVerdict::KeyRejected,
            reaction: ServerReaction::SwitchServer,
            at: now_ms(),
        },
    };
    r.servers.record_verdicts(vec![update]).expect("recorded");
    let learned = tokio::time::timeout(Duration::from_secs(5), async {
        while !reactions.verdicts().avoided(a.as_str()) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(learned.is_ok(), "the reactions never heard of the verdict");
    let b = r.ids[1].as_str();
    assert!(!reactions.verdicts().avoided(b), "only the checked server");
    cancel.cancel();
}

/// a10: verdicts stored before this start carry no network: a refused key is replayed (it is
/// refused from anywhere), a ban is not (it was taken on another network, maybe).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_network_independent_verdicts_are_replayed_at_start() {
    let r = rig("feed-replay");
    let (a, b) = (
        ProfileId::from(r.ids[0].as_str()),
        ProfileId::from(r.ids[1].as_str()),
    );
    let earlier = now_ms() - 60_000;
    let stored = vec![
        verdict(&r, &a, ServerVerdict::IpBanned, earlier),
        verdict(&r, &b, ServerVerdict::KeyRejected, earlier),
    ];
    r.servers.record_verdicts(stored).expect("recorded");
    let cancel = CancellationToken::new();
    let reactions = reactions(&r, &cancel).await;
    until("the refused key replayed", || {
        reactions.verdicts().avoided(b.as_str())
    })
    .await;
    assert!(
        !reactions.verdicts().avoided(a.as_str()),
        "a ban of another network"
    );
    cancel.cancel();
}

/// a5: a group check records dozens of verdicts in one write; every one reaches the reactions
/// (the feed waits for room in their 32-report inbox: one thread here, so nothing drains while
/// a synchronous loop fills it).
#[tokio::test]
async fn a_burst_of_verdicts_reaches_the_reactions_in_full() {
    use vpnte_base::types::ClientDevice;
    use vpnte_servers::store::AddTarget;
    let r = rig("feed-burst");
    let keys = (0..40).map(|i| {
        let uri = format!(
            "vless://00000000-0000-4000-8000-0000000001{i:02}@198.51.100.{}:443?security=tls&sni=s{i}.test&type=tcp#s{i}",
            10 + i
        );
        vpnte_profiles::uri::parse_uri(&uri).expect("fake key parses")
    });
    let target = AddTarget::Keys {
        group: None,
        device: ClientDevice::Pc,
    };
    let added = r
        .servers
        .add(keys.collect(), target)
        .expect("servers")
        .added;
    assert_eq!(added.len(), 40);
    let cancel = CancellationToken::new();
    let reactions = reactions(&r, &cancel).await;
    let burst = (added.iter())
        .map(|id| verdict(&r, id, ServerVerdict::KeyRejected, now_ms()))
        .collect();
    r.servers.record_verdicts(burst).expect("recorded");
    until("every verdict of the burst", || {
        added
            .iter()
            .all(|id| reactions.verdicts().avoided(id.as_str()))
    })
    .await;
    cancel.cancel();
}
