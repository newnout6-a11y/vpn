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

use super::coord::rig;
use crate::svc_auto::feed;
use crate::svc_auto::host::{Fingerprints, ServerHost};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recorded_verdicts_reach_the_reactions() {
    let r = rig("feed");
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
    let cancel = CancellationToken::new();
    tokio::spawn({
        let (reactions, cancel) = (reactions.clone(), cancel.clone());
        async move { reactions.run(cancel).await }
    });
    let feed = feed::run(reactions.clone(), r.servers.clone(), None, cancel.clone());
    tokio::spawn(feed);
    tokio::time::sleep(Duration::from_millis(50)).await;

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
