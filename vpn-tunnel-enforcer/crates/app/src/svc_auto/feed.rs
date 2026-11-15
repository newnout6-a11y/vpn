//! The verdict feed: every finished server check reaches the check-verdict reactions — the
//! verdicts stored at start, each verdict a check records later (key health, and whatever else
//! records one in the server list) and each finished live check of a server.
use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use vpnte_automation::adaptive::reaction::{CheckReaction, CheckVerdict, Report};
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_probes::live::{HandshakeStatus, LiveCheck, LiveCheckService};
use vpnte_servers::model::{ProfileId, VerdictRecord};
use vpnte_servers::store::{Servers, ServersEvent};

use super::AppReactions;
use super::react::{check_reaction, check_verdict};

/// A stored verdict older than this is not replayed at start (a key may have been renewed).
const STORED_MAX_AGE_MS: UnixMs = 24 * 60 * 60 * 1000;

/// What a stored verdict may teach at start. A record keeps no network identity, and a ban, a
/// freeze or a UDP cut (an offline or failed handshake too, which is how a ban looks) is a fact
/// about the path from the network it was taken on: replayed after a move, it would rule a
/// working server out for the whole evening. A refused key is refused from anywhere.
pub fn replayable(verdict: CheckVerdict) -> bool {
    verdict == CheckVerdict::KeyRejected
}

/// The report of a stored verdict; `None` for names this version does not know.
pub fn stored_report(id: &ProfileId, record: &VerdictRecord) -> Option<Report> {
    Some(Report {
        profile_id: id.0.clone(),
        verdict: check_verdict(record.verdict)?,
        reaction: check_reaction(record.reaction)?,
    })
}

/// The report of a finished live check of a server. Its handshake stage tells only these apart
/// (the classifier's transfer and reach evidence is not part of it): bytes crossed the tunnel,
/// the key was refused, or a UDP transport was cut; anything else is no verdict.
pub fn live_report(check: &LiveCheck) -> Option<Report> {
    let handshake = check.handshake.as_ref()?;
    let detail = (handshake.evidence.as_ref()).and_then(|e| e.detail.as_deref());
    let (verdict, reaction) = match (handshake.status, detail) {
        (HandshakeStatus::Ok, _) => (CheckVerdict::Healthy, CheckReaction::None),
        (HandshakeStatus::AuthFailed, _) => {
            (CheckVerdict::KeyRejected, CheckReaction::SwitchServer)
        }
        (HandshakeStatus::TransportFailed, Some("hy2-udp-blocked")) => {
            (CheckVerdict::UdpBlocked, CheckReaction::PreferTcpTransport)
        }
        _ => return None,
    };
    Some(Report {
        profile_id: check.profile_id.clone()?,
        verdict,
        reaction,
    })
}

/// The feed task, until `cancel`.
pub async fn run(
    reactions: Arc<AppReactions>,
    servers: Arc<Servers>,
    live: Option<Arc<LiveCheckService>>,
    cancel: CancellationToken,
) {
    let mut events = servers.subscribe();
    let mut seen: HashMap<ProfileId, UnixMs> = HashMap::new();
    let fresh_after = now_ms() - STORED_MAX_AGE_MS;
    for (id, record) in servers.verdicts() {
        let report = stored_report(&id, &record)
            .filter(|r| record.at >= fresh_after && replayable(r.verdict));
        if let Some(report) = report
            && !deliver(&reactions, report, &cancel).await
        {
            return;
        }
        seen.insert(id, record.at);
    }
    let mut checks = live.as_ref().map(|l| l.history().store().subscribe());
    let mut live_seen = now_ms();
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            event = events.recv() => match event {
                Ok(ServersEvent::Changed) | Err(RecvError::Lagged(_)) => {
                    if !new_verdicts(&reactions, &servers, &mut seen, &cancel).await {
                        return;
                    }
                }
                Ok(_) => {}
                Err(RecvError::Closed) => return,
            },
            Some(()) = changed(&mut checks) => {
                if let Some(live) = &live
                    && !new_live_checks(&reactions, live, &mut live_seen, &cancel).await
                {
                    return;
                }
            }
        }
    }
}

async fn changed<T>(rx: &mut Option<tokio::sync::watch::Receiver<T>>) -> Option<()> {
    match rx {
        Some(rx) => rx.changed().await.ok(),
        None => std::future::pending().await,
    }
}

/// Hands `report` over, waiting for room in the reactions' inbox (a group check records dozens
/// of verdicts in one write); `false` once cancelled or the task is gone.
async fn deliver(reactions: &AppReactions, report: Report, cancel: &CancellationToken) -> bool {
    tokio::select! {
        () = cancel.cancelled() => false,
        delivered = reactions.deliver(report) => delivered,
    }
}

/// Verdicts recorded since the last look, each marked seen only once it was delivered.
async fn new_verdicts(
    reactions: &AppReactions,
    servers: &Servers,
    seen: &mut HashMap<ProfileId, UnixMs>,
    cancel: &CancellationToken,
) -> bool {
    for (id, record) in servers.verdicts() {
        if seen.get(&id).is_some_and(|at| *at >= record.at) {
            continue;
        }
        if let Some(report) = stored_report(&id, &record)
            && !deliver(reactions, report, cancel).await
        {
            return false;
        }
        seen.insert(id, record.at);
    }
    true
}

async fn new_live_checks(
    reactions: &AppReactions,
    live: &LiveCheckService,
    seen: &mut UnixMs,
    cancel: &CancellationToken,
) -> bool {
    let checks = live.history().list(None, None);
    let after = *seen;
    // Oldest first, so a later check of the same server is the last word.
    for check in checks.iter().rev().filter(|c| c.finished_at > after) {
        if let Some(report) = live_report(check)
            && !deliver(reactions, report, cancel).await
        {
            return false;
        }
        *seen = check.finished_at.max(*seen);
    }
    true
}
