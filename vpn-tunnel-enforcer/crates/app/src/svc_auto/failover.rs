//! The tunnel runtime's post-trial failover over the server list: when a crashed server cannot
//! come back (restart budget spent, or its quiet window after a freeze), the next live sibling of
//! the same group starts instead; the selection follows a sibling that started.
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_automation::adaptive::reaction::Verdicts;
use vpnte_servers::model::{ProfileId, ServerRow, ServerVerdict};
use vpnte_servers::store::{SelectBy, Servers};
use vpnte_tunnel::api::VpnProfile;
use vpnte_tunnel::lifecycle::SessionView;
use vpnte_tunnel::runtime::Failover;

use super::host::{Fingerprints, latency};
use crate::svc_tunnel::vpn_profile;

/// A server that crashed out of a session is not picked again for this long: the RU freeze
/// window, which a dial inside it extends (the runtime's `Timings::freeze`).
const CRASHED_QUIET: Duration = Duration::from_secs(130);

pub struct ServerFailover {
    servers: Arc<Servers>,
    fingerprints: Fingerprints,
    /// The lane's session (which server crashed: the lifecycle moves it to the sibling that runs
    /// after a failover); set once the lifecycle exists.
    session: OnceLock<watch::Receiver<Option<SessionView>>>,
    /// The check verdicts of this network (the reactions' memory); set once they exist.
    verdicts: OnceLock<Arc<Verdicts>>,
    /// The crashed server of this round and the siblings already tried for it.
    round: Mutex<(String, Vec<String>)>,
    /// The crashed server of every recent round: a later round never goes back to one still in
    /// its freeze window.
    crashed: Mutex<Vec<(String, Instant)>>,
}

impl ServerFailover {
    pub fn new(servers: Arc<Servers>, fingerprints: Fingerprints) -> Self {
        Self {
            servers,
            fingerprints,
            session: OnceLock::new(),
            verdicts: OnceLock::new(),
            round: Mutex::new((String::new(), Vec::new())),
            crashed: Mutex::new(Vec::new()),
        }
    }

    pub fn attach(&self, session: watch::Receiver<Option<SessionView>>, verdicts: Arc<Verdicts>) {
        let _ = self.session.set(session);
        let _ = self.verdicts.set(verdicts);
    }
}

/// What the stored evidence says about a row: `Some(false)` = a check found it dead or blocked,
/// `Some(true)` = healthy, `None` = nothing known. A verdict older than the last health record is
/// superseded by it (a later check without a verdict has spoken since).
fn alive(row: &ServerRow) -> Option<bool> {
    let verdict =
        (row.verdict.as_ref()).filter(|v| row.health.as_ref().is_none_or(|h| v.at >= h.at));
    match (verdict, &row.health) {
        (Some(v), _) => match v.verdict {
            ServerVerdict::Healthy => Some(true),
            ServerVerdict::Frozen
            | ServerVerdict::HandshakeFailed
            | ServerVerdict::KeyRejected
            | ServerVerdict::IpBanned
            | ServerVerdict::UdpBlocked
            | ServerVerdict::Offline
            | ServerVerdict::Refused => Some(false),
            _ => None,
        },
        (None, Some(h)) => Some(h.online),
        (None, None) => None,
    }
}

/// The siblings of `base` worth a try, best first: same group, usable, not `skip`ped (tried, or
/// ruled out on this network), not known dead; healthy before unknown, then the lower latency,
/// then store order.
pub fn candidates<'a>(
    rows: &'a [ServerRow],
    base: &ServerRow,
    skip: impl Fn(&str) -> bool,
) -> Vec<&'a ServerRow> {
    let mut found: Vec<_> = (rows.iter().enumerate())
        .filter(|(_, r)| r.group_id == base.group_id && r.id != base.id)
        .filter(|(_, r)| r.archived.is_none() && !r.is_locked() && !skip(r.id.as_str()))
        .filter(|(_, r)| alive(r) != Some(false))
        .collect();
    found.sort_by_key(|(i, r)| (alive(r) != Some(true), latency(r).unwrap_or(u32::MAX), *i));
    found.into_iter().map(|(_, r)| r).collect()
}

#[async_trait]
impl Failover for ServerFailover {
    async fn next_live_sibling(&self, _cancel: &CancellationToken) -> Option<VpnProfile> {
        let base_id = self
            .session
            .get()?
            .borrow()
            .as_ref()?
            .server_id()?
            .to_owned();
        let base = self.servers.get(&ProfileId::from(base_id.as_str()))?;
        let rows = self.servers.read(|doc| doc.profiles.clone());
        let mut round = self.round.lock();
        if round.0 != base_id {
            let mut crashed = self.crashed.lock();
            crashed.retain(|(_, at)| at.elapsed() < CRASHED_QUIET);
            crashed.push((base_id.clone(), Instant::now()));
            *round = (base_id, Vec::new());
        }
        let quiet: Vec<String> = (self.crashed.lock().iter())
            .filter(|(_, at)| at.elapsed() < CRASHED_QUIET)
            .map(|(id, _)| id.clone())
            .collect();
        let verdicts = self.verdicts.get();
        let skip = |id: &str| {
            round.1.iter().chain(&quiet).any(|t| t == id) || verdicts.is_some_and(|v| v.avoided(id))
        };
        let pick = candidates(&rows, &base, skip)
            .first()
            .map(|r| (*r).clone())?;
        round.1.push(pick.id.0.clone());
        drop(round);
        vpn_profile(pick, &self.fingerprints)
    }

    fn commit(&self, profile_id: &str) {
        *self.round.lock() = (String::new(), Vec::new());
        let (servers, id) = (self.servers.clone(), ProfileId::from(profile_id));
        // Called on the runtime's actor: the store write goes to the blocking pool.
        tokio::task::spawn_blocking(move || {
            if let Err(e) = servers.select(&id, SelectBy::Automation) {
                tracing::warn!(error = %e, "failover server not saved as the selection");
            }
        });
    }
}
