//! [`AutoHost`]: what the automatic server choice reads and does through the rest of the app
//! (the trait itself: `provide.rs`).
use std::sync::Arc;

use parking_lot::Mutex;
use serde::Serialize;
use serde::de::DeserializeOwned;
use vpnte_automation::autopick::{Candidate, LaunchPick, ProviderWord, WhitelistFacts};
use vpnte_engine::clash_api::{ClashApi, ClashEndpoint};
use vpnte_probes::leak::check::is_ru_hostname;
use vpnte_profiles::text::AutoconnectPick;
use vpnte_servers::model::{ProfileId, ServerReaction, ServerRow, ServerVerdict, VerdictRecord};

use super::super::failover::alive;
use super::super::host::{latency, transport_of};
use super::super::{AppCoordinator, AppReactions, Automation};
use super::meter::Meter;
use crate::services::{Backend, TunnelOps};

pub struct AutoHost {
    pub(super) backend: Arc<Backend>,
    pub(super) coord: Arc<AppCoordinator>,
    pub(super) reactions: Arc<AppReactions>,
    /// The running engine's Clash API client, built once per run.
    pub(super) clash: Mutex<Option<(ClashEndpoint, Arc<ClashApi>)>>,
    /// The session's VPN traffic so far.
    pub(super) meter: Mutex<Meter>,
}

impl AutoHost {
    pub fn new(backend: Arc<Backend>, automation: &Automation) -> Self {
        Self {
            coord: automation.coord.clone(),
            reactions: automation.reactions.clone(),
            backend,
            clash: Mutex::new(None),
            meter: Mutex::new(Meter::default()),
        }
    }

    pub(super) fn tunnel(&self) -> Option<&Arc<dyn TunnelOps>> {
        self.backend.tunnel().ok()
    }

    /// A usable row of the list.
    pub(super) fn row(&self, id: &str) -> Option<ServerRow> {
        let row = self.backend.servers.get(&ProfileId::from(id))?;
        usable(&row).then_some(row)
    }
}

/// A row automation may dial: not archived, readable on this PC.
pub(super) fn usable(row: &ServerRow) -> bool {
    row.archived.is_none() && !row.is_locked()
}

/// Probes and the list share wire names: conversions go by name.
pub(super) fn same_wire<A: Serialize, B: DeserializeOwned>(a: A) -> Option<B> {
    serde_json::to_value(a)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
}

pub(super) fn candidate(row: &ServerRow) -> Candidate {
    let checked = [
        row.health.as_ref().map(|h| h.at),
        row.verdict.as_ref().map(|v| v.at),
    ];
    Candidate {
        id: row.id.0.clone(),
        group: row.group_id.0.clone(),
        name: row.name.clone(),
        alive: alive(row),
        checked_at: checked.into_iter().flatten().max(),
        latency_ms: latency(row),
        udp: row.profile().is_ok_and(|p| transport_of(&p).udp()),
        ru_entry: ru_entry(row),
        whitelist: WhitelistFacts {
            marked: row.whitelist.as_ref().is_some_and(|w| w.marked),
            worked_on: (row.worked_under_whitelist())
                .map(|w| w.network.clone())
                .collect(),
        },
    }
}

/// The row's entry looks Russian: a Russian host name, or Russia as the country the probes
/// verified (else the one the name claims); for a single-hop server that is its own address.
fn ru_entry(row: &ServerRow) -> bool {
    is_ru_hostname(&row.server) || row.display_country().is_some_and(|c| c.as_str() == "RU")
}

/// The provider's controls of a group as the launch rule reads them.
pub(super) fn word(
    autoconnect: Option<bool>,
    pick: Option<AutoconnectPick>,
) -> Option<ProviderWord> {
    let pick = match pick {
        Some(AutoconnectPick::LowestDelay) => LaunchPick::LowestDelay,
        Some(AutoconnectPick::Random) => LaunchPick::Random,
        Some(AutoconnectPick::LastUsed) | None => LaunchPick::LastUsed,
    };
    match autoconnect? {
        true => Some(ProviderWord::On(pick)),
        false => Some(ProviderWord::Off),
    }
}

/// A verdict in the list's terms (same wire names; a name it does not know reads `Unknown`).
pub(super) fn record(verdict: impl Serialize, reaction: impl Serialize, at: i64) -> VerdictRecord {
    VerdictRecord {
        verdict: same_wire(verdict).unwrap_or(ServerVerdict::Unknown),
        reaction: same_wire(reaction).unwrap_or(ServerReaction::Unknown),
        at,
    }
}
