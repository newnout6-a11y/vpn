//! Probe results: key health, verified countries (with the selection generation guard) and the
//! memory-only pings.
use vpnte_base::AppResult;
use vpnte_base::types::now_ms;

use super::{HealthUpdate, Servers, ServersEvent};
use crate::model::{ArchiveReason, CountrySource, Ping, ProfileId, ServerRow, VerifiedCountry};

impl Servers {
    /// Stores key-health verdicts (and the exit country of the trace). A row that was deleted,
    /// removed by the user or whose key changed while the probe ran is skipped on its own (S-13,
    /// servers §3.11); returns how many landed.
    pub fn record_health(&self, updates: Vec<HealthUpdate>) -> AppResult<usize> {
        self.update(|doc| {
            let mut applied = 0;
            for update in &updates {
                let Some(row) = doc.row_mut(&update.id) else {
                    continue;
                };
                if row.archived_for(ArchiveReason::User) || row.identity() != Some(update.identity)
                {
                    continue;
                }
                row.health = Some(update.record);
                if let Some(country) = update.country {
                    set_country(row, country);
                }
                applied += 1;
            }
            Ok(applied)
        })
    }

    /// Stores a verified country unless the row holds better evidence (S-12). Exit evidence is
    /// also dropped when a selection happened since `expected_generation` was read (the tunnel may
    /// have moved to another server meanwhile); an entry-IP lookup does not depend on the
    /// selection (servers §3.9). Returns whether it was stored.
    pub fn record_country(
        &self,
        id: &ProfileId,
        country: VerifiedCountry,
        expected_generation: u64,
    ) -> AppResult<bool> {
        self.update(|doc| {
            if country.source != CountrySource::EntryIp
                && self.geo_generation() != expected_generation
            {
                return Ok(false);
            }
            Ok(doc.row_mut(id).is_some_and(|row| set_country(row, country)))
        })
    }

    /// Remembers a ping result in memory (never persisted, S-10); unknown rows are ignored.
    pub fn record_ping(&self, id: &ProfileId, rtt_ms: Option<u32>) {
        if !self.store.read(|doc| doc.row(id).is_some()) {
            return;
        }
        let ping = Ping {
            rtt_ms,
            at: now_ms(),
        };
        self.pings.lock().insert(id.clone(), ping);
        self.emit(ServersEvent::Ping(id.clone()));
    }
}

fn set_country(row: &mut ServerRow, country: VerifiedCountry) -> bool {
    let better = row.country.is_none_or(|old| country.supersedes(&old));
    if better {
        row.country = Some(country);
    }
    better
}
