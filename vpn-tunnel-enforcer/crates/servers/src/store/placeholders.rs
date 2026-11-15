//! Placeholders an older build stored as servers (13.11.2026: a provider's «Приложение не
//! поддерживается» answer replaced a group's 14 servers). At open they leave the live list and the
//! rows their answers pushed out come back (p-live-fix D6).
use std::collections::BTreeMap;

use vpnte_base::AppResult;
use vpnte_base::types::UnixMs;

use super::Servers;
use crate::model::{ArchiveReason, Archived, GroupId, Origin, ServersDoc};

impl Servers {
    /// Archives every live placeholder row for the provider (the automatic choice, the checks and
    /// the proxies skip archived rows) and restores, in its group, the feed rows marked missing or
    /// archived for the provider since the first placeholder was stored: only placeholder answers
    /// came since, and those prove nothing about the servers. Writes nothing when there is none.
    pub(crate) fn retire_placeholders(&self, now: UnixMs) -> AppResult<usize> {
        let any = self.read(|doc| {
            doc.profiles
                .iter()
                .any(|r| r.archived.is_none() && r.is_placeholder())
        });
        if !any {
            return Ok(0);
        }
        self.update(|doc| Ok(retire(doc, now)))
    }
}

/// [`Servers::retire_placeholders`] on `doc`: how many placeholders left the list.
pub(super) fn retire(doc: &mut ServersDoc, now: UnixMs) -> usize {
    // Per group: when its first live placeholder was stored.
    let mut since: BTreeMap<GroupId, UnixMs> = BTreeMap::new();
    let live = doc
        .profiles
        .iter()
        .filter(|r| r.archived.is_none() && r.is_placeholder());
    for row in live {
        let first = since.entry(row.group_id.clone()).or_insert(row.imported_at);
        *first = (*first).min(row.imported_at);
    }
    let mut retired = 0;
    for row in &mut doc.profiles {
        let Some(&first) = since.get(&row.group_id) else {
            continue;
        };
        if row.is_placeholder() {
            if row.archived.is_none() {
                row.archived = Some(Archived {
                    at: now,
                    reason: ArchiveReason::Provider,
                });
                retired += 1;
            }
            continue;
        }
        if row.origin != Origin::Feed {
            continue;
        }
        if row.archived_for(ArchiveReason::Provider) && row.archived.is_some_and(|a| a.at >= first)
        {
            row.archived = None;
        }
        if row.missing_since.is_some_and(|at| at >= first) {
            row.missing_since = None;
        }
    }
    tracing::info!(
        retired,
        "servers: provider placeholders left the list; the servers they displaced are back"
    );
    retired
}
