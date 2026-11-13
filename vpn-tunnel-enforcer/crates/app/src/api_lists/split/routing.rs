//! Happ routing profiles on the Apps page: the subscriptions that sent one (pushed with the page
//! state), a preview against the user's rules, and the import of exactly that preview into the
//! user's own domain rules on the user's click (answer 4: the user's rules, editable and
//! removable on the Settings page). A provider's profile never changes anything by itself.
mod plan;
#[cfg(test)]
mod tests;

use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use vpnte_base::i18n::Lang;
use vpnte_base::{AppError, AppResult};
use vpnte_core::settings::Settings;
use vpnte_engine::routing::RulesDoc;
use vpnte_engine::routing::domain::{DomainAction, DomainPattern};
use vpnte_profiles::text::{RoutingValue, parse_routing};
use vpnte_servers::model::{GroupId, ServersDoc};
use vpnte_ui::split_tunnel::{RoutingImported, RoutingOffer, RoutingPreview, RoutingSource};

use super::{offer_gone, stale_preview};
use crate::services::Backend;
use plan::Plan;

/// The latest preview's plan: an import applies exactly what the user saw.
#[derive(Default)]
pub(super) struct Imports {
    latest: Mutex<Option<(u64, Plan)>>,
    tokens: AtomicU64,
}

impl Imports {
    /// Reads `source` and plans its import against the stored rules. Blocking: store reads and
    /// a parse of up to 64 KiB.
    pub(super) fn preview(
        &self,
        backend: &Backend,
        source: &RoutingSource,
    ) -> AppResult<RoutingPreview> {
        let raw = match source {
            RoutingSource::Pasted(text) => text.clone(),
            RoutingSource::Subscription(id) => backend
                .servers
                .read(|doc| stored(doc, id))
                .ok_or_else(offer_gone)?,
        };
        let value = parse_routing(&raw).map_err(|err| AppError::validation(err.msg()))?;
        let smart_on = backend.settings.read(|s| s.smart_ru_split);
        let (plan, mut preview) = backend
            .rules
            .read(|doc| plan::plan(&value, &doc.domain_rules, smart_on));
        preview.token = self.tokens.fetch_add(1, Ordering::Relaxed) + 1;
        *self.latest.lock() = Some((preview.token, plan));
        Ok(preview)
    }

    /// Applies the plan of preview `token`: its rules appended to the user's list (a site the
    /// user has a rule for meanwhile keeps the user's rule), Smart RU switched on when asked.
    /// Blocking: store writes, and a running tunnel taking the Smart RU change.
    pub(super) fn import(&self, backend: &Backend, token: u64) -> AppResult<RoutingImported> {
        let plan = match &*self.latest.lock() {
            Some((latest, plan)) if *latest == token => plan.clone(),
            _ => return Err(stale_preview()),
        };
        let (added, over_limit) = backend.rules.update(|doc| apply(doc, &plan.rules))?;
        let smart_ru_on = plan.smart_ru && !backend.settings.read(|s| s.smart_ru_split);
        if smart_ru_on {
            let old = backend.settings.snapshot();
            backend.settings.update(|s| s.smart_ru_split = true)?;
            tell_tunnel(backend, old);
        }
        // Spent: a second click on the same preview asks for a new one.
        let mut latest = self.latest.lock();
        if latest.as_ref().is_some_and(|(t, _)| *t == token) {
            *latest = None;
        }
        tracing::info!(added, over_limit, smart_ru_on, "routing profile imported");
        Ok(RoutingImported {
            added,
            over_limit,
            smart_ru_on,
        })
    }
}

/// Smart RU switched on by an import reaches a running tunnel as a change on the Settings page
/// does (`apply_settings_change`: a restart while connected, nothing while idle). On the
/// import's blocking thread, so the import answers once the tunnel took it.
fn tell_tunnel(backend: &Backend, old: Settings) {
    let (Ok(tunnel), Ok(runtime)) = (backend.tunnel(), tokio::runtime::Handle::try_current())
    else {
        return;
    };
    let new = backend.settings.snapshot();
    if let Err(err) = runtime.block_on(tunnel.apply_settings_change(old, new)) {
        tracing::warn!(error = %err.user_msg().key, "Smart RU not applied to the running tunnel");
    }
}

/// The subscriptions whose provider sent a readable profile, in list order.
pub(super) fn offers(doc: &ServersDoc, lang: Lang) -> Vec<RoutingOffer> {
    doc.groups
        .iter()
        .filter(|group| !group.is_manual())
        .filter_map(|group| {
            let raw = group.controls.routing.as_deref()?;
            match parse_routing(raw) {
                Ok(RoutingValue::Profile(profile)) => Some(RoutingOffer {
                    group_id: group.id.to_string(),
                    group: group.title().render(lang),
                    profile: profile.name,
                }),
                // «Off» turns off a routing this app never took over: nothing to offer.
                Ok(RoutingValue::Off) => None,
                Err(err) => {
                    tracing::debug!(error = %err, "a provider's routing value was not read");
                    None
                }
            }
        })
        .collect()
}

/// The routing value subscription `id` stored.
fn stored(doc: &ServersDoc, id: &str) -> Option<String> {
    doc.group(&GroupId::from(id))
        .filter(|group| !group.is_manual())
        .and_then(|group| group.controls.routing.clone())
}

/// Appends `rules` in order, one import per run of the same route; `(added, over_limit)`.
fn apply(doc: &mut RulesDoc, rules: &[(DomainPattern, DomainAction)]) -> (usize, usize) {
    let (mut added, mut over_limit) = (0, 0);
    for run in rules.chunk_by(|a, b| a.1 == b.1) {
        let Some(&(_, action)) = run.first() else {
            continue;
        };
        let patterns: Vec<DomainPattern> = run.iter().map(|(p, _)| p.clone()).collect();
        let report = doc.import_domains(&patterns, action);
        added += report.added;
        over_limit += report.over_limit;
    }
    (added, over_limit)
}
