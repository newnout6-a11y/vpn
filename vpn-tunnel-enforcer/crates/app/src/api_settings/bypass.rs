//! Keeps Soft mode's «Не через прокси» list current (RU-2026 item 14 a-b): the user's entries
//! from the settings plus, when switched on, the automatic ones the routing makes certain
//! (`vpnte_engine::routing::bypass`), handed to the system-proxy tweak for the next apply. A
//! session keeps the list it took, so a change lands at the next connection.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use vpnte_automation::tweaks::sysproxy::{self, Bypass};
use vpnte_core::settings::{RoutingMode, RuleSetMode, Settings};
use vpnte_engine::routing::bypass::{self, AutoInputs, BypassEntry, SmartLists};
use vpnte_engine::routing::smart_ru::SmartRu;

use crate::services::Backend;
use crate::support::changed;

/// How often the active rule-set directory is looked at again: a managed refresh switches it
/// without a store event of its own.
const RECHECK: Duration = Duration::from_secs(10 * 60);
/// Coalesces bursts of store events (a save writes several documents).
const DEBOUNCE: Duration = Duration::from_millis(200);

/// The Smart RU lists of one rule-set directory (generations never change in place).
type Cache = Option<(PathBuf, SmartLists)>;

/// Hands over the user's entries at once, before any connection can apply them, and starts the
/// task that adds the automatic ones and keeps the list current until `backend.shutdown`.
pub fn spawn(backend: &Arc<Backend>) {
    let settings = backend.settings.snapshot();
    sysproxy::set_bypass(lists(&settings, &[]));
    tokio::spawn(run(backend.clone()));
}

async fn run(backend: Arc<Backend>) {
    let mut settings = backend.settings.subscribe();
    let mut rules = backend.rules.subscribe();
    let mut cache: Cache = None;
    let mut last = None;
    loop {
        let s = backend.settings.snapshot();
        let auto = automatic(&backend, &s, &mut cache).await;
        let list = lists(&s, &auto);
        if last.as_ref() != Some(&list) {
            tracing::info!(
                user = s.proxy_bypass.len(),
                automatic = auto.len(),
                "bypass: list for the next proxy-mode connection updated"
            );
            sysproxy::set_bypass(list.clone());
            last = Some(list);
        }
        tokio::select! {
            () = backend.shutdown.cancelled() => break,
            () = changed(&mut settings) => {}
            () = changed(&mut rules) => {}
            () = tokio::time::sleep(RECHECK) => {}
        }
        tokio::time::sleep(DEBOUNCE).await;
    }
}

/// The user's stored entries followed by `auto`, in each reader's syntax.
fn lists(s: &Settings, auto: &[BypassEntry]) -> Bypass {
    let rendered = bypass::render(&bypass::from_stored(&s.proxy_bypass), auto);
    Bypass {
        proxy_override: rendered.proxy_override,
        no_proxy: rendered.no_proxy,
    }
}

/// The automatic entries, only while they are on and the routing mode is Proxy (the only mode
/// with a system proxy). Smart RU counts as on only with a rule-set directory, picked as the
/// tunnel picks it at each start.
async fn automatic(backend: &Backend, s: &Settings, cache: &mut Cache) -> Vec<BypassEntry> {
    if !s.proxy_bypass_auto || s.routing_mode != RoutingMode::Soft {
        return Vec::new();
    }
    let dir = if s.smart_ru_split {
        let managed = s.smart_ru_rule_set_mode == RuleSetMode::Managed;
        let rule_sets = backend.rule_sets.clone();
        tokio::task::spawn_blocking(move || rule_sets.active(managed).map(|(_, dir)| dir))
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    let smart = SmartRu {
        enabled: dir.is_some(),
        maps_direct: s.smart_ru_maps_direct,
    };
    let lists = match dir {
        Some(dir) => smart_lists(&backend.engines.singbox, dir, cache).await,
        None => None,
    };
    let doc = backend.rules.snapshot();
    bypass::automatic(&AutoInputs {
        domain_rules: &doc.domain_rules,
        apps: &doc.split_tunnel.apps,
        smart,
        lists,
    })
}

/// The lists of `dir`, read through the engine once per directory; `None` (no automatic entry
/// while Smart RU runs) when they cannot be read, retried at the next change.
async fn smart_lists<'a>(exe: &Path, dir: PathBuf, cache: &'a mut Cache) -> Option<&'a SmartLists> {
    if cache.as_ref().is_none_or(|(held, _)| *held != dir) {
        *cache = match bypass::read_smart_lists(exe, &dir).await {
            Ok(lists) => Some((dir, lists)),
            Err(err) => {
                tracing::warn!(%err, "bypass: Smart RU lists not read");
                None
            }
        };
    }
    cache.as_ref().map(|(_, lists)| lists)
}

#[cfg(test)]
mod tests;
