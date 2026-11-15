//! Keeps Soft mode's «Не через прокси» list current (RU-2026 item 14 a-b): the user's entries
//! from the settings plus, when switched on, the automatic ones the routing makes certain
//! (`vpnte_engine::routing::bypass`), handed to the system-proxy tweak. A running session follows
//! the list (`svc_tunnel::soft`): the engine re-reads rules, Smart RU and the rule sets at every
//! restart, so the list follows the same stores, the rule-set state among them (pbypass-a1/a2).
//! The Smart RU lists it reads back also tell the Settings page's rule notes which sites Smart
//! RU sends through the VPN as blocked in Russia ([`smart_lists`], psmart-b1).
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use tokio::sync::watch;
use vpnte_automation::tweaks::sysproxy::{self, Bypass};
use vpnte_core::settings::{RoutingMode, RuleSetMode, Settings};
use vpnte_engine::routing::bypass::{self, AutoInputs, BypassEntry, SmartLists};
use vpnte_engine::routing::smart_ru::SmartRu;

use crate::services::Backend;
use crate::support::changed;

/// Coalesces bursts of store events (a save writes several documents).
const DEBOUNCE: Duration = Duration::from_millis(200);
/// A failed read of the Smart RU lists is tried again this often, this many times, before the
/// next change of the stores (a decompile can fail once under logon load or a scan).
const RETRY: Duration = Duration::from_secs(30);
const RETRIES: u32 = 4;

type Lists = Option<Arc<SmartLists>>;

/// The lists of the directory Smart RU runs with, while it runs: the rule notes of the Settings
/// page read the blocked-in-Russia list from them (Smart RU's own route, psmart-b1) and are
/// projected again when they change (fixlists-a3).
static LISTS: LazyLock<watch::Sender<Lists>> = LazyLock::new(|| watch::Sender::new(None));

/// The Smart RU lists read back from the active rule sets (`None`: off, or not read yet).
pub fn smart_lists() -> Lists {
    LISTS.borrow().clone()
}

/// Wakes on every change of [`smart_lists`].
pub fn lists_changes() -> watch::Receiver<Lists> {
    LISTS.subscribe()
}

/// Hands over the user's entries at once, before any connection can apply them, and starts the
/// task that adds the automatic ones and keeps the list current until `backend.shutdown`.
pub fn spawn(backend: &Arc<Backend>) {
    let settings = backend.settings.snapshot();
    sysproxy::set_bypass(lists(&settings, &[]));
    tokio::spawn(run(backend.clone(), &LISTS));
}

/// The keeper; publishes the lists it reads to `out`.
async fn run(backend: Arc<Backend>, out: &'static watch::Sender<Lists>) {
    let mut settings = backend.settings.subscribe();
    let mut rules = backend.rules.subscribe();
    let mut rule_sets = backend.rule_sets.subscribe();
    let mut reader = Reader::default();
    loop {
        let s = backend.settings.snapshot();
        let dir = smart_dir(&backend, &s).await;
        let smart = dir.is_some();
        let wanted = automatic_wanted(&s);
        if let Some(dir) = &dir
            && reader.stale(dir)
        {
            if wanted {
                // Until the new lists are read no automatic entry is certain: none stays.
                hand_over(&s, &[]);
            }
            reader.read(&backend.engines.singbox, dir).await;
        }
        if !smart {
            reader.failures = 0;
        }
        let retry = (1..=RETRIES).contains(&reader.failures);
        let lists = dir.and(reader.cache.as_ref()).map(|(_, l)| l.clone());
        publish(out, lists.clone());
        let auto = if wanted {
            automatic(&backend, &s, smart, lists.as_deref())
        } else {
            Vec::new()
        };
        hand_over(&s, &auto);
        tokio::select! {
            () = backend.shutdown.cancelled() => break,
            () = changed(&mut settings) => {}
            () = changed(&mut rules) => {}
            () = changed(&mut rule_sets) => {}
            () = tokio::time::sleep(RETRY), if retry => {}
        }
        tokio::time::sleep(DEBOUNCE).await;
    }
}

/// The Smart RU lists of one rule-set directory, read once (generations never change in place).
/// Only lists that were read are kept: a failed read is tried again (fixlists-a2).
#[derive(Default)]
struct Reader {
    cache: Option<(PathBuf, Arc<SmartLists>)>,
    /// Failed reads in a row.
    failures: u32,
}

impl Reader {
    /// `dir` is not the directory whose lists are held.
    fn stale(&self, dir: &Path) -> bool {
        self.cache.as_ref().is_none_or(|(held, _)| held != dir)
    }

    async fn read(&mut self, exe: &Path, dir: &Path) {
        let read = read_lists(exe, dir).await;
        self.failures = if read.is_some() { 0 } else { self.failures + 1 };
        self.cache = read.map(|lists| (dir.to_owned(), Arc::new(lists)));
    }
}

/// Sends `lists` when they are other lists than the held ones (by identity: one directory's
/// lists are read once), so the Settings page projects only a real change.
fn publish(out: &watch::Sender<Lists>, lists: Lists) {
    out.send_if_modified(|held| {
        let same = match (held.as_ref(), lists.as_ref()) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (a, b) => a.is_none() && b.is_none(),
        };
        *held = lists;
        !same
    });
}
/// Sets the list; logged when it changed.
fn hand_over(s: &Settings, auto: &[BypassEntry]) {
    if sysproxy::set_bypass(lists(s, auto)) {
        tracing::info!(
            user = s.proxy_bypass.len(),
            automatic = auto.len(),
            "bypass: list updated"
        );
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

/// The automatic entries are on and the routing mode is Proxy (the only one with a system proxy).
fn automatic_wanted(s: &Settings) -> bool {
    s.proxy_bypass_auto && s.routing_mode == RoutingMode::Soft
}

/// The rule-set directory Smart RU runs with, picked as the tunnel picks it at each start;
/// `None`: Smart RU is off for the engine (switched off, or no complete directory).
async fn smart_dir(backend: &Backend, s: &Settings) -> Option<PathBuf> {
    if !s.smart_ru_split {
        return None;
    }
    let managed = s.smart_ru_rule_set_mode == RuleSetMode::Managed;
    let rule_sets = backend.rule_sets.clone();
    tokio::task::spawn_blocking(move || rule_sets.active(managed).map(|(_, dir)| dir))
        .await
        .ok()
        .flatten()
}

/// The automatic entries for the current rules (`smart`: Smart RU runs with `lists`).
fn automatic(
    backend: &Backend,
    s: &Settings,
    smart: bool,
    lists: Option<&SmartLists>,
) -> Vec<BypassEntry> {
    let doc = backend.rules.snapshot();
    bypass::automatic(&AutoInputs {
        domain_rules: &doc.domain_rules,
        apps: &doc.split_tunnel.apps,
        app_scope: s.app_scope,
        smart: SmartRu {
            enabled: smart,
            maps_direct: s.smart_ru_maps_direct,
        },
        lists,
    })
}

/// The lists of `dir`, read through the engine; `None` (no automatic entry while Smart RU runs)
/// when they cannot be read, tried again at the next change or after [`RETRY`].
async fn read_lists(exe: &Path, dir: &Path) -> Option<SmartLists> {
    bypass::read_smart_lists(exe, dir)
        .await
        .map_err(|err| tracing::warn!(%err, "bypass: Smart RU lists not read"))
        .ok()
}

#[cfg(test)]
mod tests;
