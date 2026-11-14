//! The routing inputs of the running session, as the runtime reads them at every start and when
//! a crash restart is due. Smart RU's lists (re-check item 12a): the set the app handed over
//! (protocol 3) once it passed this service's own checks (canaries and content bounds against
//! the pinned copies), else the set in use before it: the last one of the same Windows user that
//! passed, or the pinned files of the install folder (speed3 P-1: one user's lists never steer
//! another's routing). A SYSTEM process never reads a user's folder, so the app sends the bytes.
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use parking_lot::Mutex;
use vpnte_base::types::KillSwitchLevel;
use vpnte_base::{AppResult, Msg};
use vpnte_engine::routing::rulesets::RefreshFault;
use vpnte_engine::routing::rulesets::handover::{self, RuleSetFiles};
use vpnte_tunnel::api::ServerFacts;
use vpnte_tunnel::runtime::{InputsSource, UserInputs};

use crate::paths::{DataFiles, data_dir};
use crate::proto::{RoutingInputs, RuleSetSource, RuleSetsWire};

/// The last inputs a client sent, with the service's own Smart RU rule-set folders.
pub struct SharedInputs {
    /// The install folder when it holds every pinned `.srs` file (`None`: Smart RU off unless a
    /// handed-over set passes).
    pinned: Option<PathBuf>,
    /// Digest of the pinned files: the same set handed over needs no check.
    pinned_digest: Option<String>,
    /// The service's own sing-box, which checks a handed-over set.
    engine: Option<PathBuf>,
    /// Admin-only folder of the handed-over sets that passed (`None`: hand-overs unused).
    store: Option<PathBuf>,
    current: Mutex<UserInputs>,
    /// The client's set and his SID, checked at the next engine start.
    handed: Mutex<(String, Option<RuleSetFiles>)>,
    /// What the checks said so far; one check at a time.
    checked: tokio::sync::Mutex<Checked>,
    /// Which lists the last engine start ran (`None`: Smart RU off), for the app (psmart-b2).
    report: Mutex<Option<RuleSetsWire>>,
    /// The server id and facts of the request in flight (speed3 H2): taken once by its start
    /// or switch, replaced by the next request, never kept for a restart.
    facts: Mutex<Option<(String, ServerFacts)>>,
}

/// Per Windows user the last set that passed (digest, folder), and the last set that failed its
/// checks (digest, why; the same bytes fail for anyone): neither is checked again.
#[derive(Default)]
struct Checked {
    accepted: HashMap<String, (String, PathBuf)>,
    refused: Option<(String, Msg)>,
    /// The users whose store note was read since the service started.
    recalled: HashSet<String>,
}

impl SharedInputs {
    /// `install`: the service's folder with its pinned engine and Smart RU `.srs` files (`None`:
    /// Smart RU off). Handed-over sets go to `<ProgramData>\VPN Tunnel Enforcer\service\rulesets`.
    pub fn new(install: Option<PathBuf>) -> Self {
        let store = install
            .as_ref()
            .and_then(|_| data_dir().ok())
            .map(|data| DataFiles::new(&data).private.join("rulesets"));
        Self::with_store(install, store)
    }

    /// [`SharedInputs::new`] with the folder of the handed-over sets given.
    pub(crate) fn with_store(install: Option<PathBuf>, store: Option<PathBuf>) -> Self {
        let pinned_set = install.as_deref().and_then(RuleSetFiles::read);
        if install.is_some() && pinned_set.is_none() {
            tracing::warn!("the service's own Smart RU lists are incomplete");
        }
        Self {
            pinned: install.clone().filter(|_| pinned_set.is_some()),
            pinned_digest: pinned_set.map(|s| s.digest()),
            engine: install.map(|dir| dir.join("sing-box.exe")),
            store,
            current: Mutex::new(UserInputs::default()),
            handed: Mutex::new((String::new(), None)),
            checked: tokio::sync::Mutex::new(Checked::default()),
            report: Mutex::new(None),
            facts: Mutex::new(None),
        }
    }

    /// The facts of the request in flight about server `id` (`None`: it carries none).
    pub fn offer(&self, facts: Option<(String, ServerFacts)>) {
        *self.facts.lock() = facts;
    }

    /// Which Smart RU lists the last engine start ran; `None` while Smart RU is off.
    pub fn rule_sets(&self) -> Option<RuleSetsWire> {
        self.report.lock().clone()
    }

    /// Replaces the inputs with `owner`'s (the sender's SID; `level`: the kill-switch level they
    /// run under). A handed-over set is checked at once in the background (lab live-9 L9-2: the
    /// check took 4.7 s inside the first start); a start finds it accepted by its digest, or
    /// waits only for the rest.
    pub fn set(self: &Arc<Self>, routing: &RoutingInputs, level: KillSwitchLevel, owner: &str) {
        *self.current.lock() = UserInputs {
            smart_ru: routing.smart_ru,
            smart_ru_maps_direct: routing.smart_ru_maps_direct,
            rule_set_dir: self.pinned.clone().filter(|_| routing.smart_ru),
            domain_rules: routing.domain_rules.clone(),
            split_direct: routing.split_direct.clone(),
            split_vpn: routing.split_vpn.clone(),
            split_inactive: Vec::new(),
            only_listed: routing.only_listed.clone(),
            // Proxy capture runs in the app, never here.
            proxy_bypass: Vec::new(),
            dns: routing.dns.clone(),
            kill_switch: level,
            public_wifi: routing.public_wifi,
            stealth: routing.stealth,
            auto_restart_on_crash: routing.auto_restart_on_crash,
        };
        *self.handed.lock() = (owner.to_owned(), routing.rule_sets.clone());
        if routing.smart_ru
            && routing.rule_sets.is_some()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let this = Arc::clone(self);
            runtime.spawn(async move {
                this.choose().await;
            });
        }
    }

    /// Keeps the inputs, changes the kill-switch level.
    pub fn set_level(&self, level: KillSwitchLevel) {
        self.current.lock().kill_switch = level;
    }

    /// The current inputs (with the pinned rule-set folder; [`InputsSource::snapshot`] puts a
    /// handed-over set that passed in its place).
    pub fn get(&self) -> UserInputs {
        self.current.lock().clone()
    }

    /// The folder of the client's set once it passed this service's checks (`None`: none was
    /// sent, it is the pinned set itself, or it failed and no earlier set passed), and what that
    /// means for the app. A set that fails keeps the one in use before it (the last accepted
    /// set, else the pinned files), as the app keeps its generation.
    async fn choose(&self) -> (Option<PathBuf>, RuleSetsWire) {
        let pinned = |refused| RuleSetsWire {
            source: RuleSetSource::Pinned,
            digest: self.pinned.as_ref().and(self.pinned_digest.clone()),
            refused,
        };
        let (owner, Some(files)) = self.handed.lock().clone() else {
            return (None, pinned(None));
        };
        // The pinned copies are the reference of the content bounds: without them nothing passes.
        let (Some(engine), Some(store), Some(reference)) = (
            self.engine.as_ref(),
            self.store.as_ref(),
            self.pinned.as_ref(),
        ) else {
            return (None, pinned(None));
        };
        let digest = files.digest();
        if self.pinned_digest.as_deref() == Some(digest.as_str()) {
            return (None, pinned(None));
        }
        let mut checked = self.checked.lock().await;
        if checked.recalled.insert(owner.clone())
            && let Some(kept) = handover::recall(store, &owner).await
        {
            // A restart keeps the user's last set that passed, not the pinned files (fixlists-a5).
            checked.accepted.insert(owner.clone(), kept);
        }
        if let Some((known, dir)) = checked.accepted.get(&owner)
            && *known == digest
        {
            return (
                Some(dir.clone()),
                handed(RuleSetSource::Handed, digest, None),
            );
        }
        let previous = checked.accepted.get(&owner).cloned();
        let fallback = |why: Msg| match previous.clone() {
            Some((kept, dir)) => (Some(dir), handed(RuleSetSource::Kept, kept, Some(why))),
            None => (None, pinned(Some(why))),
        };
        if let Some((known, why)) = checked.refused.as_ref()
            && *known == digest
        {
            return fallback(why.clone());
        }
        let step = Instant::now();
        match handover::accept(&files, engine, store, reference, &owner).await {
            Ok(dir) => {
                let ms = step.elapsed().as_millis();
                // Every user's kept folder stays, the previous one too: a protected restart
                // starts the new engine while the old one still reads its files.
                let mut keep: Vec<PathBuf> =
                    checked.accepted.values().map(|(_, d)| d.clone()).collect();
                keep.push(dir.clone());
                prune(store.clone(), keep).await;
                tracing::info!(%digest, ms, "handed-over Smart RU lists in use");
                checked
                    .accepted
                    .insert(owner, (digest.clone(), dir.clone()));
                (Some(dir), handed(RuleSetSource::Handed, digest, None))
            }
            Err(fault) => {
                tracing::warn!(
                    ?fault,
                    kept = ?previous,
                    "handed-over Smart RU lists refused; the lists in use stay"
                );
                // A file that failed its checks fails again; an engine or disk fault may pass.
                if matches!(fault, RefreshFault::Invalid { .. }) {
                    checked.refused = Some((digest, fault.msg()));
                }
                fallback(fault.msg())
            }
        }
    }
}

fn handed(source: RuleSetSource, digest: String, refused: Option<Msg>) -> RuleSetsWire {
    RuleSetsWire {
        source,
        digest: Some(digest),
        refused,
    }
}

/// Removes the stored sets other than `keep` (blocking file work off the async threads).
async fn prune(store: PathBuf, keep: Vec<PathBuf>) {
    let _ = tokio::task::spawn_blocking(move || {
        let keep: Vec<&Path> = keep.iter().map(PathBuf::as_path).collect();
        handover::prune_store(&store, &keep);
    })
    .await;
}

#[async_trait]
impl InputsSource for SharedInputs {
    async fn snapshot(&self) -> AppResult<UserInputs> {
        let mut inputs = self.get();
        let report = if inputs.smart_ru {
            let step = Instant::now();
            let (dir, report) = self.choose().await;
            let ms = step.elapsed().as_millis();
            tracing::info!(ms, source = ?report.source, "Smart RU lists ready");
            if let Some(dir) = dir {
                inputs.rule_set_dir = Some(dir);
            }
            Some(report)
        } else {
            None
        };
        *self.report.lock() = report;
        Ok(inputs)
    }

    fn server_facts(&self, profile_id: &str) -> ServerFacts {
        let mut facts = self.facts.lock();
        match facts.take() {
            Some((id, given)) if id == profile_id => given,
            other => {
                *facts = other;
                ServerFacts::default()
            }
        }
    }
}

#[cfg(test)]
mod tests;
