//! The routing inputs of the running session, as the runtime reads them at every start and when
//! a crash restart is due. Smart RU's lists (re-check item 12a): the set the app handed over
//! (protocol 3) once it passed this service's own checks (canaries and content bounds against
//! the pinned copies), else the set in use before it: the last one that passed, or the pinned
//! files of the install folder. A SYSTEM process never reads a user's folder, so the app sends
//! the bytes.
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use parking_lot::Mutex;
use vpnte_base::AppResult;
use vpnte_base::types::KillSwitchLevel;
use vpnte_engine::routing::rulesets::RefreshFault;
use vpnte_engine::routing::rulesets::handover::{self, RuleSetFiles};
use vpnte_tunnel::runtime::{InputsSource, UserInputs};

use crate::paths::{DataFiles, data_dir};
use crate::proto::RoutingInputs;

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
    /// The client's set, checked at the next engine start.
    handed: Mutex<Option<RuleSetFiles>>,
    /// What the checks said so far; one check at a time.
    checked: tokio::sync::Mutex<Checked>,
}

/// The last set that passed (digest, folder) and the last one that failed its checks (digest):
/// neither is checked again.
#[derive(Default)]
struct Checked {
    accepted: Option<(String, PathBuf)>,
    refused: Option<String>,
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
            handed: Mutex::new(None),
            checked: tokio::sync::Mutex::new(Checked::default()),
        }
    }

    /// Replaces the inputs (`level`: the kill-switch level they run under).
    pub fn set(&self, routing: &RoutingInputs, level: KillSwitchLevel) {
        *self.current.lock() = UserInputs {
            smart_ru: routing.smart_ru,
            smart_ru_maps_direct: routing.smart_ru_maps_direct,
            rule_set_dir: self.pinned.clone().filter(|_| routing.smart_ru),
            domain_rules: routing.domain_rules.clone(),
            split_direct: routing.split_direct.clone(),
            split_vpn: routing.split_vpn.clone(),
            split_inactive: Vec::new(),
            dns: routing.dns.clone(),
            kill_switch: level,
            public_wifi: routing.public_wifi,
            stealth: routing.stealth,
            auto_restart_on_crash: routing.auto_restart_on_crash,
        };
        *self.handed.lock() = routing.rule_sets.clone();
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

    /// The folder of the client's set once it passed this service's checks; `None`: none was
    /// sent or it is the pinned set itself. A set that fails keeps the one in use before it
    /// (the last accepted set, else the pinned files), as the app keeps its generation.
    async fn handed_dir(&self) -> Option<PathBuf> {
        let files = self.handed.lock().clone()?;
        // The pinned copies are the reference of the content bounds: without them nothing passes.
        let (engine, store) = (self.engine.as_ref()?, self.store.as_ref()?);
        let reference = self.pinned.as_ref()?;
        let digest = files.digest();
        if self.pinned_digest.as_deref() == Some(digest.as_str()) {
            return None;
        }
        let mut checked = self.checked.lock().await;
        if let Some((known, dir)) = checked.accepted.as_ref()
            && *known == digest
        {
            return Some(dir.clone());
        }
        let previous = checked.accepted.as_ref().map(|(_, d)| d.clone());
        if checked.refused.as_ref() == Some(&digest) {
            return previous;
        }
        match handover::accept(&files, engine, store, reference).await {
            Ok(dir) => {
                // The previous folder stays: a protected restart starts the new engine while the
                // old one still reads its files.
                prune(store.clone(), [Some(dir.clone()), previous]).await;
                tracing::info!(%digest, "handed-over Smart RU lists in use");
                checked.accepted = Some((digest, dir.clone()));
                Some(dir)
            }
            Err(fault) => {
                tracing::warn!(
                    ?fault,
                    kept = ?previous,
                    "handed-over Smart RU lists refused; the lists in use stay"
                );
                // A file that failed its checks fails again; an engine or disk fault may pass.
                if matches!(fault, RefreshFault::Invalid { .. }) {
                    checked.refused = Some(digest);
                }
                previous
            }
        }
    }
}

/// Removes the stored sets other than `keep` (blocking file work off the async threads).
async fn prune(store: PathBuf, keep: [Option<PathBuf>; 2]) {
    let _ = tokio::task::spawn_blocking(move || {
        let keep: Vec<&Path> = keep.iter().flatten().map(PathBuf::as_path).collect();
        handover::prune_store(&store, &keep);
    })
    .await;
}

#[async_trait]
impl InputsSource for SharedInputs {
    async fn snapshot(&self) -> AppResult<UserInputs> {
        let mut inputs = self.get();
        if inputs.smart_ru
            && let Some(dir) = self.handed_dir().await
        {
            inputs.rule_set_dir = Some(dir);
        }
        Ok(inputs)
    }
}

#[cfg(test)]
mod tests;
