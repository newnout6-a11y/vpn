//! [`InputsSource`] over the user's stores: settings, routing rules and the Smart RU rule sets.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use vpnte_base::{AppError, AppResult};
use vpnte_core::settings::{AppScope, RuleSetMode, Settings};
use vpnte_core::store::Store;
use vpnte_engine::routing::RulesDoc;
use vpnte_engine::routing::process::{AppPath, InactiveReason, Probe, probe_fs};
use vpnte_engine::routing::rulesets::RuleSetService;
use vpnte_tunnel::runtime::{InactiveSplit, InputsSource, UserInputs};

/// Reads the inputs of one engine start (every start and every due crash restart).
pub(super) struct StoreInputs {
    pub settings: Arc<Store<Settings>>,
    pub rules: Arc<Store<RulesDoc>>,
    pub rule_sets: Arc<RuleSetService>,
    /// "Always" can be kept safe (the guard's flag): otherwise `strict` runs as `standard`.
    pub always: Arc<AtomicBool>,
}

#[async_trait]
impl InputsSource for StoreInputs {
    async fn snapshot(&self) -> AppResult<UserInputs> {
        let s = self.settings.snapshot();
        let doc = self.rules.snapshot();
        let rule_sets = self.rule_sets.clone();
        let managed = s.smart_ru_rule_set_mode == RuleSetMode::Managed;
        let smart_ru = s.smart_ru_split;
        let only_listed = s.app_scope == AppScope::OnlyListed;
        // File probes and the rule-set cache prune are blocking; prune only runs right before an
        // engine start (engine API), which is exactly when the runtime asks.
        let (rule_set_dir, split, doc, own) = tokio::task::spawn_blocking(move || {
            rule_sets.prune();
            let dir = smart_ru
                .then(|| rule_sets.active(managed).map(|(_, dir)| dir))
                .flatten();
            let split = doc.resolve_split(probe_fs);
            (dir, split, doc, only_listed.then(own_exe))
        })
        .await
        .map_err(AppError::internal)?;
        Ok(UserInputs {
            smart_ru,
            smart_ru_maps_direct: s.smart_ru_maps_direct,
            rule_set_dir,
            dns: doc.active_dns().map(|p| p.primary),
            domain_rules: doc.domain_rules,
            split_direct: split.direct,
            split_vpn: split.vpn,
            split_inactive: split
                .inactive
                .into_iter()
                .map(|a| InactiveSplit {
                    name: a.name,
                    path: a.path,
                    missing: a.reason == InactiveReason::FileMissing,
                })
                .collect(),
            only_listed: own,
            proxy_bypass: s.proxy_bypass.clone(),
            kill_switch: s.kill_switch.effective(self.always.load(Ordering::Relaxed)),
            public_wifi: s.public_wifi_compatibility,
            stealth: s.stealth_mode,
            auto_restart_on_crash: s.auto_restart_on_crash,
        })
    }
}

/// The app's own exe as `process_path_regex` values (as stored and in its long spelling, like
/// a listed app): with only the listed apps in the tunnel, the app's in-process probes must
/// still use it (re-check item 16). Blocking: probes the file.
pub(crate) fn own_exe() -> Vec<String> {
    let exe = std::env::current_exe().ok();
    let Some(path) = exe.and_then(|p| AppPath::parse(&p.to_string_lossy()).ok()) else {
        tracing::warn!("own exe not usable in the apps scope");
        return Vec::new();
    };
    let mut out = vec![path.regex()];
    if let Probe::File {
        canonical: Some(long),
    } = probe_fs(&path)
    {
        out.push(long.regex());
    }
    out
}
