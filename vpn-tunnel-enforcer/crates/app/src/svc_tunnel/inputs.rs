//! [`InputsSource`] over the user's stores: settings, routing rules and the Smart RU rule sets.
use std::sync::Arc;

use async_trait::async_trait;
use vpnte_base::{AppError, AppResult};
use vpnte_core::settings::{RuleSetMode, Settings};
use vpnte_core::store::Store;
use vpnte_engine::routing::RulesDoc;
use vpnte_engine::routing::process::{InactiveReason, probe_fs};
use vpnte_engine::routing::rulesets::RuleSetService;
use vpnte_tunnel::runtime::{InactiveSplit, InputsSource, UserInputs};

/// Reads the inputs of one engine start (every start and every due crash restart).
pub(super) struct StoreInputs {
    pub settings: Arc<Store<Settings>>,
    pub rules: Arc<Store<RulesDoc>>,
    pub rule_sets: Arc<RuleSetService>,
}

#[async_trait]
impl InputsSource for StoreInputs {
    async fn snapshot(&self) -> AppResult<UserInputs> {
        let s = self.settings.snapshot();
        let doc = self.rules.snapshot();
        let rule_sets = self.rule_sets.clone();
        let managed = s.smart_ru_rule_set_mode == RuleSetMode::Managed;
        let smart_ru = s.smart_ru_split;
        // File probes and the rule-set cache prune are blocking; prune only runs right before an
        // engine start (engine API), which is exactly when the runtime asks.
        let (rule_set_dir, split, doc) = tokio::task::spawn_blocking(move || {
            rule_sets.prune();
            let dir = smart_ru
                .then(|| rule_sets.active(managed).map(|(_, dir)| dir))
                .flatten();
            let split = doc.resolve_split(probe_fs);
            (dir, split, doc)
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
            kill_switch: s.kill_switch,
            public_wifi: s.public_wifi_compatibility,
            stealth: s.stealth_mode,
            auto_restart_on_crash: s.auto_restart_on_crash,
        })
    }
}
