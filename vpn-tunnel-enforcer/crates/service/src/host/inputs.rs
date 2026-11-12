//! The routing inputs of the running session, as the runtime reads them at every start and when
//! a crash restart is due.
use std::path::PathBuf;

use async_trait::async_trait;
use parking_lot::Mutex;
use vpnte_base::AppResult;
use vpnte_base::types::KillSwitchLevel;
use vpnte_tunnel::runtime::{InputsSource, UserInputs};

use crate::proto::RoutingInputs;

/// The last inputs a client sent, with the service's own Smart RU rule-set folder.
pub struct SharedInputs {
    rule_sets: Option<PathBuf>,
    current: Mutex<UserInputs>,
}

impl SharedInputs {
    /// `rule_sets`: the folder with the bundled Smart RU `.srs` files (`None`: Smart RU off).
    pub fn new(rule_sets: Option<PathBuf>) -> Self {
        Self {
            rule_sets,
            current: Mutex::new(UserInputs::default()),
        }
    }

    /// Replaces the inputs (`level`: the kill-switch level they run under).
    pub fn set(&self, routing: &RoutingInputs, level: KillSwitchLevel) {
        *self.current.lock() = UserInputs {
            smart_ru: routing.smart_ru,
            smart_ru_maps_direct: routing.smart_ru_maps_direct,
            rule_set_dir: self.rule_sets.clone().filter(|_| routing.smart_ru),
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
    }

    /// Keeps the inputs, changes the kill-switch level.
    pub fn set_level(&self, level: KillSwitchLevel) {
        self.current.lock().kill_switch = level;
    }

    /// The current inputs.
    pub fn get(&self) -> UserInputs {
        self.current.lock().clone()
    }
}

#[async_trait]
impl InputsSource for SharedInputs {
    async fn snapshot(&self) -> AppResult<UserInputs> {
        Ok(self.get())
    }
}
