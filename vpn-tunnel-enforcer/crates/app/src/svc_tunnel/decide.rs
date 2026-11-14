//! Pure decisions of the tunnel service: what a user connect starts, and what a saved settings
//! change does to a running tunnel.
use std::time::Duration;

use vpnte_base::types::{KillSwitchLevel, ProxyKind};
use vpnte_core::settings::{ConnectionMode, RoutingMode, Settings};
use vpnte_tunnel::lifecycle::ConnectTarget;

/// A local upstream proxy (`host:port`, protocol) a connect chains to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Upstream {
    pub addr: String,
    pub kind: ProxyKind,
}

/// The local proxy the user configured (`proxy_override` with `proxy_type`); `None` = detect.
pub(super) fn configured_upstream(s: &Settings) -> Option<Upstream> {
    s.proxy_override.as_ref().map(|o| Upstream {
        addr: o.addr.to_string(),
        kind: s.proxy_type,
    })
}

/// What a user connect starts: connection mode x routing mode. Direct VPN always takes the
/// active server; local-proxy mode needs `upstream` (`None` there: no proxy to chain to).
pub(super) fn connect_target(
    connection: ConnectionMode,
    routing: RoutingMode,
    upstream: Option<Upstream>,
) -> Option<ConnectTarget> {
    let soft = routing == RoutingMode::Soft;
    Some(match connection {
        ConnectionMode::DirectVpn if soft => ConnectTarget::SoftVpn { profile_id: None },
        ConnectionMode::DirectVpn => ConnectTarget::DirectVpn { profile_id: None },
        ConnectionMode::LocalProxy => {
            let Upstream { addr, kind } = upstream?;
            if soft {
                ConnectTarget::Soft { addr, kind }
            } else {
                ConnectTarget::LocalProxy { addr, kind }
            }
        }
    })
}

/// What a saved settings change does to the running tunnel (lifecycle-app §3.12, tunnel-core
/// §2.9). Everything not listed here takes effect at the next connect (engine choice, modes,
/// local proxy, Smart RU) or is read live (auto-restart on crash).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Change {
    /// Changed fields that reshape a running tunnel (log text); non-empty = restart it.
    pub restart: Vec<&'static str>,
    /// The kill-switch level to hand to the protection.
    pub kill_switch: Option<KillSwitchLevel>,
    /// The new public-IP check period.
    pub check_interval: Option<Duration>,
    /// Smart RU or rule-set download settings changed: refresh the rule sets (when auto refresh
    /// is on); the running tunnel keeps its rules until the next connect.
    pub rule_sets: bool,
}

/// The decision table for `apply_settings_change(old, new)`.
pub(super) fn settings_change(old: &Settings, new: &Settings) -> Change {
    let mut restart = Vec::new();
    if old.public_wifi_compatibility != new.public_wifi_compatibility {
        restart.push("publicWifiCompatibility");
    }
    if old.stealth_mode != new.stealth_mode {
        restart.push("stealthMode");
    }
    let rule_sets = old.smart_ru_split != new.smart_ru_split
        || old.smart_ru_rule_set_mode != new.smart_ru_rule_set_mode
        || old.smart_ru_rule_set_auto_update != new.smart_ru_rule_set_auto_update
        || old.smart_ru_rule_set_use_proxy != new.smart_ru_rule_set_use_proxy
        || old.smart_ru_rule_set_update_hours != new.smart_ru_rule_set_update_hours
        || old.bootstrap_route_mode != new.bootstrap_route_mode;
    Change {
        restart,
        kill_switch: (old.kill_switch != new.kill_switch).then_some(new.kill_switch),
        check_interval: (old.check_interval_ms != new.check_interval_ms)
            .then(|| check_interval(new)),
        rule_sets,
    }
}

/// The public-IP check period of `s` (the monitor clamps it to 5-300 s).
pub(super) fn check_interval(s: &Settings) -> Duration {
    Duration::from_millis(u64::from(s.check_interval_ms))
}
