//! Mapping of the old Electron settings (storage §2.5, §6.3, §6.6) into [`Settings`].
use serde_json::{Map, Value};
use vpnte_base::Msg;
use vpnte_base::i18n::Lang;
use vpnte_base::types::{EnginePref, KillSwitchLevel, ProxyKind};

use super::{
    BootstrapRouteMode, CHECK_INTERVAL_MS, ConnectionMode, DEEP_INSPECTION_MAX_MB,
    NotificationPrefs, ProxyOverride, RULE_SET_UPDATE_HOURS, RoutingMode, RuleSetMode, Settings,
};

/// Kill-switch level from the old app's two sources (owner decision D-16): `killSwitchLevel` of
/// `granular-kill-switch.json` and the settings boolean `firewallKillSwitch`. Strict always wins;
/// otherwise the boolean decides, exactly as the old start-up synchronisation did.
pub fn import_kill_switch(level: Option<&str>, legacy_bool: Option<bool>) -> KillSwitchLevel {
    match (level, legacy_bool) {
        (Some("strict"), _) => KillSwitchLevel::Strict,
        (_, Some(true)) => KillSwitchLevel::Standard,
        _ => KillSwitchLevel::Off,
    }
}

impl Settings {
    /// Maps the old Electron `settings` object (secrets already decrypted; the `{"settings": {…}}`
    /// wrapper of the old `settings.json` is accepted too) with the old normalisation rules and the
    /// rename table (storage §2.5, §6.3). Returns warnings for the import report.
    ///
    /// Not mapped here: `directVpn*` (the profiles importer reads them from the same object),
    /// `strictAdapterLockdown` (mechanism dropped), `deepTrafficInspectionRetainSessions` (D-67), and
    /// the level of `granular-kill-switch.json` (merge it with [`import_kill_switch`]). A `null` value
    /// counts as missing, which fixes the old `minimizeToTray` / `directVpnCachedAt` quirks (B10, B11).
    pub fn from_legacy(legacy: &Value) -> (Settings, Vec<Msg>) {
        let empty = Map::new();
        let obj = match legacy.get("settings") {
            Some(Value::Object(inner)) => inner,
            _ => legacy.as_object().unwrap_or(&empty),
        };
        let get = |key: &str| obj.get(key).filter(|v| !v.is_null());
        let text = |key: &str| get(key).and_then(Value::as_str);
        // The three boolean idioms of the old code differ on purpose (storage §2.5).
        let on_unless_false = |key: &str| get(key) != Some(&Value::Bool(false));
        let only_if_true = |key: &str| get(key) == Some(&Value::Bool(true));
        let truthy = |key: &str, default: bool| get(key).map_or(default, js_truthy);
        // `Number(x) || default`: 0 and NaN fall back to the default.
        let number = |key: &str, default: f64| {
            let n = get(key).map_or(f64::NAN, js_number);
            if n == 0.0 || n.is_nan() { default } else { n }
        };
        let bounded = |n: f64, (lo, hi): (u32, u32)| n.clamp(f64::from(lo), f64::from(hi)) as u32;

        let mut warnings = Vec::new();
        let mut settings = Settings {
            connection_mode: match text("connectionMode") {
                Some("directVpn") => ConnectionMode::DirectVpn,
                _ => ConnectionMode::LocalProxy,
            },
            routing_mode: match text("routingMode") {
                Some("soft") => RoutingMode::Soft,
                _ => RoutingMode::Hard,
            },
            proxy_type: match text("proxyType") {
                Some("http") => ProxyKind::Http,
                _ => ProxyKind::Socks5,
            },
            bootstrap_route_mode: match text("bootstrapRouteMode") {
                Some("direct") => BootstrapRouteMode::Direct,
                Some("localProxy") => BootstrapRouteMode::LocalProxy,
                _ => BootstrapRouteMode::Auto,
            },
            check_interval_ms: bounded(
                number("checkInterval", 30_000.0).round(),
                CHECK_INTERVAL_MS,
            ),
            disable_geo_lookup: truthy("disableGeoLookup", false),
            autostart: truthy("autoStart", false),
            autopilot: on_unless_false("autoPilotEnabled"),
            minimize_to_tray: truthy("minimizeToTray", true),
            location_privacy: truthy("locationPrivacyEnabled", false),
            domain_enrichment: truthy("domainEnrichmentEnabled", false),
            auto_network_baseline: truthy("autoNetworkBaseline", false),
            kill_switch: import_kill_switch(None, Some(only_if_true("firewallKillSwitch"))),
            advanced_mode: truthy("advancedMode", false),
            first_run_complete: truthy("firstRunComplete", false),
            auto_restart_on_crash: on_unless_false("autoRestartOnCrash"),
            desktop_notifications: on_unless_false("desktopNotifications"),
            public_wifi_compatibility: on_unless_false("publicWifiCompatibility"),
            deep_inspection: only_if_true("deepTrafficInspectionEnabled"),
            deep_inspection_max_mb: bounded(
                number("deepTrafficInspectionMaxSizeMb", 512.0).floor(),
                DEEP_INSPECTION_MAX_MB,
            ),
            stealth_mode: truthy("stealthMode", false),
            adaptive_bypass: on_unless_false("adaptiveBypassEnabled"),
            adaptive_bypass_server_fallback: on_unless_false("adaptiveBypassServerFallback"),
            smart_ru_split: truthy("smartRuSplit", false),
            smart_ru_maps_direct: truthy("smartRuMapsDirect", false),
            // An old explicit "bundled" stays; absent or unknown is today's default (managed).
            smart_ru_rule_set_mode: match text("smartRuRuleSetMode") {
                Some("bundled") => RuleSetMode::Bundled,
                _ => RuleSetMode::Managed,
            },
            smart_ru_rule_set_auto_update: on_unless_false("smartRuRuleSetAutoUpdate"),
            smart_ru_rule_set_use_proxy: on_unless_false("smartRuRuleSetUseProxy"),
            smart_ru_rule_set_update_hours: bounded(
                number("smartRuRuleSetUpdateIntervalHours", 24.0).floor(),
                RULE_SET_UPDATE_HOURS,
            ),
            proxy_engine: match text("proxyEngine") {
                Some("sing-box") => EnginePref::SingBox,
                Some("xray") => EnginePref::Xray,
                _ => EnginePref::Auto,
            },
            ..Settings::default()
        };
        match get("proxyOverride") {
            None => {}
            Some(Value::String(raw)) if raw.trim().is_empty() => {}
            Some(Value::String(raw)) => match ProxyOverride::parse(raw) {
                Ok((proxy, kind)) => {
                    settings.proxy_override = Some(proxy);
                    settings.proxy_type = kind.unwrap_or(settings.proxy_type);
                }
                Err(_) => warnings.push(Msg::new("core.settings.legacyProxyDropped")),
            },
            // Not a string: an envelope that could not be decrypted, or garbage.
            Some(_) => warnings.push(Msg::new("core.settings.legacyProxyDropped")),
        }
        (settings, warnings)
    }

    /// Maps the old single-purpose stores that now live in `settings.json` (storage §6.6):
    /// `i18n.json` → `locale`, `themes.json` → `active_theme_id`, `notification-prefs.json` →
    /// `notifications`. A missing or unrecognised value keeps the current one.
    pub fn apply_legacy_stores(
        &mut self,
        i18n: Option<&Value>,
        themes: Option<&Value>,
        notification_prefs: Option<&Value>,
    ) {
        // The old app persisted the detected locale on first run; it is indistinguishable from a
        // choice, so it is kept (B24).
        if let Some(lang) = i18n
            .and_then(|v| v.get("locale"))
            .and_then(Value::as_str)
            .and_then(Lang::from_tag)
        {
            self.locale = Some(lang);
        }
        if let Some(theme) = themes
            .and_then(|v| v.get("activeThemeId"))
            .and_then(Value::as_str)
            .filter(|id| !id.trim().is_empty())
        {
            self.active_theme_id = theme.to_owned();
        }
        if let Some(prefs) = notification_prefs {
            self.notifications = NotificationPrefs::from_legacy(prefs);
        }
    }
}

/// JavaScript `Boolean(x)`.
fn js_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// JavaScript `Number(x)` for the values the old store could hold (NaN for anything exotic).
fn js_number(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::String(s) if s.trim().is_empty() => 0.0,
        Value::String(s) => s
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|f| f.is_finite())
            .unwrap_or(f64::NAN),
        Value::Bool(b) => f64::from(u8::from(*b)),
        Value::Null => 0.0,
        Value::Array(_) | Value::Object(_) => f64::NAN,
    }
}
