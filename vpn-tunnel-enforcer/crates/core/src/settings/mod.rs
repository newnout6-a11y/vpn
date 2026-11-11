//! The `settings.json` document: app-wide preferences with their defaults, numeric limits, a typed
//! patch for the Settings page, lenient loading and the mapping of the old Electron settings.
//!
//! Loading is lenient per field: a wrong type or an unknown enum value falls back to that field's
//! default with a warning, numbers are clamped into range, unknown keys are kept (storage §6.3, B26).
//! The safety-relevant defaults hold by construction: the kill switch is `Off` and packet capture is
//! off unless a valid value says otherwise.
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use vpnte_base::AppResult;
use vpnte_base::i18n::Lang;
use vpnte_base::types::{EnginePref, KillSwitchLevel, ProxyKind};

use crate::secret::Secret;
use crate::store::Document;

mod legacy;
mod prefs;
mod proxy;
#[cfg(test)]
mod tests;

pub use legacy::import_kill_switch;
pub use prefs::{NotificationPrefs, UiPrefs};
pub use proxy::ProxyOverride;

/// Range of [`Settings::check_interval_ms`].
pub const CHECK_INTERVAL_MS: (u32, u32) = (5_000, 300_000);
/// Range of [`Settings::deep_inspection_max_mb`].
pub const DEEP_INSPECTION_MAX_MB: (u32, u32) = (128, 2_048);
/// Range of [`Settings::smart_ru_rule_set_update_hours`].
pub const RULE_SET_UPDATE_HOURS: (u32, u32) = (1, 720);

/// Where the upstream comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConnectionMode {
    /// A local proxy (Happ or a manual `host:port`).
    #[default]
    LocalProxy,
    /// A VPN server from the server list.
    DirectVpn,
}

/// How traffic is captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RoutingMode {
    /// Full TUN: every app goes through the tunnel.
    #[default]
    Hard,
    /// No TUN: apps are pointed at the local proxy.
    Soft,
}

/// How the engine reaches its own bootstrap endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BootstrapRouteMode {
    #[default]
    Auto,
    Direct,
    LocalProxy,
}

/// Source of the smart-RU rule sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleSetMode {
    /// Files shipped with the app.
    #[default]
    Bundled,
    /// Downloaded into the cache, falling back to the bundled files.
    Managed,
}

/// Where notifications are shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotifyMethod {
    #[default]
    System,
    InApp,
    Both,
}

/// Moves `key` out of `obj` into `slot` when it holds a valid value. A missing key keeps the current
/// value; an invalid one is ignored with a warning (`null` silently, unless `T` is an `Option`).
fn take<T: DeserializeOwned>(obj: &mut Map<String, Value>, key: &str, slot: &mut T) {
    let Some(value) = obj.remove(key) else { return };
    let was_null = value.is_null();
    match serde_json::from_value(value) {
        Ok(v) => *slot = v,
        Err(_) if was_null => {}
        // The value itself is not logged: a hand-edited file may hold anything.
        Err(_) => tracing::warn!(key, "invalid settings value ignored; default kept"),
    }
}

/// Like [`take`] for counters and limits: any JSON number is accepted and rounded (an old value could
/// be fractional); the caller clamps it into range.
fn take_u32(obj: &mut Map<String, Value>, key: &str, slot: &mut u32) {
    match obj.remove(key) {
        None | Some(Value::Null) => {}
        Some(Value::Number(n)) => match n.as_f64() {
            Some(f) => *slot = f.round().clamp(0.0, f64::from(u32::MAX)) as u32,
            None => tracing::warn!(key, "invalid settings number ignored; default kept"),
        },
        Some(_) => tracing::warn!(key, "invalid settings value ignored; default kept"),
    }
}

/// App-wide preferences, stored in `settings.json`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    /// Upstream source.
    pub connection_mode: ConnectionMode,
    /// Full TUN or proxy-only.
    pub routing_mode: RoutingMode,
    /// Manual local proxy; `None` means detect the local proxy automatically.
    pub proxy_override: Option<ProxyOverride>,
    /// Protocol of the local proxy.
    pub proxy_type: ProxyKind,
    /// Route of the engine's own bootstrap traffic.
    pub bootstrap_route_mode: BootstrapRouteMode,
    /// Public-IP monitor poll interval, [`CHECK_INTERVAL_MS`].
    pub check_interval_ms: u32,
    /// No app-initiated geo lookups.
    pub disable_geo_lookup: bool,
    /// Stored state of the Windows autostart task. Not part of [`SettingsPatch`]: only the checked
    /// toggle, which changes the OS task first, may set it (storage B13).
    pub autostart: bool,
    /// Connect on launch (hard / local-proxy mode) through the autopilot.
    pub autopilot: bool,
    /// Closing the window keeps the app in the tray.
    pub minimize_to_tray: bool,
    /// Hide location details in the UI.
    pub location_privacy: bool,
    /// Look up owner / category information for visited domains.
    pub domain_enrichment: bool,
    /// Opt-in proxy baseline: clear system / environment proxies while connected.
    pub auto_network_baseline: bool,
    /// Kill-switch level; replaces the old boolean mirror `firewallKillSwitch` (owner decision D-16).
    pub kill_switch: KillSwitchLevel,
    /// Show destructive maintenance options.
    pub advanced_mode: bool,
    /// The first-run wizard has been completed.
    pub first_run_complete: bool,
    /// Restart the engine after a crash.
    pub auto_restart_on_crash: bool,
    /// Windows toast notifications.
    pub desktop_notifications: bool,
    /// Safer TUN MTU (1380) for networks that drop large packets.
    pub public_wifi_compatibility: bool,
    /// Packet capture to disk; explicit opt-in only.
    pub deep_inspection: bool,
    /// Capture size limit in MB, [`DEEP_INSPECTION_MAX_MB`].
    pub deep_inspection_max_mb: u32,
    /// MTU 1280 plus TLS ClientHello fragmentation for non-Reality outbounds.
    pub stealth_mode: bool,
    /// Adaptive bypass (compatibility retries).
    pub adaptive_bypass: bool,
    /// Adaptive bypass may switch to a sibling server.
    pub adaptive_bypass_server_fallback: bool,
    /// Russian destinations go direct.
    pub smart_ru_split: bool,
    /// Maps services go direct too (only with `smart_ru_split`).
    pub smart_ru_maps_direct: bool,
    /// Where the smart-RU rule sets come from.
    pub smart_ru_rule_set_mode: RuleSetMode,
    /// Refresh managed rule sets automatically.
    pub smart_ru_rule_set_auto_update: bool,
    /// Download rule sets through the tunnel.
    pub smart_ru_rule_set_use_proxy: bool,
    /// Rule-set refresh interval in hours, [`RULE_SET_UPDATE_HOURS`].
    pub smart_ru_rule_set_update_hours: u32,
    /// Proxy engine choice.
    pub proxy_engine: EnginePref,
    /// UI language; `None` follows Windows (storage B24).
    #[serde(serialize_with = "ser_locale")]
    pub locale: Option<Lang>,
    /// Selected theme.
    pub active_theme_id: String,
    /// Notification switches.
    pub notifications: NotificationPrefs,
    /// Persistent UI state.
    pub ui: UiPrefs,
    /// Per-install key of the log IP pseudonyms (64 hex chars, sealed): see
    /// [`Settings::ensure_log_key`]. Never exported and not part of [`SettingsPatch`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_key: Option<Secret>,
    /// Keys written by a newer version, kept as they are (storage B26).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            connection_mode: ConnectionMode::LocalProxy,
            routing_mode: RoutingMode::Hard,
            proxy_override: None,
            proxy_type: ProxyKind::Socks5,
            bootstrap_route_mode: BootstrapRouteMode::Auto,
            check_interval_ms: 30_000,
            disable_geo_lookup: false,
            autostart: false,
            autopilot: true,
            minimize_to_tray: true,
            location_privacy: false,
            domain_enrichment: false,
            auto_network_baseline: false,
            kill_switch: KillSwitchLevel::Off,
            advanced_mode: false,
            first_run_complete: false,
            auto_restart_on_crash: true,
            desktop_notifications: true,
            public_wifi_compatibility: true,
            deep_inspection: false,
            deep_inspection_max_mb: 512,
            stealth_mode: false,
            adaptive_bypass: true,
            adaptive_bypass_server_fallback: true,
            smart_ru_split: false,
            smart_ru_maps_direct: false,
            smart_ru_rule_set_mode: RuleSetMode::Bundled,
            smart_ru_rule_set_auto_update: true,
            smart_ru_rule_set_use_proxy: true,
            smart_ru_rule_set_update_hours: 24,
            proxy_engine: EnginePref::Auto,
            locale: None,
            // The design and its reference capture are dark; "system" opened light on a light Windows.
            active_theme_id: "builtin-dark".to_owned(),
            notifications: NotificationPrefs::default(),
            ui: UiPrefs::default(),
            log_key: None,
            extra: Map::new(),
        }
    }
}

impl Document for Settings {
    const FILE: &'static str = "settings.json";
    const VERSION: u32 = 1;
    // Only optional proxy credentials are secret, and they stay sealed in the moved-aside copy, so a
    // corrupt file is moved aside and the app continues with defaults instead of going read-only.
    const HOLDS_SECRETS: bool = false;
}

impl<'de> Deserialize<'de> for Settings {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut settings = Settings::default();
        settings.merge_json(Map::deserialize(deserializer)?);
        Ok(settings)
    }
}

impl Settings {
    /// Applies the keys present in `obj` with the lenient rules: each key is validated on its own
    /// (invalid → current value kept, with a warning), nested objects merge per key, numbers are
    /// clamped, and unknown keys are kept in `extra`. Used for loading and for applying an imported
    /// `appSettings` section (the caller removes keys it does not want applied first).
    pub fn merge_json(&mut self, mut obj: Map<String, Value>) {
        let o = &mut obj;
        take(o, "connectionMode", &mut self.connection_mode);
        take(o, "routingMode", &mut self.routing_mode);
        take(o, "proxyOverride", &mut self.proxy_override);
        take(o, "proxyType", &mut self.proxy_type);
        take(o, "bootstrapRouteMode", &mut self.bootstrap_route_mode);
        take_u32(o, "checkIntervalMs", &mut self.check_interval_ms);
        take(o, "disableGeoLookup", &mut self.disable_geo_lookup);
        take(o, "autostart", &mut self.autostart);
        take(o, "autopilot", &mut self.autopilot);
        take(o, "minimizeToTray", &mut self.minimize_to_tray);
        take(o, "locationPrivacy", &mut self.location_privacy);
        take(o, "domainEnrichment", &mut self.domain_enrichment);
        take(o, "autoNetworkBaseline", &mut self.auto_network_baseline);
        take(o, "killSwitch", &mut self.kill_switch);
        take(o, "advancedMode", &mut self.advanced_mode);
        take(o, "firstRunComplete", &mut self.first_run_complete);
        take(o, "autoRestartOnCrash", &mut self.auto_restart_on_crash);
        take(o, "desktopNotifications", &mut self.desktop_notifications);
        take(
            o,
            "publicWifiCompatibility",
            &mut self.public_wifi_compatibility,
        );
        take(o, "deepInspection", &mut self.deep_inspection);
        take_u32(o, "deepInspectionMaxMb", &mut self.deep_inspection_max_mb);
        take(o, "stealthMode", &mut self.stealth_mode);
        take(o, "adaptiveBypass", &mut self.adaptive_bypass);
        take(
            o,
            "adaptiveBypassServerFallback",
            &mut self.adaptive_bypass_server_fallback,
        );
        take(o, "smartRuSplit", &mut self.smart_ru_split);
        take(o, "smartRuMapsDirect", &mut self.smart_ru_maps_direct);
        take(o, "smartRuRuleSetMode", &mut self.smart_ru_rule_set_mode);
        take(
            o,
            "smartRuRuleSetAutoUpdate",
            &mut self.smart_ru_rule_set_auto_update,
        );
        take(
            o,
            "smartRuRuleSetUseProxy",
            &mut self.smart_ru_rule_set_use_proxy,
        );
        take_u32(
            o,
            "smartRuRuleSetUpdateHours",
            &mut self.smart_ru_rule_set_update_hours,
        );
        take(o, "proxyEngine", &mut self.proxy_engine);
        take_locale(o, &mut self.locale);
        take(o, "activeThemeId", &mut self.active_theme_id);
        take(o, "logKey", &mut self.log_key);
        match o.remove("notifications") {
            Some(Value::Object(n)) => self.notifications.merge(n),
            None | Some(Value::Null) => {}
            Some(_) => tracing::warn!(key = "notifications", "invalid settings value ignored"),
        }
        match o.remove("ui") {
            Some(Value::Object(u)) => self.ui.merge(u),
            None | Some(Value::Null) => {}
            Some(_) => tracing::warn!(key = "ui", "invalid settings value ignored"),
        }
        self.extra.extend(obj);
        self.clamp();
    }

    /// Clamps the numeric fields into their ranges (storage §2.5).
    pub fn clamp(&mut self) {
        let fit = |v: &mut u32, (lo, hi): (u32, u32)| *v = (*v).clamp(lo, hi);
        fit(&mut self.check_interval_ms, CHECK_INTERVAL_MS);
        fit(&mut self.deep_inspection_max_mb, DEEP_INSPECTION_MAX_MB);
        fit(
            &mut self.smart_ru_rule_set_update_hours,
            RULE_SET_UPDATE_HOURS,
        );
    }

    /// Assigns the fields present in `patch`, then clamps. Typed fields make the old "an explicit
    /// undefined turns a flag off" class of bugs impossible (storage B10).
    pub fn apply(&mut self, patch: SettingsPatch) {
        macro_rules! assign {
            ($($field:ident),* $(,)?) => {
                $( if let Some(v) = patch.$field { self.$field = v; } )*
            };
        }
        assign!(
            connection_mode,
            routing_mode,
            proxy_override,
            proxy_type,
            bootstrap_route_mode,
            check_interval_ms,
            disable_geo_lookup,
            autopilot,
            minimize_to_tray,
            location_privacy,
            domain_enrichment,
            auto_network_baseline,
            kill_switch,
            advanced_mode,
            first_run_complete,
            auto_restart_on_crash,
            desktop_notifications,
            public_wifi_compatibility,
            deep_inspection,
            deep_inspection_max_mb,
            stealth_mode,
            adaptive_bypass,
            adaptive_bypass_server_fallback,
            smart_ru_split,
            smart_ru_maps_direct,
            smart_ru_rule_set_mode,
            smart_ru_rule_set_auto_update,
            smart_ru_rule_set_use_proxy,
            smart_ru_rule_set_update_hours,
            proxy_engine,
            locale,
            active_theme_id,
            notifications,
            ui,
        );
        self.clamp();
    }

    /// The 32-byte key for `redact::set_ip_key`, so log pseudonyms stay stable across runs. A
    /// missing or unreadable key (locked: copied from another account or PC) is replaced by a fresh
    /// random one; `None` only if the OS random source fails (the log then keeps its per-process
    /// key). Persist it with `store.update(Settings::ensure_log_key)`; a read-only store refuses
    /// that, so fall back to `store.snapshot().ensure_log_key()` (unsaved) rather than fail.
    pub fn ensure_log_key(&mut self) -> Option<[u8; 32]> {
        let stored = self.log_key.as_ref().and_then(Secret::expose);
        if let Some(key) = stored.and_then(|hex| hex::decode(hex).ok()?.try_into().ok()) {
            return Some(key);
        }
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).ok()?;
        self.log_key = Some(Secret::new(hex::encode(key)));
        Some(key)
    }
}

fn ser_locale<S: Serializer>(locale: &Option<Lang>, serializer: S) -> Result<S::Ok, S::Error> {
    match locale {
        Some(lang) => serializer.serialize_some(lang.code()),
        None => serializer.serialize_none(),
    }
}

fn take_locale(obj: &mut Map<String, Value>, slot: &mut Option<Lang>) {
    match obj.remove("locale") {
        None => {}
        Some(Value::Null) => *slot = None,
        Some(value) => match value.as_str().and_then(Lang::from_tag) {
            Some(lang) => *slot = Some(lang),
            None => tracing::warn!(
                key = "locale",
                "invalid settings value ignored; default kept"
            ),
        },
    }
}

/// A change from the Settings page: `Some` fields are assigned, `None` fields stay as they are.
/// `autostart` is deliberately absent (storage B13).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SettingsPatch {
    pub connection_mode: Option<ConnectionMode>,
    pub routing_mode: Option<RoutingMode>,
    /// `Some(None)` clears the manual proxy.
    pub proxy_override: Option<Option<ProxyOverride>>,
    pub proxy_type: Option<ProxyKind>,
    pub bootstrap_route_mode: Option<BootstrapRouteMode>,
    pub check_interval_ms: Option<u32>,
    pub disable_geo_lookup: Option<bool>,
    pub autopilot: Option<bool>,
    pub minimize_to_tray: Option<bool>,
    pub location_privacy: Option<bool>,
    pub domain_enrichment: Option<bool>,
    pub auto_network_baseline: Option<bool>,
    pub kill_switch: Option<KillSwitchLevel>,
    pub advanced_mode: Option<bool>,
    pub first_run_complete: Option<bool>,
    pub auto_restart_on_crash: Option<bool>,
    pub desktop_notifications: Option<bool>,
    pub public_wifi_compatibility: Option<bool>,
    pub deep_inspection: Option<bool>,
    pub deep_inspection_max_mb: Option<u32>,
    pub stealth_mode: Option<bool>,
    pub adaptive_bypass: Option<bool>,
    pub adaptive_bypass_server_fallback: Option<bool>,
    pub smart_ru_split: Option<bool>,
    pub smart_ru_maps_direct: Option<bool>,
    pub smart_ru_rule_set_mode: Option<RuleSetMode>,
    pub smart_ru_rule_set_auto_update: Option<bool>,
    pub smart_ru_rule_set_use_proxy: Option<bool>,
    pub smart_ru_rule_set_update_hours: Option<u32>,
    pub proxy_engine: Option<EnginePref>,
    /// `Some(None)` returns to following the Windows language.
    pub locale: Option<Option<Lang>>,
    pub active_theme_id: Option<String>,
    pub notifications: Option<NotificationPrefs>,
    pub ui: Option<UiPrefs>,
}

impl SettingsPatch {
    /// Sets the manual proxy from user input: empty clears it; otherwise it is parsed with
    /// [`ProxyOverride::parse`] and a scheme in the input also sets `proxy_type`.
    pub fn set_proxy_override(&mut self, input: &str) -> AppResult<()> {
        if input.trim().is_empty() {
            self.proxy_override = Some(None);
            return Ok(());
        }
        let (proxy, kind) = ProxyOverride::parse(input)?;
        self.proxy_override = Some(Some(proxy));
        if kind.is_some() {
            self.proxy_type = kind;
        }
        Ok(())
    }
}
