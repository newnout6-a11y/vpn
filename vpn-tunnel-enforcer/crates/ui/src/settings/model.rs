//! View models of the Settings page: display data only (never secrets, no Dioxus types). The
//! app fills them from the backend; the page renders them and sends back patches and actions.
use vpnte_base::Msg;
use vpnte_base::types::UnixMs;

pub use crate::theme::ThemeMode;
pub use vpnte_base::i18n::Lang;
pub use vpnte_base::types::{AdaptiveMode, EnginePref, KillSwitchLevel, ProxyKind};

mod channels;
mod transfer;

pub use channels::*;
pub use transfer::*;

/// Where the VPN comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ConnectionMode {
    /// A local proxy client (Happ) on 127.0.0.1.
    #[default]
    LocalProxy,
    /// Our own engine straight to the server (keys from the Servers page).
    DirectVpn,
}

/// How traffic is captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RoutingMode {
    /// TUN: all traffic goes through the tunnel.
    #[default]
    Hard,
    /// Applications are pointed at the proxy (environment variables, opt-in dev tools).
    Soft,
}

/// Route of the app's own downloads (subscriptions, Smart RU lists).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum BootstrapRouteMode {
    #[default]
    Auto,
    Direct,
    LocalProxy,
}

/// IP check interval, seconds (storage: 5 000..300 000 ms).
pub const CHECK_INTERVAL_SECS: (i64, i64) = (5, 300);
/// Packet-capture session size limit, MB (ring buffer).
pub const CAPTURE_MAX_MB: (i64, i64) = (128, 2048);
/// Disk quota for all capture sessions, MB.
pub const CAPTURE_QUOTA_MB: (i64, i64) = (1024, 65_536);
/// Rotation interval, minutes.
pub const ROTATION_INTERVAL_MIN: (i64, i64) = (5, 1440);

/// Declares the settings the page edits through the draft, once: the live [`SettingsView`], the
/// sparse [`SettingsPatch`] (one `Option` per field) and the patch operations.
macro_rules! draft_fields {
    ($( $(#[$doc:meta])* $name:ident : $ty:ty = $default:expr ),+ $(,)?) => {
        /// The settings fields edited through the draft and saved by «Сохранить» (live values).
        #[derive(Debug, Clone, PartialEq)]
        pub struct SettingsView { $( $(#[$doc])* pub $name: $ty, )+ }

        impl Default for SettingsView {
            fn default() -> Self {
                Self { $( $name: $default, )+ }
            }
        }

        /// A sparse change set over [`SettingsView`]: `Some` = edited, `None` = keep the live value.
        #[derive(Debug, Clone, PartialEq, Default)]
        pub struct SettingsPatch { $( pub $name: Option<$ty>, )+ }

        impl SettingsPatch {
            /// Field names in declaration (page) order.
            pub const FIELDS: &'static [&'static str] = &[$(stringify!($name)),+];

            /// Nothing edited.
            pub fn is_empty(&self) -> bool {
                true $( && self.$name.is_none() )+
            }

            /// Names of the edited fields, in page order (for logs: values may be private).
            pub fn fields(&self) -> Vec<&'static str> {
                let mut out = Vec::new();
                $( if self.$name.is_some() { out.push(stringify!($name)); } )+
                out
            }

            /// Writes the edited fields into `view`.
            pub fn apply_to(&self, view: &mut SettingsView) {
                $( if let Some(value) = &self.$name { view.$name = value.clone(); } )+
            }

            /// Edited fields whose value differs from `live`, in page order.
            pub fn changed(&self, live: &SettingsView) -> Vec<&'static str> {
                let mut out = Vec::new();
                $( if self.$name.as_ref().is_some_and(|v| *v != live.$name) { out.push(stringify!($name)); } )+
                out
            }

            /// Drops the edits equal to `live` (an edit reverted by hand is no longer a change).
            pub fn prune(&mut self, live: &SettingsView) {
                $( if self.$name.as_ref() == Some(&live.$name) { self.$name = None; } )+
            }

            /// Drops the edits equal to what `sent` carried (after a successful save; an edit
            /// made while the save was running stays).
            pub fn forget(&mut self, sent: &SettingsPatch) {
                $( if self.$name.is_some() && self.$name == sent.$name { self.$name = None; } )+
            }
        }
    };
}

draft_fields! {
    /// «Источник VPN».
    connection_mode: ConnectionMode = ConnectionMode::LocalProxy,
    /// «Режим маршрутизации» (Hard TUN / Soft).
    routing_mode: RoutingMode = RoutingMode::Hard,
    /// Soft mode: point Git at the proxy.
    soft_git: bool = false,
    /// Soft mode: point Gradle at the proxy.
    soft_gradle: bool = false,
    /// Soft mode: point Android Studio at the proxy.
    soft_studio: bool = false,
    proxy_engine: EnginePref = EnginePref::Auto,
    /// Leak protection while connected (old «Жёсткая блокировка адаптеров»).
    leak_protection: bool = true,
    public_wifi_compatibility: bool = true,
    auto_restart_on_crash: bool = true,
    stealth_mode: bool = false,
    adaptive_bypass: bool = true,
    disable_geo_lookup: bool = false,
    smart_ru_split: bool = false,
    smart_ru_maps_direct: bool = false,
    /// «Автообновлять списки»: on = managed lists, auto update, through the bootstrap route, 24 h.
    smart_ru_auto_update: bool = false,
    minimize_to_tray: bool = true,
    autopilot: bool = true,
    domain_enrichment: bool = false,
    advanced_mode: bool = false,
    /// Manual local proxy address without credentials ("" = detect). A patch carries what the
    /// user typed, which may include `user:pass@`.
    proxy_override: String = String::new(),
    proxy_type: ProxyKind = ProxyKind::Socks5,
    bootstrap_route_mode: BootstrapRouteMode = BootstrapRouteMode::Auto,
    check_interval_ms: u32 = 30_000,
    adaptive_bypass_server_fallback: bool = true,
    /// Packet capture («Глубокий захват трафика»). Saving `Some(true)` means the user accepted the
    /// one-time warning (the page asks first when consent was not given yet).
    deep_inspection: bool = false,
    deep_inspection_max_mb: u32 = 512,
    capture_quota_mb: u32 = 8192,
}

/// Everything the page shows besides the section lists: live draft fields, instant preferences
/// and the facts the hints depend on.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SettingsState {
    pub settings: SettingsView,
    /// Stored language; `None` = follow Windows.
    pub locale: Option<Lang>,
    pub active_theme_id: String,
    /// Built-in themes first, then the user's.
    pub themes: Vec<ThemeChoice>,
    /// Autostart as the OS task really is.
    pub autostart: bool,
    pub location_privacy: bool,
    /// The manual proxy address has saved credentials (never shown).
    pub proxy_credentials_saved: bool,
    /// The one-time packet-capture warning was accepted.
    pub capture_consent_given: bool,
    /// Disk used by capture sessions; `None` = not measured.
    pub capture_used_bytes: Option<u64>,
    /// A protected session is up.
    pub connected: bool,
    /// The session is Direct VPN (rotation acts only there).
    pub direct_session: bool,
    pub adaptive: AdaptiveView,
    pub rule_sets: RuleSetView,
    pub browser: BrowserView,
    /// The diagnostics ZIP export (single-flight app-wide) is running.
    pub diagnostics_export_running: bool,
}

/// A theme the user can pick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThemeChoice {
    pub id: String,
    pub name: String,
    pub mode: ThemeMode,
    pub builtin: bool,
}

/// Phase of adaptive bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AdaptivePhase {
    #[default]
    Idle,
    Connecting,
    Verifying,
    Adapting,
    Connected,
    Failed,
}

/// Adaptive bypass status line.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AdaptiveView {
    pub phase: AdaptivePhase,
    pub mode: AdaptiveMode,
    /// `None` = status unavailable.
    pub message: Option<Msg>,
}

/// Which Smart RU lists the engine uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleSource {
    #[default]
    Bundled,
    Managed,
}

/// State of the Smart RU rule lists.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RuleSetView {
    pub active_source: RuleSource,
    /// When the downloaded lists in use were fetched.
    pub managed_at: Option<UnixMs>,
    pub refreshing: bool,
    /// Why the last refresh did not complete.
    pub last_error: Option<Msg>,
}

/// Browser WebRTC protection, per browser.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BrowserView {
    pub browsers: Vec<BrowserState>,
    /// The policy changed while a browser was running.
    pub restart_required: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BrowserState {
    pub name: String,
    pub status: BrowserStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BrowserStatus {
    Protected,
    NotProtected,
    NotInstalled,
    NotChecked,
    Failed(Msg),
}

/// Outcome of the location-privacy switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationOutcome {
    /// Changed in Windows right now (a session is up).
    Applied,
    /// No session: stored, takes effect at the next connect.
    Stored,
    /// Windows refused the change (policy, rights).
    NotApplied,
}

/// What «Сохранить» did.
#[derive(Debug, Clone, PartialEq)]
pub struct SaveReport {
    /// The live settings after the save (normalised by the backend).
    pub settings: SettingsView,
    /// A running tunnel was restarted with the new values (`Err` = the restart failed).
    pub restart: Option<Result<(), Msg>>,
    /// Some change applies at the next connect only.
    pub next_connect: bool,
}

/// Result of the diagnostics ZIP export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticsExport {
    pub path: String,
    /// Temporary files could not be removed (shown, never hidden).
    pub cleanup_failed: bool,
}
