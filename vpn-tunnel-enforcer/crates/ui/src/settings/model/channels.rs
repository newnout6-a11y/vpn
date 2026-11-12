//! View models the page receives on their own channels: kill switch, rotation, DNS, domain rules
//! and notifications, with their patches and outcomes.
use vpnte_base::Msg;
use vpnte_base::types::UnixMs;

use super::*;

// ── Kill switch ──────────────────────────────────────────────────────────────

/// Kill-switch level, its verified state and the exceptions.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct KillSwitchView {
    /// The committed level.
    pub level: KillSwitchLevel,
    pub status: ProtectionStatus,
    pub exceptions: Vec<ExceptionView>,
    /// Windows Firewall blocks outgoing connections by default on an active profile.
    pub firewall_blocks_outbound: bool,
    /// A Hyper-V switch exists: virtual machines and WSL are not covered (a Details line).
    pub hyperv_unfiltered: bool,
    /// "Always" can be kept safe here (the helper service); otherwise it is shown disabled and a
    /// stored "Always" works as "If the VPN drops".
    pub always_available: bool,
}

/// What the WFP filters are doing now.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum ProtectionStatus {
    #[default]
    Off,
    /// "If the VPN drops", nothing to hold yet: the block goes up once the tunnel is up.
    Armed,
    /// Filters and tunnel are up.
    Engaged,
    /// Filters without a tunnel: traffic outside the VPN is blocked.
    Blocking,
    /// The filters could not be verified (a failed change and a failed compensation).
    Unconfirmed(Msg),
}

/// Kind of a kill-switch exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ExceptionKind {
    #[default]
    App,
    Ip,
}

/// A program or address allowed past the kill switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionView {
    pub id: String,
    pub kind: ExceptionKind,
    /// Canonical exe path or network (`192.0.2.0/24`).
    pub value: String,
    pub label: String,
    /// A very wide network (IPv4 prefix < 8, IPv6 < 16): warned, not refused.
    pub broad: bool,
}

/// An executable chosen in the open dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickedApp {
    pub path: String,
    /// File name without `.exe`.
    pub name: String,
}

// ── Rotation ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RotationOrder {
    #[default]
    Sequential,
    Random,
}

/// Rotation configuration and the servers it can use.
#[derive(Debug, Clone, PartialEq)]
pub struct RotationView {
    pub enabled: bool,
    pub interval_minutes: u32,
    pub order: RotationOrder,
    pub profile_ids: Vec<String>,
    pub current_profile_id: Option<String>,
    pub next_rotation_at: Option<UnixMs>,
    pub servers: Vec<RotationServer>,
}

impl Default for RotationView {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_minutes: 30,
            order: RotationOrder::Sequential,
            profile_ids: Vec::new(),
            current_profile_id: None,
            next_rotation_at: None,
            servers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationServer {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub country: Option<String>,
    pub status: ServerStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ServerStatus {
    Online,
    Offline,
    #[default]
    Unknown,
}

/// Rotation fields set one control at a time (the profile list has its own call).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RotationPatch {
    pub enabled: Option<bool>,
    pub interval_minutes: Option<u32>,
    pub order: Option<RotationOrder>,
}

/// What «Ротировать сейчас» did.
#[derive(Debug, Clone, PartialEq)]
pub enum RotationOutcome {
    Rotated {
        profile_id: String,
    },
    /// No Direct VPN session, or no other server to go to.
    NothingToRotate,
    NoProfiles,
    /// No listed server is reachable.
    NoneAvailable,
    Failed {
        reason: Msg,
        restored_previous: bool,
    },
}

// ── DNS ──────────────────────────────────────────────────────────────────────

/// Transport of a DNS address (derived from the address itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsKind {
    #[default]
    Plain,
    Doh,
    Dot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsProfileView {
    pub id: String,
    pub name: String,
    pub address: String,
    pub kind: DnsKind,
    pub builtin: bool,
}

/// DNS profiles and the choice; `active: None` is the explicit automatic entry
/// (DoH through the VPN).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DnsView {
    pub profiles: Vec<DnsProfileView>,
    pub active: Option<String>,
}

// ── Domain rules ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DomainAction {
    #[default]
    Vpn,
    Direct,
    Block,
}

impl DomainAction {
    pub const ALL: [DomainAction; 3] =
        [DomainAction::Vpn, DomainAction::Direct, DomainAction::Block];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRuleView {
    pub id: String,
    pub pattern: String,
    pub action: DomainAction,
    /// Connections whose host matched the pattern.
    pub hits: u64,
}

/// User domain rules in priority order (first = checked first).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DomainsView {
    pub rules: Vec<DomainRuleView>,
    /// Smart RU is on (its rules sit between the user's block and direct/VPN rules).
    pub smart_ru: bool,
}

/// A domain list file read and checked, waiting for the user's action choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainImportPreview {
    pub file_name: String,
    /// Valid domains that are not in the list yet.
    pub new_rules: u32,
    pub duplicates: u32,
    pub invalid: u32,
    /// Domains beyond the rule limit (not imported).
    pub over_limit: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainImportReport {
    pub added: u32,
}

// ── Notifications ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotifyEvent {
    VpnConnect,
    VpnDisconnect,
    LeakDetected,
    ProfileRotation,
    ScheduleTriggered,
    ConnectionError,
}

impl NotifyEvent {
    pub const ALL: [NotifyEvent; 6] = [
        NotifyEvent::VpnConnect,
        NotifyEvent::VpnDisconnect,
        NotifyEvent::LeakDetected,
        NotifyEvent::ProfileRotation,
        NotifyEvent::ScheduleTriggered,
        NotifyEvent::ConnectionError,
    ];

    /// Key of the old catalog label `notifications.<key>`.
    pub const fn key(self) -> &'static str {
        match self {
            NotifyEvent::VpnConnect => "vpnConnect",
            NotifyEvent::VpnDisconnect => "vpnDisconnect",
            NotifyEvent::LeakDetected => "leakDetected",
            NotifyEvent::ProfileRotation => "profileRotation",
            NotifyEvent::ScheduleTriggered => "scheduleTriggered",
            NotifyEvent::ConnectionError => "connectionError",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NotifyMethod {
    #[default]
    System,
    InApp,
    Both,
}

/// Whether Windows lets the app show notifications.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum OsNotifications {
    #[default]
    Unknown,
    Allowed,
    Blocked,
    /// The registry could not be read.
    CheckFailed(Msg),
}

#[derive(Debug, Clone, PartialEq)]
pub struct NotificationsView {
    /// Master switch (old «Уведомления Windows» row).
    pub enabled: bool,
    /// Per event, in [`NotifyEvent::ALL`] order.
    pub events: [bool; 6],
    pub method: NotifyMethod,
    pub sound: bool,
    pub os: OsNotifications,
}

impl Default for NotificationsView {
    fn default() -> Self {
        Self {
            enabled: true,
            events: [true; 6],
            method: NotifyMethod::System,
            sound: true,
            os: OsNotifications::Unknown,
        }
    }
}

impl NotificationsView {
    pub fn event(&self, event: NotifyEvent) -> bool {
        self.events[event as usize]
    }
}

/// One notification control changed (instant apply, one field per call: no lost updates).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationChange {
    Enabled(bool),
    Event(NotifyEvent, bool),
    Method(NotifyMethod),
    Sound(bool),
}

/// Result of «Снять блокировку Windows».
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResetReport {
    pub cleared: u32,
    /// Canonical reasons of the entries that could not be reset.
    pub errors: Vec<Msg>,
}
