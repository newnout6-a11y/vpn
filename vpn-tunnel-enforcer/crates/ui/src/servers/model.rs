//! View models of the Servers page: display data only (never keys, URIs or subscription URLs)
//! and no Dioxus types. The app fills them from the profiles / servers / probes stores.
use std::net::IpAddr;
use std::num::NonZeroU32;

use vpnte_base::Msg;
use vpnte_base::types::{ClientDevice, Engine, EnginePref, UnixMs};

/// Id of the synthetic group that holds every server while the store has no groups at all.
pub const VIRTUAL_ALL_GROUP: &str = "__virtual_all__";

/// Persisted result of the last latency ping of a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnlineStatus {
    Online,
    Offline,
    #[default]
    Unknown,
}

/// Transport camouflage of a key, computed by the backend from the stored profile. A display
/// hint, never evidence that the key can be dialled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stealth {
    Ech,
    Reality,
    Naive,
    Obfs,
    Utls,
    Tls,
    Plain,
}

/// Why a key-health check found a key dead (backend codes `auth-failed`, `hy2-udp-blocked`, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyHealthReason {
    AuthFailed,
    TlsFailed,
    Timeout,
    ConfigFailed,
    HandshakeFailed,
    NoOutbound,
    Hy2AuthFailed,
    Hy2UdpBlocked,
    Hy2TlsFailed,
    Hy2ConfigFailed,
    Hy2HandshakeFailed,
    /// Not a key fault: the chosen engine cannot run the key (an engine verdict, shown neutral).
    EngineSetting,
    /// A code this build does not know: shown raw.
    Other(String),
}

impl KeyHealthReason {
    const CODES: [(&'static str, KeyHealthReason); 12] = [
        ("auth-failed", KeyHealthReason::AuthFailed),
        ("tls-failed", KeyHealthReason::TlsFailed),
        ("timeout", KeyHealthReason::Timeout),
        ("config-failed", KeyHealthReason::ConfigFailed),
        ("handshake-failed", KeyHealthReason::HandshakeFailed),
        ("no-outbound", KeyHealthReason::NoOutbound),
        ("hy2-auth-failed", KeyHealthReason::Hy2AuthFailed),
        ("hy2-udp-blocked", KeyHealthReason::Hy2UdpBlocked),
        ("hy2-tls-failed", KeyHealthReason::Hy2TlsFailed),
        ("hy2-config-failed", KeyHealthReason::Hy2ConfigFailed),
        ("hy2-handshake-failed", KeyHealthReason::Hy2HandshakeFailed),
        ("engine-setting", KeyHealthReason::EngineSetting),
    ];

    /// Parses a backend reason code.
    pub fn from_code(code: &str) -> Self {
        Self::CODES.iter().find(|(c, _)| *c == code).map_or_else(
            || KeyHealthReason::Other(code.to_owned()),
            |(_, r)| r.clone(),
        )
    }

    /// The backend code (the suffix of the `servers.health.reasons.*` key).
    pub fn code(&self) -> &str {
        match self {
            KeyHealthReason::Other(code) => code,
            known => Self::CODES
                .iter()
                .find(|(_, r)| r == known)
                .map_or("", |(c, _)| c),
        }
    }
}

/// Verdict of a key-health check (is the key alive, not how far away the server is).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyHealth {
    pub online: bool,
    /// Health latency: a different metric from the ping; never shown as the ping.
    pub latency_ms: Option<u32>,
    pub reason: Option<KeyHealthReason>,
    pub checked_at: UnixMs,
}

/// What a group health check measured: the keys it checked, and how many it could not check now
/// (their server's handshake budget was used up, or the probe could not start). Those keep
/// their previous state; they are counted, never shown as dead.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HealthReport {
    pub results: Vec<(String, KeyHealth)>,
    pub not_checked: u32,
}

/// What a server check concluded under the RU network discipline (Nov 2026): a frozen or banned
/// server needs another server, not another port or retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerdictKind {
    /// The whole test transfer came through.
    Healthy,
    /// Data stopped after ~16 KB without a reset: the network throttles the server's hosting.
    Frozen,
    /// Data stopped outside the freeze band.
    Stalled,
    /// TCP connects, the TLS / REALITY handshake does not pass.
    HandshakeFailed,
    KeyRejected,
    /// Ping answers, TCP and UDP are dropped: the address is banned in this network.
    IpBanned,
    UdpBlocked,
    Offline,
    /// The server's handshake budget left it unchecked.
    Deferred,
    /// The evidence names no cause.
    NotVerified,
    /// The address answers, the key's port refuses the connection: the server is stopped or moved.
    Refused,
}

/// The step a verdict suggests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerdictAdvice {
    SwitchServer,
    TryAnotherFingerprint,
    PreferTcpTransport,
    RetryLater,
}

/// The classifier's verdict on a server with its advice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckVerdict {
    pub kind: VerdictKind,
    pub advice: Option<VerdictAdvice>,
    /// The verdict and the advice as full sentences (hover text).
    pub detail: Msg,
    pub advice_detail: Option<Msg>,
    pub checked_at: UnixMs,
}

/// Why a server is archived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchiveReason {
    /// The provider stopped publishing it: still selectable by hand (with a warning), never by
    /// automation or as an external proxy.
    Provider,
    /// The user removed it (soft delete): not selectable until restored.
    User,
}

/// Archive state of a server: it is purged for good at `purge_at` (30 days) unless restored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Archive {
    pub reason: ArchiveReason,
    pub at: UnixMs,
    pub purge_at: UnixMs,
}

/// One saved server (a redacted profile summary).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerView {
    pub id: String,
    pub name: String,
    /// Lower-case protocol: `vless`, `hysteria2`, `shadowsocks`, …
    pub protocol: String,
    pub host: String,
    pub port: u16,
    /// Latest DNS answer for `host` (the entry bridge), for display.
    pub resolved_ip: Option<IpAddr>,
    /// Best known exit country, ISO 3166-1 alpha-2 upper case.
    pub country: Option<String>,
    /// Verified exit IP (country check or probe); differs from `resolved_ip` behind relays.
    pub exit_ip: Option<IpAddr>,
    pub device: ClientDevice,
    /// The server's own engine (`Auto` = the setting in Settings).
    pub engine: EnginePref,
    /// What a connect would run under the current settings (`None`: the key cannot be opened).
    pub engine_plan: Option<EnginePlan>,
    /// uTLS fingerprint the stored profile pins (`None`: the device default applies).
    pub fingerprint: Option<String>,
    /// What is wrong with the pinned fingerprint (current REALITY servers refuse it, it fails
    /// everywhere, the engine does not know it); `None` = nothing to say.
    pub fingerprint_warning: Option<Msg>,
    /// The profile carries a full engine outbound (the «| JSON» suffix of Happ-style labels).
    pub has_outbound: bool,
    pub stealth: Option<Stealth>,
    /// Persisted ping (measured while the tunnel was down).
    pub ping_ms: Option<u32>,
    pub status: OnlineStatus,
    /// Persisted key-health verdict.
    pub health: Option<KeyHealth>,
    /// Persisted classifier verdict (never older than `health`: an outdated one is not sent).
    pub verdict: Option<CheckVerdict>,
    pub group_id: Option<String>,
    pub last_seen_in_subscription_at: Option<UnixMs>,
    /// Archived rows stay visible (and restorable) until they are purged.
    pub archived: Option<Archive>,
    /// `false`: switched off by the user; cannot be selected or started as a proxy.
    pub enabled: bool,
    /// Its provider keeps the config hidden: no key view, copy, save or export (protocol, engine,
    /// TLS / REALITY and the protection state stay visible).
    pub config_hidden: bool,
    /// What says it passes a mobile whitelist (`None`: nothing does): the row's badge.
    pub whitelist: Option<WhitelistReady>,
}

/// Why a server counts as passing a mobile whitelist (RU mobile networks): automatic picks try
/// such servers first on a whitelisted network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WhitelistReady {
    /// The user marked it «Работает в белых списках».
    pub marked: bool,
    /// When it last carried data while the network was in whitelist mode.
    pub worked_at: Option<UnixMs>,
}

/// The engine a connect would use for a server, as the backend decides it: never a silent
/// choice, so the row says which engine and why, or why none can.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnginePlan {
    /// `engine` runs the server; `reason` is the short caption («REALITY», «выбран вручную»).
    Runs { engine: Engine, reason: Msg },
    /// The chosen engine cannot run it: the full sentence with the way out.
    Refused(Msg),
}

/// Where a group's servers come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GroupSource {
    Subscription,
    #[default]
    Manual,
}

/// Result of the last subscription refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GroupStatus {
    Active,
    /// The provider answered but the feed is gone or empty; the keys are kept (they often work).
    Expired,
    /// Network error: usually the user is offline.
    Unreachable,
    #[default]
    Unknown,
}

/// Why a subscription refresh failed (typed, replaces the old Russian sentinel string, S-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// The feed answered with no profiles.
    Empty,
    /// The feed answered with nothing this app supports.
    Invalid,
    Http(u16),
    Network,
    Tls,
    Timeout,
    /// Not requested: a Mihomo provider URL that is `http` under an `https` subscription, or
    /// points into a private network.
    Refused,
    /// The provider serves the subscription only to devices that send their HWID.
    HwidRequired,
    /// Every device slot of the subscription is taken.
    DeviceLimit,
}

/// One server group (a subscription or the manual key ring).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupView {
    pub id: String,
    pub name: String,
    pub source: GroupSource,
    pub status: GroupStatus,
    pub imported_at: UnixMs,
    /// Last successful refresh.
    pub last_fetched_at: Option<UnixMs>,
    pub last_fetch_attempt_at: Option<UnixMs>,
    /// Set while the last refresh failed; cleared by a successful one.
    pub last_fetch_error: Option<FetchError>,
    pub traffic_used: Option<u64>,
    pub traffic_total: Option<u64>,
    pub expires_at: Option<UnixMs>,
    /// Provider panel link (provider-controlled text: the page opens only `http(s)` URLs).
    pub web_page_url: Option<String>,
    /// User override of the auto-refresh interval; `None` = provider / default interval.
    pub refresh_minutes: Option<NonZeroU32>,
    /// Provider support link (`support-url`; opened only as an `http(s)` URL, on a click).
    pub support_url: Option<String>,
    /// Provider announcement (`announce`, at most 200 chars): plain text, links are never opened
    /// by themselves.
    pub announce: Option<String>,
    /// The provider's refresh interval in hours (`profile-update-interval`).
    pub provider_refresh_hours: Option<u32>,
    /// The subscription sends the device HWID.
    pub send_hwid: bool,
    /// The device ID (HWID) the subscription sends when the HWID is on (`None`: manual group).
    /// An identifier the user may give the provider's support, not a credential.
    pub device_id: Option<String>,
    /// `device_id` is the subscription's own (the user reset it), not this PC's.
    pub own_device_id: bool,
    /// Names of the user's extra request headers (values are never sent to the page).
    pub header_names: Vec<String>,
    /// When the provider moved the subscription to a new address.
    pub moved_at: Option<UnixMs>,
    /// The host of the subscription URL (named in the move note: the user sees where it went).
    pub host: Option<String>,
    /// The provider keeps the configs of this group's servers hidden (`hide-settings`).
    pub settings_hidden: bool,
}

/// Everything the Servers page renders from the stores, pushed on every change.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServersView {
    /// `false` until the first store read finished (the page shows a loading line).
    pub loaded: bool,
    /// Servers in store order.
    pub servers: Vec<ServerView>,
    pub groups: Vec<GroupView>,
    /// The committed selection (what a connect would use).
    pub active_id: Option<String>,
    /// A server switch in flight; the marker moves only when it finishes.
    pub switching_to: Option<String>,
    /// Our tunnel is up (pings then go around it; the connected server is `active_id`).
    pub tunnel_running: bool,
    /// A connect / disconnect is in flight: no switch may start.
    pub tunnel_busy: bool,
    /// Another VPN's adapter is up: direct pings are unreliable.
    pub foreign_vpn: bool,
    /// The user turned third-party geo lookups off (privacy settings).
    pub geo_lookup_disabled: bool,
}

/// Where an import lands.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AddTarget {
    /// A new subscription gets its own group, a known one is refreshed, plain keys go to the
    /// manual key ring.
    #[default]
    Auto,
    Group(String),
}

/// What an import did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImportReport {
    pub group_name: String,
    /// The input was a subscription URL (fetched as `device`).
    pub subscription: bool,
    pub added: u32,
    pub updated: u32,
    pub unchanged: u32,
    /// Lines that could not be imported (their text is never echoed: it may hold a key).
    pub skipped: Vec<SkippedLine>,
    /// Mihomo providers the subscription named and the app fetched.
    pub providers: Vec<ProviderLine>,
}

/// One Mihomo provider of an imported subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderLine {
    pub name: String,
    /// New servers it added.
    pub servers: u32,
    /// Why it gave nothing.
    pub error: Option<FetchError>,
}

/// Request settings of a new subscription (the add dialog).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SubscriptionRequest {
    /// Send the device HWID (off by default; HWID-bound panels need it).
    pub send_hwid: bool,
    /// Extra request headers, one `Name: value` per line.
    pub headers: String,
    /// The text came from outside (a link Windows handed over, a QR code) and the user did not
    /// edit it: a subscription it names must not lead into the local network.
    pub from_outside: bool,
}

/// One input line that was not imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedLine {
    /// 1-based line number in the pasted text.
    pub line: u32,
    pub reason: Msg,
}

/// How a server switch ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectOutcome {
    Switched,
    /// Cancelled by the user (here or on the start page): silent.
    Cancelled,
}

/// Result of an exit-country check through the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CountryCheck {
    /// ISO 3166-1 alpha-2 code of the exit.
    Verified(String),
    /// Third-party geo lookups are off in the privacy settings.
    GeoDisabled,
    /// The lookup did not answer.
    Failed,
}

/// A bulk export written to a file the user picked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportReport {
    /// Display path of the written file.
    pub path: String,
    pub exported: u32,
    pub skipped: u32,
    /// Servers left out because their provider hides the configs.
    pub hidden: u32,
}

/// Outcome of starting external loopback proxies for servers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProxyStartReport {
    pub started: Vec<StartedProxy>,
    /// Servers already bound to a proxy slot.
    pub already_running: Vec<String>,
    pub skipped: Vec<(String, ProxySkip)>,
    pub failed: Vec<(String, Msg)>,
}

/// A proxy slot that was started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedProxy {
    pub profile_id: String,
    pub slot: u16,
    /// `127.0.0.1:port` (credentials are never part of the view).
    pub listen: Option<String>,
}

/// Why a server was not started as a proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxySkip {
    /// It is the main VPN's server.
    ActiveVpn,
    /// Removed from its subscription, switched off or without a connection config.
    Unavailable,
}

/// Outcome of a subscription refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    Refreshed {
        added: u32,
        updated: u32,
        removed: u32,
        /// The provider says the subscription expired (keys kept).
        expired: bool,
    },
    Failed(FetchError),
}

/// Passive facts about a server's endpoint (DNS, ASN, TCP latency to its own port). Never a TLS
/// or HTTP request to the endpoint: a ClientHello with a VPN front's SNI gets the IP throttled by
/// DPI boxes for minutes (users reported "the diagnostics page killed my internet").
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProbeReport {
    pub resolved_ips: Vec<IpAddr>,
    pub reverse_dns: Vec<String>,
    pub asn: Option<AsnInfo>,
    /// `None` while our tunnel runs: TCP connects would measure the tunnel, not the server.
    pub latency: Option<LatencyStats>,
    /// The server's own port when it accepted a TCP connect (no port fan: a DPI signal).
    pub open_ports: Vec<OpenPort>,
}

/// Autonomous system of an address.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsnInfo {
    pub asn: String,
    pub org: String,
    pub network: Option<String>,
    pub country: Option<String>,
}

/// TCP connect latency samples, ms.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LatencyStats {
    pub min: u32,
    pub avg: u32,
    pub median: u32,
    pub max: u32,
    pub jitter: u32,
    /// Failed connects, 0..=1.
    pub loss: f64,
    pub samples: Vec<u32>,
    pub attempted: Option<u32>,
    pub succeeded: Option<u32>,
}

/// An open TCP port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPort {
    pub port: u16,
    pub service: Option<String>,
}

/// Geolocation of a server's resolved address (cached by the backend; `None` when lookups are
/// off in the privacy settings).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GeoInfo {
    pub ip: Option<IpAddr>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub org: Option<String>,
    pub timezone: Option<String>,
}

/// A server's TLS tricks as the detail editor offers them (item 18): cutting the TLS
/// ClientHello so DPI cannot read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TricksChoice {
    /// The app default, even over the provider's own value: «Сильно» while stealth or the
    /// adaptive bypass's TLS compatibility is on, none otherwise.
    Default,
    Off,
    /// «Мягко»: the hello in several TLS records.
    Soft,
    /// «Сильно»: the records also go out as separate TCP pieces, 100-200 B, 10-20 ms apart.
    Strong,
    /// The provider's own split (with or without the record split); picking a preset replaces
    /// it, picking it again follows the provider.
    Custom {
        record: bool,
        split: TricksSplit,
    },
}

/// A TCP split of the hello: piece length in bytes and the pause in ms, as `(min, max)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TricksSplit {
    pub len: (u16, u16),
    pub interval_ms: (u16, u16),
}

/// What the detail editor reads for one server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TricksView {
    pub choice: TricksChoice,
    /// Stealth or adaptive TLS compatibility is on, so `Default` means «Сильно».
    pub default_strong: bool,
    /// The key's own split (a link's `fragment=`, a provider's header): «Как у провайдера» stays
    /// in the list after another pick, and picking it follows the provider again (twire-b1).
    pub provider: Option<TricksChoice>,
}
