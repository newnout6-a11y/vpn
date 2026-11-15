//! Pure presentation rules of the Servers page (no Dioxus): badges, ping / health precedence,
//! removed-from-subscription, grouping and sorting, byte and relative-time formatting.
use std::collections::{HashMap, HashSet};
use std::num::NonZeroU32;
use std::sync::LazyLock;

use jiff::tz::TimeZone;
use vpnte_base::i18n::{Lang, lookup};
use vpnte_base::types::{ClientDevice, Engine, EnginePref, UnixMs};

use super::model::{
    ArchiveReason, EnginePlan, GroupSource, GroupStatus, GroupView, KeyHealth, KeyHealthReason,
    OnlineStatus, ServerView, ServersView, Stealth, VIRTUAL_ALL_GROUP,
};
use crate::widgets::Tone;

/// A server the feed stopped listing at least this long before the group's last refresh counts
/// as removed even before the backend archives it.
pub const STALE_AFTER_MS: i64 = 60_000;
/// Auto-refresh choices in minutes (`None` = provider / default interval).
pub const REFRESH_CHOICES: [u32; 7] = [1, 5, 15, 30, 60, 360, 1440];
/// Group names are capped like the backend does.
pub const GROUP_NAME_MAX: u32 = 60;

/// The four device personas, in menu order.
pub const DEVICES: [ClientDevice; 4] = [
    ClientDevice::Pc,
    ClientDevice::Android,
    ClientDevice::Ios,
    ClientDevice::Mac,
];

/// Product name of a device persona (not translated).
pub fn device_label(device: ClientDevice) -> &'static str {
    match device {
        ClientDevice::Pc => "PC",
        ClientDevice::Android => "Android",
        ClientDevice::Ios => "iOS",
        ClientDevice::Mac => "Mac",
    }
}

/// Product name of an engine (not translated).
pub fn engine_name(engine: Engine) -> &'static str {
    match engine {
        Engine::SingBox => "sing-box",
        Engine::Xray => "Xray",
        #[cfg(feature = "lab")]
        Engine::Mihomo => "mihomo",
    }
}

/// The row menu's per-server engine entries (menu id, choice), in menu order.
#[cfg(not(feature = "lab"))]
pub const ENGINE_ITEMS: [(&str, EnginePref); 3] = [
    ("engine-auto", EnginePref::Auto),
    ("engine-sing-box", EnginePref::SingBox),
    ("engine-xray", EnginePref::Xray),
];

/// Lab build (WP-12): the per-server choice also offers the lab engine mihomo.
#[cfg(feature = "lab")]
pub const ENGINE_ITEMS: [(&str, EnginePref); 4] = [
    ("engine-auto", EnginePref::Auto),
    ("engine-sing-box", EnginePref::SingBox),
    ("engine-xray", EnginePref::Xray),
    ("engine-mihomo", EnginePref::Mihomo),
];

/// The engine choice a row menu id stands for.
pub fn engine_of_item(id: &str) -> Option<EnginePref> {
    ENGINE_ITEMS
        .iter()
        .find(|(item, _)| *item == id)
        .map(|&(_, pref)| pref)
}

/// The uTLS fingerprint a connect sends for `server` («—» for a key without TLS): the provider's
/// pin, else the emitters' default. REALITY servers since Xray 26.9.8 refuse the `android` /
/// `ios` hellos (RU 2026 plan fact 2), so sing-box sends `chrome` for REALITY keys and Xray never
/// sends those two; otherwise the device persona's own browser.
pub fn fingerprint(server: &ServerView) -> String {
    if let Some(pin) = &server.fingerprint {
        return pin.clone();
    }
    if server.stealth == Some(Stealth::Plain) {
        return "—".to_owned();
    }
    let device = match server.device {
        ClientDevice::Android => "android",
        ClientDevice::Ios => "ios",
        ClientDevice::Mac => "safari",
        ClientDevice::Pc => "chrome",
    };
    let refused = matches!(server.device, ClientDevice::Android | ClientDevice::Ios);
    let xray = matches!(
        server.engine_plan,
        Some(EnginePlan::Runs {
            engine: Engine::Xray,
            ..
        })
    );
    let chrome = if xray {
        refused
    } else {
        server.stealth == Some(Stealth::Reality)
    };
    if chrome { "chrome" } else { device }.to_owned()
}

/// Badge of a transport camouflage: fixed label, `ui.servers.stealth.*` key of its explanation,
/// tone (a key without any TLS marker is the one worth a warning).
pub fn stealth_badge(stealth: Stealth) -> (&'static str, &'static str, Tone) {
    match stealth {
        Stealth::Ech => ("ECH", "ui.servers.stealth.ech", Tone::Neutral),
        Stealth::Reality => ("Reality", "ui.servers.stealth.reality", Tone::Neutral),
        Stealth::Naive => ("Naive", "ui.servers.stealth.naive", Tone::Neutral),
        Stealth::Obfs => ("OBFS", "ui.servers.stealth.obfs", Tone::Neutral),
        Stealth::Utls => ("uTLS", "ui.servers.stealth.utls", Tone::Neutral),
        Stealth::Tls => ("TLS", "ui.servers.stealth.tls", Tone::Neutral),
        Stealth::Plain => ("Plain", "ui.servers.stealth.plain", Tone::Warn),
    }
}

/// Happ-style type caption: `VLESS | JSON` when the profile carries a full engine outbound.
pub fn happ_type(protocol: &str, has_outbound: bool) -> String {
    let proto = if protocol.is_empty() {
        "UNKNOWN".to_owned()
    } else {
        protocol.to_uppercase()
    };
    if has_outbound {
        format!("{proto} | JSON")
    } else {
        proto
    }
}

/// Transient ping state of a row (this session's direct pings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PingState {
    #[default]
    Unmeasured,
    /// Measuring; the previous value stays visible.
    Measuring {
        last: Option<u32>,
    },
    Done(Option<u32>),
}

impl PingState {
    /// The row's own value (`None` while unmeasured or after no answer).
    pub fn value(self) -> Option<u32> {
        match self {
            PingState::Unmeasured => None,
            PingState::Measuring { last } => last,
            PingState::Done(ms) => ms,
        }
    }

    /// The state while a new ping runs.
    pub fn measuring(self) -> PingState {
        PingState::Measuring { last: self.value() }
    }

    pub fn is_measuring(self) -> bool {
        matches!(self, PingState::Measuring { .. })
    }

    /// A finished direct ping that answered (proves the endpoint is reachable now).
    pub fn fresh_ok(self) -> bool {
        matches!(self, PingState::Done(Some(_)))
    }
}

/// The number in the ping column: a fresh row ping wins over the persisted one; health latency
/// is never shown here (it is a different metric).
pub fn displayed_ping(persisted: Option<u32>, live: PingState) -> Option<u32> {
    live.value().or(persisted)
}

/// The status mark left of the ping, by precedence: fresh direct ping › key health › persisted
/// ping status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowSignal {
    FreshPing,
    Alive,
    /// The chosen engine cannot run the key: not checked, not dead (neutral mark).
    Engine,
    Dead(Option<KeyHealthReason>),
    Online,
    Offline,
    Unknown,
}

/// See [`RowSignal`]; `health` is the effective verdict (this session's, else persisted).
pub fn row_signal(live: PingState, health: Option<&KeyHealth>, status: OnlineStatus) -> RowSignal {
    if live.fresh_ok() {
        return RowSignal::FreshPing;
    }
    match (health, status) {
        (Some(h), _) if h.online => RowSignal::Alive,
        (Some(h), _) if h.reason == Some(KeyHealthReason::EngineSetting) => RowSignal::Engine,
        (Some(h), _) => RowSignal::Dead(h.reason.clone()),
        (None, OnlineStatus::Online) => RowSignal::Online,
        (None, OnlineStatus::Offline) => RowSignal::Offline,
        (None, OnlineStatus::Unknown) => RowSignal::Unknown,
    }
}

/// The feed no longer lists the server: archived by the backend for that reason, or not seen for
/// a minute before the group's last successful refresh. One rule for the row and the detail (D-7).
pub fn is_removed_from_subscription(server: &ServerView, group: Option<&GroupView>) -> bool {
    if server
        .archived
        .is_some_and(|a| a.reason == ArchiveReason::Provider)
    {
        return true;
    }
    match (group, server.last_seen_in_subscription_at) {
        (Some(g), Some(seen)) if g.source == GroupSource::Subscription => g
            .last_fetched_at
            .is_some_and(|fetched| fetched - seen >= STALE_AFTER_MS),
        _ => false,
    }
}

/// The user removed the server (soft delete): it waits for restore or purge.
pub fn is_deleted(server: &ServerView) -> bool {
    server
        .archived
        .is_some_and(|a| a.reason == ArchiveReason::User)
}

/// Why a server cannot be selected (the backend refuses it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unusable {
    /// A provider notice stored as a server by an older build: never a server.
    Placeholder,
    /// Removed by the user: restore it first.
    Deleted,
    Disabled,
}

/// The Select rule shared by the row and the detail (S-22): user-removed and switched-off servers
/// are refused by the backend, so the row says why before the click. A server the provider
/// dropped stays selectable by hand, with a warning (`is_removed_from_subscription`).
pub fn unusable(server: &ServerView) -> Option<Unusable> {
    if server.placeholder {
        Some(Unusable::Placeholder)
    } else if is_deleted(server) {
        Some(Unusable::Deleted)
    } else if !server.enabled {
        Some(Unusable::Disabled)
    } else {
        None
    }
}

/// A server that may run as an external proxy: enabled, not archived, still in its feed.
pub fn proxy_ready(server: &ServerView, group: Option<&GroupView>) -> bool {
    unusable(server).is_none() && !is_removed_from_subscription(server, group)
}

/// Subscription groups first, then the newest import first.
pub fn sort_groups(groups: &mut [GroupView]) {
    groups.sort_by(|a, b| {
        let rank = |g: &GroupView| u8::from(g.source != GroupSource::Subscription);
        rank(a)
            .cmp(&rank(b))
            .then(b.imported_at.cmp(&a.imported_at))
    });
}

/// What a group header stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketKind {
    /// A stored group.
    Real,
    /// Servers point at a group id the store does not have (deleted group, refresh race):
    /// shown under «Восстановленные ключи» so they stay visible and can be cleaned up.
    Recovered,
    /// No groups at all: every server under «Все серверы».
    Virtual,
}

/// One group header and its servers (store order).
#[derive(Debug, Clone, PartialEq)]
pub struct GroupBucket {
    pub kind: BucketKind,
    /// The stored group; `Recovered` / `Virtual` get a synthetic one (manual, unknown status).
    pub group: GroupView,
    pub servers: Vec<ServerView>,
}

/// Group headers in display order with their servers: stored groups (sorted), then recovered
/// orphan ids in order of first appearance, then «all servers» when group-less servers have no
/// group to fall back to. A group-less server falls back to the first manual group.
pub fn buckets(view: &ServersView) -> Vec<GroupBucket> {
    let mut groups = view.groups.clone();
    sort_groups(&mut groups);
    let fallback = view
        .groups
        .iter()
        .find(|g| g.source == GroupSource::Manual)
        .or(view.groups.first())
        .map(|g| g.id.clone());
    let mut out: Vec<GroupBucket> = groups
        .into_iter()
        .map(|group| GroupBucket {
            kind: BucketKind::Real,
            group,
            servers: Vec::new(),
        })
        .collect();
    let mut index: HashMap<String, usize> = out
        .iter()
        .enumerate()
        .map(|(i, b)| (b.group.id.clone(), i))
        .collect();
    for server in &view.servers {
        let (id, kind) = match server.group_id.as_deref() {
            Some(id) if index.contains_key(id) => (id.to_owned(), BucketKind::Real),
            Some(id) => (id.to_owned(), BucketKind::Recovered),
            None => match &fallback {
                Some(id) => (id.clone(), BucketKind::Real),
                None => (VIRTUAL_ALL_GROUP.to_owned(), BucketKind::Virtual),
            },
        };
        let slot = *index.entry(id.clone()).or_insert_with(|| {
            out.push(GroupBucket {
                kind,
                group: GroupView {
                    id,
                    ..GroupView::default()
                },
                servers: Vec::new(),
            });
            out.len() - 1
        });
        out[slot].servers.push(server.clone());
    }
    // The virtual header goes last, after recovered ones that may have been created before it.
    out.sort_by_key(|b| u8::from(b.kind == BucketKind::Virtual));
    out
}

/// Protocol sections of a group: alphabetical by protocol, rows in store order.
pub fn protocol_sections(servers: &[ServerView]) -> Vec<(String, Vec<&ServerView>)> {
    let mut sections: Vec<(String, Vec<&ServerView>)> = Vec::new();
    for server in servers {
        let key = if server.protocol.is_empty() {
            "unknown"
        } else {
            server.protocol.as_str()
        };
        match sections.iter_mut().find(|(k, _)| k == key) {
            Some((_, rows)) => rows.push(server),
            None => sections.push((key.to_owned(), vec![server])),
        }
    }
    sections.sort_by(|a, b| a.0.cmp(&b.0));
    sections
}

/// Tone of a group's status badge.
pub fn group_status_tone(status: GroupStatus) -> Tone {
    match status {
        GroupStatus::Active => Tone::Ok,
        GroupStatus::Expired => Tone::Warn,
        GroupStatus::Unreachable => Tone::Fail,
        GroupStatus::Unknown => Tone::Unknown,
    }
}

/// `ui`/`servers` key of a group's status label.
pub fn group_status_key(status: GroupStatus) -> &'static str {
    match status {
        GroupStatus::Active => "servers.groups.statusActive",
        GroupStatus::Expired => "servers.groups.statusExpired",
        GroupStatus::Unreachable => "servers.groups.statusUnreachable",
        GroupStatus::Unknown => "servers.groups.statusUnknown",
    }
}

/// Traffic quota: whole percent (≤ 100), tone (over the limit → fail, above 80 % → warn) and
/// whether the limit is exceeded.
pub fn traffic(used: u64, total: u64) -> (u8, Tone, bool) {
    if total == 0 {
        return (0, Tone::Neutral, false);
    }
    let pct = ((used as f64 / total as f64) * 100.0).round().min(100.0) as u8;
    let over = used > total;
    let tone = if over {
        Tone::Fail
    } else if pct > 80 {
        Tone::Warn
    } else {
        Tone::Neutral
    };
    (pct, tone, over)
}

/// «5 минут назад» / «in 2 hours»: seconds under a minute, minutes under an hour, hours under a
/// day, else days (rounded), with the words of `ui.servers.when.*`.
pub fn relative_time(ts: UnixMs, now: UnixMs, lang: Lang) -> String {
    const MINUTE: f64 = 60_000.0;
    let diff = (ts - now) as f64;
    let abs = diff.abs();
    let (n, unit) = if abs < MINUTE {
        ((diff / 1000.0).round(), "seconds")
    } else if abs < 60.0 * MINUTE {
        ((diff / MINUTE).round(), "minutes")
    } else if abs < 24.0 * 60.0 * MINUTE {
        ((diff / (60.0 * MINUTE)).round(), "hours")
    } else {
        ((diff / (24.0 * 60.0 * MINUTE)).round(), "days")
    };
    let n = n as i64;
    let key = match (unit, n) {
        ("seconds", 0) => "ui.servers.when.now".to_owned(),
        ("days", -1) => "ui.servers.when.yesterday".to_owned(),
        ("days", 1) => "ui.servers.when.tomorrow".to_owned(),
        (unit, n) if n < 0 => format!("ui.servers.when.{unit}Ago"),
        (unit, _) => format!("ui.servers.when.{unit}In"),
    };
    lookup(lang, &key, &[("count", n.abs().to_string())], None)
}

/// Options of a group's auto-refresh select: auto, the fixed choices, and the stored value when
/// it is none of them (S-12: the select must never show a blank or a wrong value).
pub fn refresh_choices(current: Option<NonZeroU32>) -> Vec<Option<NonZeroU32>> {
    let mut out: Vec<Option<NonZeroU32>> = std::iter::once(None)
        .chain(REFRESH_CHOICES.iter().map(|&m| NonZeroU32::new(m)))
        .collect();
    if let Some(m) = current
        && !REFRESH_CHOICES.contains(&m.get())
    {
        let at = out
            .iter()
            .position(|o| o.is_some_and(|o| o > m))
            .unwrap_or(out.len());
        out.insert(at, Some(m));
    }
    out
}

/// Key and count of a refresh choice label (`refresh5Minutes`, or «every N min» for others).
pub fn refresh_label_key(minutes: Option<NonZeroU32>) -> (&'static str, Option<u32>) {
    match minutes.map(NonZeroU32::get) {
        None => ("servers.groups.refreshAuto", None),
        Some(1) => ("servers.groups.refresh1Minute", None),
        Some(5) => ("servers.groups.refresh5Minutes", None),
        Some(15) => ("servers.groups.refresh15Minutes", None),
        Some(30) => ("servers.groups.refresh30Minutes", None),
        Some(60) => ("servers.groups.refresh1Hour", None),
        Some(360) => ("servers.groups.refresh6Hours", None),
        Some(1440) => ("servers.groups.refresh1Day", None),
        Some(other) => ("ui.servers.group.refreshEvery", Some(other)),
    }
}

/// A provider-controlled link, only when it is plain `http(s)`.
pub fn safe_http_url(url: &str) -> Option<&str> {
    let url = url.trim();
    let lower = url.get(..8).unwrap_or(url).to_ascii_lowercase();
    let ok = (lower.starts_with("https://") && url.len() > 8)
        || (lower.starts_with("http://") && url.len() > 7);
    (ok && !url.chars().any(char::is_whitespace)).then_some(url)
}

/// Header counters: servers that can be used (enabled, not removed) and all of them.
pub fn counts(view: &ServersView) -> (usize, usize) {
    let usable = view
        .servers
        .iter()
        .filter(|s| s.enabled && s.archived.is_none())
        .count();
    (usable, view.servers.len())
}

/// The server's group as stored (none for recovered / virtual buckets).
pub fn group_of<'a>(view: &'a ServersView, server: &ServerView) -> Option<&'a GroupView> {
    let id = server.group_id.as_deref()?;
    view.groups.iter().find(|g| g.id == id)
}

/// Whether the shared stylesheet ships a flag coin for `country` (a `.fi-xx.fis` rule in
/// utilities.css); other countries get a mono code mark of the same size. Read from the
/// embedded sheet, so the list never falls behind the flags that are actually there.
pub fn has_flag(country: &str) -> bool {
    static FLAGS: LazyLock<HashSet<String>> = LazyLock::new(|| {
        let css = crate::assets::file("css/utilities.css")
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .unwrap_or_default();
        css.split(".fi-")
            .skip(1)
            .filter_map(|rule| rule.split_once(".fis"))
            .map(|(code, _)| code)
            .filter(|code| code.len() == 2 && code.bytes().all(|b| b.is_ascii_lowercase()))
            .map(str::to_ascii_uppercase)
            .collect()
    });
    FLAGS.contains(country)
}

/// Date and time of `ts` in the system time zone: `11.11.2026 09:12` (ru), `2026-11-11 09:12`
/// (en); «—» when the timestamp is out of range.
pub fn local_stamp(ts: UnixMs, lang: Lang) -> String {
    stamp_in(ts, lang, &TimeZone::system())
}

fn stamp_in(ts: UnixMs, lang: Lang, tz: &TimeZone) -> String {
    let pattern = match lang {
        Lang::Ru => "%d.%m.%Y %H:%M",
        Lang::En => "%Y-%m-%d %H:%M",
    };
    jiff::Timestamp::from_millisecond(ts).map_or_else(
        |_| "—".to_owned(),
        |at| at.to_zoned(tz.clone()).strftime(pattern).to_string(),
    )
}

#[cfg(test)]
mod tests;
