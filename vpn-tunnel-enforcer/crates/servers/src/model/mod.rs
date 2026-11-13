//! The persisted server list (`profiles.json`): groups, rows and the secret-free summaries the UI
//! renders. A row keeps its typed [`Profile`](vpnte_profiles::model::Profile) as JSON inside a
//! DPAPI [`Secret`]; the few fields a list or a ping needs (name, protocol, host, port) are plain
//! copies, so a view never opens keys.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use vpnte_base::Msg;
use vpnte_base::types::{ClientDevice, UnixMs};
use vpnte_core::secret::Secret;
use vpnte_core::store::Document;
use vpnte_profiles::model::SubscriptionMeta;
use vpnte_profiles::text::Controls;

use crate::common::http_url;

pub(crate) mod lenient;
mod row;
mod summary;
#[cfg(test)]
pub(crate) mod tests;

pub use row::{
    ArchiveReason, Archived, CountrySource, HealthReason, HealthRecord, Origin, ServerReaction,
    ServerRow, ServerVerdict, VerdictRecord, VerifiedCountry,
};
pub use summary::{GroupSummary, Ping, ServerSummary, ServersView};

/// How long an archived row is kept before it is purged for good (ТЗ т.3 §3.2.3, AT-04-010).
pub const ARCHIVE_TTL_MS: UnixMs = 30 * 24 * 60 * 60 * 1000;
/// Longest group name, in characters.
pub const GROUP_NAME_MAX_CHARS: usize = 60;
/// Accepted user override of a subscription's refresh interval, in minutes.
pub const REFRESH_OVERRIDE_MIN: std::ops::RangeInclusive<u16> = 1..=1440;

/// Id of a server row. Electron ids (UUID strings) are kept as they are on import, because other
/// documents (rotation, schedules) refer to them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProfileId(pub String);

/// Id of a group (same rules as [`ProfileId`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GroupId(pub String);

macro_rules! string_id {
    ($t:ident) => {
        impl $t {
            /// A fresh random id (UUID v4).
            pub fn random() -> Self {
                Self(uuid::Uuid::new_v4().to_string())
            }
            /// The id text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl From<&str> for $t {
            fn from(id: &str) -> Self {
                Self(id.to_owned())
            }
        }
        impl From<String> for $t {
            fn from(id: String) -> Self {
                Self(id)
            }
        }
    };
}
string_id!(ProfileId);
string_id!(GroupId);

/// The persisted document (`profiles.json`, storage spec §6.1).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServersDoc {
    /// The user's selection; it is never cleared by a refresh (S-37).
    #[serde(default)]
    pub active_profile_id: Option<ProfileId>,
    #[serde(default)]
    pub groups: Vec<ServerGroup>,
    #[serde(default)]
    pub profiles: Vec<ServerRow>,
    /// Device IDs (HWIDs) the user reset, per subscription group: a group without one sends
    /// this PC's ID. Kept here, not on the group, so a reset never changes the group's shape.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub device_ids: BTreeMap<GroupId, String>,
    /// Subscription groups added from a link (a deep link, a QR code, a handed-over link): every
    /// refresh keeps them out of the local network as their add did (phones-a11, fix-ks b2).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub linked: BTreeSet<GroupId>,
}

impl Document for ServersDoc {
    const FILE: &'static str = "profiles.json";
    const VERSION: u32 = 1;
    const HOLDS_SECRETS: bool = true;
}

impl ServersDoc {
    /// The group with `id`.
    pub fn group(&self, id: &GroupId) -> Option<&ServerGroup> {
        self.groups.iter().find(|g| &g.id == id)
    }
    /// Mutable access to the group with `id`.
    pub fn group_mut(&mut self, id: &GroupId) -> Option<&mut ServerGroup> {
        self.groups.iter_mut().find(|g| &g.id == id)
    }
    /// The group `id` was added from a link: its requests never reach the local network.
    pub fn linked(&self, id: &GroupId) -> bool {
        self.linked.contains(id)
    }
    /// The device ID the user reset for the group `id` (`None`: it sends this PC's ID).
    pub fn device_id(&self, id: &GroupId) -> Option<&str> {
        self.device_ids.get(id).map(String::as_str)
    }
    /// The row with `id`.
    pub fn row(&self, id: &ProfileId) -> Option<&ServerRow> {
        self.profiles.iter().find(|r| &r.id == id)
    }
    /// The provider of `row` asked to keep its config hidden (`hide-settings`): its group does,
    /// or the key carried the request out of the provider's group ([`ServerRow::hidden`]).
    pub fn hides(&self, row: &ServerRow) -> bool {
        row.hidden
            || self
                .group(&row.group_id)
                .is_some_and(ServerGroup::hides_settings)
    }
    /// Mutable access to the row with `id`.
    pub fn row_mut(&mut self, id: &ProfileId) -> Option<&mut ServerRow> {
        self.profiles.iter_mut().find(|r| &r.id == id)
    }
    /// The manual-keys group (a singleton found by kind, never by name: S-19).
    pub fn manual_group(&self) -> Option<&ServerGroup> {
        self.groups.iter().find(|g| g.is_manual())
    }
    /// The subscription group of `(url, device)`: the group key (S-05).
    pub fn subscription_group(&self, url: &url::Url, device: ClientDevice) -> Option<&ServerGroup> {
        self.groups.iter().find(|g| match &g.kind {
            GroupKind::Subscription { url: u, device: d } => {
                *d == device && u.expose().is_some_and(|text| text == url.as_str())
            }
            GroupKind::Manual => false,
        })
    }
    /// Id of the manual-keys group, created (appended) when missing.
    pub fn ensure_manual_group(&mut self, now: UnixMs) -> GroupId {
        if let Some(group) = self.manual_group() {
            return group.id.clone();
        }
        let group = ServerGroup::manual(GroupId::random(), now);
        let id = group.id.clone();
        self.groups.push(group);
        id
    }
}

/// One group of the list: the manual keys, or one subscription (URL + device).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerGroup {
    pub id: GroupId,
    /// User or provider name, at most 60 chars; empty = the default name of the kind.
    #[serde(default)]
    pub name: String,
    #[serde(flatten)]
    pub kind: GroupKind,
    pub imported_at: UnixMs,
    /// User override of the refresh interval in minutes (`None`: the provider's value or the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_override_min: Option<u16>,
    /// Bookkeeping of the subscription fetches (default for the manual group).
    #[serde(default)]
    pub fetch: FetchState,
    /// Provider metadata from the last successful fetch (traffic, expiry, links).
    #[serde(default)]
    pub info: SubscriptionMeta,
    /// Sends the device HWID (`x-hwid` / `x-device-*`, the HWID in the Happ User-Agent). A group
    /// stored before this switch existed keeps sending it: HWID-bound panels answer an empty list
    /// without it, and a changed value takes a new device slot. New groups start without it.
    #[serde(default = "stored_groups_send_hwid")]
    pub send_hwid: bool,
    /// The user's extra request headers (`Name: value` lines), sealed like the URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<Secret>,
    /// The provider's fallback URL (`fallback-url`), sealed like the URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<Secret>,
    /// When the provider last moved the subscription to a new URL (shown as a note).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moved_at: Option<UnixMs>,
    /// The provider's controls from the last successful fetch (`hide-settings`, `routing`,
    /// autoconnect): stored for the page and for the routing / autoconnect features.
    #[serde(default, skip_serializing_if = "is_default")]
    pub controls: Controls,
}

fn stored_groups_send_hwid() -> bool {
    true
}

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

/// What a group is. The subscription URL is a secret: its path or query is the access token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum GroupKind {
    Manual,
    /// Group key = (canonical URL, device): another device of the same URL is another group (S-05).
    Subscription {
        url: Secret,
        #[serde(deserialize_with = "lenient::or_default")]
        device: ClientDevice,
    },
}

/// Fetch bookkeeping of a subscription group.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FetchState {
    /// Set before any request goes out, so a blocked request does not make the sweep hammer the panel.
    pub last_attempt_at: Option<UnixMs>,
    pub last_success_at: Option<UnixMs>,
    #[serde(deserialize_with = "lenient::option")]
    pub last_outcome: Option<FetchOutcome>,
    /// Profiles in the last successful answer.
    pub last_count: Option<u32>,
}

impl FetchState {
    /// The bookkeeping of a successful fetch at `now` that read `count` profiles.
    pub(crate) fn success(now: UnixMs, count: usize, partial: bool) -> Self {
        Self {
            last_attempt_at: Some(now),
            last_success_at: Some(now),
            last_outcome: Some(FetchOutcome::Ok { partial }),
            last_count: Some(u32::try_from(count).unwrap_or(u32::MAX)),
        }
    }
}

/// Typed result of the last fetch; the group status is derived from it (S-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FetchOutcome {
    /// Profiles were read; `partial`: some entries were skipped, so absence proved nothing.
    Ok {
        partial: bool,
    },
    /// The provider answered with an empty list (the classic "trial over" signal).
    EmptyList,
    /// The panel serves this subscription only to devices that send their HWID (Remnawave's
    /// open scheme: 404 with `x-hwid-not-supported` / `x-hwid-active`, or 403 "Device
    /// fingerprint required").
    HwidRequired,
    /// Every device slot of the subscription is taken (`x-hwid-max-devices-reached`).
    DeviceLimit,
    Unparseable(BodyKind),
    Http(u16),
    Network(NetFail),
    Timeout,
}

/// What an unusable subscription body looked like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BodyKind {
    Html,
    Json,
    Base64,
    Uris,
    Other,
}

/// Transport-level failure class of a fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetFail {
    Dns,
    Connect,
    Tls,
    Proxy,
    Reset,
}

/// Status shown next to a group; derived on read, never stored (S-24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GroupStatus {
    /// Manual group, or a subscription that was never fetched.
    Unknown,
    Active,
    /// The plan date passed, the list came back empty, or the panel answered 404 / 410.
    Expired,
    /// Network failure or timeout.
    Unreachable,
    /// The panel answered, but not with a usable list.
    Failed,
}

impl ServerGroup {
    /// The manual-keys group (default name).
    pub fn manual(id: GroupId, now: UnixMs) -> Self {
        Self {
            id,
            name: String::new(),
            kind: GroupKind::Manual,
            imported_at: now,
            refresh_override_min: None,
            fetch: FetchState::default(),
            info: SubscriptionMeta::default(),
            send_hwid: false,
            headers: None,
            fallback: None,
            moved_at: None,
            controls: Controls::default(),
        }
    }

    /// A new subscription group (`send_hwid` as the user chose; see [`ServerGroup::send_hwid`]).
    pub fn subscription(id: GroupId, url: &url::Url, device: ClientDevice, now: UnixMs) -> Self {
        Self {
            kind: GroupKind::Subscription {
                url: Secret::new(url.as_str()),
                device,
            },
            ..Self::manual(id, now)
        }
    }

    /// The provider asked to keep the configs of this group's servers hidden (`hide-settings`).
    pub fn hides_settings(&self) -> bool {
        !self.is_manual() && self.controls.hides_settings()
    }

    /// True for the manual-keys group.
    pub fn is_manual(&self) -> bool {
        matches!(self.kind, GroupKind::Manual)
    }

    /// The subscription URL; `None` for the manual group, a locked secret or a value that is not
    /// an `http(s)://host` URL (such a group is never fetched, S-41).
    pub fn url(&self) -> Option<url::Url> {
        match &self.kind {
            GroupKind::Subscription { url, .. } => http_url(url.expose()?),
            GroupKind::Manual => None,
        }
    }

    /// Device a subscription is fetched as (`None` for the manual group).
    pub fn device(&self) -> Option<ClientDevice> {
        match self.kind {
            GroupKind::Subscription { device, .. } => Some(device),
            GroupKind::Manual => None,
        }
    }

    /// Title to show: the name, or the default name of the kind when it is empty.
    pub fn title(&self) -> Msg {
        match (self.name.is_empty(), &self.kind) {
            (false, _) => Msg::new("servers.group.title").arg("name", &self.name),
            (true, GroupKind::Manual) => Msg::new("servers.group.manualDefault"),
            (true, GroupKind::Subscription { .. }) => Msg::new("servers.group.subscriptionDefault"),
        }
    }

    /// Status at `now`: a passed plan date wins (old `expireGroupByClock`), then the last outcome.
    pub fn status(&self, now: UnixMs) -> GroupStatus {
        if self.is_manual() {
            return GroupStatus::Unknown;
        }
        if self.info.expires_at.is_some_and(|at| at > 0 && at < now) {
            return GroupStatus::Expired;
        }
        match self.fetch.last_outcome {
            None => GroupStatus::Unknown,
            Some(FetchOutcome::Ok { .. }) => GroupStatus::Active,
            Some(FetchOutcome::EmptyList | FetchOutcome::Http(404 | 410)) => GroupStatus::Expired,
            // Not expired: the panel refused this device and said why.
            Some(
                FetchOutcome::HwidRequired
                | FetchOutcome::DeviceLimit
                | FetchOutcome::Unparseable(_)
                | FetchOutcome::Http(_),
            ) => GroupStatus::Failed,
            Some(FetchOutcome::Network(_) | FetchOutcome::Timeout) => GroupStatus::Unreachable,
        }
    }
}

/// `name` trimmed, whitespace runs collapsed and cut to [`GROUP_NAME_MAX_CHARS`].
pub fn clean_group_name(name: &str) -> String {
    let collapsed = name.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed
        .chars()
        .take(GROUP_NAME_MAX_CHARS)
        .collect::<String>()
        .trim_end()
        .to_owned()
}

/// The host of a URL (subscription or provider web page) as a group name: the automatic name a
/// subscription gets, which a provider title may replace later.
pub(crate) fn host_name(url: &str) -> Option<String> {
    url::Url::parse(url).ok()?.host_str().map(clean_group_name)
}
