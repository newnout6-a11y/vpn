//! What lists render: rows and groups without secrets, plus the memory-only pings.
use vpnte_base::Msg;
use vpnte_base::types::{ClientDevice, EnginePref, UnixMs};
use vpnte_profiles::countries::Iso2;
use vpnte_profiles::model::SubscriptionMeta;
use vpnte_profiles::text::Controls;

use super::{
    Archived, FetchState, GroupId, GroupKind, GroupStatus, HealthRecord, Origin, ProfileId,
    ServerGroup, ServerRow,
};
use crate::subscription::header_names;

/// A memory-only ping result (pings are never persisted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ping {
    /// Round trip in ms; `None`: the server did not answer.
    pub rtt_ms: Option<u32>,
    pub at: UnixMs,
}

/// A row as lists show it: no secrets.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerSummary {
    pub id: ProfileId,
    pub group_id: GroupId,
    pub origin: Origin,
    pub name: String,
    pub protocol: String,
    pub server: String,
    pub port: u16,
    pub device: ClientDevice,
    /// The server's own engine (`Auto` = the setting).
    pub engine: EnginePref,
    /// Verified country, else the one the name claims.
    pub country: Option<Iso2>,
    pub country_verified: bool,
    pub missing_since: Option<UnixMs>,
    pub archived: Option<Archived>,
    pub purge_at: Option<UnixMs>,
    pub health: Option<HealthRecord>,
    pub ping: Option<Ping>,
    /// The key cannot be decrypted under this Windows account (re-import needed).
    pub locked: bool,
    pub selected: bool,
}

impl ServerSummary {
    /// The summary of `row`.
    pub fn of(row: &ServerRow, ping: Option<Ping>, selected: bool) -> Self {
        Self {
            id: row.id.clone(),
            group_id: row.group_id.clone(),
            origin: row.origin,
            name: row.name.clone(),
            protocol: row.protocol.clone(),
            server: row.server.clone(),
            port: row.port,
            device: row.device,
            engine: row.engine,
            country: row.display_country(),
            country_verified: row.country.is_some(),
            missing_since: row.missing_since,
            archived: row.archived,
            purge_at: row.purge_at(),
            health: row.health,
            ping,
            locked: row.is_locked(),
            selected,
        }
    }
}

/// A group as lists show it: no secrets (the subscription URL is reduced to its host).
#[derive(Debug, Clone, PartialEq)]
pub struct GroupSummary {
    pub id: GroupId,
    /// Editable name; empty = the default name ([`GroupSummary::title`] renders either).
    pub name: String,
    pub title: Msg,
    pub manual: bool,
    pub device: Option<ClientDevice>,
    pub host: Option<String>,
    /// The subscription URL cannot be decrypted under this Windows account (refresh impossible).
    pub url_locked: bool,
    pub status: GroupStatus,
    pub imported_at: UnixMs,
    pub fetch: FetchState,
    pub info: SubscriptionMeta,
    pub refresh_override_min: Option<u16>,
    /// Rows that are not archived / archived.
    pub servers: usize,
    pub archived: usize,
    /// The group sends the device HWID (see [`ServerGroup::send_hwid`]).
    pub send_hwid: bool,
    /// Names of the user's extra request headers (the values may be tokens: never here).
    pub header_names: Vec<String>,
    /// When the provider last moved the subscription to a new URL.
    pub moved_at: Option<UnixMs>,
    /// The provider's controls (`hide-settings`, `routing`, autoconnect).
    pub controls: Controls,
    /// The group's own device ID (the user reset it); `None` = this PC's ID. Not a credential.
    pub own_hwid: Option<String>,
    /// The provider's words when its last answer was placeholders instead of servers
    /// ([`crate::model::FetchNote::said`]; filled from the document, `None` here).
    pub said: Option<String>,
}

impl GroupSummary {
    /// The summary of `group` at `now`; `rows` are the rows of the document. `own_hwid` comes
    /// from the document ([`crate::model::ServersDoc::device_id`]), `None` here.
    pub fn of(group: &ServerGroup, rows: &[ServerRow], now: UnixMs) -> Self {
        let mine = || rows.iter().filter(|r| r.group_id == group.id);
        let archived = mine().filter(|r| r.archived.is_some()).count();
        let header_names = group
            .headers
            .as_ref()
            .and_then(|h| h.expose())
            .map(header_names)
            .unwrap_or_default();
        Self {
            id: group.id.clone(),
            name: group.name.clone(),
            title: group.title(),
            manual: group.is_manual(),
            device: group.device(),
            host: group.url().and_then(|u| u.host_str().map(str::to_owned)),
            url_locked: matches!(&group.kind, GroupKind::Subscription { url, .. } if url.is_locked()),
            status: group.status(now),
            imported_at: group.imported_at,
            fetch: group.fetch.clone(),
            info: group.info.clone(),
            refresh_override_min: group.refresh_override_min,
            servers: mine().count() - archived,
            archived,
            send_hwid: group.send_hwid,
            header_names,
            moved_at: group.moved_at,
            controls: group.controls.clone(),
            own_hwid: None,
            said: None,
        }
    }
}

/// Everything a server list renders.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ServersView {
    pub groups: Vec<GroupSummary>,
    pub servers: Vec<ServerSummary>,
    /// The server a connection would use, see [`crate::store::Servers::active`].
    pub active: Option<ProfileId>,
    /// True when `active` is a fallback, not the user's selection.
    pub fallback: bool,
    /// Banner text when `profiles.json` is read-only or was set aside.
    pub notice: Option<Msg>,
}
