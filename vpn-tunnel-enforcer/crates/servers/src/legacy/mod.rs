//! One-time import of the Electron server list (servers spec §2.3, storage §2.4 A2-A3). Input: the
//! `server-picker`, `server-groups` and `settings` documents already opened by `vpnte_core::legacy`
//! (secrets replaced by their plaintext, a `{"__vpnteLocked": true}` stand-in or `null`). Ids are
//! kept; nothing under the old data directory is touched. The app adopts the result with
//! [`crate::store::Servers::import_legacy`], then passes [`LegacyReport::direct`] (if any) to
//! `Servers::import_legacy_direct` of the `refresh` module (it may have to fetch a subscription).
use std::collections::{BTreeSet, HashMap, HashSet};

use serde_json::Value;
use vpnte_base::Msg;
use vpnte_base::types::{ClientDevice, UnixMs};
use vpnte_core::legacy::is_locked;
use vpnte_core::secret::Secret;
use vpnte_profiles::model::SubscriptionMeta;

use crate::common::canonical_source;
use crate::model::{
    FetchOutcome, FetchState, GROUP_NAME_MAX_CHARS, GroupId, GroupKind, NetFail, Origin, ProfileId,
    REFRESH_OVERRIDE_MIN, ServerGroup, ServersDoc, clean_group_name, host_name,
};
use rows::{DirectVpnCache, import_row};

mod country;
mod rows;
#[cfg(test)]
mod tests;

/// Old default names that become the default (localised) name.
const OLD_MANUAL_NAMES: [&str; 2] = ["Ручные ключи", "Импортированные"];
const OLD_SUBSCRIPTION_NAME: &str = "Подписка";

/// What the import did, for the app's import report.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LegacyReport {
    pub imported: usize,
    pub groups: usize,
    /// Rows and groups whose secret needs the old app's key (nothing of them was imported).
    pub locked: usize,
    pub skipped: Vec<LegacySkip>,
    /// The old single-key input still to import: set when the old list was empty and the settings
    /// cache did not belong to the accepted input (storage §7.3, the old app resolved it at connect).
    pub direct: Option<LegacyDirect>,
}

/// `settings.directVpnInput` of an old install whose server list was empty.
#[derive(Debug, Clone, PartialEq)]
pub struct LegacyDirect {
    /// Keys, a subscription URL or an app deep link, exactly as the user entered them.
    pub input: Secret,
    /// `directVpnSelectedIndex`: which of the resolved keys was in use.
    pub selected: usize,
}

/// A row or group that was not imported.
#[derive(Debug, Clone, PartialEq)]
pub struct LegacySkip {
    /// The row's display name (never a key); empty for a group.
    pub name: String,
    pub reason: Msg,
}

/// An old group as it will be imported.
struct OldGroup {
    group: ServerGroup,
    /// `Some` for a usable subscription (the canonical URL).
    url: Option<url::Url>,
    /// Stored as `source: 'manual'` (not a subscription demoted for its URL).
    was_manual: bool,
}

/// Builds the new document from the opened old documents (`None`: the file does not exist).
pub fn from_legacy(
    picker: Option<&Value>,
    groups: Option<&Value>,
    settings: Option<&Value>,
    now: UnixMs,
) -> (ServersDoc, LegacyReport) {
    let mut report = LegacyReport::default();
    let old_groups = read_groups(groups, now, &mut report);
    let mut doc = ServersDoc::default();
    // The first manual group takes in the others ("Импортированные") and demoted subscriptions.
    let manual = old_groups
        .iter()
        .find(|g| g.was_manual)
        .or_else(|| old_groups.iter().find(|g| g.url.is_none()));
    if let Some(old) = manual {
        let mut group = old.group.clone();
        if !old.was_manual {
            group.name.clear();
        }
        doc.groups.push(group);
    }
    let subscriptions: HashMap<&str, &OldGroup> = old_groups
        .iter()
        .filter(|g| g.url.is_some())
        .map(|g| (g.group.id.as_str(), g))
        .collect();

    let rows = array(picker, "profiles");
    let cache = DirectVpnCache::read(settings);
    // (old subscription id, device) of each imported feed row, to split mixed-device groups.
    let mut feed: Vec<(usize, GroupId, ClientDevice)> = Vec::new();
    let mut used_ids = HashSet::new();
    for old in rows {
        let Some(mut row) = import_row(old, &cache, now, &mut report) else {
            continue;
        };
        if !used_ids.insert(row.id.clone()) {
            row.id = ProfileId::random();
            used_ids.insert(row.id.clone());
        }
        let group = old.get("groupId").and_then(Value::as_str);
        match group.and_then(|id| subscriptions.get(id)) {
            Some(sub) => {
                row.origin = Origin::Feed;
                feed.push((doc.profiles.len(), sub.group.id.clone(), row.device));
            }
            None => row.group_id = doc.ensure_manual_group(now),
        }
        doc.profiles.push(row);
    }
    if rows.is_empty() {
        if cache.accepted {
            cache.migrate(&mut doc, now, &mut report);
        } else {
            report.direct = cache.direct();
        }
    } else {
        doc.active_profile_id = picker
            .and_then(|p| p.get("activeProfileId"))
            .and_then(Value::as_str)
            .map(ProfileId::from)
            .filter(|id| doc.row(id).is_some());
    }
    split_by_device(&mut doc, &old_groups, &feed);
    report.imported = doc.profiles.len();
    report.groups = doc.groups.len();
    (doc, report)
}

/// `doc[key]` as an array (empty when absent or not an array).
pub(super) fn array<'a>(doc: Option<&'a Value>, key: &str) -> &'a [Value] {
    doc.and_then(|d| d.get(key))
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// Readable old groups in file order. A subscription whose URL is not `http(s)://host` (a
/// redacted config import, the old "bogus SNI" groups) is imported as manual (S-41).
fn read_groups(doc: Option<&Value>, now: UnixMs, report: &mut LegacyReport) -> Vec<OldGroup> {
    let mut out: Vec<OldGroup> = Vec::new();
    for item in array(doc, "groups") {
        if is_locked(item) {
            report.locked += 1;
            continue;
        }
        let Some(id) = item
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        else {
            report.skipped.push(LegacySkip {
                name: String::new(),
                reason: Msg::new("servers.legacy.groupUnreadable"),
            });
            continue;
        };
        if out.iter().any(|g| g.group.id.as_str() == id) {
            continue;
        }
        let name = clean_group_name(item.get("name").and_then(Value::as_str).unwrap_or(""));
        let was_manual = item.get("source").and_then(Value::as_str) == Some("manual");
        let url = (!was_manual)
            .then(|| {
                item.get("sourceUrl")
                    .and_then(Value::as_str)
                    .and_then(canonical_source)
            })
            .flatten();
        let mut group =
            ServerGroup::manual(GroupId::from(id), num(item, "importedAt").unwrap_or(now));
        match &url {
            None => {
                if !OLD_MANUAL_NAMES.contains(&name.as_str()) {
                    group.name = name;
                }
            }
            Some(url) => {
                group.name = if name == OLD_SUBSCRIPTION_NAME {
                    String::new()
                } else {
                    name
                };
                group.kind = GroupKind::Subscription {
                    url: Secret::new(url.as_str()),
                    device: ClientDevice::Pc,
                };
                group.refresh_override_min = num(item, "refreshIntervalOverrideMinutes")
                    .and_then(|m| u16::try_from(m).ok())
                    .filter(|m| REFRESH_OVERRIDE_MIN.contains(m));
                group.fetch = fetch_state(item);
                group.info = info(item);
            }
        }
        out.push(OldGroup {
            group,
            url,
            was_manual,
        });
    }
    out
}

/// Old `status` -> last outcome; fetch timestamps and count kept.
fn fetch_state(item: &Value) -> FetchState {
    let last_outcome = match item.get("status").and_then(Value::as_str) {
        Some("active") => Some(FetchOutcome::Ok { partial: false }),
        Some("expired") => Some(FetchOutcome::EmptyList),
        Some("unreachable") => Some(FetchOutcome::Network(NetFail::Connect)),
        _ => None,
    };
    FetchState {
        last_attempt_at: num(item, "lastFetchAttemptAt"),
        last_success_at: num(item, "lastFetchedAt"),
        last_outcome,
        last_count: num(item, "lastRefreshProfilesCount").and_then(|n| u32::try_from(n).ok()),
    }
}

/// Provider metadata; `refreshIntervalSeconds` really held hours (S-06), so the number is kept.
fn info(item: &Value) -> SubscriptionMeta {
    let text = |key: &str| {
        item.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let bytes = |key: &str| num(item, key).and_then(|n| u64::try_from(n).ok());
    SubscriptionMeta {
        upload: bytes("trafficUploadBytes"),
        download: bytes("trafficDownloadBytes"),
        total: bytes("trafficTotalBytes"),
        expires_at: num(item, "expiresAt").filter(|&at| at > 0),
        refresh_hours: num(item, "refreshIntervalSeconds")
            .and_then(|h| u32::try_from(h).ok())
            .filter(|&h| h > 0),
        title: text("profileTitle"),
        web_page_url: text("webPageUrl"),
        support_url: text("supportUrl"),
        announce: None,
    }
}

/// A JS number field as an integer (old values may be written as floats).
pub(super) fn num(item: &Value, key: &str) -> Option<i64> {
    let v = item.get(key)?;
    v.as_i64().or_else(|| {
        v.as_f64()
            .filter(|f| f.is_finite() && f.abs() < 9.0e15)
            .map(|f| f.round() as i64)
    })
}

/// Places feed rows into their subscription group. A group whose rows carry several devices
/// becomes one group per device (same URL and metadata, ` · android` etc. on the non-pc copies):
/// the old app fetched each device with its own headers, and one shared device would archive the
/// other devices' keys at the first refresh.
fn split_by_device(
    doc: &mut ServersDoc,
    old: &[OldGroup],
    feed: &[(usize, GroupId, ClientDevice)],
) {
    for sub in old.iter().filter(|g| g.url.is_some()) {
        let mut devices: BTreeSet<ClientDevice> = feed
            .iter()
            .filter(|(_, g, _)| *g == sub.group.id)
            .map(|(_, _, d)| *d)
            .collect();
        if devices.is_empty() {
            devices.insert(ClientDevice::Pc);
        }
        let base = match (&sub.group.name, &sub.url) {
            (name, Some(url)) if name.is_empty() => host_name(url.as_str()).unwrap_or_default(),
            (name, _) => name.clone(),
        };
        for (n, &device) in devices.iter().enumerate() {
            let mut group = sub.group.clone();
            if n > 0 {
                group.id = GroupId::random();
            }
            if let GroupKind::Subscription { device: d, .. } = &mut group.kind {
                *d = device;
            }
            if devices.len() > 1 && device != ClientDevice::Pc {
                group.name = suffixed(&base, device);
            }
            for (index, _, _) in feed
                .iter()
                .filter(|(_, g, d)| *g == sub.group.id && *d == device)
            {
                doc.profiles[*index].group_id = group.id.clone();
            }
            doc.groups.push(group);
        }
    }
}

fn suffixed(base: &str, device: ClientDevice) -> String {
    let label = match device {
        ClientDevice::Pc => "pc",
        ClientDevice::Android => "android",
        ClientDevice::Ios => "ios",
        ClientDevice::Mac => "mac",
    };
    let suffix = format!(" · {label}");
    let keep = GROUP_NAME_MAX_CHARS - suffix.chars().count();
    let base: String = base.chars().take(keep).collect();
    format!("{}{suffix}", base.trim_end())
}
