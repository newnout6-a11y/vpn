//! `profiles.json`: the old server list, and the old single-key input of an install whose list
//! was empty (`settings.directVpnInput`, storage §6.6 "legacy direct path").
use serde_json::Value;
use vpnte_base::Msg;
use vpnte_base::types::{ClientDevice, now_ms};
use vpnte_core::secret::Secret;
use vpnte_core::store::Document;
use vpnte_profiles::model::{Profile, SubscriptionMeta};
use vpnte_servers::legacy::{self, LegacyDirect};
use vpnte_servers::model::{FetchState, GroupId, GroupKind, ServerGroup, ServersDoc};
use vpnte_servers::parse::parse_text;
use vpnte_servers::store::{AddTarget, SelectBy, Servers, subscription_name};
use vpnte_servers::subscription::canonical_source;

use super::super::run::Ctx;

/// Imports the old list once; an existing new list is the user's and is kept.
pub(super) fn import(cx: &mut Ctx<'_>, settings: Option<&Value>) {
    let picker = cx.open("server-picker");
    let groups = cx.open("server-groups");
    if picker.is_none() && groups.is_none() && settings.is_none() {
        return;
    }
    let (mut doc, report) =
        legacy::from_legacy(picker.as_ref(), groups.as_ref(), settings, now_ms());
    if !report.skipped.is_empty() {
        let count = report.skipped.len();
        cx.report.dropped += count;
        cx.note(Msg::new("app.import.serversSkipped").arg("count", count));
    }
    let keys = report.direct.as_ref().and_then(|d| direct(cx, &mut doc, d));
    let servers = Servers::open(cx.root);
    match servers.import_legacy(doc) {
        Ok(true) => {}
        Ok(false) => {
            tracing::info!("kept: the new server list has entries already");
            return;
        }
        Err(err) => return cx.write_failed(ServersDoc::FILE, &err),
    }
    if let Some((profiles, selected)) = keys {
        add_keys(cx, &servers, profiles, selected);
    }
    let (rows, groups) = servers.read(|doc| (doc.profiles.len(), doc.groups.len()));
    if rows > 0 || groups > 0 {
        cx.imported(ServersDoc::FILE, rows);
    }
}

/// Resolves the old direct input without network: the import runs before the window and must not
/// fetch (`Servers::import_legacy_direct` would). Keys come back with the old selected index, to
/// be added like a paste for `pc`; a subscription becomes an empty subscription group in `doc`
/// (the URL is kept; its servers arrive with the group's first refresh).
fn direct(
    cx: &mut Ctx<'_>,
    doc: &mut ServersDoc,
    old: &LegacyDirect,
) -> Option<(Vec<Profile>, usize)> {
    let input = old.input.expose()?.trim();
    if let Ok(parsed) = parse_text(input)
        && !parsed.profiles.is_empty()
    {
        return Some((parsed.profiles, old.selected));
    }
    let Some(url) = canonical_source(input) else {
        tracing::warn!("old direct input holds neither keys nor a subscription");
        cx.report.dropped += 1;
        return None;
    };
    let info = SubscriptionMeta::default();
    doc.groups.push(ServerGroup {
        id: GroupId::random(),
        name: subscription_name(&url, &info),
        kind: GroupKind::Subscription {
            url: Secret::new(url.as_str()),
            device: ClientDevice::Pc,
        },
        imported_at: now_ms(),
        refresh_override_min: None,
        fetch: FetchState::default(),
        info,
        // Migrated: the old app sent its HWID, the panel knows this device by it.
        send_hwid: true,
        headers: None,
        fallback: None,
        moved_at: None,
        controls: Default::default(),
    });
    cx.note(Msg::new("app.import.subscriptionPending"));
    None
}

/// Adds the old direct keys and selects the one the old app had in use (index clamped).
fn add_keys(cx: &mut Ctx<'_>, servers: &Servers, profiles: Vec<Profile>, selected: usize) {
    let target = AddTarget::Keys {
        group: None,
        device: ClientDevice::Pc,
    };
    let added = match servers.add(profiles, target) {
        Ok(added) => added,
        Err(err) => return cx.write_failed(ServersDoc::FILE, &err),
    };
    let index = selected.min(added.added.len().saturating_sub(1));
    if let Some(id) = added.added.get(index)
        && added.selected.as_ref() != Some(id)
        && let Err(err) = servers.select(id, SelectBy::User)
    {
        tracing::warn!(%err, "old selection not restored");
    }
}
