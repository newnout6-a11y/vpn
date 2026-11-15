//! Adding keys (pasted keys, a first subscription import) and adopting the Electron list.
use std::collections::HashMap;

use vpnte_base::types::{ClientDevice, UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::secret::Secret;
use vpnte_profiles::model::{Profile, SubscriptionMeta};

use super::{AddReport, AddTarget, Servers, group_not_found};
use crate::model::{
    ArchiveReason, FetchState, GroupId, Origin, RowTricks, ServerGroup, ServerRow, ServersDoc,
    clean_group_name, host_name,
};

impl Servers {
    /// Adds parsed `profiles` to `target`, skipping keys the target group already holds (same
    /// [`Profile::identity`]; the scope is that group only, S-21). A key matching a row archived in
    /// that group restores the row; pasted [`AddTarget::Keys`] turn a provider-archived feed row
    /// into a manual one. When nothing was selected, the first new row becomes the selection.
    pub fn add(&self, profiles: Vec<Profile>, target: AddTarget) -> AppResult<AddReport> {
        self.add_marked(profiles, target, false)
    }

    /// [`Servers::add`]; `hidden`: the keys come from a provider that hides its configs and go
    /// into another group, so every new or restored row keeps that ([`ServerRow::hidden`]).
    pub(crate) fn add_marked(
        &self,
        profiles: Vec<Profile>,
        target: AddTarget,
        hidden: bool,
    ) -> AppResult<AddReport> {
        if profiles.is_empty() {
            return Err(AppError::validation(Msg::new("servers.parse.nothingFound")));
        }
        let now = now_ms();
        // The provider's TLS tricks go on its new rows once; afterwards the value is the user's.
        let tricks = match &target {
            AddTarget::Subscription(sub) => sub.controls.tls_tricks.map(RowTricks::Set),
            AddTarget::Keys { .. } => None,
        };
        self.update(|doc| {
            let (group, origin, device) = resolve_target(doc, &target, profiles.len(), now)?;
            let mut known: HashMap<[u8; 16], usize> = doc
                .profiles
                .iter()
                .enumerate()
                .filter(|(_, r)| r.group_id == group)
                .filter_map(|(i, r)| Some((r.identity()?, i)))
                .collect();
            let mut report = AddReport {
                group: group.clone(),
                added: Vec::new(),
                restored: Vec::new(),
                duplicates: 0,
                selected: None,
            };
            for profile in &profiles {
                let identity = profile.identity();
                if let Some(&index) = known.get(&identity) {
                    let row = &mut doc.profiles[index];
                    match row.archived.take() {
                        Some(archived) => {
                            // A key the provider dropped and the user pastes back is the user's
                            // now: as a feed row the next refresh would archive it again (S-22).
                            if archived.reason == ArchiveReason::Provider
                                && origin == Origin::Manual
                            {
                                row.origin = Origin::Manual;
                                row.device = device;
                            }
                            row.missing_since = None;
                            row.hidden |= hidden;
                            report.restored.push(row.id.clone());
                        }
                        None => report.duplicates += 1,
                    }
                    continue;
                }
                let mut row = ServerRow::new(profile, group.clone(), origin, device, now)?;
                row.hidden = hidden;
                row.tls_tricks = tricks;
                known.insert(identity, doc.profiles.len());
                report.added.push(row.id.clone());
                doc.profiles.push(row);
            }
            let has_selection = doc
                .active_profile_id
                .as_ref()
                .is_some_and(|id| doc.row(id).is_some());
            if !has_selection && let Some(first) = report.added.first() {
                doc.active_profile_id = Some(first.clone());
                report.selected = Some(first.clone());
            }
            Ok(report)
        })
    }
}

/// The group, origin and device of new rows; creates the manual or subscription group on demand.
fn resolve_target(
    doc: &mut ServersDoc,
    target: &AddTarget,
    fetched: usize,
    now: UnixMs,
) -> AppResult<(GroupId, Origin, ClientDevice)> {
    match target {
        AddTarget::Keys {
            group: None,
            device,
        } => Ok((doc.ensure_manual_group(now), Origin::Manual, *device)),
        AddTarget::Keys {
            group: Some(id),
            device,
        } => {
            doc.group(id).ok_or_else(group_not_found)?;
            Ok((id.clone(), Origin::Manual, *device))
        }
        AddTarget::Subscription(sub) => {
            if let Some(group) = doc.subscription_group(&sub.url, sub.device) {
                return Ok((group.id.clone(), Origin::Feed, sub.device));
            }
            let mut group = ServerGroup::subscription(GroupId::random(), &sub.url, sub.device, now);
            group.name = subscription_name(&sub.url, &sub.info);
            group.fetch = FetchState::success(now, fetched, sub.partial);
            group.info = sub.info.clone();
            group.send_hwid = sub.send_hwid;
            group.headers = sub.headers.as_deref().map(Secret::new);
            group.fallback = sub.fallback.as_ref().map(|u| Secret::new(u.as_str()));
            group.moved_at = sub.moved_at;
            group.controls = sub.controls.clone();
            let id = group.id.clone();
            doc.groups.push(group);
            Ok((id, Origin::Feed, sub.device))
        }
    }
}

/// Group name of a new subscription: provider title, else host of its web page, else host of the
/// URL; empty (the default name) otherwise. Never the raw input: it is the access token (S-48).
pub fn subscription_name(url: &url::Url, info: &SubscriptionMeta) -> String {
    [
        info.title.as_deref().map(clean_group_name),
        info.web_page_url.as_deref().and_then(host_name),
        host_name(url.as_str()),
    ]
    .into_iter()
    .flatten()
    .find(|name| !name.is_empty())
    .unwrap_or_default()
}

// --- one-time import ---
impl Servers {
    /// One-time Electron import: adopts `doc` (built by [`crate::legacy::from_legacy`]) when the
    /// list is still empty. Returns false, changing nothing, when there is data already.
    pub fn import_legacy(&self, doc: ServersDoc) -> AppResult<bool> {
        self.update(|current| {
            if !current.groups.is_empty() || !current.profiles.is_empty() {
                return Ok(false);
            }
            *current = doc;
            Ok(true)
        })
    }
}
