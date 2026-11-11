//! Changing the list: soft delete, restore and purge of rows; renaming, deleting and re-pointing
//! groups; per-row and per-group devices.
use vpnte_base::types::{ClientDevice, UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, Msg};

use super::{Servers, group_not_found, server_not_found};
use crate::model::{
    ArchiveReason, Archived, GroupId, GroupKind, Origin, ProfileId, REFRESH_OVERRIDE_MIN,
    ServersDoc, clean_group_name,
};

// --- archive and purge ---
impl Servers {
    /// Soft delete (S-34): the row is archived for the user, is no longer selectable and is purged
    /// after 30 days unless restored. A removed selection is cleared.
    pub fn remove(&self, id: &ProfileId) -> AppResult<()> {
        let now = now_ms();
        self.update(|doc| {
            let row = doc.row_mut(id).ok_or_else(server_not_found)?;
            // The purge clock keeps running from the first archiving (the provider dropped it then).
            let at = row.archived.map_or(now, |a| a.at);
            row.archived = Some(Archived {
                at,
                reason: ArchiveReason::User,
            });
            if doc.active_profile_id.as_ref() == Some(id) {
                doc.active_profile_id = None;
            }
            Ok(())
        })
    }

    /// Brings an archived row back (a no-op for a row that is not archived).
    pub fn restore(&self, id: &ProfileId) -> AppResult<()> {
        self.update(|doc| {
            let row = doc.row_mut(id).ok_or_else(server_not_found)?;
            if row.archived.take().is_some() {
                row.missing_since = None;
            }
            Ok(())
        })
    }

    /// Deletes a row for good ("delete now" in the archive).
    pub fn purge(&self, id: &ProfileId) -> AppResult<()> {
        self.update(|doc| {
            let before = doc.profiles.len();
            doc.profiles.retain(|r| &r.id != id);
            if doc.profiles.len() == before {
                return Err(server_not_found());
            }
            forget_dangling_selection(doc);
            Ok(())
        })?;
        self.pings.lock().remove(id);
        Ok(())
    }

    /// Deletes every row archived at least 30 days before `now` (both reasons); returns how many.
    pub fn purge_expired(&self, now: UnixMs) -> AppResult<usize> {
        let purged = self.update(|doc| {
            let mut purged = Vec::new();
            doc.profiles.retain(|r| {
                let expired = r.purge_at().is_some_and(|at| at <= now);
                if expired {
                    purged.push(r.id.clone());
                }
                !expired
            });
            forget_dangling_selection(doc);
            Ok(purged)
        })?;
        if !purged.is_empty() {
            let mut pings = self.pings.lock();
            for id in &purged {
                pings.remove(id);
            }
            tracing::info!("servers: purged {} archived rows", purged.len());
        }
        Ok(purged.len())
    }
}

/// Clears a selection that points to a row that no longer exists.
fn forget_dangling_selection(doc: &mut ServersDoc) {
    if let Some(id) = &doc.active_profile_id
        && doc.row(id).is_none()
    {
        doc.active_profile_id = None;
    }
}

// --- groups and devices ---
impl Servers {
    /// Renames a group (trimmed, at most 60 chars); an empty name changes nothing.
    pub fn rename_group(&self, id: &GroupId, name: &str) -> AppResult<()> {
        let name = clean_group_name(name);
        self.update(|doc| {
            let group = doc.group_mut(id).ok_or_else(group_not_found)?;
            if !name.is_empty() {
                group.name = name;
            }
            Ok(())
        })
    }

    /// Deletes a group with its rows, or moves its rows into the manual-keys group right away (S-40;
    /// they become `origin = manual`). The manual group itself can only go together with its rows.
    pub fn delete_group(&self, id: &GroupId, delete_servers: bool) -> AppResult<()> {
        let now = now_ms();
        let mut dropped = Vec::new();
        self.update(|doc| {
            let manual = doc.group(id).ok_or_else(group_not_found)?.is_manual();
            if delete_servers {
                doc.profiles.retain(|r| {
                    let mine = &r.group_id == id;
                    if mine {
                        dropped.push(r.id.clone());
                    }
                    !mine
                });
                forget_dangling_selection(doc);
            } else {
                if manual {
                    return Err(AppError::validation(Msg::new("servers.group.keepManual")));
                }
                let target = doc.ensure_manual_group(now);
                for row in doc.profiles.iter_mut().filter(|r| &r.group_id == id) {
                    row.group_id = target.clone();
                    row.origin = Origin::Manual;
                    row.missing_since = None;
                }
            }
            doc.groups.retain(|g| &g.id != id);
            Ok(())
        })?;
        let mut pings = self.pings.lock();
        for row in &dropped {
            pings.remove(row);
        }
        Ok(())
    }

    /// Sets (`Some(1..=1440)` minutes) or clears (`None`: provider value / default) a
    /// subscription's refresh interval.
    pub fn set_refresh_override(&self, id: &GroupId, minutes: Option<u16>) -> AppResult<()> {
        if minutes.is_some_and(|m| !REFRESH_OVERRIDE_MIN.contains(&m)) {
            return Err(AppError::validation(Msg::new(
                "servers.group.overrideInvalid",
            )));
        }
        self.update(|doc| {
            let group = doc.group_mut(id).ok_or_else(group_not_found)?;
            if group.is_manual() {
                return Err(AppError::validation(Msg::new(
                    "servers.group.manualNoRefresh",
                )));
            }
            group.refresh_override_min = minutes;
            Ok(())
        })
    }

    /// Changes the device a subscription is fetched as; its feed rows follow. Refresh it afterwards.
    pub fn set_group_device(&self, id: &GroupId, device: ClientDevice) -> AppResult<()> {
        self.update(|doc| {
            let group = doc.group(id).ok_or_else(group_not_found)?;
            if group.device() == Some(device) {
                return Ok(());
            }
            if group.is_manual() {
                return Err(AppError::validation(Msg::new(
                    "servers.group.manualNoDevice",
                )));
            }
            let Some(url) = group.url() else {
                return Err(AppError::conflict(Msg::new("servers.locked")));
            };
            if doc.subscription_group(&url, device).is_some() {
                return Err(AppError::conflict(Msg::new("servers.group.deviceTaken")));
            }
            if let Some(GroupKind::Subscription { device: d, .. }) =
                doc.group_mut(id).map(|g| &mut g.kind)
            {
                *d = device;
            }
            for row in doc.profiles.iter_mut() {
                if &row.group_id == id && row.origin == Origin::Feed {
                    row.device = device;
                }
            }
            Ok(())
        })
    }

    /// Changes the device of a hand-added key (feed rows follow their group's device).
    pub fn set_profile_device(&self, id: &ProfileId, device: ClientDevice) -> AppResult<()> {
        self.update(|doc| {
            let row = doc.row_mut(id).ok_or_else(server_not_found)?;
            if row.origin == Origin::Feed {
                return Err(AppError::validation(Msg::new("servers.deviceFollowsGroup")));
            }
            row.device = device;
            Ok(())
        })
    }
}
