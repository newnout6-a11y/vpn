//! A subscription's request settings (the HWID switch, the extra headers) and the provider's
//! `hide-settings` guard in front of every key export.
use std::collections::HashSet;

use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::secret::Secret;
use vpnte_profiles::device;
use vpnte_profiles::model::Profile;

use super::{Servers, group_not_found, server_not_found};
use crate::model::{GroupId, ProfileId};
use crate::subscription::{parse_headers, stored_headers};

impl Servers {
    /// Turns the HWID of a subscription group on or off; the next refresh sends accordingly.
    pub fn set_group_send_hwid(&self, id: &GroupId, on: bool) -> AppResult<()> {
        self.update(|doc| {
            let group = doc.group_mut(id).ok_or_else(group_not_found)?;
            if group.is_manual() {
                return Err(manual_no_request());
            }
            group.send_hwid = on;
            Ok(())
        })
    }

    /// Gives a subscription group its own fresh device ID (`own`; the provider then counts this
    /// PC as a new device) or takes it back to this PC's ID (undo). Off-switch groups keep the
    /// choice for when the HWID is turned on.
    pub fn set_own_device_id(&self, id: &GroupId, own: bool) -> AppResult<()> {
        self.update(|doc| {
            let group = doc.group(id).ok_or_else(group_not_found)?;
            if group.is_manual() {
                return Err(manual_no_request());
            }
            if own {
                doc.device_ids.insert(id.clone(), device::random_hwid());
            } else {
                doc.device_ids.remove(id);
            }
            Ok(())
        })
    }

    /// The subscription group `id` came from a link (fix-ks b2): its refreshes are checked and
    /// pinned like its add. A later add of the same subscription by hand keeps the mark: the
    /// safe side.
    pub(crate) fn mark_linked(&self, id: &GroupId) -> AppResult<()> {
        self.update(|doc| {
            doc.group(id).ok_or_else(group_not_found)?;
            doc.linked.insert(id.clone());
            Ok(())
        })
    }

    /// The client identity (User-Agent family) that brought the first servers of the new
    /// subscription group `id`: its refreshes try it first (p-live-fix 1c).
    pub(crate) fn remember_agent(&self, id: &GroupId, agent: String) -> AppResult<()> {
        self.update(|doc| {
            doc.group(id).ok_or_else(group_not_found)?;
            doc.fetch_notes.entry(id.clone()).or_default().agent = Some(agent);
            Ok(())
        })
    }

    /// Replaces the extra request headers of a subscription group with the `Name: value` lines of
    /// `text` (blank: none), sealed like the URL. Returns the names now set.
    pub fn set_group_headers(&self, id: &GroupId, text: &str) -> AppResult<Vec<String>> {
        let headers = parse_headers(text)?;
        let stored = stored_headers(&headers);
        self.update(|doc| {
            let group = doc.group_mut(id).ok_or_else(group_not_found)?;
            if group.is_manual() {
                return Err(manual_no_request());
            }
            group.headers = stored.as_deref().map(Secret::new);
            Ok(())
        })?;
        Ok(headers.into_iter().map(|(name, _)| name).collect())
    }

    /// The profile of `id` for a key export (copy, save, QR code): refused with
    /// `servers.hidden.refused` when its provider asked to keep the configs hidden.
    pub fn shareable_profile(&self, id: &ProfileId) -> AppResult<Profile> {
        let row = self.read(|doc| {
            let row = doc.row(id).ok_or_else(server_not_found)?;
            if doc.hides(row) {
                return Err(hidden_refused());
            }
            Ok(row.clone())
        })?;
        row.profile()
    }

    /// Rows whose provider asked to keep the configs hidden ([`crate::model::ServersDoc::hides`]):
    /// exports of every key skip them.
    pub fn hidden_rows(&self) -> HashSet<ProfileId> {
        self.read(|doc| {
            doc.profiles
                .iter()
                .filter(|r| doc.hides(r))
                .map(|r| r.id.clone())
                .collect()
        })
    }
}

/// The refusal of a key export the provider hid (`hide-settings`).
pub fn hidden_refused() -> AppError {
    AppError::validation(Msg::new("servers.hidden.refused"))
}

fn manual_no_request() -> AppError {
    AppError::validation(Msg::new("servers.group.manualNoRequest"))
}
