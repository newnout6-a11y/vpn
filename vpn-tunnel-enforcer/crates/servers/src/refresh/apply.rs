//! Bookkeeping of a refresh on the list: what a group's fetch sends, the attempt stamp, a failure,
//! and a fetched list committed with the provider's metadata, controls and relocation.
use url::Url;
use vpnte_base::types::{ClientDevice, UnixMs};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::secret::Secret;
use vpnte_profiles::model::{ParseReport, SubscriptionMeta};

use super::{RefreshReport, reconcile, same_group, source_of};
use crate::common::http_url;
use crate::model::{
    FetchOutcome, FetchState, GroupId, GroupKind, ServerGroup, clean_group_name, host_name,
};
use crate::store::{Servers, group_not_found};
use crate::subscription::{FetchRequest, Fetched, parse_headers};

/// The subscription key of a group in flight: a result is stale once it changed.
pub(super) type Key = (Url, ClientDevice);

impl Servers {
    /// The subscription a refresh of `id` fetches, with the group's own request settings.
    pub(super) fn refresh_request(&self, id: &GroupId) -> AppResult<(Key, FetchRequest)> {
        self.read(|doc| {
            let group = doc.group(id).ok_or_else(group_not_found)?;
            if group.is_manual() {
                return Err(AppError::validation(Msg::new(
                    "servers.group.manualNoRefresh",
                )));
            }
            let key = source_of(group)
                .ok_or_else(|| AppError::validation(Msg::new("servers.refresh.unusableUrl")))?;
            Ok((key.clone(), request_of(group, key)))
        })
    }

    /// Stamps the attempt before any request, so a blocked or cancelled request does not make the
    /// sweep hammer the panel every minute (old `serverGroups.ts`).
    pub(super) fn mark_attempt(&self, id: &GroupId, key: &Key, now: UnixMs) -> AppResult<()> {
        self.update(|doc| {
            same_group(doc, id, key)?.fetch.last_attempt_at = Some(now);
            Ok(())
        })
    }

    /// Records a failed fetch; rows and the selection stay as they are.
    pub(super) fn record_failure(
        &self,
        id: &GroupId,
        key: &Key,
        outcome: FetchOutcome,
        now: UnixMs,
    ) -> AppResult<()> {
        self.update(|doc| {
            let fetch = &mut same_group(doc, id, key)?.fetch;
            fetch.last_attempt_at = Some(now);
            fetch.last_outcome = Some(outcome);
            Ok(())
        })
    }

    /// Commits a fetched list: reconcile, provider metadata and controls, fetch bookkeeping, the
    /// provider title as the name while the name is still an automatic one, the fallback URL, and
    /// a permanent move of the URL (unless another group of the device has that URL already).
    pub(super) fn apply_refresh(
        &self,
        id: &GroupId,
        key: &Key,
        fetched: Fetched,
        now: UnixMs,
    ) -> AppResult<RefreshReport> {
        let complete = fetched.complete();
        let Fetched {
            report,
            controls,
            moved_to,
            fallback,
            ..
        } = fetched;
        let count = report.profiles.len();
        let ParseReport { profiles, meta, .. } = report;
        self.update(|doc| {
            let before = same_group(doc, id, key)?.clone();
            let out = reconcile(&before, &mut doc.profiles, profiles, complete, now)?;
            let taken = moved_to
                .as_ref()
                .is_some_and(|url| doc.subscription_group(url, key.1).is_some());
            let group = same_group(doc, id, key)?;
            if let Some(title) = meta.title.as_deref().map(clean_group_name)
                && !title.is_empty()
                && is_automatic_name(&before, &meta)
            {
                group.name = title;
            }
            group.info = meta;
            group.controls = controls;
            group.fetch = FetchState::success(now, count, !complete);
            if let Some(url) = fallback {
                group.fallback = Some(Secret::new(url.as_str()));
            }
            match moved_to {
                Some(url) if !taken => {
                    group.kind = GroupKind::Subscription {
                        url: Secret::new(url.as_str()),
                        device: key.1,
                    };
                    group.moved_at = Some(now);
                    tracing::info!(group = %id, host = ?url.host_str(),
                        "servers: the provider moved the subscription");
                }
                Some(_) => tracing::info!(group = %id,
                    "servers: a move was not applied: another group has that subscription"),
                None => {}
            }
            Ok(out)
        })
    }
}

/// What a fetch of `group` sends: its HWID choice, its extra headers, its fallback URL.
pub(super) fn request_of(group: &ServerGroup, (url, device): Key) -> FetchRequest {
    let mut req = FetchRequest::new(url, device);
    req.send_hwid = group.send_hwid;
    req.headers = group
        .headers
        .as_ref()
        .and_then(Secret::expose)
        .and_then(|text| parse_headers(text).ok())
        .unwrap_or_default();
    req.fallback = group
        .fallback
        .as_ref()
        .and_then(Secret::expose)
        .and_then(http_url);
    req
}

/// True while the group's name is one the app derived (empty, the host of the URL or of the
/// provider's web page, or the provider's previous title): only then does a new provider title
/// rename it, so a user's own name survives every refresh.
fn is_automatic_name(group: &ServerGroup, fresh: &SubscriptionMeta) -> bool {
    let name = group.name.as_str();
    if name.is_empty() {
        return true;
    }
    let derived = [
        group.url().as_ref().map(Url::as_str).and_then(host_name),
        group.info.web_page_url.as_deref().and_then(host_name),
        fresh.web_page_url.as_deref().and_then(host_name),
        group.info.title.as_deref().map(clean_group_name),
    ];
    derived.iter().flatten().any(|d| d == name)
}
