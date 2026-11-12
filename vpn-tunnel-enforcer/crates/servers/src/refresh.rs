//! Subscription refresh (servers §3.1-§3.4): the refresh interval and due rule, the pure
//! [`reconcile`], adding keys or subscriptions from user input, one group's refresh as an operation
//! of the registry (120 s, owner priority: a manual refresh pre-empts a scheduled one) and the
//! background sweep (first after 10 s, then every 60 s) that also purges the 30-day archive.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;
use vpnte_base::types::{ClientDevice, Owner, UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::ops::{FeatureKind, OperationRegistry, RunOpts, Source};
use vpnte_profiles::model::Skipped;

use crate::legacy::LegacyDirect;
use crate::model::{FetchOutcome, GroupId, ServerGroup, ServersDoc};
use crate::store::{AddReport, SelectBy, Servers, ServersEvent};
use crate::subscription::{FetchError, Fetched, ProviderFetch, SubscriptionFetcher};

mod add;
mod apply;
#[cfg(test)]
mod device_tests;
mod reconcile;
#[cfg(test)]
mod relocation_tests;
#[cfg(test)]
mod tests;

pub use reconcile::{MISSING_GRACE_MS, RefreshReport, reconcile};

/// Interval without a provider value or user override.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30 * 60);
/// Bounds of the provider's `profile-update-interval` (hours) once converted.
pub const PROVIDER_INTERVAL: (Duration, Duration) =
    (Duration::from_secs(15 * 60), Duration::from_secs(24 * 3600));
/// Bounds of the user's override (minutes) once converted.
pub const OVERRIDE_INTERVAL: (Duration, Duration) =
    (Duration::from_secs(60), Duration::from_secs(24 * 3600));
/// Delay of the first background sweep after start, then the sweep period.
pub const FIRST_SWEEP_DELAY: Duration = Duration::from_secs(10);
pub const SWEEP_PERIOD: Duration = Duration::from_secs(60);

/// How often `group` is refreshed: the user's override (minutes, 1 min ..= 24 h), else the
/// provider's `profile-update-interval` (hours per Happ, S-06; 15 min ..= 24 h), else 30 min.
pub fn refresh_interval(group: &ServerGroup) -> Duration {
    if let Some(min) = group.refresh_override_min.filter(|&m| m > 0) {
        let (lo, hi) = OVERRIDE_INTERVAL;
        return Duration::from_secs(u64::from(min) * 60).clamp(lo, hi);
    }
    if let Some(hours) = group.info.refresh_hours.filter(|&h| h > 0) {
        let (lo, hi) = PROVIDER_INTERVAL;
        return Duration::from_secs(u64::from(hours) * 3600).clamp(lo, hi);
    }
    DEFAULT_INTERVAL
}

/// Whether the sweep should refresh `group` at `now`: a subscription with a usable URL (S-41)
/// whose last attempt (else last success, else import) is at least one interval old.
pub fn is_due(group: &ServerGroup, now: UnixMs) -> bool {
    if source_of(group).is_none() {
        return false;
    }
    let fetch = &group.fetch;
    let since = fetch
        .last_attempt_at
        .or(fetch.last_success_at)
        .unwrap_or(group.imported_at);
    let interval = i64::try_from(refresh_interval(group).as_millis()).unwrap_or(i64::MAX);
    // A stamp from the future (the clock was wrong then) would stop refreshes until that date.
    since > now || now - since >= interval
}

/// The URL and device a subscription group is fetched with; `None` for the manual group and for a
/// URL that is locked or not `http(s)://host`.
fn source_of(group: &ServerGroup) -> Option<(Url, ClientDevice)> {
    Some((group.url()?, group.device()?))
}

/// The group `id` if it still has the subscription `key` (else a refresh result is stale:
/// deleted, or its URL / device changed meanwhile).
fn same_group<'a>(
    doc: &'a mut ServersDoc,
    id: &GroupId,
    key: &(Url, ClientDevice),
) -> AppResult<&'a mut ServerGroup> {
    doc.group_mut(id)
        .filter(|g| source_of(g).as_ref() == Some(key))
        .ok_or_else(|| AppError::conflict(Msg::new("servers.refresh.groupChanged")))
}

/// What a refresh needs besides the list: the fetcher and the operation registry.
#[derive(Clone)]
pub struct RefreshCtx {
    pub fetcher: Arc<SubscriptionFetcher>,
    pub ops: OperationRegistry,
    /// Work budget of one refresh or import (servers §2.4: 120 s).
    pub deadline: Duration,
}

impl RefreshCtx {
    /// A context with the standard 120 s budget.
    pub fn new(fetcher: Arc<SubscriptionFetcher>, ops: OperationRegistry) -> Self {
        Self {
            fetcher,
            ops,
            deadline: FeatureKind::Refresh.deadline(),
        }
    }
}

/// Result of [`Servers::add_from_input`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddOutcome {
    /// Keys were added: pasted text, a new subscription, or a URL appended into a chosen group.
    Added {
        report: AddReport,
        /// Entries that looked like keys but were not imported (redacted excerpts).
        skipped: Vec<Skipped>,
        /// Mihomo providers the subscription named, fetched and merged (for the import report).
        providers: Vec<ProviderFetch>,
    },
    /// The subscription already existed for this device: it was refreshed instead (servers §3.1).
    Refreshed {
        group: GroupId,
        report: RefreshReport,
    },
}

/// Where user input goes and how a new subscription is fetched.
#[derive(Debug, Clone)]
pub struct AddOptions {
    /// A chosen group (`None`: the manual group, or a new subscription group).
    pub into: Option<GroupId>,
    pub device: ClientDevice,
    /// A new subscription group sends the HWID (off by default; a known group keeps its own).
    pub send_hwid: bool,
    /// Extra request headers of a new subscription group (checked).
    pub headers: Vec<(String, String)>,
    /// The input came from outside (a link Windows handed over, a QR code): a subscription it
    /// names must not lead into the local network. A deep link counts as such by its form.
    pub from_link: bool,
}

impl AddOptions {
    /// `into` as `device`, without the HWID or extra headers, typed by the user.
    pub fn new(into: Option<GroupId>, device: ClientDevice) -> Self {
        Self {
            into,
            device,
            send_hwid: false,
            headers: Vec::new(),
            from_link: false,
        }
    }
}

/// Result of one background sweep; cancelled and pre-empted refreshes count as neither.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    pub refreshed: usize,
    pub failed: usize,
}

// --- orchestration ---
impl Servers {
    /// Refreshes one subscription group as the operation `refresh:<id>` (deadline 120 s). A higher
    /// owner pre-empts a running lower one (manual over schedule); an equal one gets `Conflict`.
    /// A failure records its typed outcome and changes no row; a cancellation records nothing
    /// beyond the attempt time; the deadline records `Timeout` at that moment (servers §3.2).
    pub async fn refresh_group(
        self: &Arc<Self>,
        ctx: &RefreshCtx,
        id: &GroupId,
        owner: Owner,
        cancel: CancellationToken,
    ) -> AppResult<RefreshReport> {
        let (key, request) = self.refresh_request(id)?;
        let started = Arc::new(AtomicBool::new(false));
        let source = if owner == Owner::Schedule {
            Source::Runtime
        } else {
            Source::Ui
        };
        let opts = RunOpts {
            owner,
            source,
            resource: Some(format!("refresh:{id}").into()),
            cancel: Some(cancel),
            timeout: Some(ctx.deadline),
            ..RunOpts::default()
        };
        let (servers, fetcher) = (self.clone(), ctx.fetcher.clone());
        let (gid, gkey, flag) = (id.clone(), key.clone(), started.clone());
        let result = ctx
            .ops
            .run(FeatureKind::Refresh, opts, move |lease| async move {
                servers.mark_attempt(&gid, &gkey, now_ms())?;
                flag.store(true, Ordering::SeqCst);
                servers.emit(ServersEvent::RefreshStarted(gid.clone()));
                match fetcher.fetch_request(&request, lease.token()).await {
                    Ok(fetched) => {
                        lease.commit(|| servers.apply_refresh(&gid, &gkey, fetched, now_ms()))
                    }
                    Err(FetchError::Failed(outcome)) => {
                        lease.assert_active()?;
                        servers.record_failure(&gid, &gkey, outcome, now_ms())?;
                        Err(FetchError::Failed(outcome).for_group(request.send_hwid))
                    }
                    Err(err) => Err(lease.assert_active().err().unwrap_or_else(|| err.into())),
                }
            })
            .await;
        if started.load(Ordering::SeqCst) {
            if let Err(err) = &result
                && err.kind == ErrorKind::Timeout
            {
                // Unreachable at the deadline; a group deleted or re-pointed meanwhile stays as is.
                let _ = self.record_failure(id, &key, FetchOutcome::Timeout, now_ms());
            }
            self.emit(ServersEvent::RefreshFinished(id.clone()));
        }
        match &result {
            Ok(r) => tracing::info!(group = %id, added = r.added.len(), updated = r.updated,
                archived = r.archived, partial = r.partial, "servers: subscription refreshed"),
            Err(err) => tracing::info!(group = %id, "servers: subscription refresh failed: {err}"),
        }
        result
    }

    /// Storage §7.3 `import_legacy_direct`: the old app's single-key input ([`LegacyDirect`], from
    /// [`crate::legacy::from_legacy`]) goes in like a paste as `pc` (keys are parsed, a
    /// subscription URL or deep link is fetched), and the key the old app had selected becomes the
    /// selection. Only into a list that is still empty: `Ok(None)` and nothing done otherwise.
    pub async fn import_legacy_direct(
        self: &Arc<Self>,
        ctx: &RefreshCtx,
        direct: &LegacyDirect,
        cancel: CancellationToken,
    ) -> AppResult<Option<AddOutcome>> {
        if self.read(|doc| !doc.groups.is_empty() || !doc.profiles.is_empty()) {
            return Ok(None);
        }
        let Some(input) = direct.input.expose() else {
            return Err(AppError::conflict(Msg::new("servers.locked")));
        };
        // A migrated subscription keeps sending the HWID the old app sent (its device slot).
        let mut options = AddOptions::new(None, ClientDevice::Pc);
        options.send_hwid = true;
        let outcome = self
            .add_from_input_with(ctx, input, options, cancel)
            .await?;
        if let AddOutcome::Added { report, .. } = &outcome
            && let Some(first) = &report.selected
            && let Some(id) = report
                .added
                .get(direct.selected.min(report.added.len().saturating_sub(1)))
            && id != first
        {
            self.select(id, SelectBy::User)?;
        }
        Ok(Some(outcome))
    }

    /// One background pass: purges the archive past 30 days, then refreshes every due group in
    /// turn as the scheduler (a manual refresh pre-empts it).
    pub async fn sweep(
        self: &Arc<Self>,
        ctx: &RefreshCtx,
        cancel: &CancellationToken,
    ) -> SweepReport {
        let now = now_ms();
        if let Err(err) = self.purge_expired(now) {
            tracing::warn!("servers: archive purge failed: {err}");
        }
        let due: Vec<GroupId> = self.read(|doc| {
            let due = doc.groups.iter().filter(|g| is_due(g, now));
            due.map(|g| g.id.clone()).collect()
        });
        let mut out = SweepReport::default();
        for id in due {
            if cancel.is_cancelled() {
                break;
            }
            match self
                .refresh_group(ctx, &id, Owner::Schedule, cancel.child_token())
                .await
            {
                Ok(_) => out.refreshed += 1,
                // Cancelled, pre-empted, busy, or the group changed meanwhile: not a failure.
                Err(err) if matches!(err.kind, ErrorKind::Cancelled | ErrorKind::Conflict) => {}
                Err(_) => out.failed += 1,
            }
        }
        out
    }

    /// Starts the background refresher: the first sweep after 10 s, then one 60 s after the
    /// previous ended. `shutdown` stops it and cancels a running refresh.
    pub fn spawn_scheduler(
        self: &Arc<Self>,
        ctx: RefreshCtx,
        shutdown: CancellationToken,
    ) -> JoinHandle<()> {
        let servers = self.clone();
        tokio::spawn(async move {
            let mut wait = FIRST_SWEEP_DELAY;
            loop {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(wait) => {}
                }
                let report = servers.sweep(&ctx, &shutdown).await;
                if report != SweepReport::default() {
                    tracing::info!(
                        refreshed = report.refreshed,
                        failed = report.failed,
                        "servers: sweep done"
                    );
                }
                wait = SWEEP_PERIOD;
            }
        })
    }
}

/// Single-flight key of an import: the same URL for the same device and target is one operation.
fn import_resource(url: &Url, device: ClientDevice, into: Option<&GroupId>) -> String {
    let mut hash = Sha256::new();
    let device = format!("{device:?}");
    for part in [
        url.as_str(),
        device.as_str(),
        into.map_or("", GroupId::as_str),
    ] {
        hash.update(part.as_bytes());
        hash.update([0]);
    }
    format!("profile-import:{}", &hex::encode(hash.finalize())[..16])
}
