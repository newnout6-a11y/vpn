//! The pushed view, computed from the document, the accepted feed, the engine store and what
//! this run hid or did.
use vpnte_ui::updates::{
    AppOffer, CheckLine, CheckResult, EngineOffer, EngineRow, UpdateOutcome, UpdatesView,
};
use vpnte_update::feed::{AppRelease, Feed};
use vpnte_update::net::Via;
use vpnte_update::pending::Outcome;
use vpnte_update::policy::{self, SINGBOX, XRAY, bundled_version, engine_allowed};
use vpnte_update::store::{Choice, EngineStore, Origin};
use vpnte_update::version::Version;

use super::Updates;
use super::doc::{Found, UpdatesDoc};

/// The engines the store manages, with their display names.
pub(super) const ENGINES: [(&str, &str); 2] = [(SINGBOX, "sing-box"), (XRAY, "Xray")];

pub(super) fn compute(u: &Updates) -> UpdatesView {
    let doc = u.doc.snapshot();
    let inner = u.inner.lock();
    let feed = inner.feed.as_ref().map(|s| &s.feed);
    let running = policy::app_version();
    UpdatesView {
        ready: policy::keys_ready(),
        auto_check: doc.auto_check,
        download_ahead: doc.download_ahead,
        skipped: doc.skipped.clone(),
        last_check: doc.last_check.as_ref().map(|c| CheckLine {
            at: c.at,
            host: c.host.clone(),
            via_vpn: c.via == Some(Via::Session),
            result: match c.result {
                Found::UpToDate => CheckResult::UpToDate,
                Found::Newer => CheckResult::Found,
                Found::Stale => CheckResult::Stale,
                Found::Failed => CheckResult::Failed,
            },
        }),
        checking: inner.checking,
        app: feed
            .and_then(|f| app_offer(f, &doc, running))
            .filter(|_| !inner.hidden_app),
        engines: feed
            .map(|f| engine_offers(f, &u.store, running))
            .unwrap_or_default()
            .into_iter()
            .filter(|o| !inner.hidden_engines.contains(&o.id))
            .collect(),
        installed: installed(&u.store),
        rollback_to: feed
            .and_then(|f| rollback(f, running))
            .map(|v| v.to_string()),
        outcome: inner.outcome.as_ref().map(|o| match o {
            Outcome::Updated { to } => UpdateOutcome::Updated {
                version: to.to_string(),
            },
            Outcome::Failed { to, .. } => UpdateOutcome::Failed {
                version: to.to_string(),
            },
        }),
        progress: inner.progress.clone(),
        note: inner.note.clone(),
    }
}

/// The stable release when it is newer than this build and not skipped (a security update, or
/// a build below `warn_below`, cannot be skipped — never forced either).
pub(super) fn app_offer(feed: &Feed, doc: &UpdatesDoc, running: Version) -> Option<AppOffer> {
    let release = newer_release(feed, running)?;
    let pressing = pressing(feed, release, running);
    let version = release.version.to_string();
    if doc.skipped.contains(&version) && !pressing {
        return None;
    }
    Some(AppOffer {
        version,
        notes: release.notes.clone(),
        security: release.severity.is_security(),
        can_skip: !pressing,
    })
}

/// The stable release when it is newer than `running`.
pub(super) fn newer_release(feed: &Feed, running: Version) -> Option<&AppRelease> {
    feed.app.stable.as_ref().filter(|r| r.version > running)
}

/// A security update, or this build is below the feed's `warn_below`.
pub(super) fn pressing(feed: &Feed, release: &AppRelease, running: Version) -> bool {
    release.severity.is_security() || feed.app.warn_below.is_some_and(|w| running < w)
}

/// Tested engine versions newer than what is active, allowed by this build and meant for it.
pub(super) fn engine_offers(
    feed: &Feed,
    store: &EngineStore,
    running: Version,
) -> Vec<EngineOffer> {
    ENGINES
        .iter()
        .filter_map(|&(id, name)| {
            let entry = feed.engine(id)?;
            let current = active_version(store, id)?;
            let fits = engine_allowed(id, entry.version) && entry.app.contains(running);
            (fits && entry.version > current).then(|| EngineOffer {
                id: id.to_owned(),
                name: name.to_owned(),
                from: current.to_string(),
                to: entry.version.to_string(),
                tested_on: entry.tested_on.clone(),
                notes: entry.notes.clone(),
            })
        })
        .collect()
}

/// The version that runs from the next start on: the usable downloaded one, else the bundled.
pub(super) fn active_version(store: &EngineStore, id: &str) -> Option<Version> {
    match store.resolve(id).origin {
        Origin::Downloaded { version, .. } => Some(version),
        Origin::Bundled => bundled_version(id),
    }
}

/// The «Движки» rows.
fn installed(store: &EngineStore) -> Vec<EngineRow> {
    let state = store.state();
    ENGINES
        .iter()
        .filter_map(|&(id, name)| {
            let resolved = store.resolve(id);
            let (version, updated_on) = match resolved.origin {
                Origin::Downloaded { version, on } => (version, Some(day(on))),
                Origin::Bundled => (bundled_version(id)?, None),
            };
            let previous = state.engine(id).and_then(|r| match r.previous {
                Some(Choice::Downloaded(v)) if v != version => Some(v.to_string()),
                _ => None,
            });
            Some(EngineRow {
                id: id.to_owned(),
                name: name.to_owned(),
                version: version.to_string(),
                can_restore_bundled: updated_on.is_some(),
                updated_on,
                previous,
            })
        })
        .collect()
}

/// The feed's rollback target while this build is the newest release and an installer for the
/// target is listed (the data format allows going back to it).
pub(super) fn rollback(feed: &Feed, running: Version) -> Option<Version> {
    let stable = feed.app.stable.as_ref()?;
    let target = stable.rollback_to?;
    (stable.version == running && target < running && stable.rollback_file.is_some())
        .then_some(target)
}

/// `UnixMs` -> local `YYYY-MM-DD` (empty when unknown).
fn day(at: vpnte_base::types::UnixMs) -> String {
    jiff::Timestamp::from_millisecond(at)
        .map(|ts| ts.to_zoned(jiff::tz::TimeZone::system()).date().to_string())
        .unwrap_or_default()
}
