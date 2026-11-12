//! Imports (pasted keys, JSON, a subscription URL) with their report, and subscription refresh.
//! Both run through the servers crate, which takes the operation registry slot (`import:…` /
//! `refresh:<id>`, 120 s) for every network fetch.
use std::sync::Arc;

use vpnte_base::types::{ClientDevice, Owner, UnixMs, now_ms};
use vpnte_base::{AppResult, ErrorKind};
use vpnte_profiles::caps::skip_msg;
use vpnte_profiles::model::Skipped;
use vpnte_profiles::uri;
use vpnte_servers::model::{GroupId, GroupStatus, ServerGroup};
use vpnte_servers::refresh::{AddOptions, AddOutcome, RefreshReport};
use vpnte_servers::subscription::{
    ProviderFailure, ProviderFetch, canonical_source, parse_headers,
};
use vpnte_ui::servers::{
    AddTarget, FetchError, ImportReport, ProviderLine, RefreshOutcome, SkippedLine,
    SubscriptionRequest,
};

use super::{Shared, project};

/// Imports `input` into `target` (a subscription is fetched as `device`; a new subscription group
/// takes `request`) and reports it.
pub(super) async fn add(
    shared: Arc<Shared>,
    input: String,
    target: AddTarget,
    device: ClientDevice,
    request: SubscriptionRequest,
) -> AppResult<ImportReport> {
    let backend = &shared.backend;
    let into = match target {
        AddTarget::Auto => None,
        AddTarget::Group(id) => Some(GroupId::from(id)),
    };
    let options = AddOptions {
        send_hwid: request.send_hwid,
        headers: parse_headers(&request.headers)?,
        ..AddOptions::new(into, device)
    };
    let cancel = backend.shutdown.child_token();
    let outcome = backend
        .servers
        .add_from_input_with(&backend.refresh, &input, options, cancel)
        .await?;
    shared.publish();
    let lang = shared.backend.lang();
    let title = |id: &GroupId| {
        backend
            .servers
            .read(|doc| doc.group(id).map(ServerGroup::title))
            .map(|msg| msg.render(lang))
            .unwrap_or_default()
    };
    let subscription = canonical_source(input.trim()).is_some();
    Ok(report(&outcome, &input, subscription, title))
}

/// The page's import report of `outcome`; `input` is the pasted text.
pub(super) fn report(
    outcome: &AddOutcome,
    input: &str,
    subscription: bool,
    title: impl Fn(&GroupId) -> String,
) -> ImportReport {
    match outcome {
        AddOutcome::Added {
            report,
            skipped,
            providers,
        } => ImportReport {
            group_name: title(&report.group),
            subscription,
            added: count(report.added.len()),
            updated: count(report.restored.len()),
            unchanged: count(report.duplicates),
            // A subscription's skips come from the fetched body, which has no pasted lines.
            skipped: skipped_lines((!subscription).then_some(input), skipped),
            providers: providers.iter().map(provider_line).collect(),
        },
        AddOutcome::Refreshed { group, report } => ImportReport {
            group_name: title(group),
            subscription: true,
            added: count(report.added.len()),
            updated: count(report.updated + report.restored),
            unchanged: 0,
            skipped: Vec::new(),
            providers: Vec::new(),
        },
    }
}

/// A Mihomo provider of the import as the report names it.
fn provider_line(p: &ProviderFetch) -> ProviderLine {
    ProviderLine {
        name: p.name.clone(),
        servers: count(p.servers),
        error: p.failed.and_then(|why| match why {
            ProviderFailure::Fetch(outcome) => project::fetch_error(outcome),
            ProviderFailure::Refused => Some(FetchError::Refused),
        }),
    }
}

/// Line numbers of the skipped entries. Skips carry only a redacted excerpt, so a pasted list is
/// matched line by line in document order (`uri::excerpt` of the line equals the excerpt);
/// when an entry maps to no line (JSON, Clash, base64, a fetched body) every entry is numbered
/// by its position instead, so the numbers stay unique.
pub(super) fn skipped_lines(input: Option<&str>, skipped: &[Skipped]) -> Vec<SkippedLine> {
    let lines: Vec<(u32, String)> = input
        .unwrap_or_default()
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(i, line)| (count(i + 1), uri::excerpt(line)))
        .collect();
    let mut matched = Vec::with_capacity(skipped.len());
    let mut from = 0;
    for entry in skipped {
        let Some(k) = lines[from..].iter().position(|(_, e)| *e == entry.excerpt) else {
            break;
        };
        matched.push(lines[from + k].0);
        from += k + 1;
    }
    let by_line = matched.len() == skipped.len();
    skipped
        .iter()
        .enumerate()
        .map(|(i, entry)| SkippedLine {
            line: if by_line { matched[i] } else { count(i + 1) },
            reason: skip_msg(&entry.reason),
        })
        .collect()
}

/// Refreshes subscription `id` as the user (pre-empts a scheduled run of the same group).
pub(super) async fn refresh(shared: Arc<Shared>, id: GroupId) -> AppResult<RefreshOutcome> {
    let backend = &shared.backend;
    let started = now_ms();
    let cancel = backend.shutdown.child_token();
    let result = backend
        .servers
        .refresh_group(&backend.refresh, &id, Owner::Manual, cancel)
        .await;
    shared.publish();
    let group = backend.servers.read(|doc| doc.group(&id).cloned());
    outcome(result, group.as_ref(), started, now_ms())
}

/// The page's refresh outcome. A failed fetch is an answer, not an error: the store recorded its
/// typed outcome on the group (for this attempt: stamped at or after `started`). Busy, cancel,
/// a group that is gone or cannot be fetched stay errors.
pub(super) fn outcome(
    result: AppResult<RefreshReport>,
    group: Option<&ServerGroup>,
    started: UnixMs,
    now: UnixMs,
) -> AppResult<RefreshOutcome> {
    let err = match result {
        Ok(report) => {
            return Ok(RefreshOutcome::Refreshed {
                added: count(report.added.len()),
                updated: count(report.updated + report.restored),
                removed: count(report.archived),
                expired: group.is_some_and(|g| g.status(now) == GroupStatus::Expired),
            });
        }
        Err(err) => err,
    };
    let fetch_failed = matches!(
        err.kind,
        ErrorKind::Network | ErrorKind::Validation | ErrorKind::Timeout
    );
    group
        .filter(|g| fetch_failed && g.fetch.last_attempt_at.is_some_and(|at| at >= started))
        .and_then(|g| g.fetch.last_outcome)
        .and_then(project::fetch_error)
        .map(RefreshOutcome::Failed)
        .ok_or(err)
}

pub(super) fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}
