//! Adding what the user pasted (servers §3.1): keys go in as they are; a subscription URL is
//! fetched (a known one refreshes its group) and becomes a new group with the user's request
//! settings, the provider's controls and, when the first answer moved it, its new address.
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::{ClientDevice, Owner, now_ms};
use vpnte_base::{AppError, AppResult};
use vpnte_core::ops::{FeatureKind, RunOpts, Source};
use vpnte_profiles::model::ParseReport;
use vpnte_profiles::{deeplink, text};

use super::{AddOptions, AddOutcome, Fetched, RefreshCtx, import_resource};
use crate::model::GroupId;
use crate::parse;
use crate::store::{AddTarget, NewSubscription, Servers};
use crate::subscription::{FetchError, FetchRequest, canonical_source, stored_headers};

impl Servers {
    /// [`Servers::add_from_input_with`] into `into` as `device`, a new subscription group without
    /// the HWID or extra headers (the default of new groups).
    pub async fn add_from_input(
        self: &Arc<Self>,
        ctx: &RefreshCtx,
        input: &str,
        into: Option<GroupId>,
        device: ClientDevice,
        cancel: CancellationToken,
    ) -> AppResult<AddOutcome> {
        let options = AddOptions::new(into, device);
        self.add_from_input_with(ctx, input, options, cancel).await
    }

    /// Adds what the user pasted. A subscription URL (plain, or carried by a `happ://` /
    /// `mantaray://` link) is fetched as `options.device`: already known for that device -> that
    /// group is refreshed with its own settings; `into` a chosen group -> its keys are appended
    /// there; else a new subscription group with `send_hwid` and `headers` of `options`. Any other
    /// text is parsed for keys, added to `into` or the manual group.
    pub async fn add_from_input_with(
        self: &Arc<Self>,
        ctx: &RefreshCtx,
        input: &str,
        options: AddOptions,
        cancel: CancellationToken,
    ) -> AppResult<AddOutcome> {
        let AddOptions {
            into,
            device,
            send_hwid,
            headers,
            from_link,
        } = options;
        let input = input.trim();
        // A deep link names an internet host (checked here, before any request); one that
        // names a public host is still checked by its addresses at the first request.
        let wrapped = match deeplink::unwrap_deeplink(input) {
            Ok(inner) => inner.is_some(),
            Err(err) => return Err(AppError::validation(err.msg())),
        };
        let Some(url) = canonical_source(input) else {
            // Up to 1 MiB of text is CPU work: the blocking pool, as for a fetched body.
            let pasted = input.to_owned();
            let report = tokio::task::spawn_blocking(move || parse::parse_text(&pasted))
                .await
                .map_err(AppError::internal)?
                .map_err(|_| parse::too_large(text::MAX_INPUT_BYTES))?;
            if report.profiles.is_empty() {
                return Err(parse::no_profiles(&report));
            }
            let target = AddTarget::Keys {
                group: into,
                device,
            };
            let added = self.add(report.profiles, target)?;
            return Ok(AddOutcome::Added {
                report: added,
                skipped: report.skipped,
                providers: Vec::new(),
            });
        };
        if into.is_none()
            && let Some(group) = self.find_subscription(&url, device)
        {
            let report = self
                .refresh_group(ctx, &group, Owner::Manual, cancel)
                .await?;
            return Ok(AddOutcome::Refreshed { group, report });
        }
        let opts = RunOpts {
            source: Source::Ui,
            resource: Some(import_resource(&url, device, into.as_ref()).into()),
            cancel: Some(cancel),
            timeout: Some(ctx.deadline),
            ..RunOpts::default()
        };
        let (servers, fetcher) = (self.clone(), ctx.fetcher.clone());
        let mut request = FetchRequest::new(url.clone(), device);
        request.send_hwid = send_hwid;
        request.headers = headers;
        request.from_link = from_link || wrapped;
        ctx.ops
            .run(FeatureKind::Import, opts, move |lease| async move {
                let fetched = match fetcher.fetch_request(&request, lease.token()).await {
                    Ok(fetched) => fetched,
                    Err(err) => {
                        let err = match err {
                            FetchError::Failed(_) => err.for_group(send_hwid),
                            other => other.into(),
                        };
                        return Err(lease.assert_active().err().unwrap_or(err));
                    }
                };
                let partial = !fetched.complete();
                let Fetched {
                    report,
                    controls,
                    moved_to,
                    fallback,
                    providers,
                    ..
                } = fetched;
                let ParseReport {
                    profiles,
                    skipped,
                    meta,
                } = report;
                // Keys fetched into another group keep the provider's hide-settings with them.
                let hidden = into.is_some() && controls.hides_settings();
                let target = match into {
                    Some(group) => AddTarget::Keys {
                        group: Some(group),
                        device,
                    },
                    None => AddTarget::Subscription(Box::new(NewSubscription {
                        moved_at: moved_to.as_ref().map(|_| now_ms()),
                        url: moved_to.unwrap_or(url),
                        device,
                        info: meta,
                        partial,
                        send_hwid,
                        headers: stored_headers(&request.headers),
                        controls,
                        fallback,
                    })),
                };
                let added = lease.commit(|| servers.add_marked(profiles, target, hidden))?;
                Ok(AddOutcome::Added {
                    report: added,
                    skipped,
                    providers,
                })
            })
            .await
    }
}
