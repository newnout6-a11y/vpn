//! «Start as proxies» of the Servers page over the slots the tunnel hosts: one slot per chosen
//! server (never the main VPN's), as the manager's batch start reports it.
use vpnte_base::Msg;
use vpnte_proxies::model::{BatchSkipReason, BatchStartResult};
use vpnte_ui::servers::{ProxySkip, ProxyStartReport, StartedProxy};

/// The page's report of a batch start.
pub(super) fn report(r: BatchStartResult) -> ProxyStartReport {
    ProxyStartReport {
        started: r
            .started
            .into_iter()
            .map(|i| StartedProxy {
                profile_id: i.profile_id.unwrap_or_default(),
                slot: i.slot.get(),
                listen: i.port.map(|p| format!("127.0.0.1:{p}")),
            })
            .collect(),
        already_running: r.already_running_profile_ids,
        skipped: r
            .skipped
            .into_iter()
            .map(|s| {
                let why = match s.reason {
                    BatchSkipReason::ActiveVpn => ProxySkip::ActiveVpn,
                    BatchSkipReason::Unavailable => ProxySkip::Unavailable,
                };
                (s.profile_id, why)
            })
            .collect(),
        // The manager's failure text is technical English (engine, port, resolver).
        failed: r
            .failed
            .into_iter()
            .map(|f| {
                let msg = Msg::new("app.proxies.detail").arg("detail", f.error);
                (f.profile_id, msg)
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use vpnte_proxies::model::{BatchFailure, BatchSkip, InstanceStatus};
    use vpnte_proxies::slot::Slot;

    use super::*;

    /// The manager's batch answer as the page's report: listen address without credentials,
    /// skip reasons, technical failure texts through `app.proxies.detail`.
    #[test]
    fn a_batch_start_becomes_the_page_report() {
        let started = InstanceStatus {
            profile_id: Some("p-2".into()),
            port: Some(17991),
            ..InstanceStatus::stopped(Slot::new(2).unwrap())
        };
        let r = report(BatchStartResult {
            requested: 4,
            started: vec![started],
            already_running_profile_ids: vec!["p-3".into()],
            skipped: vec![BatchSkip {
                profile_id: "p-1".into(),
                reason: BatchSkipReason::ActiveVpn,
            }],
            failed: vec![BatchFailure {
                profile_id: "p-4".into(),
                error: "engine did not start".into(),
            }],
        });
        assert_eq!(
            r.started,
            [StartedProxy {
                profile_id: "p-2".into(),
                slot: 2,
                listen: Some("127.0.0.1:17991".into()),
            }]
        );
        assert_eq!(r.already_running, ["p-3"]);
        assert_eq!(r.skipped, [("p-1".to_owned(), ProxySkip::ActiveVpn)]);
        let detail = Msg::new("app.proxies.detail").arg("detail", "engine did not start");
        assert_eq!(r.failed, [("p-4".to_owned(), detail)]);
    }
}
