//! The session's VPN traffic out of the Clash API's open flows: only flows whose route ends in
//! `proxy-out` count (direct-routed flows, Smart RU's among them, would hide a dead server);
//! summed per flow, so a flow that closes keeps what it carried.
use std::collections::HashMap;

use vpnte_engine::clash_api::{ClashEndpoint, Connection};
use vpnte_engine::tags::PROXY_OUT;

/// Running VPN totals of one engine run.
#[derive(Default)]
pub(super) struct Meter {
    /// The run the totals are about (its Clash API secret is fresh with every engine run).
    run: Option<ClashEndpoint>,
    /// What each open flow carried at the last read: (up, down).
    flows: HashMap<String, (u64, u64)>,
    up: u64,
    down: u64,
}

impl Meter {
    /// Adds one read of `run`'s open flows; the run's VPN totals `(up, down)` so far.
    pub(super) fn add(&mut self, run: &ClashEndpoint, flows: &[Connection]) -> (u64, u64) {
        if self.run.as_ref() != Some(run) {
            *self = Meter {
                run: Some(run.clone()),
                ..Meter::default()
            };
        }
        let mut open = HashMap::with_capacity(flows.len());
        let vpn = |f: &&Connection| f.chains.last().is_some_and(|out| out == PROXY_OUT);
        for flow in flows.iter().filter(vpn) {
            let (up, down) = self.flows.get(&flow.id).copied().unwrap_or_default();
            self.up += flow.upload.saturating_sub(up);
            self.down += flow.download.saturating_sub(down);
            open.insert(
                flow.id.clone(),
                (flow.upload.max(up), flow.download.max(down)),
            );
        }
        self.flows = open;
        (self.up, self.down)
    }
}
