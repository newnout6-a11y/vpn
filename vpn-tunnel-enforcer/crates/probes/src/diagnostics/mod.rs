//! System diagnostics: the health-check report (a checklist of items judged with [`Verdict`]),
//! the routing self-test ("is the split real?") and system snapshots for support. Native Win32 reads only; no PowerShell, netsh or tasklist.
mod checks;
mod endpoints;
mod listeners;
pub mod report;
pub mod routing;
pub mod snapshot;
mod sysinfo;

use serde::Serialize;
use vpnte_base::Msg;
use vpnte_base::types::{UnixMs, Verdict};

pub use listeners::{ListenerInfo, proxy_listeners};
pub use report::{Hy2Facts, ProfileFacts, ReportInputs, TunnelFacts, system_report};
pub use routing::{
    RoutingInputs, RoutingResult, RoutingVerdict, SmartRuCheck, derive_routing_verdict,
    direct_egress_ip, routing_test,
};
pub use snapshot::{SnapshotReason, Snapshotter};
pub use sysinfo::{OsInfo, ProcessRow, ServiceRow, ServiceStart, os_info, processes, service};

/// Group of a report item. A failure in a critical group fails the whole report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    App,
    Tun,
    Proxy,
    Network,
    Internet,
    Windows,
    Logs,
    Routing,
    Profile,
}

impl Category {
    /// App, TUN, Proxy, Network, Internet and Routing failures are critical.
    pub fn is_critical(self) -> bool {
        matches!(
            self,
            Category::App
                | Category::Tun
                | Category::Proxy
                | Category::Network
                | Category::Internet
                | Category::Routing
        )
    }

    /// Group heading.
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            Category::App => "probes.diag.category.app",
            Category::Tun => "probes.diag.category.tun",
            Category::Proxy => "probes.diag.category.proxy",
            Category::Network => "probes.diag.category.network",
            Category::Internet => "probes.diag.category.internet",
            Category::Windows => "probes.diag.category.windows",
            Category::Logs => "probes.diag.category.logs",
            Category::Routing => "probes.diag.category.routing",
            Category::Profile => "probes.diag.category.profile",
        })
    }
}

/// One row of a checklist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckItem {
    /// Stable id (`adapters`, `endpoint-google`, `routing-<leak item>`).
    pub id: String,
    pub category: Category,
    pub label: Msg,
    /// `None`: an informational row, nothing judged. `Some(NotChecked)`: a check that could
    /// not run; never shown as fine.
    pub verdict: Option<Verdict>,
    pub value: Msg,
    /// Technical rows (adapters, routes, log lines): redacted, not localized.
    pub details: Vec<String>,
    /// Localized remarks (warnings, hints).
    pub notes: Vec<Msg>,
}

impl CheckItem {
    /// Item with an id, category, label key and verdict; value / details / notes added after.
    pub fn new(
        id: impl Into<String>,
        category: Category,
        label: &'static str,
        verdict: Option<Verdict>,
        value: Msg,
    ) -> Self {
        Self {
            id: id.into(),
            category,
            label: Msg::new(label),
            verdict,
            value,
            details: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// Replaces the details with `rows`, capped at `max` (see [`cap_rows`]).
    #[must_use]
    pub fn details(mut self, rows: Vec<String>, max: usize) -> Self {
        self.details = cap_rows(rows, max);
        self
    }

    /// Adds a localized remark.
    #[must_use]
    pub fn note(mut self, note: Msg) -> Self {
        self.notes.push(note);
        self
    }
}

/// A leak-check item as a row for [`ReportInputs::routing`]: `Info` stays informational,
/// `NotChecked` stays not checked, the localized details become notes.
impl From<&crate::leak::CheckItem> for CheckItem {
    fn from(item: &crate::leak::CheckItem) -> Self {
        Self {
            id: item.id.to_owned(),
            category: Category::Routing,
            label: item.label.clone(),
            verdict: item.status.verdict(),
            value: item.value.clone(),
            details: Vec::new(),
            notes: item.details.clone(),
        }
    }
}

/// The health-check report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemReport {
    pub ran_at: UnixMs,
    pub summary: Verdict,
    pub items: Vec<CheckItem>,
}

/// Summary rule: `Fail` iff an item of a critical category failed; else `Warn` if any item
/// warned or a non-critical one failed; else `Ok` when at least one item was judged `Ok`;
/// `NotChecked` when nothing was (informational and not-checked rows never count as fine).
pub fn summarize(items: &[CheckItem]) -> Verdict {
    let judged = |v: Verdict| items.iter().filter(move |i| i.verdict == Some(v));
    if judged(Verdict::Fail).any(|i| i.category.is_critical()) {
        Verdict::Fail
    } else if judged(Verdict::Warn).next().is_some() || judged(Verdict::Fail).next().is_some() {
        Verdict::Warn
    } else if judged(Verdict::Ok).next().is_some() {
        Verdict::Ok
    } else {
        Verdict::NotChecked
    }
}

/// At most `max` rows, then `... +K more` (the old report's `joinRows`).
pub fn cap_rows(mut rows: Vec<String>, max: usize) -> Vec<String> {
    if rows.len() > max {
        let more = rows.len() - max;
        rows.truncate(max);
        rows.push(format!("... +{more} more"));
    }
    rows
}

#[cfg(test)]
mod tests;
