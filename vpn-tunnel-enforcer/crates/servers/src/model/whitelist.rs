//! Whitelist evidence of a row (RU mobile networks, Nov 2026): on a mobile network that passes
//! only whitelisted Russian addresses a foreign server is unreachable over any protocol, so the
//! automatic choice tries first what is known to pass. Known = the user's own mark, or a server
//! that carried at least 64 KiB while the network was in whitelist mode (learned, per network).
use serde::{Deserialize, Serialize};
use vpnte_base::types::UnixMs;

use super::ServerRow;

/// Networks remembered per server: a phone's hotspot, a USB modem, a second operator.
pub const WHITELIST_NETWORKS_MAX: usize = 4;

/// What says a server passes a mobile whitelist; stored only while something does.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Whitelist {
    /// The user marked it «Работает в белых списках».
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub marked: bool,
    /// Where it carried >= 64 KiB while the network was in whitelist mode, newest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub worked: Vec<WorkedUnder>,
}

/// One network on which the server carried data while that network was in whitelist mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkedUnder {
    /// One-way tag of the network (no adapter, MAC or gateway in it); `None`: not known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// The `host:port` it worked at: a provider that moves the key elsewhere voids it.
    pub endpoint: String,
    pub at: UnixMs,
}

impl Whitelist {
    /// Nothing says anything: the row drops the field.
    pub fn is_empty(&self) -> bool {
        !self.marked && self.worked.is_empty()
    }

    /// It worked at `endpoint` on `network` at `at`: that network's entry moves to the front.
    pub fn record(&mut self, network: Option<String>, endpoint: String, at: UnixMs) {
        self.worked
            .retain(|w| !(w.network == network && w.endpoint == endpoint));
        self.worked.insert(
            0,
            WorkedUnder {
                network,
                endpoint,
                at,
            },
        );
        self.worked.truncate(WHITELIST_NETWORKS_MAX);
    }
}

impl ServerRow {
    /// `host:port` as whitelist evidence names it.
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.server.to_ascii_lowercase(), self.port)
    }

    /// The learned evidence that still applies (it worked at the row's current endpoint).
    pub fn worked_under_whitelist(&self) -> impl Iterator<Item = &WorkedUnder> {
        let endpoint = self.endpoint();
        (self.whitelist.iter())
            .flat_map(|w| w.worked.iter())
            .filter(move |w| w.endpoint == endpoint)
    }

    /// The user's mark or evidence that applies: the row counts as whitelist-ready.
    pub fn whitelist_ready(&self) -> bool {
        self.whitelist.as_ref().is_some_and(|w| w.marked)
            || self.worked_under_whitelist().next().is_some()
    }
}
