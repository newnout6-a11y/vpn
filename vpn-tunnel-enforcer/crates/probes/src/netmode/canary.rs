//! The DNS canary (RU audit item 11): do the Windows resolver's queries end up at our engine?
//! Every session's sing-box runs `dns.strategy = ipv4_only` (engine `singbox_config::dns`), so
//! while our TUN captures DNS an AAAA question comes back empty. Asked for names that have
//! AAAA records everywhere, from the network only (no cache, no hosts file): any AAAA record
//! means another resolver answered — a path around the tunnel. Proxy (Soft) mode captures no
//! DNS at all; the caller reports that state instead of running the canary, never "protected".
use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use vpnte_base::Msg;
use vpnte_base::types::Verdict;

/// Names with A and AAAA records on every resolver (Yandex and Google run dual stack).
pub const CANARY_NAMES: [&str; 2] = ["ya.ru", "www.google.com"];
const LOOKUP_LIMIT: Duration = Duration::from_secs(4);

/// What the canary showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Canary {
    /// A answered and no AAAA came back: the answers are our engine's.
    Captured,
    /// AAAA records came back: a resolver other than our engine answered.
    Escaped,
    /// No A answer at all: nothing proven either way.
    NoAnswer,
    /// Proxy mode: the engine takes no DNS; programs ask the system resolver directly.
    NotCaptured,
}

impl Canary {
    /// The line the page shows (`probes.netmode.canary.*`).
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            Canary::Captured => "probes.netmode.canary.captured",
            Canary::Escaped => "probes.netmode.canary.escaped",
            Canary::NoAnswer => "probes.netmode.canary.noAnswer",
            Canary::NotCaptured => "probes.netmode.canary.notCaptured",
        })
    }

    /// As a check mark: only the captured state is a pass, proxy mode is never one.
    pub fn verdict(self) -> Verdict {
        match self {
            Canary::Captured => Verdict::Ok,
            Canary::Escaped => Verdict::Fail,
            Canary::NoAnswer | Canary::NotCaptured => Verdict::NotChecked,
        }
    }
}

/// The resolver the canary asks (the Windows DNS client in production, fakes in tests).
pub trait CanaryLookup: Send + Sync {
    /// Addresses of `name` (AAAA when `v6`), from the network only.
    fn lookup(
        &self,
        name: &str,
        v6: bool,
    ) -> impl Future<Output = Result<Vec<IpAddr>, String>> + Send;
}

/// The Windows DNS client with `DNS_QUERY_WIRE_ONLY`.
pub struct WireLookup;

impl CanaryLookup for WireLookup {
    async fn lookup(&self, name: &str, v6: bool) -> Result<Vec<IpAddr>, String> {
        crate::live_stages::wire_addrs(name.to_owned(), v6).await
    }
}

/// Runs the canary for TUN capture: A and AAAA of every [`CANARY_NAMES`] entry.
pub async fn dns_canary<L: CanaryLookup>(lookup: &L) -> Canary {
    let mut answered = false;
    for name in CANARY_NAMES {
        let ask = |v6| async move {
            timeout(LOOKUP_LIMIT, lookup.lookup(name, v6))
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default()
        };
        let (a, aaaa) = tokio::join!(ask(false), ask(true));
        if aaaa.iter().any(IpAddr::is_ipv6) {
            return Canary::Escaped;
        }
        answered |= !a.is_empty();
    }
    if answered {
        Canary::Captured
    } else {
        Canary::NoAnswer
    }
}
