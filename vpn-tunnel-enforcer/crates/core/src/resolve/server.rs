//! VPN server names: the chain first (it sees through poisoning), the OS resolver when every
//! public resolver is cut off (mobile whitelists leave the ISP's own DNS), and the addresses the
//! name had last time when all of that fails (ru-2026 §2.8: "last-known-good IP cache").
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use vpnte_base::Msg;

use super::chain::{Chain, Transport, block_page};
use super::{ResolveError, filtered};

/// Names remembered at most; the one stored longest ago goes first.
const CAPACITY: usize = 256;

/// The addresses of a VPN server name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAddrs {
    /// Deduplicated, IPv4 first, all accepted by the caller's filter.
    pub addrs: Vec<IpAddr>,
    /// Every live lookup failed: these are the addresses the name had last time.
    pub last_known: bool,
}

impl ServerAddrs {
    /// What the user should be told: a bridged lookup is never silent.
    pub fn warning(&self) -> Option<Msg> {
        self.last_known
            .then(|| Msg::new("core.net.resolveLastKnown"))
    }
}

/// The last good addresses per server name, for the lifetime of the process (no document
/// stores DNS answers; a restart starts empty).
#[derive(Default)]
pub(super) struct LastKnown {
    /// Addresses per name with the stamp of their last update.
    names: Mutex<HashMap<String, (Vec<IpAddr>, u64)>>,
    stamp: AtomicU64,
}

impl LastKnown {
    pub(super) fn remember(&self, name: &str, addrs: &[IpAddr]) {
        let stamp = self.stamp.fetch_add(1, Ordering::Relaxed);
        let mut names = self.names.lock();
        if names.len() >= CAPACITY && !names.contains_key(name) {
            let oldest = names
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(name, _)| name.clone());
            if let Some(oldest) = oldest {
                names.remove(&oldest);
            }
        }
        names.insert(name.to_owned(), (addrs.to_vec(), stamp));
    }

    /// The remembered addresses that `keep` accepts (the caller's filter may be stricter than
    /// the one they were stored under).
    pub(super) fn recall(&self, name: &str, keep: &impl Fn(IpAddr) -> bool) -> Option<Vec<IpAddr>> {
        let addrs = self.names.lock().get(name)?.0.clone();
        filtered(addrs, keep).ok()
    }
}

/// `resolve_server` with its parts passed in. `name` is a parsed host name; `system` is the
/// bounded OS lookup.
pub(super) async fn server<T: Transport, F>(
    name: &str,
    keep: &impl Fn(IpAddr) -> bool,
    chain: &Chain<T>,
    cache: &LastKnown,
    system: impl FnOnce() -> F,
) -> Result<ServerAddrs, ResolveError>
where
    F: Future<Output = Result<Vec<IpAddr>, ResolveError>>,
{
    let live = match chain.resolve(name, keep).await {
        Ok(addrs) => Ok(addrs),
        Err(err) => {
            tracing::warn!(error = %err, "public resolvers gave no server address; asking the OS resolver");
            let os = match system().await {
                Ok(addrs) if !addrs.is_empty() && addrs.iter().all(|ip| block_page(*ip)) => {
                    Err(ResolveError::Poisoned)
                }
                Ok(addrs) => filtered(
                    addrs.into_iter().filter(|ip| !block_page(*ip)).collect(),
                    keep,
                ),
                Err(os) => Err(os),
            };
            // The OS resolver cannot tell a forged NXDOMAIN from a real one: the chain's
            // verdict stands unless the chain merely failed.
            os.map_err(|os| if err == ResolveError::Failed { os } else { err })
        }
    };
    match live {
        Ok(addrs) => {
            cache.remember(name, &addrs);
            Ok(ServerAddrs {
                addrs,
                last_known: false,
            })
        }
        // A real answer the caller refuses is not a DNS failure to bridge.
        Err(ResolveError::Filtered) => Err(ResolveError::Filtered),
        Err(err) => match cache.recall(name, keep) {
            Some(addrs) => {
                tracing::warn!(error = %err, "server name unresolvable; using its last known address");
                Ok(ServerAddrs {
                    addrs,
                    last_known: true,
                })
            }
            None => Err(err),
        },
    }
}

#[cfg(test)]
mod tests;
