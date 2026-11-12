//! VPN server names: the chain first (it sees through poisoning), the OS resolver when every
//! public resolver is cut off (mobile whitelists leave the ISP's own DNS), and the addresses the
//! name had last time when all of that fails (ru-2026 §2.8: "last-known-good IP cache").
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use vpnte_base::Msg;
use vpnte_base::types::{UnixMs, now_ms};

use super::chain::{Chain, Transport, block_page};
use super::{MEMORY_TTL, ResolveError, filtered};

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

/// What is remembered of a name.
struct Entry {
    addrs: Vec<IpAddr>,
    /// Order stamp of the last update (the oldest goes first at capacity).
    order: u64,
    at: UnixMs,
    /// Answered by the chain (public resolvers asked directly), not only by the OS resolver,
    /// whose answer may be an ISP stub page or a captive portal.
    verified: bool,
}

/// The last good addresses per server name. Process memory first; `resolve::memory` writes the
/// chain-verified ones to a sealed document and seeds them back at the next start, so a cold
/// start in a DNS-blocked network still has something to dial. Nothing older than
/// [`MEMORY_TTL`] is ever handed out, however long the process runs.
#[derive(Default)]
pub(super) struct LastKnown {
    names: Mutex<HashMap<String, Entry>>,
    stamp: AtomicU64,
}

impl LastKnown {
    /// The chain's answer for `name`: replaces whatever was known.
    pub(super) fn remember(&self, name: &str, addrs: &[IpAddr]) {
        self.insert(name, addrs.to_vec(), now_ms(), true);
    }

    /// An OS-resolver answer taken while the chain failed: kept for this run only, and never
    /// over a chain-verified address (a forged answer must not replace a good one).
    pub(super) fn remember_unverified(&self, name: &str, addrs: &[IpAddr]) {
        if self.names.lock().get(name).is_some_and(|e| e.verified) {
            return;
        }
        self.insert(name, addrs.to_vec(), now_ms(), false);
    }

    fn insert(&self, name: &str, addrs: Vec<IpAddr>, at: UnixMs, verified: bool) {
        let order = self.stamp.fetch_add(1, Ordering::Relaxed);
        let mut names = self.names.lock();
        if names.len() >= CAPACITY && !names.contains_key(name) {
            let oldest = names
                .iter()
                .min_by_key(|(_, e)| e.order)
                .map(|(name, _)| name.clone());
            if let Some(oldest) = oldest {
                names.remove(&oldest);
            }
        }
        let entry = Entry {
            addrs,
            order,
            at,
            verified,
        };
        names.insert(name.to_owned(), entry);
    }

    /// The remembered addresses that `keep` accepts (the caller's filter may be stricter than
    /// the one they were stored under), unless they are older than [`MEMORY_TTL`].
    pub(super) fn recall(&self, name: &str, keep: &impl Fn(IpAddr) -> bool) -> Option<Vec<IpAddr>> {
        let addrs = {
            let names = self.names.lock();
            let entry = names.get(name)?;
            if !fresh(entry.at, now_ms()) {
                return None;
            }
            entry.addrs.clone()
        };
        filtered(addrs, keep).ok()
    }

    /// The chain-verified entries as `(name, addresses, learned at)`, oldest first (what the
    /// document stores).
    pub(super) fn entries(&self) -> Vec<(String, Vec<IpAddr>, UnixMs)> {
        let names = self.names.lock();
        let mut all: Vec<_> = names.iter().filter(|(_, e)| e.verified).collect();
        all.sort_by_key(|(_, e)| e.order);
        all.into_iter()
            .map(|(name, e)| (name.clone(), e.addrs.clone(), e.at))
            .collect()
    }

    /// Takes stored entries in (oldest first); a name already learned in this run is kept.
    pub(super) fn seed(&self, entries: Vec<(String, Vec<IpAddr>, UnixMs)>) {
        for (name, addrs, at) in entries {
            if !self.names.lock().contains_key(&name) && !addrs.is_empty() {
                self.insert(&name, addrs, at, true);
            }
        }
    }
}

/// `at` is within [`MEMORY_TTL`] of `now`.
pub(super) fn fresh(at: UnixMs, now: UnixMs) -> bool {
    let ttl = UnixMs::try_from(MEMORY_TTL.as_millis()).unwrap_or(UnixMs::MAX);
    now.saturating_sub(at) <= ttl
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
        Ok(addrs) => Ok((addrs, true)),
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
            os.map(|addrs| (addrs, false))
                .map_err(|os| if err == ResolveError::Failed { os } else { err })
        }
    };
    match live {
        Ok((addrs, verified)) => {
            if verified {
                cache.remember(name, &addrs);
            } else {
                cache.remember_unverified(name, &addrs);
            }
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
