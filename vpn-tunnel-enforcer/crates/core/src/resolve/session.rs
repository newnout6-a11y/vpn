//! The running session's server names (lab F11, p-follow3): resolved once per session start over
//! the direct chain (DoH / TCP to public resolvers, never the OS resolver) and kept until the
//! session ends. While a name is kept, every lookup of it in this process (pings, key checks,
//! the server detail, a restart's pin) gets the kept answer and nothing leaves the PC: the OS
//! resolver would send the server's name in clear text to the local network and the ISP. While a
//! session runs, [`super::resolve_server`] never falls back to the OS resolver either.
use std::collections::HashMap;
use std::net::IpAddr;

use parking_lot::Mutex;
use vpnte_base::types::UnixMs;

use super::{ResolveError, chain, last_known, server};
use crate::net::Host;

/// The session that runs (its start) and the names kept for it.
struct Kept {
    started: UnixMs,
    names: HashMap<String, Vec<IpAddr>>,
}

static KEPT: Mutex<Option<Kept>> = Mutex::new(None);

/// The session that started at `started` dials `names`: each one not kept yet is resolved over
/// the chain (its last known address when the chain fails; never the OS resolver) and kept for
/// the session. A new start forgets the names of the one before. Names that give no address stay
/// unkept (their lookups take the usual way).
pub async fn keep_for_session(started: UnixMs, names: &[String]) {
    begin(started);
    for name in names {
        // A literal address needs no lookup.
        let Ok(Host::Name(name)) = Host::parse(name) else {
            continue;
        };
        let name = name.as_str();
        if kept(name).is_some() {
            continue;
        }
        let no_os = || async { Err(ResolveError::Failed) };
        match server::server(name, &|_| true, chain(), last_known(), no_os).await {
            Ok(found) => keep(started, name, found.addrs),
            Err(err) => tracing::debug!(error = %err, "session server name not kept"),
        }
    }
}

/// The session ended: lookups take their usual way again.
pub fn end_session() {
    *KEPT.lock() = None;
}

/// A session runs (kept names or not).
pub(super) fn running() -> bool {
    KEPT.lock().is_some()
}

/// The kept answer for `name`, while its session runs.
pub(super) fn kept(name: &str) -> Option<Vec<IpAddr>> {
    KEPT.lock().as_ref()?.names.get(name).cloned()
}

fn begin(started: UnixMs) {
    let mut held = KEPT.lock();
    if held.as_ref().is_none_or(|k| k.started != started) {
        *held = Some(Kept {
            started,
            names: HashMap::new(),
        });
    }
}

/// Keeps `addrs` for `name` in the session of `started` (a lookup that ended after its session
/// did is dropped).
fn keep(started: UnixMs, name: &str, addrs: Vec<IpAddr>) {
    if let Some(k) = KEPT.lock().as_mut().filter(|k| k.started == started) {
        k.names.insert(name.to_owned(), addrs);
    }
}

#[cfg(test)]
pub(super) fn keep_for_test(started: UnixMs, name: &str, addrs: Vec<IpAddr>) {
    begin(started);
    keep(started, name, addrs);
}
