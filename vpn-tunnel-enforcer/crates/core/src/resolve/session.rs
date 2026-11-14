//! The running session's server names (lab F11, p-follow3): resolved once per session start over
//! the direct chain (DoH / TCP to public resolvers, never the OS resolver) and kept until the
//! session ends. While a name is kept, every lookup of it in this process (pings, key checks,
//! the server detail, a restart's pin) gets the kept answer and nothing leaves the PC: the OS
//! resolver would send the server's name in clear text to the local network and the ISP. While a
//! session runs, [`super::resolve_server`] never falls back to the OS resolver either.
//!
//! speed3 S3-09 (a): a session's names stay answerable for [`RECENT_FOR`] after it ended
//! (memory only), so a reconnect plans its upstream without a lookup. They belong to the
//! Windows user whose session it was: the helper service serves every user of the PC and
//! names the one whose request runs ([`owned_by`]); nobody named, nothing is kept or answered.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::time::Instant;
use vpnte_base::types::UnixMs;

use super::{ResolveError, chain, last_known, server};
use crate::net::Host;

/// How long the names of an ended session answer lookups. Never longer: a stale address is a
/// dial target and, for a native key, the TUN's route exclusion for a whole session.
pub const RECENT_FOR: Duration = Duration::from_secs(600);

/// The session that runs (its start), whose it is, and the names kept for it.
struct Kept {
    started: UnixMs,
    owner: Option<String>,
    names: HashMap<String, Vec<IpAddr>>,
}

static KEPT: Mutex<Option<Kept>> = Mutex::new(None);

/// One owner's names of ended sessions, with the moment their session ended.
type Recent = HashMap<String, (Vec<IpAddr>, Instant)>;

/// [`Recent`] per owner.
static RECENT: Mutex<Option<HashMap<String, Recent>>> = Mutex::new(None);

type OwnerOf = Box<dyn Fn() -> Option<String> + Send + Sync>;

static OWNER: OnceLock<OwnerOf> = OnceLock::new();

/// Whose names this process keeps and answers: the helper service names the Windows user whose
/// request runs (his SID). Without it the process serves one user (the app). Set once.
pub fn owned_by(owner: impl Fn() -> Option<String> + Send + Sync + 'static) {
    let _ = OWNER.set(Box::new(owner));
}

fn owner() -> Option<String> {
    OWNER.get().map_or(Some(String::new()), |of| of())
}

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

/// The session ended: its names answer for [`RECENT_FOR`] more (S3-09 (a)), then lookups take
/// their usual way again.
pub fn end_session() {
    let Some(ended) = KEPT.lock().take() else {
        return;
    };
    let Some(owner) = ended.owner else {
        return;
    };
    let now = Instant::now();
    let mut recent = RECENT.lock();
    let names = recent.get_or_insert_default().entry(owner).or_default();
    names.retain(|_, (_, at)| at.elapsed() < RECENT_FOR);
    names.extend(ended.names.into_iter().map(|(n, addrs)| (n, (addrs, now))));
}

/// The names of `owner`'s ended sessions go («Забыть меня»; speed3 H3, the helper service).
pub fn forget(owner: &str) {
    if let Some(recent) = RECENT.lock().as_mut() {
        recent.remove(owner);
    }
}

/// A start that dialled `names` failed at the dial or the exit proof: what this process kept or
/// remembered of them goes, so the next start asks the resolvers (S3-09 (e)).
pub fn drop_names(names: &[String]) {
    if let Some(kept) = KEPT.lock().as_mut() {
        kept.names.retain(|n, _| !names.contains(n));
    }
    drop_of(owner().as_deref(), names);
}

fn drop_of(owner: Option<&str>, names: &[String]) {
    let Some(owner) = owner else {
        return;
    };
    if let Some(mine) = RECENT.lock().as_mut().and_then(|r| r.get_mut(owner)) {
        mine.retain(|n, _| !names.contains(n));
    }
}

/// The answer an ended session of the current owner left for `name`, while it is recent.
pub(super) fn recent(name: &str) -> Option<Vec<IpAddr>> {
    recent_of(owner().as_deref(), name)
}

fn recent_of(owner: Option<&str>, name: &str) -> Option<Vec<IpAddr>> {
    let mut recent = RECENT.lock();
    let mine = recent.as_mut()?.get_mut(owner?)?;
    match mine.get(name) {
        Some((addrs, at)) if at.elapsed() < RECENT_FOR => Some(addrs.clone()),
        Some(_) => {
            mine.remove(name);
            None
        }
        None => None,
    }
}

/// A recent answer for `name` would be used now (the runtime's start tests read it).
pub fn remembers(name: &str) -> bool {
    recent(name).is_some()
}

/// The session that started at `started` dials the names its start resolved itself (`answers`):
/// they are kept for it without a second lookup, like [`keep_for_session`]'s.
pub fn keep_resolved(started: UnixMs, answers: &[(String, Vec<IpAddr>)]) {
    begin(started);
    for (name, addrs) in answers {
        if let (Ok(Host::Name(name)), false) = (Host::parse(name), addrs.is_empty()) {
            keep(started, name.as_str(), addrs.clone());
        }
    }
}

/// Remembers `addrs` for `name` as if a session had just used them (S3-09 (b): the app's own
/// lookup of the selected server, over the foreign IP-literal resolvers only).
pub fn remember(name: &str, addrs: Vec<IpAddr>) {
    remember_of(owner(), name, addrs);
}

fn remember_of(owner: Option<String>, name: &str, addrs: Vec<IpAddr>) {
    let (Some(owner), Ok(Host::Name(name)), false) = (owner, Host::parse(name), addrs.is_empty())
    else {
        return;
    };
    let mut recent = RECENT.lock();
    let mine = recent.get_or_insert_default().entry(owner).or_default();
    mine.insert(name, (addrs, Instant::now()));
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
            owner: owner(),
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

#[cfg(test)]
mod tests;
