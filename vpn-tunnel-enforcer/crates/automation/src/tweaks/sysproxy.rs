//! The per-user system proxy as a Soft-mode tweak (NOADMIN §2): while Soft is on, WinINet's
//! default connection names the engine's loopback mixed inbound for every protocol, loopback and
//! local names go direct, and the setup script and auto-detection are off (either would take
//! precedence over the proxy). The whole settings block is one journal value, so the baseline is
//! restored exactly and a change the user made to any part of it meanwhile keeps all of it.
//! Programs that ignore the system proxy go direct; Soft never claims more than that.
//!
//! Beside loopback and local names the bypass list holds the entries of «Не через прокси»
//! (RU-2026 item 14 a-b: the user's own list and the routing's certain-direct names, built by
//! `vpnte_engine::routing::bypass`). The app keeps them current with [`set_bypass`]; each apply
//! takes them as the session's list, which is journalled with the rest of the value, and a
//! running session follows a change ([`changes`]): the engine re-reads the rules at every
//! restart, and an entry the rules no longer justify must not outlive one (owner answer 4).
use std::io;
use std::sync::LazyLock;

use parking_lot::Mutex;
use tokio::sync::watch;
use vpnte_core::net::HostPort;
use vpnte_winnet::sysproxy::{self, ProxyConfig};

use super::env::os_error;
use super::journal::{Feature, Target, Val};

/// The bypass list while Soft is on: the proxy itself and local names never go through it. No
/// `127.*`: Chromium reads a glob as a host-name pattern, so `127.0.0.1.t.example` would leave
/// around the proxy; Chromium bypasses all of loopback on its own, and the engine sends the rest
/// of `127.0.0.0/8` direct.
pub const BYPASS: &str = "localhost;127.0.0.1;[::1];<local>";

/// Longest exception list Windows keeps (IEAK 11, Proxy Settings page: 2064 characters).
pub const MAX_OVERRIDE: usize = 2064;

/// Longest journal text admitted for the settings (corporate bypass lists run to kilobytes).
const MAX_TEXT: usize = 64 * 1024;

/// Longest `NO_PROXY` text Soft writes: the journal must also hold the user's own value.
pub(super) const MAX_NO_PROXY: usize = 32 * 1024;

/// Entries beside the local ones, in each reader's syntax.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bypass {
    /// WinINet `ProxyOverride` items, after [`BYPASS`].
    pub proxy_override: Vec<String>,
    /// `NO_PROXY` items, after [`super::env::NO_PROXY`].
    pub no_proxy: Vec<String>,
}

/// The list for the next apply and the one the current session took. Process-wide because the
/// Soft session API has no list of its own: the app sets it from settings and rules, Soft takes
/// it at each apply.
#[derive(Debug, Default)]
struct Lists {
    next: Bypass,
    taken: Bypass,
}

impl Lists {
    /// Makes the next list the session's; until the next apply [`applied`] reads back what was
    /// written, so the session never looks taken over by a list that merely changed.
    fn take(&mut self) -> Bypass {
        self.taken = self.next.clone();
        self.taken.clone()
    }

    /// Sets the next list; `true` when it differs.
    fn set(&mut self, list: Bypass) -> bool {
        let changed = self.next != list;
        self.next = list;
        changed
    }
}

const NONE: Bypass = Bypass {
    proxy_override: Vec::new(),
    no_proxy: Vec::new(),
};

static LISTS: Mutex<Lists> = Mutex::new(Lists {
    next: NONE,
    taken: NONE,
});

/// Counts the changes of the next list (a running session's follower waits on it).
static CHANGES: LazyLock<watch::Sender<u64>> = LazyLock::new(|| watch::Sender::new(0));

/// Sets the entries of the next Soft apply; a running session is told through [`changes`].
/// `true` when the list changed.
pub fn set_bypass(list: Bypass) -> bool {
    let changed = LISTS.lock().set(list);
    if changed {
        CHANGES.send_modify(|n| *n = n.wrapping_add(1));
    }
    changed
}

/// Wakes on each change of the next list.
pub fn changes() -> watch::Receiver<u64> {
    CHANGES.subscribe()
}

/// The entries the current Soft session took (empty before the first apply).
pub fn taken() -> Bypass {
    LISTS.lock().taken.clone()
}

/// The entries of the next apply (a running session compares its journalled values with them).
pub fn next() -> Bypass {
    LISTS.lock().next.clone()
}

/// `base` followed by the items it does not hold yet, joined with `sep`, at most `max` long.
pub(super) fn join(base: &str, sep: char, items: &[String], max: usize) -> String {
    let mut text = base.to_owned();
    for item in items {
        if base.split(sep).any(|b| b == item) {
            continue;
        }
        if text.len() + 1 + item.len() > max {
            tracing::warn!(left = items.len(), "bypass list over the size limit cut");
            break;
        }
        text.push(sep);
        text.push_str(item);
    }
    text
}

/// Reads and writes the system proxy; production uses [`WinInet`], tests a fake (no test may
/// change the real setting: this machine's own network depends on it).
pub trait SystemProxy: Send + Sync + std::fmt::Debug {
    /// The current settings; `Err` = cannot tell.
    fn read(&self) -> io::Result<ProxyConfig>;
    /// Writes every field and notifies running programs.
    fn write(&self, config: &ProxyConfig) -> io::Result<()>;
}

/// The real per-user settings (`vpnte_winnet::sysproxy`).
#[derive(Debug, Clone, Copy, Default)]
pub struct WinInet;

impl SystemProxy for WinInet {
    fn read(&self) -> io::Result<ProxyConfig> {
        sysproxy::read().map_err(os_error)
    }
    fn write(&self, config: &ProxyConfig) -> io::Result<()> {
        sysproxy::write(config).map_err(os_error)
    }
}

/// What Soft mode writes for `addr` (the engine's mixed inbound, which also speaks HTTP: WinINet
/// has no SOCKS5, so the address is named as an HTTP proxy whatever the session's proxy kind),
/// with the session's bypass entries ([`taken`]).
pub fn applied(addr: &HostPort) -> ProxyConfig {
    applied_with(addr, &taken())
}

/// [`applied`] with the given entries.
pub fn applied_with(addr: &HostPort, list: &Bypass) -> ProxyConfig {
    ProxyConfig {
        use_proxy: true,
        server: addr.to_string(),
        bypass: join(BYPASS, ';', &list.proxy_override, MAX_OVERRIDE),
        use_pac: false,
        pac_url: String::new(),
        auto_detect: false,
    }
}

/// The journal step for `addr`; takes the next bypass list as the session's (call before
/// `env::plan`, which writes the same list into `NO_PROXY`).
pub fn plan(addr: &HostPort) -> Vec<(Feature, Target, Val)> {
    let list = LISTS.lock().take();
    vec![(
        Feature::SoftProxy,
        Target::SystemProxy,
        encode(&applied_with(addr, &list)),
    )]
}

/// The journal form: JSON with the struct's fixed field order, so equal settings are equal values.
pub fn encode(config: &ProxyConfig) -> Val {
    // Plain bools and strings: serializing cannot fail.
    Val::Text(serde_json::to_string(config).expect("plain data serializes"))
}

/// Back from the journal form; `None` for anything else.
pub fn decode(value: &Val) -> Option<ProxyConfig> {
    match value {
        Val::Text(text) if text.len() <= MAX_TEXT => serde_json::from_str(text).ok(),
        _ => None,
    }
}

/// Backend read of [`Target::SystemProxy`].
pub(crate) fn read(proxy: &dyn SystemProxy) -> io::Result<Val> {
    proxy.read().map(|config| encode(&config))
}

/// Backend write of [`Target::SystemProxy`]; nothing is ever created.
pub(crate) fn write(proxy: &dyn SystemProxy, value: &Val) -> io::Result<bool> {
    let config = decode(value)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a system proxy value"))?;
    proxy.write(&config).map(|()| false)
}

#[cfg(test)]
mod tests;
