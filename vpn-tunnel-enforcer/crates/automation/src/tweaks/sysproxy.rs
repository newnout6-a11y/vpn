//! The per-user system proxy as a Soft-mode tweak (NOADMIN §2): while Soft is on, WinINet's
//! default connection names the engine's loopback mixed inbound for every protocol, loopback and
//! local names go direct, and the setup script and auto-detection are off (either would take
//! precedence over the proxy). The whole settings block is one journal value, so the baseline is
//! restored exactly and a change the user made to any part of it meanwhile keeps all of it.
//! Programs that ignore the system proxy go direct; Soft never claims more than that.
use std::io;

use vpnte_core::net::HostPort;
use vpnte_winnet::sysproxy::{self, ProxyConfig};

use super::env::os_error;
use super::journal::{Feature, Target, Val};

/// The bypass list while Soft is on: the proxy itself and local names never go through it.
pub const BYPASS: &str = "localhost;127.*;[::1];<local>";

/// Longest journal text admitted for the settings (corporate bypass lists run to kilobytes).
const MAX_TEXT: usize = 64 * 1024;

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
/// has no SOCKS5, so the address is named as an HTTP proxy whatever the session's proxy kind).
pub fn applied(addr: &HostPort) -> ProxyConfig {
    ProxyConfig {
        use_proxy: true,
        server: addr.to_string(),
        bypass: BYPASS.to_owned(),
        use_pac: false,
        pac_url: String::new(),
        auto_detect: false,
    }
}

/// The journal step for `addr`.
pub fn plan(addr: &HostPort) -> Vec<(Feature, Target, Val)> {
    vec![(
        Feature::SoftProxy,
        Target::SystemProxy,
        encode(&applied(addr)),
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
