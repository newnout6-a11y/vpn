//! The start page's quiet network banner (RU audit item 9): while the latest network check of
//! the current network found a restriction, one line names the most limiting one. Pure: the
//! app supplies the modes (`vpnte_probes::netmode::Mode`, same names) and drops them when the
//! network changes.
use vpnte_base::Msg;

/// A restriction the network check can find, most limiting first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NetMode {
    /// Only whitelisted Russian hosts are reachable.
    Whitelist,
    /// Foreign transfers freeze after ~16 KB.
    Freeze,
    /// A server of the list has its address banned.
    ServerBlocked,
    /// QUIC / UDP is cut.
    UdpBlocked,
    /// DoH by name is cut (the app falls back on its own).
    DohBlocked,
}

impl NetMode {
    fn key(self) -> &'static str {
        match self {
            NetMode::Whitelist => "whitelist",
            NetMode::Freeze => "freeze",
            NetMode::ServerBlocked => "serverBlocked",
            NetMode::UdpBlocked => "udpBlocked",
            NetMode::DohBlocked => "dohBlocked",
        }
    }
}

/// The banner's two lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetBanner {
    pub mode: NetMode,
    pub title: Msg,
    pub body: Msg,
}

/// The banner for the modes found (any order); `None` when nothing limits the network.
pub fn net_banner(modes: &[NetMode]) -> Option<NetBanner> {
    let mode = modes.iter().min().copied()?;
    Some(NetBanner {
        mode,
        title: Msg::new(format!("view.netmode.{}.title", mode.key())),
        body: Msg::new(format!("view.netmode.{}.body", mode.key())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_locales::{assert_resolves, catalogs};

    #[test]
    fn the_most_limiting_mode_is_named() {
        assert_eq!(net_banner(&[]), None);
        let b = net_banner(&[NetMode::UdpBlocked, NetMode::Whitelist]).unwrap();
        assert_eq!(b.mode, NetMode::Whitelist);
        assert_eq!(b.title.key, "view.netmode.whitelist.title");
        let b = net_banner(&[NetMode::DohBlocked, NetMode::Freeze]).unwrap();
        assert_eq!(b.mode, NetMode::Freeze);
    }

    #[test]
    fn every_banner_resolves() {
        let catalogs = catalogs();
        for mode in [
            NetMode::Whitelist,
            NetMode::Freeze,
            NetMode::ServerBlocked,
            NetMode::UdpBlocked,
            NetMode::DohBlocked,
        ] {
            let b = net_banner(&[mode]).unwrap();
            assert_resolves(&b.title, &catalogs);
            assert_resolves(&b.body, &catalogs);
        }
    }
}
