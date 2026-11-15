//! The engine contract of AT-12-001 ("CoreAdapter"): what each engine can do in this app, so a
//! caller asks the capability instead of the engine name. sing-box is the reference; every
//! deviation of the WP-12 lab engine mihomo is declared here and handled by the caller (the
//! tunnel refuses a TUN start for an engine without `tun_capture`, and an in-place switch needs
//! `selector_switch`). The conformance set in `core_adapter/tests.rs` runs the same lifecycle on
//! sing-box and mihomo.
use vpnte_base::types::Engine;

/// How an engine proves it is ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// A start line in its output (`sing-box started (`).
    LogMarker,
    /// The authenticated SOCKS5 handshake on its loopback listener (Xray slots).
    Socks,
    /// The SOCKS5 handshake, the keyed hop listening in the run and the controller answering
    /// with the run's secret (mihomo).
    SocksAndController,
}

/// What one engine does in this app (not what it could do elsewhere).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Runs AmneziaWG keys.
    pub amneziawg: bool,
    /// Runs the other key kinds (VLESS, Hysteria2, plain WireGuard, ...).
    pub other_kinds: bool,
    /// Can carry a proxy-capture (no administrator rights) session.
    pub proxy_capture: bool,
    /// Can carry a TUN (elevated) session.
    pub tun_capture: bool,
    /// Owns the session's loopback inbound, routing rules, DNS and Clash API statistics; an
    /// engine without it is chained behind sing-box, which keeps them.
    pub session_owner: bool,
    /// Clash API of its own (version, connections, traffic).
    pub controller: bool,
    /// The upstream changes in place behind a running session (sing-box's `proxy-out`
    /// selector over two staged instances); otherwise a server change restarts the session.
    pub selector_switch: bool,
    pub readiness: Readiness,
    /// Ends by itself on CTRL_BREAK (the graceful stop).
    pub graceful_stop: bool,
    /// Checks a config without running it (`check` / `-test` / `-t`).
    pub config_check: bool,
    /// Config only on stdin, never in a file.
    pub stdin_config: bool,
}

/// The capabilities of `engine` (sing-box first: the reference the others are compared with).
pub fn capabilities(engine: Engine) -> Capabilities {
    let sing_box = Capabilities {
        amneziawg: false,
        other_kinds: true,
        proxy_capture: true,
        tun_capture: true,
        session_owner: true,
        controller: true,
        selector_switch: false,
        readiness: Readiness::LogMarker,
        graceful_stop: true,
        config_check: true,
        stdin_config: true,
    };
    match engine {
        Engine::SingBox => sing_box,
        Engine::Xray => Capabilities {
            session_owner: false,
            controller: false,
            selector_switch: true,
            readiness: Readiness::Socks,
            ..sing_box
        },
        // Declared deviations: AmneziaWG only, chained behind sing-box (no session of its own),
        // no TUN chain yet (mihomo.exe would need a direct route and a WFP permit: not built),
        // one instance per session (a server change restarts it).
        Engine::Mihomo => Capabilities {
            amneziawg: true,
            other_kinds: false,
            tun_capture: false,
            session_owner: false,
            readiness: Readiness::SocksAndController,
            ..sing_box
        },
    }
}

#[cfg(test)]
mod tests;
