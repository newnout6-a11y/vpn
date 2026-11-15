//! sing-box tags of the generated configuration: one vocabulary for the config builder, the
//! routing fragments, Clash API calls (selector group and members) and traffic attribution
//! (Clash `chains`).

/// The outbound (or selector / WireGuard endpoint) every tunnelled flow ends in; also the
/// Clash selector group in Xray-slot mode.
pub const PROXY_OUT: &str = "proxy-out";
/// Plain direct outbound for bypassed flows (real address).
pub const DIRECT_OUT: &str = "direct-out";
/// The TUN inbound.
pub const TUN_IN: &str = "tun-in";
/// Unauthenticated loopback mixed inbound of the proxy capture (`singbox_config::Capture::Proxy`):
/// the system proxy points at it.
pub const PROXY_IN: &str = "proxy-in";
/// Authenticated loopback mixed inbound that exits directly (pings, key checks, self-tests).
pub const DIRECT_IN: &str = "mixed-direct-in";
/// Authenticated loopback mixed inbound that always exits through `proxy-out` (live checks).
pub const PROBE_IN: &str = "live-check-in";
/// Loopback DNS inbound answered by the direct bootstrap resolver (Xray-slot mode).
pub const DNS_BOOTSTRAP_IN: &str = "dns-bootstrap-in";
/// Tags of the two Xray slot outbounds behind the `proxy-out` selector, in [`crate::slot::Slot`]
/// order.
pub const SLOT_TAGS: [&str; 2] = ["vpnte-upstream-a", "vpnte-upstream-b"];
/// Final DNS server (and `route.default_domain_resolver`); always through `proxy-out`.
pub const DNS_REMOTE: &str = "dns-remote";
/// Resolves hostname remote DNS servers, also through `proxy-out` (never circular).
pub const DNS_RESOLVER: &str = "dns-resolver";
/// Direct resolver for hostname upstream servers (no detour: the server's default dialer).
pub const DNS_BOOTSTRAP: &str = "dns-bootstrap";
/// Second step of the slot mode's bootstrap order (`dns-bootstrap-in`): DoH to Yandex by IP.
pub const DNS_BOOTSTRAP_YANDEX: &str = "dns-bootstrap-yandex";
/// Third step: DoH to Quad9 by IP.
pub const DNS_BOOTSTRAP_QUAD9: &str = "dns-bootstrap-quad9";
/// Fourth step: DoH to Google by IP.
pub const DNS_BOOTSTRAP_GOOGLE: &str = "dns-bootstrap-google";
/// Fifth step: DNS over TCP to Google.
pub const DNS_BOOTSTRAP_TCP: &str = "dns-bootstrap-tcp";
/// Last step: the physical adapter's resolver over UDP (when one is usable).
pub const DNS_BOOTSTRAP_ISP: &str = "dns-bootstrap-isp";
/// ISP-visible direct resolver of Smart RU / user "direct" domains (built by `routing`).
pub const DNS_DIRECT: &str = "dns-direct";
