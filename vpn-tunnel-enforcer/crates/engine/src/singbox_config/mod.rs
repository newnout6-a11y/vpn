//! The complete sing-box 1.14 configuration of one tunnel start: pure and deterministic.
//!
//! Inputs are plain data decided by the caller (tunnel runtime): the upstream (a local proxy,
//! the outbound / endpoint emitted from a typed profile, or the two authenticated Xray slots),
//! the capture (a TUN in the form agreed with the WFP layer, or an unprivileged loopback proxy
//! the app points the system proxy at), loopback listeners and the route / DNS fragments
//! built by `routing` (which also owns every process rule: own engines, third-party cores and
//! split-tunnel apps). Key order is stable (`serde_json` `preserve_order`), so the same inputs
//! always give the same text. Tags: [`crate::tags`].
mod dns;
mod inbounds;
mod outbounds;
mod route;
mod spoof;

#[cfg(test)]
mod check;
#[cfg(test)]
mod live;
#[cfg(test)]
mod proxy_tests;
#[cfg(test)]
mod tests;
/// Item 18: the started config carries the TLS tricks.
#[cfg(test)]
mod tricks_tests;

use std::fmt;
use std::net::Ipv4Addr;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vpnte_base::types::{AdaptiveMode, Creds, Loopback, ProxyKind};
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::net::HostPort;
use vpnte_profiles::emit_singbox::{
    EmitError, EmitPolicy, SingBoxFragment, block_quic, emit_singbox, udp_capable,
};
use vpnte_profiles::model::Profile;

pub use dns::usable_physical_dns;
pub use spoof::{SPOOF_KEYS, gate_spoof};

use crate::slot::{Slot, SlotEndpoint};
use crate::tags::{DIRECT_OUT, DNS_BOOTSTRAP, PROXY_OUT};

/// Everything that shapes the generated JSON.
#[derive(Debug, Clone)]
pub struct ConfigInputs {
    pub upstream: Upstream,
    pub capture: Capture,
    pub listeners: Listeners,
    pub routing: RoutingParts,
    /// Physical adapters' IPv4 resolvers in priority order (`winnet::adapters::physical_dns_v4`);
    /// the first usable one is the last step of the slot mode's bootstrap order.
    pub phys_dns: Vec<Ipv4Addr>,
}

/// Where `proxy-out` sends tunnelled traffic. `Debug` hides the fragment and credentials.
#[derive(Clone)]
pub enum Upstream {
    /// An external client's loopback proxy ("hard mode" over another VPN app).
    LocalProxy {
        addr: HostPort,
        kind: ProxyKind,
        creds: Option<Creds>,
    },
    /// A profile sing-box runs itself; build it with [`Upstream::native`].
    Native {
        fragment: SingBoxFragment,
        udp: UdpPolicy,
    },
    /// Two authenticated Xray SOCKS slots behind a selector (the endpoints the supervisor runs
    /// them on); `active` is the selector default.
    XraySlots {
        slots: [SlotEndpoint; 2],
        active: Slot,
        udp: UdpPolicy,
    },
}

impl Upstream {
    /// Emits `p` as `proxy-out` with hostname servers resolved by `dns-bootstrap`, and takes
    /// its UDP policy; `policy.domain_resolver` is overridden for that reason.
    pub fn native(p: &Profile, policy: &EmitPolicy) -> Result<Upstream, EmitError> {
        let policy = EmitPolicy {
            domain_resolver: Some(DNS_BOOTSTRAP.to_owned()),
            ..policy.clone()
        };
        Ok(Upstream::Native {
            fragment: emit_singbox(p, PROXY_OUT, &policy)?,
            udp: UdpPolicy::of(p),
        })
    }
}

impl fmt::Debug for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Upstream::LocalProxy { addr, kind, creds } => f
                .debug_struct("LocalProxy")
                .field("addr", addr)
                .field("kind", kind)
                .field("creds", creds)
                .finish(),
            // The fragment holds UUIDs, passwords and keys.
            Upstream::Native { udp, .. } => f
                .debug_struct("Native")
                .field("udp", udp)
                .finish_non_exhaustive(),
            Upstream::XraySlots { slots, active, udp } => f
                .debug_struct("XraySlots")
                .field("slots", slots)
                .field("active", active)
                .field("udp", udp)
                .finish(),
        }
    }
}

/// UDP behaviour of the upstream (tunnel-core §3.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpPolicy {
    /// The upstream relays UDP; `false` adds the all-UDP drop rule.
    pub udp: bool,
    /// Reject UDP/443 so browsers fall back from QUIC to TCP at once.
    pub block_quic: bool,
}

impl UdpPolicy {
    /// The policy of a profile as `emit_singbox` emits it.
    pub fn of(p: &Profile) -> Self {
        Self {
            udp: udp_capable(p),
            block_quic: block_quic(p),
        }
    }
}

/// How traffic reaches the engine (NOADMIN.md §2: `routing_mode` Hard = `Tun`, Soft = `Proxy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capture {
    /// The TUN inbound (`tun-in`); creating the adapter needs administrator rights.
    Tun(TunParams),
    /// A loopback `mixed` inbound (`proxy-in`, HTTP + SOCKS on `127.0.0.1:port`, no
    /// authentication) that needs no privileges. The app points the system proxy at it itself,
    /// reversibly: sing-box's `set_system_proxy` is never used. Nothing that exists only for the
    /// TUN is generated: no TUN DNS hijack and no physical interface binding.
    Proxy { port: u16 },
}

/// The TUN inbound. The WFP layer and the TUN must agree (review winnet-wfp D1 / D2): pass
/// `ipv6 = dns_hijack == false = Protection::session_guarded()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunParams {
    /// Adapter alias (`interface_name`); sing-tun derives the adapter GUID from it.
    pub alias: String,
    /// From [`select_mtu`].
    pub mtu: u16,
    /// Dual-stack TUN with the IPv6 reject rule. sing-tun's own hard "block all IPv6" WFP
    /// filter exists only for an IPv4-only TUN and would override the app's IPv6 LAN / DHCPv6 /
    /// exception permits, so dual-stack is right exactly while the app's WFP layer blocks
    /// non-TUN IPv6 itself; IPv4-only (sing-tun's block as the guard) otherwise.
    pub ipv6: bool,
    /// `dns_mode: hijack` (sing-tun adds a hard WFP block of remote port 53 outside the TUN)
    /// instead of `native`. Use `native` whenever the app's WFP layer blocks DNS itself: the
    /// hard block would override the app's resolver exceptions and engine permits.
    pub dns_hijack: bool,
    pub stack: TunStack,
}

/// TCP/IP stack of the TUN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TunStack {
    /// System TCP + gVisor UDP (field-proven). The system half accepts tunnelled TCP as
    /// inbound connections and relies on the Windows Firewall rule sing-tun adds itself.
    #[default]
    Mixed,
    /// Userspace only: no listener and no firewall rule. For machines whose Windows Firewall
    /// blocks inbound connections regardless of rules (more CPU).
    Gvisor,
}

impl TunStack {
    fn as_str(self) -> &'static str {
        match self {
            TunStack::Mixed => "mixed",
            TunStack::Gvisor => "gvisor",
        }
    }
}

/// App-owned loopback listeners of this start (ports from the shared allocator, fresh secrets).
/// `Debug` hides the controller secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Listeners {
    pub clash_port: u16,
    pub clash_secret: String,
    /// `mixed-direct-in`; credentials required.
    pub direct: Loopback,
    /// `live-check-in` (direct VPN modes only); credentials required.
    pub probe: Option<Loopback>,
    /// `dns-bootstrap-in` (Xray-slot mode: Xray resolves its server names through it).
    pub dns_bootstrap: Option<u16>,
}

impl fmt::Debug for Listeners {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Listeners")
            .field("clash_port", &self.clash_port)
            .field("direct", &self.direct)
            .field("probe", &self.probe)
            .field("dns_bootstrap", &self.dns_bootstrap)
            .finish_non_exhaustive()
    }
}

/// sing-box JSON fragments built by `routing::build` (each element one object), placed as is.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RoutingParts {
    /// Process rules (own engines, third-party cores, split-tunnel apps), right after the
    /// loopback inbound rules and before every other routing decision.
    pub process_rules: Vec<Value>,
    /// Domain / Smart RU route rules, after the UDP guards and the STUN pin.
    pub domain_rules: Vec<Value>,
    /// `route.rule_set` entries (local `.srs` only).
    pub rule_sets: Vec<Value>,
    /// DNS servers (`dns-remote` from the active profile, `dns-direct`); the builder adds the
    /// default `dns-remote` when it is missing and owns `dns-resolver` / `dns-bootstrap`.
    pub dns_servers: Vec<Value>,
    /// DNS rules, after the builder's own `dns-bootstrap-in` rule.
    pub dns_rules: Vec<Value>,
    /// «VPN только для выбранных приложений»: the apps that take the tunnel
    /// (`process_path_regex` values). `Some`: the route guards (QUIC and IPv6 rejects, the UDP
    /// drop, the STUN pins) apply to them alone, every other app leaves directly with its own
    /// QUIC, IPv6, UDP and STUN; `None`: every app takes the tunnel.
    pub listed_only: Option<Vec<String>>,
}

/// Why no configuration could be built: always a caller bug or inconsistent inputs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid Xray upstream slots: {0}")]
    InvalidSlots(&'static str),
    #[error("invalid loopback listeners: {0}")]
    InvalidListeners(&'static str),
    #[error("invalid TUN parameters: {0}")]
    InvalidTun(&'static str),
    #[error("unusable upstream: {0}")]
    BadUpstream(&'static str),
    #[error("invalid routing fragment: {0}")]
    BadRouting(String),
}

impl From<ConfigError> for AppError {
    fn from(err: ConfigError) -> Self {
        AppError::msg(ErrorKind::Internal, Msg::new("engine.config.invalid")).with_source(err)
    }
}

/// Builds the whole configuration (sing-box reads it from stdin).
pub fn build(i: &ConfigInputs) -> Result<Value, ConfigError> {
    let up = outbounds::upstream(&i.upstream)?;
    let mut inbounds = vec![match &i.capture {
        Capture::Tun(t) => inbounds::tun(t, &up.exclude)?,
        Capture::Proxy { port } => inbounds::proxy(*port),
    }];
    inbounds.extend(inbounds::listeners(i)?);
    let dns = dns::section(i, &up)?;
    let route = route::section(i, &up)?;
    let mut config = json!({
        "log": { "level": "info", "timestamp": true },
        "dns": dns,
        "inbounds": inbounds,
    });
    if !up.endpoints.is_empty() {
        config["endpoints"] = Value::Array(up.endpoints);
    }
    let mut outs = up.outbounds;
    outs.push(json!({ "type": "direct", "tag": DIRECT_OUT }));
    config["outbounds"] = Value::Array(outs);
    config["route"] = route;
    config["experimental"] = json!({
        "clash_api": {
            "external_controller": format!("127.0.0.1:{}", i.listeners.clash_port),
            "secret": i.listeners.clash_secret,
            "default_mode": "rule",
        }
    });
    Ok(config)
}

/// TUN MTU: 1280 for stealth / adaptive MTU compatibility, 1380 for public Wi-Fi
/// compatibility, else 1500.
pub fn select_mtu(stealth: bool, adaptive: AdaptiveMode, public_wifi: bool) -> u16 {
    if stealth || adaptive == AdaptiveMode::MtuCompatibility {
        1280
    } else if public_wifi {
        1380
    } else {
        1500
    }
}

/// SHA-256 over every input that shapes the JSON except the upstream's identity (profile,
/// addresses, slots), the TUN alias, the app-owned listener ports and secrets. The proxy-capture
/// port counts: the system proxy points at it. Meaningful between two Xray-slot inputs only (the
/// one upstream that switches without a restart): equal keys mean the running config can serve
/// the other slot; never a proof of OS or security state.
pub fn compat_key(i: &ConfigInputs) -> [u8; 32] {
    let upstream = match &i.upstream {
        Upstream::LocalProxy { kind, .. } => json!({ "kind": "local-proxy", "proxy": kind }),
        Upstream::Native { udp, .. } => {
            json!({ "kind": "native", "udp": udp.udp, "blockQuic": udp.block_quic })
        }
        Upstream::XraySlots { udp, .. } => {
            json!({ "kind": "xray-slots", "udp": udp.udp, "blockQuic": udp.block_quic })
        }
    };
    let capture = match &i.capture {
        Capture::Tun(t) => json!({
            "tun": {
                "mtu": t.mtu,
                "ipv6": t.ipv6,
                "dnsHijack": t.dns_hijack,
                "stack": t.stack.as_str(),
            }
        }),
        Capture::Proxy { port } => json!({ "proxy": { "port": port } }),
    };
    let r = &i.routing;
    let canonical = json!({
        "v": 2,
        "upstream": upstream,
        "capture": capture,
        "probe": i.listeners.probe.is_some(),
        "dnsBootstrapIn": i.listeners.dns_bootstrap.is_some(),
        "routing": {
            "process": r.process_rules,
            "domain": r.domain_rules,
            "ruleSets": r.rule_sets,
            "dnsServers": r.dns_servers,
            "dnsRules": r.dns_rules,
        },
        "physDns": i.phys_dns,
    });
    Sha256::digest(canonical.to_string().as_bytes()).into()
}

/// Every element of a routing fragment list must be a JSON object.
fn require_objects(list: &[Value], what: &str) -> Result<(), ConfigError> {
    match list.iter().position(|v| !v.is_object()) {
        Some(n) => Err(ConfigError::BadRouting(format!(
            "{what} #{n} is not an object"
        ))),
        None => Ok(()),
    }
}
