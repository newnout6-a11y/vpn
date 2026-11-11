//! Start inputs that do not depend on the capture: loopback listeners, the routing fragments,
//! the local-proxy address and the published session endpoints.
use std::net::Ipv4Addr;
use std::path::PathBuf;

use vpnte_base::types::{Creds, Loopback};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::net::HostPort;
use vpnte_engine::clash_api::ClashEndpoint;
use vpnte_engine::ports;
use vpnte_engine::routing::process::AppPath;
use vpnte_engine::routing::smart_ru::SmartRu;
use vpnte_engine::routing::{self, RoutingInputs};
use vpnte_engine::singbox_config::{Listeners, RoutingParts};
use vpnte_profiles::model::{Host, Kind, Profile};

use super::UserInputs;
use super::capture::CaptureProof;
use crate::api::{ProxyEndpoint, SessionEndpoints};

/// Fresh loopback listeners for one sing-box run: controller, `mixed-direct-in`, the probe
/// inbound for direct VPN modes and `dns-bootstrap-in` for the Xray slots. `taken` = ports the
/// session already uses (the Xray slots).
pub(super) fn listeners(
    direct_vpn: bool,
    slots: bool,
    taken: &[u16],
) -> AppResult<(ClashEndpoint, Listeners)> {
    let mut used = taken.to_vec();
    let clash = ClashEndpoint::allocate(&used)?;
    used.push(clash.port);
    let loopback = |used: &mut Vec<u16>, udp: bool| -> AppResult<u16> {
        let port = ports::alloc_port(udp, used)?;
        used.push(port);
        Ok(port)
    };
    let direct = Loopback {
        port: loopback(&mut used, false)?,
        creds: Some(ports::creds()),
    };
    let probe = if direct_vpn {
        Some(Loopback {
            port: loopback(&mut used, false)?,
            creds: Some(ports::creds()),
        })
    } else {
        None
    };
    let dns_bootstrap = if slots {
        Some(loopback(&mut used, true)?)
    } else {
        None
    };
    let listeners = Listeners {
        clash_port: clash.port,
        clash_secret: clash.secret.clone(),
        direct,
        probe,
        dns_bootstrap,
    };
    Ok((clash, listeners))
}

/// Every app-owned port of a run (a bind failure on one of them is retried once).
pub(super) fn own_ports(l: &Listeners) -> Vec<u16> {
    let mut ports = vec![l.clash_port, l.direct.port];
    ports.extend(l.probe.as_ref().map(|p| p.port));
    ports.extend(l.dns_bootstrap);
    ports
}

/// Strict `host:port` of a local upstream proxy.
pub(super) fn proxy_addr(raw: &str) -> AppResult<HostPort> {
    HostPort::parse(raw).map_err(|e| {
        AppError::validation(Msg::new("tunnel.runtime.proxyAddressInvalid")).with_source(e)
    })
}

/// The profile dials a host name (server or a WireGuard peer), so the engine needs its
/// bootstrap resolver.
pub(super) fn endpoint_is_hostname(p: &Profile) -> bool {
    let named = |h: &Host| matches!(h, Host::Domain(_));
    named(&p.server)
        || matches!(&p.kind, Kind::Wireguard(wg) if wg.peers.iter().any(|peer| named(&peer.host)))
}

/// Route / DNS fragments of this run plus the warnings the user must see.
pub(super) fn routing(
    user: &UserInputs,
    engine_paths: &[PathBuf],
    local_proxy: bool,
    physical_dns: &[Ipv4Addr],
    endpoint_is_hostname: bool,
) -> (RoutingParts, Vec<Msg>) {
    let engines: Vec<AppPath> = engine_paths
        .iter()
        .filter_map(|p| match AppPath::parse(&p.to_string_lossy()) {
            Ok(path) => Some(path),
            Err(e) => {
                tracing::warn!(error = %e, "engine path not usable in a process rule");
                None
            }
        })
        .collect();
    let split = user.split();
    let fragments = routing::build(&RoutingInputs {
        smart: SmartRu {
            enabled: user.smart_ru,
            maps_direct: user.smart_ru_maps_direct,
        },
        rule_set_dir: user.rule_set_dir.as_deref(),
        domain_rules: &user.domain_rules,
        split: &split,
        engine_paths: &engines,
        third_party_cores: local_proxy,
        dns: user.dns.as_ref(),
        physical_dns,
        endpoint_is_hostname,
    });
    let warnings = fragments.warnings.iter().map(|w| w.msg()).collect();
    (fragments.parts, warnings)
}

fn proxy_endpoint(l: &Loopback) -> ProxyEndpoint {
    let (user, pass) = l
        .creds
        .as_ref()
        .map(|Creds { user, pass }| (user.clone(), pass.clone()))
        .unwrap_or_default();
    ProxyEndpoint {
        port: l.port,
        user,
        pass,
    }
}

/// The plain data the app reads to observe the session.
pub(super) fn endpoints(
    clash: &ClashEndpoint,
    l: &Listeners,
    proof: &CaptureProof,
    logs: Vec<PathBuf>,
) -> SessionEndpoints {
    SessionEndpoints {
        clash_port: clash.port,
        clash_secret: clash.secret.clone(),
        direct: proxy_endpoint(&l.direct),
        probe: l.probe.as_ref().map(proxy_endpoint),
        tun_luid: proof.luid,
        tun_alias: proof.alias.clone(),
        proxy_port: proof.port,
        logs,
    }
}
