//! The service's typed start from the lifecycle's request: the upstream, the routing inputs the
//! app keeps (Smart RU uses the service's own pinned rule sets) and the kill-switch settings with
//! this session's level.
use std::net::SocketAddr;

use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_service::proto::{RoutingInputs, ServerUpstream, TunnelStart, Upstream};
use vpnte_tunnel::api::{Mode, StartRequest, VpnProfile};
use vpnte_tunnel::runtime::UserInputs;
use vpnte_winnet::wfp::ProtectionSettings;

/// The routing part of the app's inputs (the rule-set folder and inactive splits stay here).
pub(super) fn routing(inputs: &UserInputs) -> RoutingInputs {
    RoutingInputs {
        smart_ru: inputs.smart_ru,
        smart_ru_maps_direct: inputs.smart_ru_maps_direct,
        domain_rules: inputs.domain_rules.clone(),
        split_direct: inputs.split_direct.clone(),
        split_vpn: inputs.split_vpn.clone(),
        dns: inputs.dns.clone(),
        public_wifi: inputs.public_wifi,
        stealth: inputs.stealth,
        auto_restart_on_crash: inputs.auto_restart_on_crash,
    }
}

pub(super) fn server(profile: &VpnProfile) -> ServerUpstream {
    ServerUpstream {
        id: profile.id.clone(),
        profile: (*profile.profile).clone(),
        device: profile.device,
        engine: profile.engine,
    }
}

/// `req` as the service's start; `protection` = the saved settings, the level is the session's.
pub(super) fn tunnel_start(
    req: &StartRequest,
    inputs: &UserInputs,
    protection: ProtectionSettings,
) -> AppResult<TunnelStart> {
    let upstream = match &req.mode {
        Mode::LocalProxy { addr, kind } => Upstream::LocalProxy {
            addr: addr.parse::<SocketAddr>().map_err(|_| {
                AppError::msg(
                    ErrorKind::Validation,
                    Msg::new("tunnel.runtime.proxyAddressInvalid"),
                )
            })?,
            kind: *kind,
        },
        Mode::DirectVpn { profile } => Upstream::Server(Box::new(server(profile))),
    };
    let mut routing = routing(inputs);
    routing.public_wifi = req.public_wifi;
    routing.stealth = req.stealth;
    Ok(TunnelStart {
        upstream,
        routing,
        protection: ProtectionSettings {
            level: req.kill_switch,
            ..protection
        },
        adaptive: req.adaptive,
        engine: req.engine,
        origin: req.origin,
    })
}

#[cfg(test)]
mod tests {
    use vpnte_base::types::{AdaptiveMode, EnginePref, KillSwitchLevel, ProxyKind};
    use vpnte_tunnel::api::{CaptureKind, Origin};

    use super::*;

    fn request(addr: &str) -> StartRequest {
        StartRequest {
            mode: Mode::LocalProxy {
                addr: addr.into(),
                kind: ProxyKind::Socks5,
            },
            capture: CaptureKind::Tun,
            kill_switch: KillSwitchLevel::Standard,
            public_wifi: true,
            stealth: false,
            adaptive: AdaptiveMode::default(),
            engine: EnginePref::Auto,
            origin: Origin::User,
        }
    }

    #[test]
    fn the_session_level_and_switches_win_over_the_saved_ones() {
        let inputs = UserInputs {
            smart_ru: true,
            stealth: true,
            ..UserInputs::default()
        };
        let start = tunnel_start(
            &request("127.0.0.1:10808"),
            &inputs,
            ProtectionSettings::default(),
        )
        .expect("start");
        assert_eq!(start.protection.level, KillSwitchLevel::Standard);
        assert!(start.routing.smart_ru && start.routing.public_wifi);
        assert!(!start.routing.stealth, "the request's stealth");
        assert!(matches!(start.upstream, Upstream::LocalProxy { .. }));
        let bad = tunnel_start(
            &request("localhost:1"),
            &inputs,
            ProtectionSettings::default(),
        );
        assert_eq!(bad.expect_err("not an address").kind, ErrorKind::Validation);
    }
}
