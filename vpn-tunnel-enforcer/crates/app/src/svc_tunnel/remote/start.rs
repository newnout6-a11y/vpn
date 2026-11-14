//! The service's typed start from the lifecycle's request: the upstream, the routing inputs the
//! app keeps (with the bytes of Smart RU's active lists, which the service checks again before it
//! uses them instead of its pinned ones) and the kill-switch settings with this session's level.
use std::net::SocketAddr;

use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_engine::routing::RoutingWarning;
use vpnte_engine::routing::rulesets::handover::RuleSetFiles;
use vpnte_service::proto::{RoutingInputs, SCOPE_PROTOCOL, ServerUpstream, TunnelStart, Upstream};
use vpnte_tunnel::api::{Mode, StartRequest, VpnProfile};
use vpnte_tunnel::runtime::UserInputs;
use vpnte_winnet::wfp::ProtectionSettings;

/// The routing part of the app's inputs (inactive splits stay here; the rule-set folder's files
/// travel, read here: about 0.8 MB of local files per start). The apps page's scope travels
/// with the app's own exe in it: the service is not the app.
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
        rule_sets: inputs.rule_set_dir.as_deref().and_then(RuleSetFiles::read),
        only_listed: inputs.only_listed.clone(),
    }
}

/// The warnings of the app's inactive split entries, which never reach the service
/// (appsplit-a1): worded for the scope the service runs, the apps page's one, or every app on
/// a service older than [`SCOPE_PROTOCOL`] (it drops the scope).
pub(super) fn inactive_warnings(inputs: &UserInputs, protocol: Option<u32>) -> Vec<Msg> {
    let scoped = inputs.only_listed.is_some() && protocol.is_some_and(|p| p >= SCOPE_PROTOCOL);
    let warning = if scoped {
        RoutingWarning::InactiveAppDirect
    } else {
        RoutingWarning::InactiveApp
    };
    inputs
        .split()
        .inactive
        .into_iter()
        .map(|a| warning(a).msg())
        .collect()
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

    /// appsplit-a1: an inactive app is worded for the scope the service runs: directly under
    /// the scope, in the tunnel without it or on a service that drops it (protocol 3).
    #[test]
    fn an_inactive_app_is_worded_for_the_scope_the_service_runs() {
        let mut inputs = UserInputs {
            split_inactive: vec![vpnte_tunnel::runtime::InactiveSplit {
                name: "Discord".into(),
                path: r"C:\Apps\Discord.exe".into(),
                missing: true,
            }],
            only_listed: Some(vec!["own".into()]),
            ..UserInputs::default()
        };
        let key = |inputs: &UserInputs, protocol| {
            let warnings = inactive_warnings(inputs, protocol);
            assert_eq!(warnings.len(), 1);
            let name = warnings[0].args.iter().find(|(k, _)| k == "name");
            assert_eq!(name.map(|(_, v)| v.as_str()), Some("Discord"));
            warnings[0].key.to_string()
        };
        let direct = "engine.routing.warn.appMissingDirect";
        assert_eq!(key(&inputs, Some(SCOPE_PROTOCOL)), direct);
        assert_eq!(key(&inputs, Some(3)), "engine.routing.warn.appMissing");
        inputs.only_listed = None;
        assert_eq!(
            key(&inputs, Some(SCOPE_PROTOCOL)),
            "engine.routing.warn.appMissing"
        );
        inputs.split_inactive.clear();
        assert!(inactive_warnings(&inputs, Some(SCOPE_PROTOCOL)).is_empty());
    }

    /// Re-check item 16: the apps page's scope travels with the routing inputs, the app's own
    /// exe in it; every app stays without one.
    #[test]
    fn the_scope_travels_with_the_routing_inputs() {
        let mut inputs = UserInputs {
            split_vpn: vec!["browser".into()],
            only_listed: Some(vec!["own".into()]),
            ..UserInputs::default()
        };
        let sent = routing(&inputs);
        assert_eq!(sent.only_listed, Some(vec!["own".to_owned()]));
        assert_eq!(sent.split_vpn, ["browser"]);
        inputs.only_listed = None;
        assert_eq!(routing(&inputs).only_listed, None);
    }

    /// Re-check item 16, end to end on the app side: with only the listed apps the store
    /// inputs carry this process's own exe (the regex the engine matches) and the service's
    /// start carries them; with every app, none.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_app_exe_joins_the_scope_of_the_store_inputs() {
        use std::sync::Arc;

        use vpnte_core::settings::AppScope;
        use vpnte_engine::routing::process::AppPath;
        use vpnte_tunnel::runtime::InputsSource;

        use crate::api_settings::test_support::{FakeTunnel, TempDir, backend};
        use crate::svc_tunnel::inputs::StoreInputs;

        let dir = TempDir::new("start-scope");
        let backend = backend(&dir, FakeTunnel::new(false));
        let source = StoreInputs {
            settings: backend.settings.clone(),
            rules: backend.rules.clone(),
            rule_sets: backend.rule_sets.clone(),
            always: Arc::default(),
        };
        assert_eq!(source.snapshot().await.expect("inputs").only_listed, None);
        backend
            .settings
            .update(|s| s.app_scope = AppScope::OnlyListed)
            .expect("saved");
        let inputs = source.snapshot().await.expect("inputs");
        let own = inputs.only_listed.clone().expect("the scope");
        let exe = std::env::current_exe().expect("exe");
        let regex = AppPath::parse(&exe.to_string_lossy())
            .expect("path")
            .regex();
        assert_eq!(own.first(), Some(&regex));
        assert_eq!(routing(&inputs).only_listed, Some(own));
    }

    /// Re-check item 12a: the active rule-set folder's files travel with the routing inputs
    /// (the service checks them again); an incomplete folder sends none.
    #[test]
    fn the_active_lists_travel_with_the_routing_inputs() {
        let resources =
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources"));
        let mut inputs = UserInputs {
            smart_ru: true,
            rule_set_dir: Some(resources.to_owned()),
            ..UserInputs::default()
        };
        let sent = routing(&inputs).rule_sets.expect("the bundled lists");
        assert_eq!(Some(sent), RuleSetFiles::read(resources));
        inputs.rule_set_dir = Some(resources.join("missing"));
        assert_eq!(routing(&inputs).rule_sets, None);
        inputs.rule_set_dir = None;
        assert_eq!(routing(&inputs).rule_sets, None);
    }
}
