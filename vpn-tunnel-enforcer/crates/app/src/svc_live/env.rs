//! [`LiveEnv`] over the backend: the saved servers, our tunnel (runtime status, lifecycle snapshot
//! and session), the split-tunnel rules, the bundled engines and the geo switch. Every call is a
//! cheap read of in-memory state.
use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::watch;
use vpnte_base::types::{Creds, EnginePref, Loopback};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_engine::routing::RulesDoc;
use vpnte_engine::routing::process::{AppRule, SplitApp, SplitTarget};
use vpnte_probes::live::{
    EngineSetup, LiveEnv, ProfileTarget, SplitTunnelRules, TunnelState, TunnelView,
};
use vpnte_probes::live_stages::geo::OtherProfile;
use vpnte_servers::model::{ArchiveReason, ProfileId};
use vpnte_servers::store::Servers;
use vpnte_tunnel::api::{ProxyEndpoint, TunStatus};
use vpnte_tunnel::fsm::TunnelSnapshot;
use vpnte_tunnel::lifecycle::SessionView;

use crate::services::Engines;

/// The app side of the live check.
pub(crate) struct AppLiveEnv {
    pub servers: Arc<Servers>,
    pub settings: Arc<Store<Settings>>,
    pub rules: Arc<Store<RulesDoc>>,
    pub engines: Engines,
    pub status: watch::Receiver<TunStatus>,
    pub snapshot: watch::Receiver<TunnelSnapshot>,
    pub session: watch::Receiver<Option<SessionView>>,
}

impl LiveEnv for AppLiveEnv {
    fn profile(&self, id: &str) -> Option<ProfileTarget> {
        let row = self
            .servers
            .get(&ProfileId::from(id))
            .filter(|r| !r.archived_for(ArchiveReason::User))?;
        let profile = row.profile().ok()?;
        Some(ProfileTarget {
            // A key gone from its subscription is checked on its own, never in a batch.
            eligible: row.archived.is_none(),
            country: row.display_country().map(|c| c.as_str().to_owned()),
            device: row.device,
            id: row.id.0,
            profile,
        })
    }

    fn tunnel(&self) -> TunnelView {
        tunnel_view(
            &self.snapshot.borrow(),
            &self.status.borrow(),
            self.session.borrow().as_ref(),
        )
    }

    fn other_profiles(&self, except_id: Option<&str>) -> Vec<OtherProfile> {
        self.servers.read(|doc| {
            doc.profiles
                .iter()
                .filter(|r| Some(r.id.as_str()) != except_id)
                .filter(|r| !r.archived_for(ArchiveReason::User))
                .map(|r| OtherProfile {
                    name: r.name.clone(),
                    server: r.server.clone(),
                    resolved_ip: r.server.parse::<IpAddr>().ok(),
                })
                .collect()
        })
    }

    fn split_tunnel(&self) -> Result<SplitTunnelRules, String> {
        Ok(self.rules.read(|doc| split_rules(&doc.split_tunnel.apps)))
    }

    fn engine_setup(&self) -> EngineSetup {
        EngineSetup {
            singbox_exe: self.engines.singbox.clone(),
            xray_exe: self.engines.xray.clone(),
            engine_pref: self.settings.read(|s| s.proxy_engine),
            // The runtime publishes no DNS bootstrap listener: probe engines resolve on their own.
            dns_bootstrap_in: None,
        }
    }

    fn server_engine(&self, id: &str) -> EnginePref {
        // A row gone since the check was queued has no choice of its own left: the setting rules.
        self.servers
            .get(&ProfileId::from(id))
            .map_or(EnginePref::Auto, |row| row.engine)
    }

    fn geo_enabled(&self) -> bool {
        !self.settings.read(|s| s.disable_geo_lookup)
    }
}

/// Our tunnel as the check sees it. A connect, switch or stop in flight makes the network stages
/// `not_checked`; a running engine lends its `live-check-in` (direct VPN modes) and
/// `mixed-direct-in` inbounds, in Soft as in Hard mode.
pub(crate) fn tunnel_view(
    snap: &TunnelSnapshot,
    status: &TunStatus,
    session: Option<&SessionView>,
) -> TunnelView {
    if snap.transition.is_some() {
        return TunnelView {
            state: TunnelState::Transition,
            ..TunnelView::down()
        };
    }
    match (status.running, &status.session) {
        (true, Some(s)) => TunnelView {
            state: TunnelState::Up,
            active_profile_id: session.map(|v| v.profile_id.clone()),
            live_check_in: s.probe.as_ref().map(loopback),
            mixed_direct_in: Some(loopback(&s.direct)),
            tun_luid: s.tun_luid,
        },
        _ => TunnelView::down(),
    }
}

fn loopback(e: &ProxyEndpoint) -> Loopback {
    Loopback {
        port: e.port,
        creds: Some(Creds {
            user: e.user.clone(),
            pass: e.pass.clone(),
        }),
    }
}

/// The routed split-tunnel entries (`AppRule::None` entries are only listed, not routed). A
/// VPN-forced app path counts by its file name: the check compares process names.
pub(crate) fn split_rules(apps: &[SplitApp]) -> SplitTunnelRules {
    let mut rules = SplitTunnelRules::default();
    for app in apps {
        match (app.rule, &app.target) {
            (AppRule::Direct, SplitTarget::Command(name)) => {
                rules.direct_names.push(name.as_str().to_owned());
            }
            (AppRule::Direct, SplitTarget::App(path)) => {
                rules.direct_paths.push(path.as_str().to_owned());
            }
            (AppRule::Vpn, SplitTarget::Command(name)) => {
                rules.vpn_names.push(name.as_str().to_owned());
            }
            (AppRule::Vpn, SplitTarget::App(path)) => rules.vpn_names.extend(
                path.as_path()
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned()),
            ),
            (AppRule::None, _) => {}
        }
    }
    rules.enabled = !(rules.direct_names.is_empty()
        && rules.direct_paths.is_empty()
        && rules.vpn_names.is_empty());
    rules
}
