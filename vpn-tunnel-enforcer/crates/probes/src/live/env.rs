//! What a check needs from the app, as snapshots taken when a check starts. `probes` cannot
//! depend on the server list, the tunnel or the routing rules (CONTRACT §2), so the app
//! implements [`LiveEnv`] over them.
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use vpnte_base::types::{ClientDevice, EnginePref, Loopback};
use vpnte_profiles::model::Profile;

use crate::key_health::ProbeCtx;
use crate::live_stages::geo::OtherProfile;
use crate::ping::NetPath;

/// The app side of the live check. Calls are cheap reads of in-memory state.
pub trait LiveEnv: Send + Sync + 'static {
    /// The saved profile `id`, `None` when unknown.
    fn profile(&self, id: &str) -> Option<ProfileTarget>;
    /// Our tunnel right now.
    fn tunnel(&self) -> TunnelView;
    /// The other saved profiles (shared-/24 hint).
    fn other_profiles(&self, except_id: Option<&str>) -> Vec<OtherProfile>;
    /// Split-tunnel rules for the extended snapshot; `Err` (English text) when unreadable.
    fn split_tunnel(&self) -> Result<SplitTunnelRules, String>;
    /// Engines and settings for a temporary probe engine.
    fn engine_setup(&self) -> EngineSetup;
    /// The server's own engine choice (`ServerRow::engine`): sing-box / Xray force it, `Auto`
    /// follows [`EngineSetup::engine_pref`] (`server_pref`, as at tunnel start and in key health).
    /// The default keeps every server on the app setting until the app reports the row's choice.
    fn server_engine(&self, _id: &str) -> EnginePref {
        EnginePref::Auto
    }
    /// `!settings.disable_geo_lookup`.
    fn geo_enabled(&self) -> bool;
}

/// A saved profile with what the check needs besides the key itself.
#[derive(Clone)]
pub struct ProfileTarget {
    pub id: String,
    pub profile: Profile,
    /// The server list's country for this server (`infrastructure.endpointCountry`).
    pub country: Option<String>,
    /// Client device of the profile's group (default uTLS fingerprint, Xray translation).
    pub device: ClientDevice,
    /// False for disabled profiles and keys removed from their subscription (a batch skips them).
    pub eligible: bool,
}

/// Our tunnel's state as the check sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TunnelState {
    Down,
    Up,
    /// Connecting, switching or stopping: paths are not stable, network stages are not run.
    Transition,
}

/// The running tunnel's facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelView {
    pub state: TunnelState,
    pub active_profile_id: Option<String>,
    /// sing-box `live-check-in` (direct-VPN mode), routed to `proxy-out`: the self-probe inbound.
    pub live_check_in: Option<Loopback>,
    /// sing-box `mixed-direct-in`, routed to `direct-out`: the probe engine's detour.
    pub mixed_direct_in: Option<Loopback>,
    /// LUID of our TUN adapter (path stage: "is the route through our TUN").
    pub tun_luid: Option<u64>,
}

impl TunnelView {
    /// No tunnel.
    pub fn down() -> Self {
        TunnelView {
            state: TunnelState::Down,
            active_profile_id: None,
            live_check_in: None,
            mixed_direct_in: None,
            tun_luid: None,
        }
    }

    pub(crate) fn up(&self) -> bool {
        self.state == TunnelState::Up
    }
}

/// Engines and settings for the temporary probe engine.
#[derive(Debug, Clone)]
pub struct EngineSetup {
    pub singbox_exe: PathBuf,
    /// The executable the running tunnel routes `direct-out` (see `key_health::ProbeCtx`).
    pub xray_exe: PathBuf,
    pub engine_pref: EnginePref,
    pub dns_bootstrap_in: Option<SocketAddr>,
}

impl EngineSetup {
    /// The key-health probe context: detour through `mixed-direct-in` only while our tunnel is
    /// up, else the engine binds to the physical adapter.
    pub(crate) fn ctx(&self, device: ClientDevice, tunnel: &TunnelView) -> ProbeCtx {
        let tun_direct = if tunnel.up() {
            tunnel.mixed_direct_in.clone()
        } else {
            None
        };
        ProbeCtx {
            singbox_exe: self.singbox_exe.clone(),
            xray_exe: self.xray_exe.clone(),
            engine_pref: self.engine_pref,
            device,
            net: NetPath { tun_direct },
            dns_bootstrap_in: self.dns_bootstrap_in,
        }
    }
}

/// Split-tunnel rules (routing-dns slice), read-only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SplitTunnelRules {
    pub enabled: bool,
    /// Process names routed `direct-out`.
    pub direct_names: Vec<String>,
    /// Application paths routed `direct-out`.
    pub direct_paths: Vec<String>,
    /// Process names forced through the VPN.
    pub vpn_names: Vec<String>,
}
