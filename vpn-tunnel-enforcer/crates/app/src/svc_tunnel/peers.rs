//! The lifecycle's view of the server list, and the tunnel's peers: the external proxy slots
//! (stopped with the VPN) and the live server check (it reads the tunnel's state).
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::watch;
use vpnte_probes::live::LiveCheckService;
use vpnte_proxies::control::ControlConfig;
use vpnte_servers::model::{ArchiveReason, ProfileId, ServerRow};
use vpnte_servers::store::Servers;
use vpnte_tunnel::api::{Runtime, TunStatus, VpnProfile};
use vpnte_tunnel::lifecycle::{ExternalProxies, Lifecycle, ProfileSource, ServerChoice};
use vpnte_tunnel::runtime::TunnelHandle;

use crate::services::Backend;
use crate::svc_auto::Fingerprints;
use crate::svc_live::{self, AppLiveEnv};
use crate::svc_proxies::{ProbeCtxFn, Proxies, ServerProfiles};

/// The slots over the server list, with the control API on 127.0.0.1 (port 17873 or
/// `VPNTE_CONTROL_PORT`); key checks of `/profiles/healthcheck` take the path `status` allows.
pub(super) fn proxies(b: &Backend, status: watch::Receiver<TunStatus>) -> Arc<Proxies> {
    let (engines, settings) = (b.engines.clone(), b.settings.clone());
    let probe_ctx: ProbeCtxFn = Arc::new(move |device| {
        let pref = settings.read(|s| s.proxy_engine);
        super::probe::probe_ctx(&engines, pref, device, &status.borrow())
    });
    let source = ServerProfiles {
        servers: b.servers.clone(),
        settings: b.settings.clone(),
        ops: b.ops.clone(),
        probe_ctx,
    };
    Proxies::start(
        Arc::new(source),
        &b.dirs.resources,
        ControlConfig::from_env(&b.dirs.root),
        &b.shutdown,
    )
}

/// The live check over the backend and this tunnel's published state.
pub(super) fn live_checks(
    b: &Backend,
    runtime: &TunnelHandle,
    lifecycle: &Lifecycle,
) -> Option<Arc<LiveCheckService>> {
    let env = AppLiveEnv {
        servers: b.servers.clone(),
        settings: b.settings.clone(),
        rules: b.rules.clone(),
        engines: b.engines.clone(),
        status: runtime.status(),
        snapshot: lifecycle.snapshot(),
        session: lifecycle.session(),
    };
    svc_live::start(Arc::new(env), &b.dirs.root, &b.servers)
}

/// [`ProfileSource`] over the server list (single source of truth for server sessions), with
/// the uTLS fingerprints the check-verdict reactions set for this app run.
pub(super) struct ServerSource {
    pub servers: Arc<Servers>,
    pub fingerprints: Fingerprints,
}

impl ProfileSource for ServerSource {
    fn resolve(&self, id: Option<&str>) -> Option<ServerChoice> {
        let row = match id {
            // A row the user removed is gone for connects; a provider-archived one may still be
            // picked by the user (servers `SelectBy::User`).
            Some(id) => self
                .servers
                .get(&ProfileId::from(id))
                .filter(|r| !r.archived_for(ArchiveReason::User))?,
            None => self.servers.active()?.row,
        };
        let country = row.display_country().map(|c| c.as_str().to_owned());
        Some(ServerChoice {
            country,
            server: vpn_profile(row, &self.fingerprints)?,
        })
    }
}

/// The engine's view of a row; a fingerprint override (never stored) replaces the profile's own
/// for this app run. `None` when the profile is locked (another PC / account) or unreadable.
pub(crate) fn vpn_profile(row: ServerRow, fingerprints: &Fingerprints) -> Option<VpnProfile> {
    let mut profile = match row.profile() {
        Ok(profile) => profile,
        Err(e) => {
            // Locked or unreadable: the lifecycle reports "no server".
            tracing::warn!(error = %e, "server profile not usable");
            return None;
        }
    };
    let forced = fingerprints.lock().get(row.id.as_str()).copied();
    if let (Some(fp), Some(tls)) = (forced, profile.tls.as_mut()) {
        tls.fingerprint = Some(fp.to_owned());
    }
    Some(VpnProfile {
        id: row.id.0,
        profile: Arc::new(profile),
        device: Some(row.device),
        engine: row.engine,
    })
}

/// The lifecycle's stop of the external proxy slots (spec external-proxy §3.28): the stop of an
/// app exit (`"shutdown"`) stops every slot and closes the control API for good; any other reason
/// (`"vpn-stop"` today) takes the milder VPN-stop path: the unleased slots stop, leased ones keep
/// serving their clients. Only the explicit word is irreversible.
pub(super) struct Slots(pub Arc<Proxies>);

#[async_trait]
impl ExternalProxies for Slots {
    async fn stop_all(&self, reason: &str) {
        if reason == "shutdown" {
            self.0.shutdown().await;
        } else {
            self.0.vpn_stopped().await;
        }
    }
}
