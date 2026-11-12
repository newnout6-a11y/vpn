//! The tunnel's side of the automation wiring: the local-proxy detection automation shares with
//! a manual connect, and the automation services over this tunnel's lifecycle, runtime and the
//! one tweak journal of the process.
use std::sync::Arc;

use vpnte_automation::coordinator::ProxyEndpoint;
use vpnte_automation::hardening::{self, BrowserDirs, Browsers, Location, WinSystem};
use vpnte_automation::tweaks::Journal;
use vpnte_core::net::HostPort;
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_probes::public_ip::IpReader;
use vpnte_tunnel::lifecycle::Lifecycle;
use vpnte_tunnel::runtime::{ProxyCapture, TunnelHandle};

use super::{decide, make_detector};
use crate::services::Backend;
use crate::svc_auto::{
    AppCoordinator, Automation, Detect, Fingerprints, Parts, Privacy, ServerFailover, ServerHost,
};

/// The local proxy a manual connect would use: the configured one, else a detected one (our own
/// mixed inbound is never a candidate).
pub(super) fn detect(settings: Arc<Store<Settings>>, capture: Arc<ProxyCapture>) -> Detect {
    Arc::new(move || {
        let (settings, capture) = (settings.clone(), capture.clone());
        Box::pin(async move {
            if let Some(up) = decide::configured_upstream(&settings.snapshot()) {
                let addr = HostPort::parse(&up.addr).ok()?;
                return Some(ProxyEndpoint {
                    addr,
                    kind: up.kind,
                    creds: None,
                });
            }
            let found = make_detector(&capture).detect().await?;
            let addr = HostPort::parse(&found.addr.to_string()).ok()?;
            Some(ProxyEndpoint {
                addr,
                kind: found.kind,
                creds: None,
            })
        })
    })
}

/// What [`build`] needs from `svc_tunnel::build`.
pub(super) struct Inputs<'a> {
    pub lifecycle: &'a Lifecycle,
    pub runtime: &'a TunnelHandle,
    pub journal: Arc<Journal>,
    pub capture: Arc<ProxyCapture>,
    pub reader: Arc<IpReader>,
    pub fingerprints: Fingerprints,
    pub failover: Arc<ServerFailover>,
    pub tun: bool,
}

/// The automation services over this tunnel (no task runs yet).
pub(super) fn build(b: &Backend, i: Inputs<'_>) -> Arc<Automation> {
    let lane = Arc::new(i.lifecycle.clone());
    let detect = detect(b.settings.clone(), i.capture);
    let coord = Arc::new(AppCoordinator::new(
        lane.clone(),
        b.servers.clone(),
        b.notifier.clone(),
        detect.clone(),
        i.tun,
    ));
    let host = Arc::new(ServerHost::new(
        b.servers.clone(),
        b.settings.clone(),
        vpnte_tunnel::api::Runtime::status(i.runtime),
        i.reader,
        i.fingerprints,
        lane,
    ));
    let sys: Arc<dyn hardening::System> = Arc::new(WinSystem::new());
    let browsers = Browsers::new(i.journal.clone(), sys.clone(), BrowserDirs::current_user());
    let privacy = Arc::new(Privacy {
        location: Location::new(i.journal, sys),
        settings: b.settings.clone(),
        notifier: b.notifier.clone(),
    });
    Automation::build(
        b,
        Parts {
            coord,
            host,
            browsers,
            privacy,
            detect,
            failover: i.failover,
        },
    )
}
