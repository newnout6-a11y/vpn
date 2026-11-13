//! The tunnel service (work package `app-tunnel`): the runtime actor with both capture strategies
//! and the real engines, the lifecycle with its collaborators over the backend, the kill switch,
//! and the [`TunnelOps`] the API packages call (`ops.rs`).
//!
//! The choice at start (package svc-wire, owner decision 12.11.2026): the helper service is
//! installed -> Tunnel mode and the WFP kill switch go through it (`remote`; the pipe's server
//! must be its exe) and "Always" is offered; else the app runs elevated -> TUN and WFP in this
//! process, as before; neither -> proxy mode, and Settings offer to install the service.
mod auto;
mod decide;
mod domains;
mod gate;
mod guard;
mod inputs;
#[cfg(feature = "lab")]
mod lab;
mod leaks;
mod legacy;
mod monitor;
mod ops;
mod peers;
mod probe;
mod remote;
mod soft;
#[cfg(test)]
mod tests;
mod traffic;
#[cfg(test)]
mod wiring_tests;

use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::{Notify, broadcast, watch};
use tokio_util::sync::CancellationToken;
use vpnte_automation::{hardening, tweaks};
use vpnte_base::AppResult;
use vpnte_base::types::{Level, Notice, Owner, ProxyKind};
use vpnte_core::ops::Source;
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_probes::diagnostics::{SnapshotReason, Snapshotter};
use vpnte_probes::ip_monitor::IpMonitor;
use vpnte_probes::local_proxy::{LocalProxyDetector, ScanOptions};
use vpnte_probes::public_ip::IpReader;
use vpnte_servers::store::Servers;
use vpnte_service::proto::KeptSession;
use vpnte_tunnel::api::Runtime;
use vpnte_tunnel::api::StopOptions;
use vpnte_tunnel::fsm::FaultState;
use vpnte_tunnel::lifecycle::{ConnectTarget, Lifecycle, LifecycleDeps, SystemForeignVpn};
use vpnte_tunnel::runtime::{
    Capture, EngineExes, EngineFeed, ProxyCapture, RealEngines, RuntimeDeps, Timings, TunCapture,
    TunnelHandle,
};

use crate::services::{Backend, Engines, TunnelOps};
use crate::svc_auto::{AppCoordinator, Automation, Fingerprints, ServerFailover};
use crate::svc_core::notify::{NoticeCategory, Notifier};

pub use domains::DomainHistory;
pub(crate) use gate::BudgetGate;
pub(crate) use monitor::exit_route;
pub(crate) use peers::vpn_profile;
pub(crate) use probe::session_route;

/// The tunnel service and the automation over it, built together: automation drives this
/// tunnel's lifecycle and shares its one tweak journal.
pub struct Built {
    /// The caller stores it in `backend.tunnel`.
    pub tunnel: Arc<dyn TunnelOps>,
    /// For the pages that edit automation (Schedule, Settings).
    pub automation: Arc<Automation>,
    /// The domain history and its site names (Traffic page).
    pub domains: Arc<DomainHistory>,
    /// The engine cores' lines and last config (diagnostics export).
    pub feed: EngineFeed,
    /// The one tweak journal (its records are recovery state in the diagnostics export).
    pub journal: Arc<tweaks::Journal>,
}

/// Builds the tunnel service and its automation. Runs inside the tokio runtime (it spawns the
/// actors and the background tasks under `backend.shutdown`).
pub fn build(backend: &Arc<Backend>) -> AppResult<Built> {
    let b = backend;
    let store_inputs = |always| {
        Arc::new(inputs::StoreInputs {
            settings: b.settings.clone(),
            rules: b.rules.clone(),
            rule_sets: b.rule_sets.clone(),
            always,
        })
    };
    // The service gets the routing inputs only (its level comes with each start).
    let remote = remote::Remote::new(
        store_inputs(Arc::default()),
        b.protection.clone(),
        b.shutdown.clone(),
    );
    let guard = Arc::new(guard::Guard::new(
        b.elevated,
        &b.engines,
        b.settings.clone(),
        b.protection.clone(),
        remote.clone(),
    ));
    let reader = Arc::new(IpReader::new());
    let fingerprints = Fingerprints::default();
    let failover = Arc::new(ServerFailover::new(b.servers.clone(), fingerprints.clone()));
    let ip = IpMonitor::new(reader.clone());
    // One Soft capture for the whole process: the runtime writes its mixed port, the local-proxy
    // detector reads it so a scan can never pick our own inbound as the upstream.
    let proxy_capture = Arc::new(ProxyCapture::new());
    // The engine paths follow the update channel (`TunnelOps::set_engines`): every engine start
    // reads them. The slot egress probe takes a slot of the handshake budget every check shares.
    let exes = watch::Sender::new(EngineExes {
        singbox: b.engines.singbox.clone(),
        xray: b.engines.xray.clone(),
    });
    let engines = RealEngines::following(exes.subscribe(), Some(b.dirs.logs.clone()))
        .with_gate(Arc::new(gate::BudgetGate));
    // WP-12 lab build only: the lab gate and the mihomo engine (AmneziaWG in Proxy mode).
    #[cfg(feature = "lab")]
    let engines = match b.engines.singbox.parent() {
        Some(resources) => lab::with_lab_engine(engines, &b.dirs.root, resources),
        None => engines,
    };
    let feed = engines.feed();
    let local = TunnelHandle::spawn(RuntimeDeps {
        engines: Arc::new(engines),
        // No TUN without the protection, i.e. without elevation: a Hard start answers
        // `Permission` up front instead of failing halfway (tunnel API, privilege model).
        tun: guard
            .wfp
            .as_ref()
            .map(|p| Arc::new(TunCapture::new(p.clone())) as Arc<dyn Capture>),
        proxy: Arc::clone(&proxy_capture) as Arc<dyn Capture>,
        inputs: store_inputs(guard.always.clone()),
        failover: Some(failover.clone()),
        confirmations: Some(Arc::new(monitor::Alive(ip.clone()))),
        timings: Timings::default(),
    });
    // Tunnel mode in the service while it is installed, everything else here.
    let runtime = remote::Split::spawn(Arc::new(local), remote.clone(), b.shutdown.child_token());
    let status = runtime.status();

    let journal = Arc::new(tweaks::Journal::open(&b.dirs.root, hardening::admit));
    if let Some(notice) = journal.notice() {
        b.notifier.notify(Notice::new(Level::Warn, notice), None);
    }
    let soft = Arc::new(soft::SoftTweaks {
        soft: tweaks::Soft::new(journal.clone(), tweaks::SoftSystem::current_user()),
        journal: journal.clone(),
        doc: b.soft.clone(),
        notifier: b.notifier.clone(),
    });
    // Every TUN session, in this process or in the helper service, gets the leak self-test and
    // the re-checks after a wake or a network change: the canary runs here, the self-test and the
    // filter check where the filters are (RU audit item 11).
    let leaks = Some(leaks::Leaks::spawn(
        status.clone(),
        b.settings.clone(),
        &remote,
        guard.wfp.is_some(),
    ));
    let auto_reader = reader.clone();
    let ip = Arc::new(monitor::IpWatch::new(
        ip,
        reader,
        b.settings.clone(),
        status.clone(),
        leaks,
        b.shutdown.clone(),
    ));
    ip.ip
        .set_interval(decide::check_interval(&b.settings.snapshot()));
    ip.spawn_home_reads(b.geo.clone(), b.shutdown.child_token());
    let domains = DomainHistory::open(b, status.clone(), feed.subscribe_lines());
    let snapshots = Snapshotter::new(
        &b.dirs.root,
        env!("CARGO_PKG_VERSION").to_owned(),
        traffic::app_state(status.clone(), b.settings.clone()),
    );
    // The network as the app found it, then every 5 minutes: a drop mid-session shows between two.
    snapshots.start_periodic();
    tokio::spawn({
        let snapshots = snapshots.clone();
        async move { snapshots.capture(SnapshotReason::AppStart).await }
    });
    let forensics = Arc::new(traffic::SessionForensics::new(
        status,
        domains.history.clone(),
        b.servers.clone(),
        snapshots,
        b.shutdown.clone(),
    ));
    let proxies = peers::proxies(b, runtime.status(), exes.subscribe());
    let lifecycle = Lifecycle::spawn(LifecycleDeps {
        runtime: Arc::new(runtime.clone()),
        profiles: Arc::new(peers::ServerSource {
            servers: b.servers.clone(),
            fingerprints: fingerprints.clone(),
        }),
        soft: soft.clone(),
        monitor: ip.clone(),
        forensics: forensics.clone(),
        proxies: Arc::new(peers::Slots(proxies.clone())),
        notifier: b.notifier.clone(),
        history: b.history.clone(),
        settings: b.settings.clone(),
        always_available: guard.always.clone(),
        foreign_vpn: Arc::new(SystemForeignVpn),
    });
    let live = peers::live_checks(b, &runtime, &lifecycle);

    if let Some(leaks) = &ip.leaks {
        leaks.forward(
            lifecycle.clone(),
            b.notifier.clone(),
            guard.wfp.clone(),
            b.shutdown.child_token(),
        );
    }
    if let Some(p) = &guard.wfp {
        tokio::spawn(p.clone().run_watchdog(b.shutdown.child_token()));
        tokio::spawn(forward(
            p.notices(),
            b.notifier.clone(),
            b.shutdown.child_token(),
        ));
    }
    tokio::spawn(forward(
        remote.notices(),
        b.notifier.clone(),
        b.shutdown.child_token(),
    ));
    let automation = auto::build(
        b,
        auto::Inputs {
            lifecycle: &lifecycle,
            runtime: &runtime,
            journal: journal.clone(),
            capture: Arc::clone(&proxy_capture),
            reader: auto_reader,
            fingerprints,
            failover,
            tun: guard.tun_available(),
        },
    );
    automation.spawn_forwarder(Arc::new(runtime.clone()), b.shutdown.child_token());
    tokio::spawn({
        let (b, lifecycle, guard, soft) =
            (b.clone(), lifecycle.clone(), guard.clone(), soft.clone());
        let (automation, live) = (automation.clone(), live.clone());
        let remote = remote.clone();
        async move {
            recover(b.clone(), lifecycle, guard, soft, automation.clone()).await;
            // On its own task: a service still starting with Windows must not hold the rest up.
            tokio::spawn({
                let (automation, cancel) = (automation.clone(), b.shutdown.child_token());
                let losses = remote.losses();
                async move {
                    if let Some(kept) = remote.attach().await {
                        take_over(&remote, &automation, kept).await;
                    }
                    reattach(&remote, &automation, losses, cancel).await;
                }
            });
            let (servers, notifier) = (b.servers.clone(), b.notifier.clone());
            automation
                .run_tasks(servers, live, notifier, b.shutdown.child_token())
                .await;
        }
    });
    let rule_sets = Arc::new(Notify::new());
    tokio::spawn(probe::refresh_rule_sets(
        b.rule_sets.clone(),
        b.settings.clone(),
        runtime.status(),
        b.notifier.clone(),
        rule_sets.clone(),
        b.shutdown.child_token(),
    ));

    let tunnel: Arc<dyn TunnelOps> = Arc::new(TunnelService {
        coord: automation.coord.clone(),
        automation: automation.clone(),
        lifecycle,
        runtime,
        guard,
        soft,
        ip,
        forensics,
        domains: domains.clone(),
        settings: b.settings.clone(),
        servers: b.servers.clone(),
        exes,
        detector: Arc::clone(&proxy_capture),
        pending: Mutex::new(None),
        rule_sets,
        proxies,
        live,
    });
    Ok(Built {
        tunnel,
        automation,
        domains,
        feed,
        journal,
    })
}

impl From<&EngineExes> for Engines {
    fn from(exes: &EngineExes) -> Self {
        Self {
            singbox: exes.singbox.clone(),
            xray: exes.xray.clone(),
        }
    }
}

/// The local-proxy detector for one scan. Our own mixed inbound is always skipped (NOADMIN §2):
/// while Soft runs, the per-user system proxy we applied points at that port, so a scan that found
/// it would chain the engine to itself.
fn make_detector(proxy: &ProxyCapture) -> LocalProxyDetector {
    LocalProxyDetector::new(ScanOptions {
        skip_ports: proxy.port().into_iter().collect(),
        skip_pids: Vec::new(),
    })
}

/// The [`TunnelOps`] implementation (methods in `ops.rs`).
struct TunnelService {
    /// Every start goes through the coordinator (owner order, the adaptive bypass's mode).
    coord: Arc<AppCoordinator>,
    /// Automation of this process (scheduler, rotation, hardening, …).
    automation: Arc<Automation>,
    lifecycle: Lifecycle,
    runtime: remote::Split,
    guard: Arc<guard::Guard>,
    soft: Arc<soft::SoftTweaks>,
    ip: Arc<monitor::IpWatch>,
    forensics: Arc<traffic::SessionForensics>,
    /// The domain history and its site-name cache («clear all» empties both).
    domains: Arc<DomainHistory>,
    settings: Arc<Store<Settings>>,
    servers: Arc<Servers>,
    /// The engine paths every engine start of this process reads (the update channel moves
    /// them).
    exes: watch::Sender<EngineExes>,
    /// The Soft capture: the runtime owns its mixed port, the detector skips it (see [`make_detector`]).
    detector: Arc<ProxyCapture>,
    /// The token of the user's connect / switch in flight, cancelled by "Cancel".
    pending: Mutex<Option<CancellationToken>>,
    /// Wakes the rule-set refresh task (a Smart RU / rule-set setting changed).
    rule_sets: Arc<Notify>,
    /// External proxy slots (stopped by the lifecycle with the VPN, and at exit).
    proxies: Arc<crate::svc_proxies::Proxies>,
    /// The live server check; `None` when its runner could not start.
    live: Option<Arc<vpnte_probes::live::LiveCheckService>>,
}

/// Start-up recovery with the lane held (no connect can interleave): WFP leftovers of a crashed
/// run (elevated only), the old version's network cleanup (elevated only, after the WFP start-up),
/// then the Soft tweaks a crashed run left pointing at its dead engine (NOADMIN §2) and the
/// location privacy of a session that never ended (automation API). Anything
/// unconfirmed leaves the state `unknown`, never "disconnected".
async fn recover(
    backend: Arc<Backend>,
    lifecycle: Lifecycle,
    guard: Arc<guard::Guard>,
    soft: Arc<soft::SoftTweaks>,
    automation: Arc<Automation>,
) {
    let outcome = lifecycle
        .maintenance(move || async move {
            let elevated = guard.wfp.is_some();
            let wfp = match tokio::task::spawn_blocking(move || guard.startup()).await {
                Ok(result) => result,
                Err(e) => Err(vpnte_base::AppError::internal(e)),
            };
            if elevated {
                legacy::startup(backend, wfp.is_ok()).await;
            }
            let tweaks = if soft.soft.is_applied() {
                tracing::info!("startup: rolling back the Soft tweaks of a previous run");
                soft.restore().await
            } else {
                Ok(())
            };
            // Location privacy is session-scoped: a crashed run's denial goes back.
            automation.privacy.session_down().await;
            (wfp, tweaks)
        })
        .await;
    match outcome {
        Ok((Ok(()), Ok(()))) => return,
        Ok((wfp, tweaks)) => {
            if let Err(e) = wfp {
                tracing::error!(error = %e, "startup: kill-switch recovery failed");
            }
            if let Err(e) = tweaks {
                tracing::error!(error = %e, "startup: Soft rollback incomplete");
            }
        }
        Err(e) => tracing::error!(error = %e, "startup recovery did not run"),
    }
    lifecycle.fault(FaultState::Unknown);
}

/// A session the service kept after this app's window crashed (owner question 23) is taken over
/// by the lifecycle's own connect of the same upstream: it shows as connected again, with its
/// history and notices. If that connect fails, the session is stopped rather than left running
/// unseen.
async fn take_over(remote: &remote::Remote, automation: &Automation, kept: KeptSession) {
    let target = match (kept.server_id, kept.local_proxy) {
        (Some(id), _) => ConnectTarget::DirectVpn {
            profile_id: Some(id),
        },
        (None, Some(addr)) => ConnectTarget::LocalProxy {
            addr: addr.to_string(),
            kind: (remote.parked().and_then(|s| s.proxy_type)).unwrap_or(ProxyKind::Socks5),
        },
        (None, None) => return,
    };
    let taken = automation
        .coord
        .start(target, Owner::Manual, Source::Lifecycle)
        .await;
    if let Err(err) = taken {
        tracing::warn!(error = %err.user_msg().key, "kept session not taken over: stopped");
        if remote.parked().is_some() {
            let receipt = vpnte_tunnel::api::Runtime::stop(remote, StopOptions::default()).await;
            tracing::info!(ok = receipt.ok, "kept session stopped");
        }
    }
}

/// A link to the helper service lost without the app asking (the service restarted; the session
/// shows as ended meanwhile): the session the restarted service resumes is taken over as at
/// start-up, once per loss.
async fn reattach(
    remote: &remote::Remote,
    automation: &Automation,
    mut losses: watch::Receiver<u64>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            changed = losses.changed() => if changed.is_err() { return },
        }
        tracing::info!("helper service link lost: re-attaching");
        if let Some(kept) = remote.reattach().await {
            take_over(remote, automation, kept).await;
        }
    }
}

/// Protection notices (blocked traffic, skipped exceptions, unconfirmed protection) as toasts.
async fn forward(
    mut notices: broadcast::Receiver<Notice>,
    notifier: Arc<Notifier>,
    cancel: CancellationToken,
) {
    loop {
        let notice = tokio::select! {
            () = cancel.cancelled() => return,
            next = notices.recv() => next,
        };
        match notice {
            Ok(n) => notifier.notify(n, Some(NoticeCategory::ConnectionError)),
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(skipped = n, "protection notices dropped");
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}
