//! The tunnel service (work package `app-tunnel`): the runtime actor with both capture strategies
//! and the real engines, the lifecycle with its collaborators over the backend, the kill switch,
//! and the [`TunnelOps`] the API packages call (`ops.rs`). Privileged parts (TUN capture, WFP)
//! exist only when the process itself is elevated (NOADMIN §0); everything else runs unelevated.
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
mod soft;
#[cfg(test)]
mod tests;
mod traffic;
#[cfg(test)]
mod wiring_tests;

use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::{Notify, broadcast};
use tokio_util::sync::CancellationToken;
use vpnte_automation::{hardening, tweaks};
use vpnte_base::AppResult;
use vpnte_base::types::{Level, Notice};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_probes::diagnostics::{SnapshotReason, Snapshotter};
use vpnte_probes::ip_monitor::IpMonitor;
use vpnte_probes::local_proxy::{LocalProxyDetector, ScanOptions};
use vpnte_probes::public_ip::IpReader;
use vpnte_servers::store::Servers;
use vpnte_tunnel::api::Runtime;
use vpnte_tunnel::fsm::FaultState;
use vpnte_tunnel::lifecycle::{Lifecycle, LifecycleDeps};
use vpnte_tunnel::runtime::{
    Capture, EngineFeed, ProxyCapture, RealEngines, RuntimeDeps, Timings, TunCapture, TunnelHandle,
};

use crate::services::{Backend, Engines, TunnelOps};
use crate::svc_auto::{AppCoordinator, Automation, Fingerprints, ServerFailover};
use crate::svc_core::notify::{NoticeCategory, Notifier};

pub use domains::DomainHistory;
pub(crate) use gate::BudgetGate;
pub(crate) use monitor::exit_route;
pub(crate) use peers::vpn_profile;

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
    let guard = Arc::new(guard::Guard::new(
        b.elevated,
        &b.engines,
        b.settings.clone(),
        b.protection.clone(),
        b.notifier.clone(),
    ));
    let reader = Arc::new(IpReader::new());
    let fingerprints = Fingerprints::default();
    let failover = Arc::new(ServerFailover::new(b.servers.clone(), fingerprints.clone()));
    let ip = IpMonitor::new(reader.clone());
    // One Soft capture for the whole process: the runtime writes its mixed port, the local-proxy
    // detector reads it so a scan can never pick our own inbound as the upstream.
    let proxy_capture = Arc::new(ProxyCapture::new());
    // The slot egress probe takes a slot of the handshake budget every check shares.
    let engines = RealEngines::new(
        b.engines.singbox.clone(),
        b.engines.xray.clone(),
        Some(b.dirs.logs.clone()),
    )
    .with_gate(Arc::new(gate::BudgetGate));
    // WP-12 lab build only: the lab gate and the mihomo engine (AmneziaWG in Proxy mode).
    #[cfg(feature = "lab")]
    let engines = match b.engines.singbox.parent() {
        Some(resources) => lab::with_lab_engine(engines, &b.dirs.root, resources),
        None => engines,
    };
    let feed = engines.feed();
    let runtime = TunnelHandle::spawn(RuntimeDeps {
        engines: Arc::new(engines),
        // No TUN without the protection, i.e. without elevation: a Hard start answers
        // `Permission` up front instead of failing halfway (tunnel API, privilege model).
        tun: guard
            .wfp
            .as_ref()
            .map(|p| Arc::new(TunCapture::new(p.clone())) as Arc<dyn Capture>),
        proxy: Arc::clone(&proxy_capture) as Arc<dyn Capture>,
        inputs: Arc::new(inputs::StoreInputs {
            settings: b.settings.clone(),
            rules: b.rules.clone(),
            rule_sets: b.rule_sets.clone(),
        }),
        failover: Some(failover.clone()),
        confirmations: Some(Arc::new(monitor::Alive(ip.clone()))),
        timings: Timings::default(),
    });
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
    // Unelevated there is no TUN session whose blocking a self-test could check.
    let leaks = guard
        .wfp
        .is_some()
        .then(|| leaks::Leaks::spawn(status.clone(), b.settings.clone()));
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
    let proxies = peers::proxies(b, runtime.status());
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
            tun: guard.wfp.is_some(),
        },
    );
    automation.spawn_forwarder(Arc::new(runtime.clone()), b.shutdown.child_token());
    tokio::spawn({
        let (b, lifecycle, guard, soft) =
            (b.clone(), lifecycle.clone(), guard.clone(), soft.clone());
        let (automation, live) = (automation.clone(), live.clone());
        async move {
            recover(b.clone(), lifecycle, guard, soft, automation.clone()).await;
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
        engines: b.engines.clone(),
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
    runtime: TunnelHandle,
    guard: Arc<guard::Guard>,
    soft: Arc<soft::SoftTweaks>,
    ip: Arc<monitor::IpWatch>,
    forensics: Arc<traffic::SessionForensics>,
    /// The domain history and its site-name cache («clear all» empties both).
    domains: Arc<DomainHistory>,
    settings: Arc<Store<Settings>>,
    servers: Arc<Servers>,
    engines: Engines,
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
