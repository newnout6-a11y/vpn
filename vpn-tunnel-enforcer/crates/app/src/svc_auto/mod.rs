//! Automation in the product (work package `w3-automation`): the [`AppCoordinator`] over the
//! tunnel lifecycle, the one scheduler, the check-verdict reactions, rotation, adaptive bypass,
//! the AutoPilot launch run, the runtime's failover, browser hardening and location privacy
//! (`crates/automation/API.md`, "Wiring in the app"). Built by `svc_tunnel::build` (it owns the
//! one tweak journal and the lifecycle); the long tasks start after the start-up recovery.
mod coord;
mod decide;
mod events;
mod failover;
mod feed;
mod host;
mod lane;
mod pick;
mod pilot;
mod react;
#[cfg(test)]
mod tests;

use std::sync::{Arc, OnceLock};

use tokio_util::sync::CancellationToken;
use vpnte_automation::adaptive::reaction::Reactions;
use vpnte_automation::adaptive::{Adaptive, AdaptiveDoc};
use vpnte_automation::autopilot::{AutoPilot, AutoPilotResult, AutoPilotTrigger, StepStatus};
use vpnte_automation::hardening::{BrowserReport, Browsers};
use vpnte_automation::rotation::{Rotation, RotationConfig};
use vpnte_automation::scheduler::{Scheduler, Schedules};
use vpnte_base::types::{Level, Notice};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::store::Store;
use vpnte_probes::live::LiveCheckService;
use vpnte_tunnel::api::Runtime;

pub use coord::{AppCoordinator, Detect, Hooks, UserAct};
pub use events::{Followed, Privacy};
pub use failover::ServerFailover;
pub use host::{Fingerprints, ServerHost};
pub use lane::Lane;
pub use pick::{AppPick, spawn_autopick, traffic_exposure};
pub use pilot::PilotEnv;

use crate::services::Backend;

pub type AppAdaptive = Adaptive<AppCoordinator, ServerHost>;
pub type AppReactions = Reactions<AppCoordinator, ServerHost>;
pub type AppRotation = Rotation<AppCoordinator, ServerHost>;
pub type AppScheduler = Scheduler<AppCoordinator>;

/// Everything automation of this process: one instance each, shared by the tasks, the tunnel's
/// connect path and the Settings / Schedule pages.
pub struct Automation {
    pub coord: Arc<AppCoordinator>,
    pub schedules: Arc<Store<Schedules>>,
    pub scheduler: Arc<AppScheduler>,
    pub reactions: Arc<AppReactions>,
    pub rotation: Arc<AppRotation>,
    pub adaptive: Arc<AppAdaptive>,
    /// Browser policies (HKLM): only an elevated process may apply or roll them back.
    pub browsers: Browsers,
    /// Location privacy for the length of a session (per user, no elevation).
    pub privacy: Arc<Privacy>,
    pub elevated: bool,
    /// The automatic server choice (launch connect, stall watch, retries); set once by
    /// [`spawn_autopick`] when the backend is complete.
    pub autopick: OnceLock<Arc<AppPick>>,
    pilot: AutoPilot<AppCoordinator, PilotEnv>,
}

/// What `svc_tunnel::build` hands over.
pub struct Parts {
    pub coord: Arc<AppCoordinator>,
    pub host: Arc<ServerHost>,
    pub browsers: Browsers,
    pub privacy: Arc<Privacy>,
    pub detect: Detect,
    pub failover: Arc<ServerFailover>,
}

impl Automation {
    /// Opens the automation documents and builds the services (no task runs yet).
    pub fn build(b: &Backend, parts: Parts) -> Arc<Self> {
        let Parts {
            coord,
            host,
            browsers,
            privacy,
            detect,
            failover,
        } = parts;
        let schedules = Arc::new(Store::<Schedules>::open(&b.dirs.root));
        let scheduler = Arc::new(Scheduler::new(schedules.clone(), coord.clone()));
        let reactions = Arc::new(Reactions::new(
            coord.clone(),
            host.clone(),
            b.settings.clone(),
        ));
        let rotation_doc = Arc::new(Store::<RotationConfig>::open(&b.dirs.root));
        let rotation = Arc::new(
            Rotation::new(rotation_doc, coord.clone(), host.clone())
                .with_verdicts(reactions.verdicts()),
        );
        let learning = Arc::new(Store::<AdaptiveDoc>::open(&b.dirs.root));
        let adaptive = Arc::new(
            Adaptive::new(coord.clone(), host.clone(), b.settings.clone(), learning)
                .with_verdicts(reactions.verdicts()),
        );
        failover.attach(coord.lane.session(), reactions.verdicts());
        let _ = coord.hooks.set(Hooks {
            adaptive: adaptive.clone(),
            host,
        });
        let env = Arc::new(PilotEnv { detect });
        let pilot = AutoPilot::new(
            coord.clone(),
            env,
            b.settings.clone(),
            Some(scheduler.status()),
        );
        Arc::new(Self {
            coord,
            schedules,
            scheduler,
            reactions,
            rotation,
            adaptive,
            browsers,
            privacy,
            elevated: b.elevated,
            autopick: OnceLock::new(),
            pilot,
        })
    }

    /// Applies (`true`) or rolls back the browser policies (HKLM). Only an elevated process may
    /// (NOADMIN §0): otherwise `Permission` before anything is touched.
    pub async fn browser_policies(&self, apply: bool) -> AppResult<BrowserReport> {
        if !self.elevated {
            return Err(AppError::msg(
                ErrorKind::Permission,
                Msg::new("automation.hardening.needsAdmin"),
            ));
        }
        if apply {
            self.browsers.apply().await
        } else {
            self.browsers.rollback().await
        }
    }

    /// The forwarder (session events, faults, network changes, location privacy): from the start,
    /// so no session change is missed by the tasks that subscribe later.
    pub fn spawn_forwarder(&self, runtime: Arc<dyn Runtime>, cancel: CancellationToken) {
        let changes = vpnte_winnet::adapters::watch_network(NET_SETTLE, cancel.clone())
            .inspect_err(|e| tracing::warn!(error = %e, "no network-change watch for automation"))
            .ok();
        let privacy = Some(self.privacy.clone());
        tokio::spawn(events::sessions(
            self.coord.clone(),
            privacy,
            cancel.child_token(),
        ));
        tokio::spawn(events::engine(self.coord.clone(), runtime, changes, cancel));
    }

    /// The long tasks, after the start-up recovery: the scheduler first (AutoPilot waits for
    /// its first pass), then the reactions with their feed, rotation, adaptive bypass, and the
    /// AutoPilot launch run.
    pub async fn run_tasks(
        self: Arc<Self>,
        servers: Arc<vpnte_servers::store::Servers>,
        live: Option<Arc<LiveCheckService>>,
        notifier: Arc<crate::svc_core::notify::Notifier>,
        cancel: CancellationToken,
    ) {
        let (s, c) = (self.scheduler.clone(), cancel.child_token());
        tokio::spawn(async move { s.run(c).await });
        let (r, c) = (self.reactions.clone(), cancel.child_token());
        tokio::spawn(async move { r.run(c).await });
        tokio::spawn(feed::run(
            self.reactions.clone(),
            servers,
            live,
            cancel.child_token(),
        ));
        let (r, c) = (self.rotation.clone(), cancel.child_token());
        tokio::spawn(async move { r.run(c).await });
        let (a, c) = (self.adaptive.clone(), cancel.child_token());
        tokio::spawn(async move { a.run(c).await });
        let run = self.pilot.run(AutoPilotTrigger::AppLaunch);
        let result = tokio::select! {
            () = cancel.cancelled() => return,
            result = run => result,
        };
        if let Some(result) = result {
            announce(&result, &notifier);
        }
    }
}

/// How long the network must stay quiet before a change counts (as the IP monitor's watch).
const NET_SETTLE: std::time::Duration = std::time::Duration::from_millis(1500);

/// The AutoPilot result once: one notice (toast per the user's switches) and a log line per step.
fn announce(result: &AutoPilotResult, notifier: &crate::svc_core::notify::Notifier) {
    for step in &result.steps {
        tracing::info!(label = %step.label.key, after = %step.after.key, "AutoPilot step");
    }
    let level = match result.summary {
        StepStatus::Ok => Level::Success,
        StepStatus::Info => Level::Info,
        StepStatus::Warn => Level::Warn,
        StepStatus::Fail => Level::Error,
    };
    let notice = Notice::new(level, result.title.clone()).body(result.message.clone());
    notifier.notify(notice, None);
}
