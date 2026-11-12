//! [`DemoMaintenanceApi`]: a fake backend with realistic data for `demo_maintenance` and the
//! tests. Scenes: `default` (connected, healthy), `off` (disconnected; the repair finishes with
//! an error), `problems` (BFE stopped, leftovers, capture stop unconfirmed, a caught error,
//! corrupt profiles), `leak` (the leak test finds a leak), `inconclusive` (it proves nothing).
use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::now_ms;
use vpnte_base::{AppError, AppResult, ErrorKind};

use super::MaintenanceApi;
use super::model::*;

mod data;

pub(super) use data::report;
use data::*;

/// Which story the fake backend tells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scene {
    Default,
    Off,
    Problems,
    Leak,
    Inconclusive,
}

impl Scene {
    /// Parses `--scene`; unknown names fall back to `Default`.
    pub fn parse(name: &str) -> Self {
        match name {
            "off" => Scene::Off,
            "problems" => Scene::Problems,
            "leak" => Scene::Leak,
            "inconclusive" => Scene::Inconclusive,
            _ => Scene::Default,
        }
    }

    fn connected(self) -> bool {
        matches!(self, Scene::Default | Scene::Leak | Scene::Inconclusive)
    }
}

/// The fake backend.
pub struct DemoMaintenanceApi {
    scene: Scene,
    /// Shared with the repair task, which outlives the caller's future.
    state: Arc<watch::Sender<MaintenanceState>>,
    exports: Cell<u32>,
}

impl DemoMaintenanceApi {
    /// A backend telling `scene`.
    pub fn new(scene: Scene) -> Rc<Self> {
        Rc::new(Self {
            scene,
            state: Arc::new(watch::Sender::new(initial_state(scene))),
            exports: Cell::new(0),
        })
    }
}

/// Waits `ms`, or fails with `Cancelled` when `token` fires first.
async fn pause(ms: u64, token: &CancellationToken) -> AppResult<()> {
    tokio::select! {
        () = tokio::time::sleep(Duration::from_millis(ms)) => Ok(()),
        () = token.cancelled() => Err(AppError::cancelled()),
    }
}

/// Clears the export flag even when the caller's future is dropped mid-way.
struct ExportGuard(Arc<watch::Sender<MaintenanceState>>);

impl Drop for ExportGuard {
    fn drop(&mut self) {
        self.0.send_modify(|s| s.export = ExportView::default());
    }
}

const EXPORT_STAGES: [&str; 4] = [
    "export.stageSnapshots",
    "export.stageLogs",
    "export.stageCapture",
    "export.stageZip",
];

#[async_trait(?Send)]
impl MaintenanceApi for DemoMaintenanceApi {
    fn state(&self) -> watch::Receiver<MaintenanceState> {
        self.state.subscribe()
    }

    async fn system_report(&self, cancel: CancellationToken) -> AppResult<SystemReport> {
        pause(1_200, &cancel).await?;
        Ok(report(self.scene))
    }

    async fn verify_protection(&self) -> AppResult<ProtectionView> {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut p = protection(self.scene);
        p.last_verified = Some(now_ms());
        self.state.send_modify(|s| s.protection = Some(p.clone()));
        Ok(p)
    }

    async fn repair(&self) -> AppResult<RepairView> {
        if self.state.borrow().tunnel != TunnelPhase::Off {
            return Err(AppError::conflict(demo("repairRefused")));
        }
        let (scene, state) = (self.scene, self.state.clone());
        // Its own task: the page may go away, the repair still finishes every step.
        let task = tokio::spawn(async move {
            state.send_modify(|s| {
                s.repair.running = true;
                for (_, st) in &mut s.repair.steps {
                    *st = StepState::Pending;
                }
            });
            for (i, step) in RepairStep::ALL.iter().enumerate() {
                state.send_modify(|s| s.repair.steps[i].1 = StepState::Running);
                tokio::time::sleep(Duration::from_millis(700)).await;
                let outcome = step_outcome(scene, *step);
                state.send_modify(|s| s.repair.steps[i].1 = StepState::Done(outcome));
            }
            state.send_modify(|s| {
                s.repair.running = false;
                if scene == Scene::Problems {
                    s.protection = Some(ProtectionView {
                        persistent_filters: 0,
                        last_verified: Some(now_ms()),
                        ..protection(scene)
                    });
                }
            });
            state.borrow().repair.clone()
        });
        task.await.map_err(AppError::internal)
    }

    async fn leak_self_test(&self, cancel: CancellationToken) -> AppResult<LeakTestView> {
        pause(1_500, &cancel).await?;
        Ok(leak_result(self.scene))
    }

    async fn routing_self_test(&self, cancel: CancellationToken) -> AppResult<RouteTestView> {
        pause(1_000, &cancel).await?;
        Ok(route_result(self.scene))
    }

    async fn check_network(&self, cancel: CancellationToken) -> AppResult<NetCheckView> {
        self.state.send_modify(|s| s.network.running = true);
        let paused = pause(1_500, &cancel).await;
        self.state.send_modify(|s| s.network.running = false);
        paused?;
        let result = network_result(self.scene);
        self.state
            .send_modify(|s| s.network.last = Some(result.clone()));
        Ok(result)
    }

    async fn export_diagnostics(&self, cancel: CancellationToken) -> AppResult<Option<ExportDone>> {
        if self.state.borrow().export.running {
            return Err(AppError::conflict(demo("exportBusy")));
        }
        let _guard = ExportGuard(self.state.clone());
        self.state.send_modify(|s| {
            s.export = ExportView {
                running: true,
                progress: None,
                stage: None,
            }
        });
        pause(400, &cancel).await?;
        for i in 0..=10u32 {
            let stage =
                EXPORT_STAGES[(i as usize * EXPORT_STAGES.len() / 11).min(EXPORT_STAGES.len() - 1)];
            self.state.send_modify(|s| {
                s.export.progress = Some(f64::from(i) / 10.0);
                s.export.stage = Some(demo(stage));
            });
            if self.scene == Scene::Problems && i == 6 {
                return Err(AppError::new(ErrorKind::Permission));
            }
            pause(220, &cancel).await?;
        }
        if self.scene == Scene::Inconclusive {
            return Ok(None);
        }
        let n = self.exports.get() + 1;
        self.exports.set(n);
        Ok(Some(ExportDone {
            path: format!(
                r"C:\Users\Demo\Desktop\vpn-tunnel-enforcer-diagnostics-2026-11-11T09-4{n}-12-345Z.zip"
            ),
            cleanup_failed: n.is_multiple_of(2),
        }))
    }

    async fn restart_capture(&self) -> AppResult<CaptureView> {
        tokio::time::sleep(Duration::from_millis(800)).await;
        let mut view = capture(self.scene);
        if self.scene == Scene::Problems {
            view = CaptureView {
                enabled: true,
                start_failed: true,
                last_error: Some(demo("captureStartError")),
                ..CaptureView::default()
            };
        }
        self.state.send_modify(|s| s.capture = view.clone());
        Ok(view)
    }

    async fn open_snapshots_folder(&self) -> AppResult<()> {
        tokio::time::sleep(Duration::from_millis(150)).await;
        if self.scene == Scene::Problems {
            return Err(AppError::new(ErrorKind::Internal));
        }
        Ok(())
    }

    async fn delete_legacy_data(&self) -> AppResult<()> {
        tokio::time::sleep(Duration::from_millis(600)).await;
        self.state.send_modify(|s| s.legacy.data_dir = None);
        Ok(())
    }

    async fn retry_secrets_import(&self) -> AppResult<SecretsImport> {
        tokio::time::sleep(Duration::from_millis(700)).await;
        let report = SecretsImport {
            restored: 3,
            pending: true,
        };
        Ok(report)
    }

    async fn set_aside_corrupt(&self, id: String) -> AppResult<()> {
        tokio::time::sleep(Duration::from_millis(400)).await;
        self.state
            .send_modify(|s| s.legacy.corrupt.retain(|c| c.id != id));
        Ok(())
    }
}
