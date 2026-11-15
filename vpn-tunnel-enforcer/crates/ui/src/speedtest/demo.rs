//! A fake [`SpeedTestApi`] with realistic figures (documentation IPs, no network): used by
//! `demo_tools` and the page tests. A run walks through the phases with live progress, then
//! saves a result; without a tunnel it fails like the backend (`Conflict`).
use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

use super::SpeedTestApi;
use super::model::{Egress, SpeedPhase, SpeedProgress, SpeedResult, SpeedTestState};

const HOUR: UnixMs = 3_600_000;

/// How the next demo run ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DemoOutcome {
    /// A normal result through the tunnel.
    #[default]
    Normal,
    /// A result whose exit IP differs from the app's.
    Mismatch,
    /// A network failure during the download.
    Fail,
}

/// The fake backend of the Speed test page.
pub struct DemoSpeedTest {
    state: watch::Sender<SpeedTestState>,
    step: Duration,
    outcome: Cell<DemoOutcome>,
    next_id: Cell<u32>,
}

impl DemoSpeedTest {
    /// Tunnel up or down, with five saved results.
    pub fn new(tunnel_running: bool) -> Self {
        let now = now_ms();
        let row = |id: &str, ago: UnixMs, down: f64, up: f64, ms: u32, profile: &str| SpeedResult {
            id: id.to_owned(),
            timestamp: now - ago,
            download_mbps: down,
            upload_mbps: Some(up),
            latency_ms: ms,
            server_name: "Cloudflare".to_owned(),
            profile_used: profile.to_owned(),
            egress: Egress::Match,
            plain_http: false,
        };
        let mut history = vec![
            row(
                "st-5",
                25 * 60_000,
                87.4,
                41.2,
                38,
                "Netherlands · Amsterdam",
            ),
            row("st-4", 3 * HOUR, 92.13, 44.8, 31, "Germany · Frankfurt"),
            row("st-3", 26 * HOUR, 54.6, 22.3, 54, "Finland · Helsinki"),
            row("st-2", 50 * HOUR, 12.8, 6.1, 142, "USA · New York"),
            row("st-1", 98 * HOUR, 76.0, 35.5, 47, "Poland · Warsaw"),
        ];
        history[2].egress = Egress::Changed {
            seen: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77))),
        };
        history[3].server_name = "OVH".to_owned();
        history[3].plain_http = true;
        history[4].egress = Egress::NotChecked;
        Self::with_state(SpeedTestState {
            tunnel_running,
            history,
            history_error: None,
        })
    }

    /// Exactly this state.
    pub fn with_state(state: SpeedTestState) -> Self {
        Self {
            state: watch::Sender::new(state),
            step: Duration::from_millis(160),
            outcome: Cell::new(DemoOutcome::Normal),
            next_id: Cell::new(6),
        }
    }

    /// Pause between two progress events (zero in tests).
    #[must_use]
    pub fn with_step(mut self, step: Duration) -> Self {
        self.step = step;
        self
    }

    /// How the following runs end.
    #[must_use]
    pub fn with_outcome(self, outcome: DemoOutcome) -> Self {
        self.outcome.set(outcome);
        self
    }

    /// Pushes a state change, as the app does when the tunnel or the history changes.
    pub fn update(&self, change: impl FnOnce(&mut SpeedTestState)) {
        self.state.send_modify(change);
    }

    async fn report(
        &self,
        progress: &watch::Sender<SpeedProgress>,
        cancel: &CancellationToken,
        percent: u8,
        phase: SpeedPhase,
    ) -> AppResult<()> {
        progress.send_replace(SpeedProgress { percent, phase });
        tokio::select! {
            () = cancel.cancelled() => Err(AppError::cancelled()),
            () = tokio::time::sleep(self.step) => Ok(()),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl SpeedTestApi for DemoSpeedTest {
    fn state(&self) -> watch::Receiver<SpeedTestState> {
        self.state.subscribe()
    }

    async fn run(
        &self,
        progress: watch::Sender<SpeedProgress>,
        cancel: CancellationToken,
    ) -> AppResult<SpeedResult> {
        if !self.state.borrow().tunnel_running {
            return Err(AppError::conflict(Msg::new("speedTest.vpnNotConnected")));
        }
        for _ in 0..4 {
            self.report(&progress, &cancel, 0, SpeedPhase::Latency)
                .await?;
        }
        for percent in (5..=50).step_by(5) {
            self.report(&progress, &cancel, percent, SpeedPhase::Download)
                .await?;
            if self.outcome.get() == DemoOutcome::Fail && percent == 30 {
                return Err(AppError::new(ErrorKind::Network));
            }
        }
        for percent in (55..=100).step_by(5) {
            self.report(&progress, &cancel, percent, SpeedPhase::Upload)
                .await?;
        }
        self.report(&progress, &cancel, 100, SpeedPhase::Complete)
            .await?;
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        let egress = match self.outcome.get() {
            DemoOutcome::Mismatch => Egress::Changed {
                seen: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77))),
            },
            _ => Egress::Match,
        };
        let result = SpeedResult {
            id: format!("st-{id}"),
            timestamp: now_ms(),
            download_mbps: (f64::from(fastrand::u32(6000..12_000)) / 100.0),
            upload_mbps: Some(f64::from(fastrand::u32(2500..6000)) / 100.0),
            latency_ms: fastrand::u32(28..64),
            server_name: "Cloudflare".to_owned(),
            profile_used: "Netherlands · Amsterdam".to_owned(),
            egress,
            plain_http: false,
        };
        self.state.send_modify(|state| {
            state.history.insert(0, result.clone());
            state.history.truncate(50);
        });
        Ok(result)
    }
}
