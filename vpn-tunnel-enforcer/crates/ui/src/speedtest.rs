//! Speed test page («Тест скорости»): download, upload and latency through the tunnel, live
//! progress, the result with its exit-IP warning, and the saved history (ui-pages §3.13,
//! monitoring §3.11).
//!
//! The page talks to the backend only through [`SpeedTestApi`], handed down as
//! `Rc<dyn SpeedTestApi>` in context; [`demo::DemoSpeedTest`] is the fake used by `demo_tools`
//! and the tests.
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;

mod ctl;
pub mod demo;
mod format;
mod model;
mod page;

pub use format::{egress_look, fmt_mbps, format_date_time, phase_key};
pub use model::{Egress, SpeedPhase, SpeedProgress, SpeedResult, SpeedTestState};
pub use page::SpeedTestPage;

/// What the Speed test page needs from the backend (implemented by the app over the probes).
#[async_trait::async_trait(?Send)]
pub trait SpeedTestApi: 'static {
    /// Tunnel state and the saved history, pushed on every change.
    fn state(&self) -> watch::Receiver<SpeedTestState>;
    /// Runs one test through the tunnel, reporting through `progress` (a channel of this run
    /// only, so a late event of an older run cannot reach the page). The backend saves the
    /// result to the history before returning; no tunnel is `ErrorKind::Conflict`; cancelling
    /// `cancel` drops every stream and ends the run with `ErrorKind::Cancelled`.
    async fn run(
        &self,
        progress: watch::Sender<SpeedProgress>,
        cancel: CancellationToken,
    ) -> AppResult<SpeedResult>;
}
