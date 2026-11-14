//! View-model of the Speed test page.
use std::net::IpAddr;

use vpnte_base::Msg;
use vpnte_base::types::UnixMs;

/// Pushed page state (one snapshot; the page mirrors it into a signal).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SpeedTestState {
    /// A test can only run through a running tunnel.
    pub tunnel_running: bool,
    /// Saved results in the backend's order (newest first, at most 50).
    pub history: Vec<SpeedResult>,
    /// The saved history could not be read: shown instead of "no tests yet" (U-06).
    pub history_error: Option<Msg>,
}

/// One finished speed test.
#[derive(Debug, Clone, PartialEq)]
pub struct SpeedResult {
    pub id: String,
    pub timestamp: UnixMs,
    pub download_mbps: f64,
    /// `None`: the upload could not be measured (the download and latency still count).
    pub upload_mbps: Option<f64>,
    pub latency_ms: u32,
    /// The measuring server (Cloudflare, OVH, Tele2).
    pub server_name: String,
    /// The VPN server the test ran through.
    pub profile_used: String,
    /// The exit IP seen during the test compared with the tunnel's exit.
    pub egress: Egress,
    /// The download was measured over plain HTTP because no HTTPS server answered.
    pub plain_http: bool,
}

/// What the exit-IP check during the test showed (owner §10.5: a warning only, the figures
/// are kept).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Egress {
    /// The test left through the tunnel's exit.
    Match,
    /// The test saw another exit IP than the app reports.
    Changed { seen: Option<IpAddr> },
    /// The test left from the user's real address: it bypassed the tunnel.
    Direct { seen: IpAddr },
    /// The exit IP could not be checked.
    #[default]
    NotChecked,
}

/// Live progress of a run (sent by the backend through the run's own channel).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SpeedProgress {
    /// 0..=100: latency 0, download 5..50, upload 50..100, complete 100.
    pub percent: u8,
    pub phase: SpeedPhase,
}

/// Stage of a running test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SpeedPhase {
    #[default]
    Latency,
    Download,
    Upload,
    Complete,
}
