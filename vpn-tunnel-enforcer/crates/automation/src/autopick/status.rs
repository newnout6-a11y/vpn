//! What the automatic choice is doing, as the start page's status line shows it.
use vpnte_base::Msg;
use vpnte_base::types::UnixMs;

/// What the user's traffic does right now; the app computes it from the live state (capture,
/// kill-switch level, lane state) on every change, never from a stored snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Exposure {
    /// No session and nothing that blocks: programs go out without the VPN.
    Direct,
    /// The kill switch keeps the TUN's block: traffic waits until the connection is back.
    Blocked,
    /// The kill switch keeps the system proxy at the engine's dead port: programs that use it
    /// wait, the others go direct (proxy capture never holds everything).
    ProxyBlocked,
    /// A TUN session runs: all traffic stays inside it (also while it carries nothing).
    Tunnel,
    /// A proxy-capture session runs: programs that use the system proxy stay inside it, the
    /// others go direct.
    ProxyTunnel,
    /// Not proven either way.
    #[default]
    Unknown,
}

/// The current step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Phase {
    #[default]
    Idle,
    /// Connecting at launch.
    Launching,
    /// The running session looked stalled: one transfer through it decides.
    Confirming,
    /// Every server failed: the failed server's subscription is being fetched again.
    Refreshing,
    /// Trying a server.
    Trying,
    /// Pausing before the next round.
    Waiting,
    /// Rounds used up: nothing more is tried until the user or the network changes something.
    GaveUp,
}

/// The status snapshot (watch).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PickStatus {
    pub phase: Phase,
    /// The server the step is about (display name).
    pub server: Option<String>,
    /// Round of the retries after everything failed (1-based; 0 outside them).
    pub round: u8,
    /// When the next round starts (`Waiting`).
    pub retry_at: Option<UnixMs>,
}

impl PickStatus {
    /// The status line, `None` while idle.
    pub fn headline(&self) -> Option<Msg> {
        let name = self.server.clone().unwrap_or_default();
        let key = match self.phase {
            Phase::Idle => return None,
            Phase::Launching => "automation.autopick.status.launching",
            Phase::Confirming => "automation.autopick.status.confirming",
            Phase::Refreshing => "automation.autopick.status.refreshing",
            Phase::Trying => "automation.autopick.status.trying",
            Phase::Waiting => "automation.autopick.status.waiting",
            Phase::GaveUp => "automation.autopick.status.gaveUp",
        };
        Some(
            Msg::new(key)
                .arg("name", name)
                .arg("round", u64::from(self.round))
                .arg("rounds", u64::from(super::rescue::ROUNDS)),
        )
    }

    /// What traffic does meanwhile (`now`: the live exposure), in every step; `None` while idle.
    pub fn exposure_line(&self, now: Exposure) -> Option<Msg> {
        (self.phase != Phase::Idle).then(|| now.msg())
    }
}

impl Exposure {
    /// The line that says it.
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            Exposure::Direct => "automation.autopick.exposure.direct",
            Exposure::Blocked => "automation.autopick.exposure.blocked",
            Exposure::ProxyBlocked => "automation.autopick.exposure.proxyBlocked",
            Exposure::Tunnel => "automation.autopick.exposure.tunnel",
            Exposure::ProxyTunnel => "automation.autopick.exposure.proxyTunnel",
            Exposure::Unknown => "automation.autopick.exposure.unknown",
        })
    }
}
