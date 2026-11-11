//! Per-slot route health (spec 3.15–3.19, B-5, B-30): what the probes established about a slot
//! and the pure transitions of its state machine. The manager owns the state, runs the probes
//! and follows the returned [`Next`]; nothing here does I/O or reads a clock.
use std::net::IpAddr;
use std::time::Duration;

use vpnte_base::types::UnixMs;

use crate::model::ready::is_healthy_route;
use crate::model::{Degradation, Health, Lifecycle};
use crate::probe::{ProbeError, ProbeOk};
use crate::slot::Slot;

/// Consecutive counted failures that stop a slot (old threshold: the three cooldowns + 1).
pub const FAILURE_BUDGET: u32 = 4;

/// When the probes run (spec 2.4; B-30 for the success interval). Tests scale it down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// First probe after a start: `first_probe + (slot % 5) * first_stagger`, so a batch of
    /// starts does not open all probe tunnels at once.
    pub first_probe: Duration,
    pub first_stagger: Duration,
    /// Re-probe after a success: `success + (slot % 5) * success_stagger`. Shorter than the
    /// 60 s freshness window, so a healthy slot never drops out of "ready" between probes
    /// (the old 60 s interval made every slot flap once a minute, B-30).
    pub success: Duration,
    pub success_stagger: Duration,
    /// Retry after the 1st / 2nd / 3rd consecutive counted failure.
    pub cooldowns: [Duration; 3],
    /// Re-probe after a failure that does not count (the route answered).
    pub recheck: Duration,
    /// Re-probe of a leased slot whose automatic stop is blocked.
    pub leased_recheck: Duration,
    /// A transport hint in the engine log pulls the next probe this close...
    pub hint_delay: Duration,
    /// ...at most once per this interval, so a noisy client app cannot cause probe storms.
    pub hint_spacing: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        let s = Duration::from_secs;
        let ms = Duration::from_millis;
        Self {
            // The readiness wait already saw the listener accept, so no fixed 750 ms head start.
            first_probe: ms(0),
            first_stagger: ms(100),
            success: s(45),
            success_stagger: ms(250),
            cooldowns: [s(15), s(30), s(60)],
            recheck: s(60),
            leased_recheck: s(300),
            hint_delay: s(15),
            hint_spacing: s(30),
        }
    }
}

impl Timing {
    /// Delay of the first probe of `slot` after a start.
    pub fn first(&self, slot: Slot) -> Duration {
        self.first_probe + self.first_stagger * u32::from(slot.get() % 5)
    }

    /// Delay of the next probe of `slot` after a success.
    pub fn after_success(&self, slot: Slot) -> Duration {
        self.success + self.success_stagger * u32::from(slot.get() % 5)
    }

    /// Retry delay after `failures` consecutive counted failures (1 → first cooldown).
    pub fn cooldown(&self, failures: u32) -> Duration {
        let index = failures.saturating_sub(1).min(2) as usize;
        self.cooldowns[index]
    }
}

/// What the health loop does after a transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Probe again after this delay.
    In(Duration),
    /// No scheduled probe: a degraded identity waits for a rotate, a start or a probe someone
    /// asks for (`check_health`, prewarm, the stale-probe side effect of `instances`).
    Park,
    /// The failure budget is spent: stop the slot (a leased one is blocked instead).
    Disable,
    /// The slot's own listener refused: kill the engine (it may hang while holding the port).
    Kill,
}

/// How a duplicate egress IP is resolved (spec 3.17): a leased route is never taken away from
/// its consumer; otherwise the lowest-numbered slot keeps the IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Duplicate {
    /// This slot is quarantined; `keeper` holds the IP.
    Quarantine { keeper: Slot },
    /// This slot is leased and keeps the IP; the unleased `peer` is quarantined.
    QuarantinePeer(Slot),
}

/// Picks who keeps a duplicate IP. `dups` = the other healthy slots on the same IP, in slot
/// order, with whether each is leased.
pub fn resolve_duplicate(self_leased: bool, dups: &[(Slot, bool)]) -> Option<Duplicate> {
    let lowest = dups.iter().map(|(slot, _)| *slot).min()?;
    let leased_peer = dups.iter().find(|(_, leased)| *leased).map(|(s, _)| *s);
    Some(match leased_peer {
        None if self_leased => Duplicate::QuarantinePeer(lowest),
        peer => Duplicate::Quarantine {
            keeper: peer.unwrap_or(lowest),
        },
    })
}

/// Engine output that hints at a dying route (old `recordExternalProxyTransportSignal` regex).
pub fn is_transport_hint(line: &str) -> bool {
    const NEEDLES: [&str; 6] = [
        "context deadline exceeded",
        "timeout",
        "timed out",
        "eof",
        "socket hang up",
        "econnreset",
    ];
    let line = line.to_ascii_lowercase();
    NEEDLES.iter().any(|needle| line.contains(needle))
}

/// What the probes established about one slot (the health part of the old per-slot state).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Route {
    pub lifecycle: Lifecycle,
    pub health: Health,
    /// Exit address of the last successful probe (cleared by a failed one).
    pub egress_ip: Option<IpAddr>,
    pub latency_ms: Option<u32>,
    pub last_checked_at: Option<UnixMs>,
    pub last_success_at: Option<UnixMs>,
    pub last_error: Option<String>,
    pub last_error_at: Option<UnixMs>,
    pub degradation: Option<Degradation>,
    pub consecutive_failures: u32,
    /// When the next scheduled probe runs (`None` = none scheduled).
    pub next_check_at: Option<UnixMs>,
    /// Egress before a rotation: landing on it again means the rotation changed nothing.
    pub rotation_prev_egress: Option<IpAddr>,
    /// Last engine-log hint that pulled a probe in.
    pub last_hint_at: Option<UnixMs>,
}

impl Route {
    /// Fresh health of a (re)start (3.15); a rotation remembers the egress it leaves.
    pub fn begin(&mut self, rotating: bool) {
        let (lifecycle, health) = if rotating {
            (Lifecycle::Rotating, Health::Rotating)
        } else {
            (Lifecycle::Starting, Health::Starting)
        };
        let previous = self.egress_ip;
        *self = Route {
            lifecycle,
            health,
            rotation_prev_egress: previous.filter(|_| rotating),
            ..Route::default()
        };
    }

    /// The health of an explicitly stopped slot (3.20).
    pub fn stopped(now: UnixMs) -> Self {
        Route {
            last_checked_at: Some(now),
            ..Route::default()
        }
    }

    /// A healthy route at `now`: engine running, ready, healthy, egress confirmed recently (the
    /// rule readiness builds on).
    pub fn is_healthy(&self, running: bool, now: UnixMs) -> bool {
        is_healthy_route(
            running,
            self.lifecycle,
            self.health,
            self.egress_ip,
            self.last_success_at,
            now,
        )
    }

    /// Applies a successful probe (3.17 checks A, B, C). Returns `true` when the slot is now
    /// healthy; the caller then runs the duplicate check. A drifted exit (the server's NAT pool
    /// or balancer moved it without a rotation) or a rotation that kept the old exit leaves the
    /// slot degraded with no scheduled probe: its identity cannot be trusted.
    pub fn succeeded(&mut self, ok: ProbeOk, now: UnixMs) -> bool {
        let previous = self.egress_ip;
        self.egress_ip = Some(ok.egress_ip);
        self.latency_ms = Some(ok.latency_ms);
        self.last_checked_at = Some(now);
        self.last_success_at = Some(now);
        if let Some(previous) = previous.filter(|p| *p != ok.egress_ip) {
            let msg = format!(
                "Egress IP changed from {previous} to {} without a route rotation",
                ok.egress_ip
            );
            self.degrade(Degradation::EgressIpChangedWithoutRotation, msg, false, now);
            return false;
        }
        if self.rotation_prev_egress == Some(ok.egress_ip) {
            let msg = format!("Rotation kept the previous egress IP {}", ok.egress_ip);
            self.degrade(Degradation::RotationDidNotChangeEgressIp, msg, false, now);
            return false;
        }
        self.health = Health::Healthy;
        self.lifecycle = Lifecycle::Ready;
        self.last_error = None;
        self.last_error_at = None;
        self.consecutive_failures = 0;
        self.degradation = None;
        self.rotation_prev_egress = None;
        true
    }

    /// Applies a failed probe (3.17 catch branch, classified by stage, B-5). The egress is
    /// cleared, so a route that fails once and returns on another IP is accepted (no drift).
    pub fn failed(&mut self, err: &ProbeError, now: UnixMs, timing: &Timing) -> Next {
        self.lifecycle = Lifecycle::Degraded;
        self.health = Health::Degraded;
        self.egress_ip = None;
        self.latency_ms = None;
        self.last_checked_at = Some(now);
        self.last_error = Some(err.to_string());
        self.last_error_at = Some(now);
        self.degradation = Some(Degradation::EgressProbeFailed);
        self.next_check_at = None;
        match err {
            ProbeError::LocalInbound(_) => Next::Kill,
            ProbeError::Transport(_) => {
                self.consecutive_failures += 1;
                if self.consecutive_failures >= FAILURE_BUDGET {
                    Next::Disable
                } else {
                    Next::In(timing.cooldown(self.consecutive_failures))
                }
            }
            ProbeError::Service(_) => {
                self.consecutive_failures = 0;
                Next::In(timing.recheck)
            }
        }
    }

    /// Degraded or quarantined with no scheduled probe (old `markExternalProxyDegraded`); the
    /// egress IP is kept, so a later probe that sees the same IP heals the slot.
    pub fn degrade(
        &mut self,
        reason: Degradation,
        message: String,
        quarantined: bool,
        now: UnixMs,
    ) {
        let (lifecycle, health) = if quarantined {
            (Lifecycle::Quarantined, Health::Quarantined)
        } else {
            (Lifecycle::Degraded, Health::Degraded)
        };
        self.lifecycle = lifecycle;
        self.health = health;
        self.degradation = Some(reason);
        self.last_error = Some(message);
        self.last_error_at = Some(now);
        self.next_check_at = None;
    }

    /// The engine died or could not start (old `markExternalProxyProcessFailure`). No automatic
    /// restart: a manual start or rotate is the recovery.
    pub fn process_failed(&mut self, message: String, now: UnixMs) {
        self.lifecycle = Lifecycle::Failed;
        self.health = Health::Failed;
        self.egress_ip = None;
        self.latency_ms = None;
        self.last_checked_at = Some(now);
        self.last_error = Some(message);
        self.last_error_at = Some(now);
        self.degradation = Some(Degradation::ProcessFailed);
        self.next_check_at = None;
    }

    /// The failure budget is spent but a lease forbids stopping: never yank a route from under
    /// its consumer; stay degraded and re-probe at `leased_recheck` (3.16).
    pub fn disable_blocked(&mut self, now: UnixMs) {
        self.lifecycle = Lifecycle::Degraded;
        self.health = Health::Degraded;
        self.degradation = Some(Degradation::LeasedRouteRecoveryBlocked);
        self.last_error.get_or_insert_with(|| {
            "Automatic stop is blocked while a Buyer Search lease is active".into()
        });
        self.last_error_at = Some(now);
    }

    /// The failure budget is spent and the slot is stopped (3.16). Restarting the same config
    /// would only create a new burst of failing handshakes; a manual start or rotate recovers.
    pub fn disabled(&mut self, now: UnixMs) {
        self.lifecycle = Lifecycle::Failed;
        self.health = Health::Failed;
        self.degradation = Some(Degradation::HealthFailureBudgetExhausted);
        self.last_error.get_or_insert_with(|| {
            "External proxy disabled after repeated transport failures".into()
        });
        self.last_error_at = Some(now);
        self.next_check_at = None;
    }

    /// Engine output hinting that the route died (3.19): while healthy, pull the next probe in
    /// to `hint_delay`, at most once per `hint_spacing`. Returns the delay to probe after.
    pub fn hint(&mut self, line: &str, now: UnixMs, timing: &Timing) -> Option<Duration> {
        if self.health != Health::Healthy || !is_transport_hint(line) {
            return None;
        }
        let spacing = ms(timing.hint_spacing);
        if self.last_hint_at.is_some_and(|t| now - t < spacing) {
            return None;
        }
        self.last_hint_at = Some(now);
        let soon = now + ms(timing.hint_delay);
        self.next_check_at
            .is_none_or(|next| soon < next)
            .then_some(timing.hint_delay)
    }
}

/// A duration as [`UnixMs`] (saturating).
pub fn ms(d: Duration) -> UnixMs {
    UnixMs::try_from(d.as_millis()).unwrap_or(UnixMs::MAX)
}

#[cfg(test)]
mod tests;
