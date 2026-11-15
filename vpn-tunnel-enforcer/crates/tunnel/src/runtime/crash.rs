//! Crash policy (tunnel-core §3.5, decided): what follows an unexpected end of the core, or a
//! failed recovery start. Pure, so the table is pinned by tests.
//!
//! RU discipline (Nov 2026): a server name that saw a handful of TLS handshakes within a minute
//! is frozen for the client for ~120 s, and dialling it again inside that window extends it. A
//! restart brings the user's traffic back to the server at once, so after a crash with an
//! outbound fault on record the same server waits out the window ([`Timings::freeze`]); a fresh
//! server through the failover may be dialled at once.
//!
//! [`Timings::freeze`]: super::Timings::freeze
use std::time::Duration;

use vpnte_base::types::{KillSwitchLevel, OutboundFault};

use super::MAX_RESTARTS;
use crate::api::{Mode, StartRequest};

/// What the actor does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CrashAction {
    /// Restart the last start (origin `Recovery`) after `delay`; `attempt` of [`MAX_RESTARTS`].
    Restart { attempt: u8, delay: Duration },
    /// Try the post-trial failover once before the terminal outcome (budget exhausted), or at
    /// once while the crashed server must stay quiet.
    Failover,
    /// The kill switch keeps the internet paused (`KillSwitchActive`) and the last start is
    /// retried slowly after `delay`: a paused session is never released silently (ks-a).
    SlowRetry { delay: Duration },
    /// Terminal: protection keeps blocking (`KillSwitchActive`; the lifecycle tells the user).
    Block,
    /// Terminal: protection released, `Stopped` (`restart_attempt` in the status tells whether
    /// the budget was exhausted).
    Release,
}

/// The facts the decision reads.
#[derive(Debug, Clone, Copy)]
pub(super) struct CrashFacts {
    /// Restarts already made in this crash window.
    pub attempt: u8,
    /// Slow retries already made in this pause.
    pub slow: u8,
    /// The setting, re-read now.
    pub auto_restart: bool,
    /// Kill-switch level the session's protection enforces.
    pub guard: KillSwitchLevel,
    /// A failover policy exists and was not tried in this window.
    pub failover_available: bool,
    /// What is left of the freeze window of the server a restart would dial (zero = none).
    pub quiet: Duration,
}

/// First match wins (tunnel-core §3.5 "New (decided)"), with the freeze window on top. A
/// kill switch that pauses the internet keeps it paused once the budget is spent and retries
/// slowly; with auto-restart off it keeps the pause without retrying (no automatic action).
pub(super) fn decide(f: CrashFacts, backoff: &[Duration; 3], slow: &[Duration; 3]) -> CrashAction {
    if f.auto_restart && f.attempt < MAX_RESTARTS {
        if !f.quiet.is_zero() && f.failover_available {
            return CrashAction::Failover;
        }
        let delay = backoff[usize::from(f.attempt).min(backoff.len() - 1)].max(f.quiet);
        return CrashAction::Restart {
            attempt: f.attempt + 1,
            delay,
        };
    }
    let exhausted = f.auto_restart;
    if exhausted && f.failover_available {
        return CrashAction::Failover;
    }
    match f.guard {
        KillSwitchLevel::Off => CrashAction::Release,
        _ if !exhausted => CrashAction::Block,
        _ => CrashAction::SlowRetry {
            delay: slow[usize::from(f.slow).min(slow.len() - 1)].max(f.quiet),
        },
    }
}

/// The profile id of the server a crashed session dialled itself, when its engines saw an
/// outbound fault: refused, failed or unanswered handshakes all read as a server that may be
/// frozen (a freeze shows as dial or handshake timeouts, and Xray cannot tell a REALITY refusal
/// from an unreachable server). A local proxy's server is dialled by another client: not ours.
pub(super) fn frozen_server(req: &StartRequest, fault: Option<OutboundFault>) -> Option<&str> {
    match (&req.mode, fault) {
        (Mode::DirectVpn { profile }, Some(_)) => Some(&profile.id),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::Timings;

    fn facts(attempt: u8, auto_restart: bool, guard: KillSwitchLevel) -> CrashFacts {
        CrashFacts {
            attempt,
            slow: 0,
            auto_restart,
            guard,
            failover_available: false,
            quiet: Duration::ZERO,
        }
    }

    fn decide_now(f: CrashFacts) -> CrashAction {
        let t = Timings::default();
        decide(f, &t.backoff, &t.slow_retry)
    }

    /// AT-02-003 (§2.10 / §7.20; speed3 S3-01, owner default 3): the first restart at once,
    /// then after 5 s and 10 s, at most three per window.
    #[test]
    fn backoff_schedule() {
        let delays: Vec<_> = (0..3)
            .map(|n| decide_now(facts(n, true, KillSwitchLevel::Off)))
            .collect();
        let want = [(1, 0), (2, 5), (3, 10)].map(|(attempt, s)| CrashAction::Restart {
            attempt,
            delay: Duration::from_secs(s),
        });
        assert_eq!(delays, want);
    }

    /// The terminal table, first match wins: no protection → stopped; auto-restart off → keep
    /// the pause without retrying; a spent budget with the kill switch on → keep the pause and
    /// retry slowly (ks-a: never released silently).
    #[test]
    fn terminal_outcomes() {
        use KillSwitchLevel::{Off, Standard, Strict};
        let slow = CrashAction::SlowRetry {
            delay: Duration::from_secs(60),
        };
        let cases = [
            (3, true, Off, CrashAction::Release),
            (0, false, Off, CrashAction::Release),
            (3, true, Strict, slow),
            (0, false, Strict, CrashAction::Block),
            (0, false, Standard, CrashAction::Block),
            (3, true, Standard, slow),
        ];
        for (attempt, auto, guard, want) in cases {
            assert_eq!(decide_now(facts(attempt, auto, guard)), want, "{guard:?}");
        }
    }

    /// ks-a (research 5.4): slow retries after 1, 2, 5 minutes, then every 5 minutes, never
    /// inside the freeze window of the server they would dial.
    #[test]
    fn slow_retries_back_off_to_five_minutes() {
        let mut f = facts(3, true, KillSwitchLevel::Standard);
        let delays: Vec<u64> = (0..5)
            .map(|n| {
                f.slow = n;
                match decide_now(f) {
                    CrashAction::SlowRetry { delay } => delay.as_secs(),
                    other => panic!("{other:?}"),
                }
            })
            .collect();
        assert_eq!(delays, [60, 120, 300, 300, 300]);
        f.slow = 0;
        f.quiet = Duration::from_secs(130);
        assert_eq!(
            decide_now(f),
            CrashAction::SlowRetry {
                delay: Duration::from_secs(130)
            }
        );
    }

    /// The failover is tried once, only after the budget is exhausted (never with auto-restart
    /// off: the user asked for no automatic action).
    #[test]
    fn failover_only_after_exhaustion() {
        let mut f = facts(3, true, KillSwitchLevel::Standard);
        f.failover_available = true;
        assert_eq!(decide_now(f), CrashAction::Failover);
        f.auto_restart = false;
        assert_eq!(decide_now(f), CrashAction::Block);
        f = facts(1, true, KillSwitchLevel::Off);
        f.failover_available = true;
        assert!(matches!(
            decide_now(f),
            CrashAction::Restart { attempt: 2, .. }
        ));
    }

    /// RU discipline: no restart of a frozen server inside the window, whichever attempt; the
    /// backoff still applies once the window is shorter; a fresh server (failover) at once.
    #[test]
    fn the_same_server_waits_out_the_freeze_window() {
        let window = Timings::default().freeze;
        assert_eq!(window, Duration::from_secs(130));
        let mut f = facts(0, true, KillSwitchLevel::Strict);
        f.quiet = window;
        for attempt in 0..3 {
            f.attempt = attempt;
            assert_eq!(
                decide_now(f),
                CrashAction::Restart {
                    attempt: attempt + 1,
                    delay: window
                }
            );
        }
        f.attempt = 2;
        f.quiet = Duration::from_secs(4);
        assert_eq!(
            decide_now(f),
            CrashAction::Restart {
                attempt: 3,
                delay: Duration::from_secs(10)
            }
        );
        f.attempt = 0;
        f.failover_available = true;
        assert_eq!(decide_now(f), CrashAction::Failover);
        f.auto_restart = false;
        assert_eq!(decide_now(f), CrashAction::Block, "no automatic action");
    }

    /// Only a server our engines dialled, and only with a fault on record, is held back.
    #[test]
    fn frozen_server_needs_a_direct_session_and_a_fault() {
        let uri = "trojan://fake-password@203.0.113.12:443?security=tls&sni=example.com#Fake";
        let vpn = crate::runtime::tests::vpn_req(uri, vpnte_base::types::EnginePref::Auto);
        let local = crate::runtime::tests::local_req();
        for fault in [
            OutboundFault::RealityKeyMismatch,
            OutboundFault::TlsHandshakeFailed,
            OutboundFault::UpstreamUnreachable,
        ] {
            assert_eq!(frozen_server(&vpn, Some(fault)), Some("Fake"));
            assert_eq!(frozen_server(&local, Some(fault)), None);
        }
        assert_eq!(frozen_server(&vpn, None), None);
    }
}
