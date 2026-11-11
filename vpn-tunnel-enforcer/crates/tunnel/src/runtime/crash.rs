//! Crash policy (tunnel-core §3.5, decided): what follows an unexpected end of the core, or a
//! failed recovery start. Pure, so the table is pinned by tests.
use std::time::Duration;

use vpnte_base::types::KillSwitchLevel;

use super::MAX_RESTARTS;

/// What the actor does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CrashAction {
    /// Restart the last start (origin `Recovery`) after `delay`; `attempt` of [`MAX_RESTARTS`].
    Restart { attempt: u8, delay: Duration },
    /// Budget exhausted: try the post-trial failover once before the terminal outcome.
    Failover,
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
    /// The setting, re-read now.
    pub auto_restart: bool,
    /// Kill-switch level the session's protection enforces.
    pub guard: KillSwitchLevel,
    /// A failover policy exists and was not tried in this window.
    pub failover_available: bool,
}

/// First match wins (tunnel-core §3.5 "New (decided)").
pub(super) fn decide(f: CrashFacts, backoff: &[Duration; 3]) -> CrashAction {
    if f.auto_restart && f.attempt < MAX_RESTARTS {
        let delay = backoff[usize::from(f.attempt).min(backoff.len() - 1)];
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
        KillSwitchLevel::Strict => CrashAction::Block,
        KillSwitchLevel::Standard if !exhausted => CrashAction::Block,
        KillSwitchLevel::Standard => CrashAction::Release,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::Timings;

    fn facts(attempt: u8, auto_restart: bool, guard: KillSwitchLevel) -> CrashFacts {
        CrashFacts {
            attempt,
            auto_restart,
            guard,
            failover_available: false,
        }
    }

    /// AT-02-005 (§2.10 / §7.20): restarts after 2 s, 5 s, 10 s, at most three per window.
    #[test]
    fn backoff_schedule() {
        let backoff = Timings::default().backoff;
        let delays: Vec<_> = (0..3)
            .map(|n| decide(facts(n, true, KillSwitchLevel::Off), &backoff))
            .collect();
        let want = [(1, 2), (2, 5), (3, 10)].map(|(attempt, s)| CrashAction::Restart {
            attempt,
            delay: Duration::from_secs(s),
        });
        assert_eq!(delays, want);
    }

    /// The terminal table, first match wins: no protection → stopped; strict → keep blocking;
    /// auto-restart off → keep blocking and say so; exhausted standard → release.
    #[test]
    fn terminal_outcomes() {
        use KillSwitchLevel::{Off, Standard, Strict};
        let b = Timings::default().backoff;
        let cases = [
            (3, true, Off, CrashAction::Release),
            (0, false, Off, CrashAction::Release),
            (3, true, Strict, CrashAction::Block),
            (0, false, Strict, CrashAction::Block),
            (0, false, Standard, CrashAction::Block),
            (3, true, Standard, CrashAction::Release),
        ];
        for (attempt, auto, guard, want) in cases {
            assert_eq!(decide(facts(attempt, auto, guard), &b), want, "{guard:?}");
        }
    }

    /// The failover is tried once, only after the budget is exhausted (never with auto-restart
    /// off: the user asked for no automatic action).
    #[test]
    fn failover_only_after_exhaustion() {
        let b = Timings::default().backoff;
        let mut f = facts(3, true, KillSwitchLevel::Standard);
        f.failover_available = true;
        assert_eq!(decide(f, &b), CrashAction::Failover);
        f.auto_restart = false;
        assert_eq!(decide(f, &b), CrashAction::Block);
        f = facts(1, true, KillSwitchLevel::Off);
        f.failover_available = true;
        assert!(matches!(
            decide(f, &b),
            CrashAction::Restart { attempt: 2, .. }
        ));
    }
}
