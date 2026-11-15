//! The per-user marker `legacy-network-cleanup.json` in the data dir: completion, attempts and
//! the last run's step records. The old journals are machine-wide; the marker only decides
//! whether this user's start runs the cleanup again.
use serde::{Deserialize, Serialize};
use vpnte_base::types::UnixMs;
use vpnte_core::store::Document;

use super::report::{CleanupReport, StepRecord};

/// Runs with a failed step before the start-up cleanup stops retrying (the maintenance action
/// "run legacy cleanup again" still works).
pub const MAX_ATTEMPTS: u32 = 3;

/// `legacy-network-cleanup.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CleanupMarker {
    /// Set by the first run without a failed step.
    pub completed_at: Option<UnixMs>,
    /// Runs started so far (counted before acting, so a crash mid-run counts too).
    pub attempts: u32,
    /// Start of the last run.
    pub last_attempt_at: Option<UnixMs>,
    /// Records of the last finished run.
    pub steps: Vec<StepRecord>,
}

impl Document for CleanupMarker {
    const FILE: &'static str = "legacy-network-cleanup.json";
    const VERSION: u32 = 1;
}

impl CleanupMarker {
    /// The start-up cleanup should run.
    pub fn is_due(&self) -> bool {
        self.completed_at.is_none() && self.attempts < MAX_ATTEMPTS
    }

    /// Retries are exhausted with failures left: keep the diagnostics entry and offer the
    /// maintenance action.
    pub fn gave_up(&self) -> bool {
        self.completed_at.is_none() && self.attempts >= MAX_ATTEMPTS
    }

    pub(crate) fn begin(&mut self, now: UnixMs) {
        self.attempts = self.attempts.saturating_add(1);
        self.last_attempt_at = Some(now);
    }

    pub(crate) fn finish(&mut self, report: &CleanupReport, now: UnixMs) {
        self.steps = report.steps.clone();
        if !report.failed() {
            self.completed_at = Some(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::report::{Outcome, StepId};
    use super::*;

    fn report(outcome: Outcome) -> CleanupReport {
        CleanupReport {
            steps: vec![StepRecord::new(StepId::Firewall, outcome, "d")],
            ..CleanupReport::default()
        }
    }

    #[test]
    fn retries_at_most_three_times() {
        let mut m = CleanupMarker::default();
        for attempt in 1..=MAX_ATTEMPTS {
            assert!(m.is_due());
            m.begin(attempt as i64);
            m.finish(&report(Outcome::Failed), 10);
        }
        assert!(!m.is_due());
        assert!(m.gave_up());
        assert_eq!(m.attempts, 3);
        assert_eq!(m.completed_at, None);
        // The maintenance action may still run and complete it.
        m.begin(20);
        m.finish(&report(Outcome::Skipped), 21);
        assert_eq!(m.completed_at, Some(21));
        assert!(!m.is_due() && !m.gave_up());
    }

    #[test]
    fn a_crash_mid_run_counts_as_an_attempt() {
        let mut m = CleanupMarker::default();
        m.begin(1);
        assert_eq!(m.attempts, 1);
        assert!(m.steps.is_empty());
        assert!(m.is_due());
    }

    #[test]
    fn marker_shape() {
        let mut m = CleanupMarker::default();
        m.begin(5);
        m.finish(&report(Outcome::Done), 6);
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["completedAt"], 6);
        assert_eq!(v["attempts"], 1);
        assert_eq!(v["steps"][0]["step"], "firewall");
        assert_eq!(v["steps"][0]["outcome"], "done");
        let back: CleanupMarker = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(back, CleanupMarker::default());
    }
}
