//! Outcome of one cleanup run: one record per independent step, plus the notices to show.
use serde::{Deserialize, Serialize};
use vpnte_base::Msg;
use vpnte_base::types::{Level, Notice};

/// One independent cleanup step (wire names are the marker's `step` values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepId {
    /// Old engine processes still running from `%ProgramData%\VPNTE\runtime`.
    Processes,
    /// Reading and trusting the old journals in `%ProgramData%\VPNTE\manifests`.
    Journals,
    /// Windows Firewall: `VPNTE-killswitch*` rules and the profile outbound defaults.
    Firewall,
    /// sing-box's own `sing-tun (<engine path>)` inbound rules.
    SingTunRules,
    /// The old WFP IPv6 sublayer `VPNTE.IPv6.v1` and its filters.
    LegacyWfp,
    /// IPv6 bindings and static DNS of physical adapters (old adapter lockdown).
    Adapters,
    /// The two DNS client policy values of the old adapter lockdown.
    DnsPolicy,
    /// The old Wintun adapter recorded in `tun-owner.json`.
    TunAdapter,
    /// The old SYSTEM boot-recovery tasks.
    Tasks,
    /// Old journals, scripts and staged engine copies (configs with credentials).
    Files,
}

impl StepId {
    /// The step's segment of its i18n keys.
    pub fn key(self) -> &'static str {
        match self {
            StepId::Processes => "processes",
            StepId::Journals => "journals",
            StepId::Firewall => "firewall",
            StepId::SingTunRules => "singTunRules",
            StepId::LegacyWfp => "legacyWfp",
            StepId::Adapters => "adapters",
            StepId::DnsPolicy => "dnsPolicy",
            StepId::TunAdapter => "tunAdapter",
            StepId::Tasks => "tasks",
            StepId::Files => "files",
        }
    }
}

/// How a step ended. Only `Failed` makes the next start retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// Finished: leftovers removed or restored, or nothing was there.
    Done,
    /// Deliberately left alone (no proof of ownership, invalid record, not supported here).
    Skipped,
    /// An action failed or could not be confirmed; retried on a later start.
    Failed,
}

impl Outcome {
    fn key(self) -> &'static str {
        match self {
            Outcome::Done => "done",
            Outcome::Skipped => "skipped",
            Outcome::Failed => "failed",
        }
    }
}

/// The result of one step, as stored in the marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StepRecord {
    /// Which step.
    pub step: StepId,
    /// How it ended.
    pub outcome: Outcome,
    /// Something on the machine was changed (removed, restored, stopped).
    #[serde(default)]
    pub changed: bool,
    /// Technical English detail for logs and diagnostics (names and paths, never secrets).
    pub detail: String,
}

impl StepRecord {
    pub(crate) fn new(step: StepId, outcome: Outcome, detail: impl Into<String>) -> Self {
        Self {
            step,
            outcome,
            changed: false,
            detail: detail.into(),
        }
    }

    pub(crate) fn changed(mut self, changed: bool) -> Self {
        self.changed = changed;
        self
    }

    /// The user-facing line for this step (`cleanup.legacy.step.<step>.<outcome>`).
    pub fn msg(&self) -> Msg {
        Msg::new(format!(
            "cleanup.legacy.step.{}.{}",
            self.step.key(),
            self.outcome.key()
        ))
    }
}

/// Everything one run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanupReport {
    /// One record per step that ran, in run order.
    pub steps: Vec<StepRecord>,
    /// The old strict mode had set Windows Firewall to block all outgoing traffic; it was reset
    /// to Allow (B31).
    pub firewall_reset: bool,
    /// Rules of the old kill switch existed without a usable journal: every profile was set to
    /// Allow, the original values being unknown.
    pub firewall_allow_all: bool,
}

impl CleanupReport {
    pub(crate) fn push(&mut self, record: StepRecord) {
        match record.outcome {
            Outcome::Failed => {
                tracing::warn!(step = ?record.step, detail = %record.detail, "legacy cleanup step failed")
            }
            _ => {
                tracing::info!(step = ?record.step, outcome = ?record.outcome, detail = %record.detail, "legacy cleanup step")
            }
        }
        self.steps.push(record);
    }

    /// The outcome of `step`, `None` when it did not run.
    pub fn outcome(&self, step: StepId) -> Option<Outcome> {
        self.steps
            .iter()
            .find(|r| r.step == step)
            .map(|r| r.outcome)
    }

    /// Some step failed (the run counts as an attempt and is retried).
    pub fn failed(&self) -> bool {
        self.steps.iter().any(|r| r.outcome == Outcome::Failed)
    }

    /// Process exit code of `--cleanup`: 0 on success, 1 otherwise.
    pub fn exit_code(&self) -> i32 {
        i32::from(self.failed())
    }

    /// What to show once: the Windows Firewall warnings, then a summary when something was
    /// changed or failed. A machine without leftovers gets no notice at all.
    pub fn notices(&self) -> Vec<Notice> {
        let mut out = Vec::new();
        if self.firewall_reset {
            out.push(
                Notice::new(Level::Warn, "cleanup.legacy.notice.firewallResetTitle")
                    .body("cleanup.legacy.notice.firewallReset"),
            );
        }
        if self.firewall_allow_all {
            out.push(
                Notice::new(Level::Warn, "cleanup.legacy.notice.firewallAllowAllTitle")
                    .body("cleanup.legacy.notice.firewallAllowAll"),
            );
        }
        let changed = self.steps.iter().filter(|r| r.changed).count();
        let failed = self
            .steps
            .iter()
            .filter(|r| r.outcome == Outcome::Failed)
            .count();
        let body = Msg::new("cleanup.legacy.notice.summary")
            .arg("changed", changed)
            .arg("failed", failed);
        if failed > 0 {
            out.push(Notice::new(Level::Warn, "cleanup.legacy.notice.failedTitle").body(body));
        } else if changed > 0 {
            out.push(Notice::new(Level::Success, "cleanup.legacy.notice.doneTitle").body(body));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(step: StepId, outcome: Outcome, changed: bool) -> StepRecord {
        StepRecord::new(step, outcome, "x").changed(changed)
    }

    #[test]
    fn wire_names_match_the_marker_format() {
        let r = record(StepId::SingTunRules, Outcome::Skipped, false);
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(
            json,
            r#"{"step":"sing-tun-rules","outcome":"skipped","changed":false,"detail":"x"}"#
        );
        let back: StepRecord =
            serde_json::from_str(r#"{"step":"legacy-wfp","outcome":"failed","detail":"d"}"#)
                .unwrap();
        assert_eq!(back.step, StepId::LegacyWfp);
        assert!(!back.changed);
        assert_eq!(r.msg().key, "cleanup.legacy.step.singTunRules.skipped");
    }

    #[test]
    fn notices_only_when_something_happened() {
        let mut report = CleanupReport::default();
        report.push(record(StepId::Tasks, Outcome::Done, false));
        assert!(report.notices().is_empty());
        assert_eq!(report.exit_code(), 0);

        report.push(record(StepId::Firewall, Outcome::Done, true));
        let notices = report.notices();
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].title.key, "cleanup.legacy.notice.doneTitle");

        report.push(record(StepId::LegacyWfp, Outcome::Failed, false));
        report.firewall_reset = true;
        let notices = report.notices();
        assert_eq!(
            notices[0].title.key,
            "cleanup.legacy.notice.firewallResetTitle"
        );
        assert_eq!(notices[1].title.key, "cleanup.legacy.notice.failedTitle");
        let body = notices[1].body.as_ref().unwrap();
        assert_eq!(body.args[0].1, "1");
        assert_eq!(body.args[1].1, "1");
        assert!(report.failed());
        assert_eq!(report.exit_code(), 1);
        assert_eq!(report.outcome(StepId::LegacyWfp), Some(Outcome::Failed));
        assert_eq!(report.outcome(StepId::Files), None);
    }
}
