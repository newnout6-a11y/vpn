//! Texts built from history data: evidence lines, the copied diagnostics, the summary of a
//! technical-logs clear, the export file name.
use jiff::civil::Date;
use vpnte_base::Msg;
use vpnte_base::types::OutboundFault;

use super::format::iso_utc;
use super::history::{non_empty, shown_headline};
use super::model::{
    ArtifactReport, Evidence, EvidenceKey, EvidenceValue, ExportFormat, SessionRow, Text,
};

/// Wire name of a fault (`reality-key-mismatch`).
pub fn fault_key(fault: OutboundFault) -> &'static str {
    match fault {
        OutboundFault::RealityKeyMismatch => "reality-key-mismatch",
        OutboundFault::TlsHandshakeFailed => "tls-handshake-failed",
        OutboundFault::UpstreamUnreachable => "upstream-unreachable",
    }
}

/// Label of a fault: `logs.outboundFault.<fault>`.
pub fn fault_label(fault: OutboundFault) -> Msg {
    Msg::new(format!("logs.outboundFault.{}", fault_key(fault)))
}

/// The present evidence values in display order (absent and blank ones are skipped; `false`
/// and `0` are facts and stay).
pub fn evidence_items(evidence: &Evidence) -> Vec<(EvidenceKey, EvidenceValue)> {
    let text = |t: &Option<String>| {
        non_empty(t.as_deref()).map(|t| EvidenceValue::Text(Text::Plain(t.to_owned())))
    };
    EvidenceKey::ALL
        .into_iter()
        .filter_map(|key| {
            let value = match key {
                EvidenceKey::SingboxExitCode => {
                    evidence.singbox_exit_code.map(EvidenceValue::Number)
                }
                EvidenceKey::SingboxStderrTail => text(&evidence.singbox_stderr_tail),
                EvidenceKey::OutboundFault => evidence.outbound_fault.map(EvidenceValue::Fault),
                EvidenceKey::AdaptiveMode => text(&evidence.adaptive_mode),
                EvidenceKey::AdaptiveAttempts => evidence
                    .adaptive_attempts
                    .map(|n| EvidenceValue::Number(n.into())),
                EvidenceKey::AutoRestartAttempts => evidence
                    .auto_restart_attempts
                    .map(|n| EvidenceValue::Number(n.into())),
                EvidenceKey::KillSwitchEngaged => {
                    evidence.kill_switch_engaged.map(EvidenceValue::Flag)
                }
                EvidenceKey::LeakDetectedDuringSession => evidence
                    .leak_detected_during_session
                    .map(EvidenceValue::Flag),
                EvidenceKey::NetworkTransition => text(&evidence.network_transition),
                EvidenceKey::EgressCountry => text(&evidence.egress_country),
                EvidenceKey::EgressIp => text(&evidence.egress_ip),
                EvidenceKey::ProxyEngine => evidence.proxy_engine.map(EvidenceValue::Engine),
                EvidenceKey::ProxyEngineReason => evidence
                    .proxy_engine_reason
                    .as_ref()
                    .filter(|r| !matches!(r, Text::Plain(p) if p.trim().is_empty()))
                    .cloned()
                    .map(EvidenceValue::Text),
                EvidenceKey::Hint => evidence
                    .hint
                    .as_ref()
                    .filter(|h| !matches!(h, Text::Plain(p) if p.trim().is_empty()))
                    .cloned()
                    .map(EvidenceValue::Text),
            };
            value.map(|v| (key, v))
        })
        .collect()
}

/// An evidence value as shown in the detail grid: faults by label, flags as «✓» / «—».
pub fn evidence_text(value: &EvidenceValue, tr: &dyn Fn(&Msg) -> String) -> String {
    match value {
        EvidenceValue::Number(n) => n.to_string(),
        EvidenceValue::Flag(true) => "✓".to_owned(),
        EvidenceValue::Flag(false) => "—".to_owned(),
        EvidenceValue::Fault(fault) => tr(&fault_label(*fault)),
        EvidenceValue::Engine(engine) => crate::servers::engine_name(*engine).to_owned(),
        EvidenceValue::Text(text) => text.render_with(tr),
    }
}

/// An evidence value in the copied text: raw values (wire names, `true` / `false`), easy to
/// search for in a support chat.
fn evidence_raw(value: &EvidenceValue, tr: &dyn Fn(&Msg) -> String) -> String {
    match value {
        EvidenceValue::Flag(flag) => flag.to_string(),
        EvidenceValue::Fault(fault) => fault_key(*fault).to_owned(),
        other => evidence_text(other, tr),
    }
}

/// The «Скопировать диагностику» text of one row (labels from `logs.copy.*`, times in UTC ISO,
/// raw kinds and evidence values).
pub fn diagnostics_text(row: &SessionRow, tr: &dyn Fn(&Msg) -> String) -> String {
    let mut lines = vec![
        tr(&Msg::new("logs.copy.profile")
            .arg("name", &row.profile_name)
            .arg("mode", row.mode.key())),
        tr(&Msg::new("logs.copy.started").arg("time", iso_utc(row.started_at))),
    ];
    if let Some(end) = row.ended_at {
        lines.push(tr(&Msg::new("logs.copy.ended").arg("time", iso_utc(end))));
    }
    lines.push(tr(&Msg::new("logs.copy.traffic")
        .arg("down", row.bytes_down)
        .arg("up", row.bytes_up)));
    if let Some(outcome) = &row.outcome {
        lines.push(tr(&Msg::new("logs.copy.outcome")
            .arg("kind", outcome.kind.key())
            .arg("headline", outcome.headline.render_with(tr))));
        let items = evidence_items(&outcome.evidence);
        if !items.is_empty() {
            lines.push(tr(&Msg::new("logs.copy.details")));
            lines.extend(
                items
                    .iter()
                    .map(|(key, value)| format!("  {}: {}", key.name(), evidence_raw(value, tr))),
            );
        }
    } else if row.ended_at.is_some() {
        // a running session has no disconnect reason yet (the stored default would say «user»)
        lines.push(tr(
            &Msg::new("logs.copy.reason").arg("reason", row.reason.key())
        ));
    }
    if let Some(message) = non_empty(row.error_message.as_deref()) {
        lines.push(tr(&Msg::new("logs.copy.message").arg("message", message)));
    }
    lines.join("\n")
}

/// The headline of a row, rendered (detail and failure lines).
pub fn headline_text(row: &SessionRow, tr: &dyn Fn(&Msg) -> String) -> String {
    shown_headline(row).render_with(tr)
}

/// The counts of a technical-logs clear (the old toast arithmetic): every cleared file counts
/// one, every failure counts one with its reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearSummary {
    pub cleared: usize,
    pub absent: usize,
    pub failed: usize,
    /// Distinct reasons, first occurrence first.
    pub reasons: Vec<Msg>,
}

impl ClearSummary {
    pub fn of(report: &ArtifactReport) -> Self {
        let mut reasons: Vec<Msg> = Vec::new();
        for (_, kind) in &report.failed {
            let msg = Msg::new(kind.i18n_key());
            if !reasons.contains(&msg) {
                reasons.push(msg);
            }
        }
        ClearSummary {
            cleared: report.cleared.len(),
            absent: report.absent.len(),
            failed: report.failed.len(),
            reasons,
        }
    }

    pub fn is_success(&self) -> bool {
        self.failed == 0
    }

    /// Toast title and description.
    pub fn toast(&self, tr: &dyn Fn(&Msg) -> String) -> (String, String) {
        if self.is_success() {
            return (
                tr(&Msg::new("logs.cleanup.successTitle")),
                tr(&Msg::new("logs.cleanup.success")),
            );
        }
        let reason = self.reasons.iter().map(tr).collect::<Vec<_>>().join("; ");
        let body = Msg::new("logs.cleanup.partial")
            .arg("cleared", self.cleared)
            .arg("absent", self.absent)
            .arg("failed", self.failed)
            .arg("reason", reason);
        (tr(&Msg::new("logs.cleanup.partialTitle")), tr(&body))
    }
}

/// `connection-history-2026-11-11.csv` (the local date: the user's day, not UTC's).
pub fn export_file_name(format: ExportFormat, date: Date) -> String {
    format!(
        "connection-history-{}.{}",
        date.strftime("%Y-%m-%d"),
        format.extension()
    )
}
