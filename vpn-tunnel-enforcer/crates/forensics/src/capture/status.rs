//! The status snapshot published to the UI and system diagnostics (§2.11 shape, typed), and the
//! pure health / warning rules.
use std::path::PathBuf;

use serde::Serialize;
use vpnte_base::Msg;
use vpnte_base::types::UnixMs;
use vpnte_core::settings::ConnectionMode;

use super::manifest::{EtwState, PktmonState};
use crate::etw::{DigestSnapshot, LossStats};

/// ETW counts as "warming up" this long after the session start (TF:447-493).
pub const WARM_UP_MS: i64 = 30_000;

/// Capture state for the Diagnostics card, tray and system diagnostics.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureStatus {
    /// The setting (deep inspection) is on.
    pub enabled: bool,
    pub running: bool,
    /// `pktmon stop` was not confirmed: the packet capture may still be writing.
    pub cleanup_pending: bool,
    pub session_id: Option<String>,
    pub session_dir: Option<PathBuf>,
    pub mode: Option<ConnectionMode>,
    pub target: Option<String>,
    pub started_at: Option<UnixMs>,
    pub stopped_at: Option<UnixMs>,
    pub max_size_mb: u32,
    pub stop_reason: Option<String>,
    pub last_error: Option<Msg>,
    pub pktmon: PktmonState,
    pub etw: EtwState,
    /// Live digest of a running session, or the final one of a session stopped in this process
    /// (an older session never looks live).
    pub digest: Option<DigestSnapshot>,
    pub health: Health,
    /// Most important first; the card shows the first one.
    pub warnings: Vec<Msg>,
    /// Bytes used by all sessions (shown next to «clear»).
    pub total_bytes: u64,
}

/// Artefact sizes and ETW liveness of the current session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Health {
    pub artifact_count: usize,
    pub etl_bytes: u64,
    pub events_bytes: u64,
    pub etw_warming_up: bool,
    pub etw_only_lifecycle: bool,
}

/// Inputs of [`liveness_and_warnings`].
pub struct HealthInput<'a> {
    pub enabled: bool,
    pub etw: &'a EtwState,
    pub digest: Option<&'a DigestSnapshot>,
    pub loss: Option<LossStats>,
    pub pktmon: &'a PktmonState,
    /// Size of `pktmon.etl`; `None` when missing.
    pub etl_bytes: Option<u64>,
    pub started_at: Option<UnixMs>,
    pub now: UnixMs,
    pub quota_reached: bool,
}

/// `(warming_up, only_lifecycle, warnings)`. "Warming up" uses the session start, not the ETW
/// start (TF:1233); without a start time the age is infinite.
pub fn liveness_and_warnings(i: &HealthInput) -> (bool, bool, Vec<Msg>) {
    let etw_running = *i.etw == EtwState::Running;
    let no_data = i.digest.is_none_or(|d| d.data_events == 0);
    let young = i
        .started_at
        .is_some_and(|t| i.now.saturating_sub(t) < WARM_UP_MS);
    let warming_up = etw_running && no_data && young;
    let only_lifecycle = etw_running && no_data && !warming_up;
    let mut warnings = Vec::new();
    if !i.enabled {
        return (warming_up, only_lifecycle, warnings);
    }
    if only_lifecycle {
        warnings.push(Msg::new("forensics.capture.warn.onlyLifecycle"));
    }
    let pktmon_started = matches!(
        i.pktmon,
        PktmonState::Running | PktmonState::Stopped | PktmonState::StopUnconfirmed(_)
    );
    if pktmon_started && i.etl_bytes.unwrap_or(0) == 0 {
        warnings.push(Msg::new("forensics.capture.warn.etlEmpty"));
    }
    if let EtwState::Failed(_) = i.etw {
        warnings.push(Msg::new("forensics.capture.warn.etwFailed"));
    }
    if let Some(d) = i.digest {
        // Kernel losses (events and whole buffers) plus our own queue drops and write failures.
        let loss = i.loss.unwrap_or_default();
        let lost = u64::from(loss.events_lost)
            + u64::from(loss.buffers_lost)
            + d.backpressure_dropped
            + d.write_errors;
        if lost > 0 {
            warnings.push(Msg::new("forensics.capture.warn.eventsLost").arg("count", lost));
        }
        if d.unparsed > 0 {
            warnings.push(Msg::new("forensics.capture.warn.unparsed").arg("count", d.unparsed));
        }
    }
    if i.quota_reached {
        warnings.push(Msg::new("forensics.capture.warn.quota"));
    } else if let PktmonState::Unavailable(_) = i.pktmon {
        warnings.push(Msg::new("forensics.capture.warn.pktmonUnavailable"));
    }
    (warming_up, only_lifecycle, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(digest: &'a DigestSnapshot, age_ms: i64) -> HealthInput<'a> {
        HealthInput {
            enabled: true,
            etw: &EtwState::Running,
            digest: Some(digest),
            loss: None,
            pktmon: &PktmonState::Running,
            etl_bytes: Some(4096),
            started_at: Some(1_000_000),
            now: 1_000_000 + age_ms,
            quota_reached: false,
        }
    }

    /// §7.5 'reports packet capture health…' / 'warns when sidecar stays lifecycle-only…'.
    #[test]
    fn warming_up_then_lifecycle_only() {
        let lifecycle_only = DigestSnapshot {
            events: 1,
            ..Default::default()
        };
        let (warming, only, warnings) = liveness_and_warnings(&input(&lifecycle_only, 29_000));
        assert!(warming && !only);
        assert!(warnings.is_empty());
        let (warming, only, warnings) = liveness_and_warnings(&input(&lifecycle_only, 31_000));
        assert!(!warming && only);
        assert_eq!(warnings[0].key, "forensics.capture.warn.onlyLifecycle");
    }

    #[test]
    fn data_clears_the_lifecycle_warning_and_losses_are_reported() {
        let d = DigestSnapshot {
            events: 10,
            data_events: 9,
            backpressure_dropped: 2,
            unparsed: 3,
            ..Default::default()
        };
        let mut i = input(&d, 60_000);
        i.loss = Some(LossStats {
            events_lost: 5,
            buffers_lost: 1,
        });
        let (warming, only, warnings) = liveness_and_warnings(&i);
        assert!(!warming && !only);
        let keys: Vec<&str> = warnings.iter().map(|m| m.key.as_ref()).collect();
        assert_eq!(
            keys,
            [
                "forensics.capture.warn.eventsLost",
                "forensics.capture.warn.unparsed"
            ]
        );
        assert_eq!(
            warnings[0],
            Msg::new("forensics.capture.warn.eventsLost").arg("count", 8)
        );
        // Lost buffers alone still warn, with a count that is not zero.
        let clean = DigestSnapshot {
            data_events: 9,
            ..Default::default()
        };
        let mut i = input(&clean, 60_000);
        i.loss = Some(LossStats {
            events_lost: 0,
            buffers_lost: 2,
        });
        assert_eq!(
            liveness_and_warnings(&i).2,
            [Msg::new("forensics.capture.warn.eventsLost").arg("count", 2)]
        );
    }

    /// An empty capture is never "fine" (B-04 neighbour): 0-byte or missing ETL warns; a disabled
    /// setting shows no warnings; the quota warning names the reason for an ETW-only session.
    #[test]
    fn etl_quota_and_disabled_rules() {
        let d = DigestSnapshot {
            data_events: 1,
            ..Default::default()
        };
        let mut i = input(&d, 60_000);
        i.etl_bytes = None;
        let (_, _, w) = liveness_and_warnings(&i);
        assert_eq!(w[0].key, "forensics.capture.warn.etlEmpty");
        i.enabled = false;
        assert!(liveness_and_warnings(&i).2.is_empty());
        let quota = PktmonState::Unavailable("storage quota reached".into());
        let mut i = input(&d, 60_000);
        i.pktmon = &quota;
        i.quota_reached = true;
        let keys: Vec<String> = liveness_and_warnings(&i)
            .2
            .into_iter()
            .map(|m| m.key.into())
            .collect();
        assert_eq!(keys, ["forensics.capture.warn.quota"]);
    }
}
