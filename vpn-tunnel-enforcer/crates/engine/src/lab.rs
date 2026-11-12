//! WP-12 lab gate (AT-12-002). The mihomo engine exists only in a build with the `lab` feature,
//! and even there it runs only after a person recorded that its lab criteria passed: the record
//! `<data dir>\lab\at-12.json` names the AT-12 criteria and the app version they ran on. The app
//! reads it once at start-up ([`activate`]); without it every AmneziaWG start is refused with
//! [`Reject::Lab`].
use std::path::{Path, PathBuf};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use vpnte_base::msg::Msg;
use vpnte_base::types::{Engine, EnginePref};
use vpnte_profiles::model::{Kind, Profile};

use crate::xray_config::{Decision, Reject, SelectReason};

/// The record's place under the data dir.
pub const RECORD_FILE: &str = "lab/at-12.json";
/// The criteria a mihomo run depends on: conformance, the gate itself, the AmneziaWG handshake
/// probe, the preflight refusal and the unchanged sing-box lifecycle.
pub const REQUIRED: [&str; 5] = [
    "AT-12-001",
    "AT-12-002",
    "AT-12-003",
    "AT-12-004",
    "AT-12-007",
];
/// The record is bound to the app version the criteria ran on.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The lab record as written by hand after the criteria passed (unknown keys are ignored).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LabRecord {
    /// The app version (`2.0.0`) the criteria ran on.
    pub version: String,
    /// Criteria ids that passed, e.g. `"AT-12-003"`.
    pub passed: Vec<String>,
    /// Who ran them (informational, logged).
    #[serde(default)]
    pub by: String,
}

/// Why the lab engine is not active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LabGap {
    /// No record (also before [`activate`] ran).
    Missing,
    /// The record is not readable JSON of the documented shape.
    Unreadable,
    /// The record does not name every [`REQUIRED`] criterion.
    Incomplete,
    /// The record was written for another app version.
    OtherVersion,
}

impl LabGap {
    /// User-facing explanation (`engine.lab.gap.*`).
    pub fn msg(self) -> Msg {
        let key = match self {
            LabGap::Missing => "engine.lab.gap.missing",
            LabGap::Unreadable => "engine.lab.gap.unreadable",
            LabGap::Incomplete => "engine.lab.gap.incomplete",
            LabGap::OtherVersion => "engine.lab.gap.otherVersion",
        };
        Msg::new(key)
            .arg("file", RECORD_FILE)
            .arg("criteria", REQUIRED.join(", "))
            .arg("version", VERSION)
    }
}

/// The process-wide gate: written once by the app at start-up, read by every engine choice.
static GATE: RwLock<Result<(), LabGap>> = RwLock::new(Err(LabGap::Missing));

/// The record file under `data_dir`.
pub fn record_path(data_dir: &Path) -> PathBuf {
    data_dir.join(RECORD_FILE)
}

/// Reads and checks the record under `data_dir` (blocking file I/O).
pub fn load(data_dir: &Path) -> Result<LabRecord, LabGap> {
    let text = match std::fs::read(record_path(data_dir)) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Err(LabGap::Missing),
        Err(_) => return Err(LabGap::Unreadable),
    };
    let record: LabRecord = serde_json::from_slice(&text).map_err(|_| LabGap::Unreadable)?;
    check(&record)?;
    Ok(record)
}

/// The record names every required criterion for this version.
pub fn check(record: &LabRecord) -> Result<(), LabGap> {
    if record.version.trim() != VERSION {
        return Err(LabGap::OtherVersion);
    }
    let named = |id: &str| {
        record
            .passed
            .iter()
            .any(|p| p.trim().eq_ignore_ascii_case(id))
    };
    if REQUIRED.iter().all(|id| named(id)) {
        Ok(())
    } else {
        Err(LabGap::Incomplete)
    }
}

/// Loads the record and opens (or keeps closed) the gate for this process; returns the outcome.
pub fn activate(data_dir: &Path) -> Result<(), LabGap> {
    let outcome = load(data_dir).map(|record| {
        tracing::warn!(by = %record.by, "WP-12 lab engine mihomo activated by the lab record");
    });
    if let Err(gap) = outcome {
        tracing::info!(?gap, "WP-12 lab engine mihomo not activated");
    }
    *GATE.write() = outcome;
    outcome
}

/// The gate as [`activate`] left it (`Err(Missing)` before it ran).
pub fn gate() -> Result<(), LabGap> {
    *GATE.read()
}

/// The lab engine may run.
pub fn active() -> bool {
    gate().is_ok()
}

/// The lab rows of the engine choice, before the bundled engines' table: AmneziaWG under Auto or
/// a forced mihomo runs on mihomo when the gate is open and is refused with the gap otherwise; a
/// forced mihomo never runs anything else (no silent switch to another engine). `None` = the
/// bundled table decides (AmneziaWG under forced sing-box / Xray stays `Reject::Amneziawg`).
pub fn select(p: &Profile, pref: EnginePref, gate: Result<(), LabGap>) -> Option<Decision> {
    let awg = matches!(p.kind, Kind::Amneziawg { .. });
    match (awg, pref) {
        (true, EnginePref::Auto | EnginePref::Mihomo) => Some(match gate {
            Ok(()) => Decision::Selected {
                engine: Engine::Mihomo,
                reason: SelectReason::Amneziawg,
            },
            Err(gap) => Decision::Rejected(Reject::Lab(gap)),
        }),
        (false, EnginePref::Mihomo) => Some(Decision::Rejected(Reject::MihomoAwgOnly)),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
