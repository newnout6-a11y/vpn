//! On-disk records of a capture: the per-session manifest, the write-ahead ownership marker and
//! the legacy "a capture may still be running" hints of the old app.
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use vpnte_base::types::UnixMs;
use vpnte_core::settings::ConnectionMode;

use crate::etw::EtwStopStats;

/// Manifest file inside a session directory.
pub const MANIFEST_FILE: &str = "session-manifest.json";
/// Write-ahead marker in the root: the id of the session whose pktmon capture we started.
pub const MARKER_FILE: &str = "capture.owned";
/// Written into the root once an old app's hint got its recovery `pktmon stop`.
pub const LEGACY_DONE_FILE: &str = "legacy-capture.stopped";
/// Session directories live in `<root>\sessions\<id>`.
pub const SESSIONS_DIR: &str = "sessions";
/// Manifest schema (keys compatible with the old v2 manifest where they overlap).
pub const SCHEMA_VERSION: u32 = 2;
/// Old hints larger than this are unreadable on purpose (TF:174-195).
const LEGACY_HINT_MAX: u64 = 64 * 1024;

/// Packet capture part of a session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "state", content = "detail")]
pub enum PktmonState {
    #[default]
    NotStarted,
    Running,
    /// Not started (storage quota, pktmon missing or refused); the session is ETW-only.
    Unavailable(String),
    Stopped,
    /// `pktmon stop` was not confirmed: the capture may still be writing.
    StopUnconfirmed(String),
}

/// ETW part of a session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "state", content = "detail")]
pub enum EtwState {
    #[default]
    NotStarted,
    Running,
    Failed(String),
    Stopped,
}

/// `<session dir>\session-manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionManifest {
    pub schema_version: u32,
    pub app_version: String,
    pub session_id: String,
    pub running: bool,
    /// `"pktmon"` when the packet capture ran; `None` for an ETW-only session.
    pub engine: Option<String>,
    pub mode: Option<ConnectionMode>,
    pub target: Option<String>,
    pub started_at: UnixMs,
    pub stopped_at: Option<UnixMs>,
    pub max_size_mb: u32,
    pub stop_reason: Option<String>,
    /// Technical cause (English, logs and support only).
    pub last_error: Option<String>,
    #[serde(default)]
    pub pktmon: PktmonState,
    #[serde(default)]
    pub etw: EtwState,
    #[serde(default)]
    pub etw_stats: Option<EtwStopStats>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub app_events_dropped: u64,
}

/// Session id from a UTC time: `2026-11-11T07-20-30-123Z` (the old `toISOString` with `:` and
/// `.` replaced).
pub fn session_id(now: UnixMs) -> String {
    crate::etw::writer::rfc3339_ms(now).replace([':', '.'], "-")
}

/// Ids we create and accept from disk: `[A-Za-z0-9_-]{1,100}` (never a path).
pub fn valid_session_id(id: &str) -> bool {
    (1..=100).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `<root>\sessions\<id>`.
pub fn session_dir(root: &Path, id: &str) -> PathBuf {
    root.join(SESSIONS_DIR).join(id)
}

/// Writes the manifest atomically (pretty JSON).
pub fn write_manifest(dir: &Path, manifest: &SessionManifest) -> io::Result<()> {
    let bytes = crate::pretty_json(manifest).map_err(io::Error::other)?;
    vpnte_core::store::write_atomic(&dir.join(MANIFEST_FILE), &bytes)
}

/// Reads a manifest; `None` when missing, unreadable or of a newer schema.
pub fn read_manifest(dir: &Path) -> Option<SessionManifest> {
    let bytes = std::fs::read(dir.join(MANIFEST_FILE)).ok()?;
    let manifest: SessionManifest = serde_json::from_slice(crate::strip_bom(&bytes)).ok()?;
    (manifest.schema_version <= SCHEMA_VERSION).then_some(manifest)
}

/// Writes the marker before pktmon is launched, so a crash at any later point is recoverable.
pub fn write_marker(root: &Path, id: &str) -> io::Result<()> {
    vpnte_core::store::write_atomic(&root.join(MARKER_FILE), id.as_bytes())
}

/// The marker: `Some(Some(id))` with a valid id, `Some(None)` when present but unusable.
pub fn read_marker(root: &Path) -> Option<Option<String>> {
    let text = std::fs::read_to_string(root.join(MARKER_FILE)).ok()?;
    let id = text.trim();
    Some(valid_session_id(id).then(|| id.to_string()))
}

/// Removes the marker after a confirmed stop (missing = fine).
pub fn remove_marker(root: &Path) -> io::Result<()> {
    match std::fs::remove_file(root.join(MARKER_FILE)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Where the old app kept `latest-session.json`: the AppData copy of pre-ProgramData builds and
/// `%ProgramData%\VPNTE\runtime\<instance>\traffic-forensics`, `<instance>` = first 32 hex chars of
/// sha256 of the lowercased old userData path (RP:10-23).
pub fn legacy_hint_paths(legacy_electron: &Path, program_data: &Path) -> [PathBuf; 2] {
    let user_data = legacy_electron.to_string_lossy().to_lowercase();
    let instance = hex::encode(Sha256::digest(user_data.as_bytes()));
    [
        legacy_electron
            .join("traffic-forensics")
            .join("latest-session.json"),
        program_data
            .join("VPNTE")
            .join("runtime")
            .join(&instance[..32])
            .join("traffic-forensics")
            .join("latest-session.json"),
    ]
}

/// Whether an old hint says a capture may still be running (rules TF:174-195). A missing file is
/// fine; anything unreadable, oversized or not clearly stopped counts as "maybe running". Paths
/// inside the hint are never used.
pub fn legacy_hint_pending(path: &Path) -> bool {
    let mut bytes = Vec::new();
    match std::fs::File::open(path) {
        Err(e) => return e.kind() != io::ErrorKind::NotFound,
        Ok(f) => {
            if f.take(LEGACY_HINT_MAX + 1).read_to_end(&mut bytes).is_err() {
                return true;
            }
        }
    }
    legacy_bytes_pending(&bytes)
}

fn legacy_bytes_pending(bytes: &[u8]) -> bool {
    if bytes.len() as u64 > LEGACY_HINT_MAX {
        return true;
    }
    let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(crate::strip_bom(bytes)) else {
        return true;
    };
    let stopped_ok = m
        .get("stoppedAt")
        .and_then(Value::as_f64)
        .is_some_and(|t| t.is_finite() && t > 0.0);
    let last_error = m
        .get("lastError")
        .is_some_and(|e| !e.is_null() && e.as_str() != Some(""));
    m.get("running") != Some(&Value::Bool(false))
        || last_error
        || !stopped_ok
        || m.get("sidecar").and_then(|s| s.get("running")) == Some(&Value::Bool(true))
        || matches!(
            m.get("stopReason").and_then(Value::as_str),
            Some("status-reconciled-stop" | "zombie-recovery")
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    #[test]
    fn session_ids_have_the_old_shape() {
        let id = session_id(1_781_827_200_123);
        assert_eq!(id, "2026-06-19T00-00-00-123Z");
        assert!(valid_session_id(&id));
        for bad in ["", "..", "a/b", r"a\b", "a b", &"x".repeat(101)] {
            assert!(!valid_session_id(bad), "{bad:?}");
        }
    }

    /// §7.5 legacy hints (old AT-08-004): running, corrupt and oversized hints are pending;
    /// a cleanly stopped one is not; a missing file is fine.
    #[test]
    fn legacy_hint_rules() {
        assert!(legacy_bytes_pending(br#"{"running":true,"stoppedAt":1}"#));
        assert!(legacy_bytes_pending(b"{"));
        assert!(legacy_bytes_pending(b"[]"));
        assert!(legacy_bytes_pending(&vec![b' '; 65_537]));
        assert!(!legacy_bytes_pending(
            br#"{"running":false,"stoppedAt":1,"lastError":null}"#
        ));
        assert!(legacy_bytes_pending(
            br#"{"running":false,"stoppedAt":1,"lastError":"CaptureStopUnconfirmed: x"}"#
        ));
        assert!(legacy_bytes_pending(br#"{"running":false,"stoppedAt":0}"#));
        assert!(legacy_bytes_pending(
            br#"{"running":false,"stoppedAt":5,"sidecar":{"running":true}}"#
        ));
        assert!(legacy_bytes_pending(
            br#"{"running":false,"stoppedAt":5,"stopReason":"zombie-recovery"}"#
        ));

        let dir = TempDir::new("legacy-hint");
        let path = dir.path().join("latest-session.json");
        assert!(!legacy_hint_pending(&path));
        std::fs::write(&path, vec![b'x'; 70_000]).unwrap();
        assert!(legacy_hint_pending(&path));
    }

    #[test]
    fn legacy_paths_follow_the_old_layout() {
        let [appdata, programdata] = legacy_hint_paths(
            Path::new(r"C:\Users\u\AppData\Roaming\vpn-tunnel-enforcer"),
            Path::new(r"C:\ProgramData"),
        );
        assert!(appdata.ends_with(r"vpn-tunnel-enforcer\traffic-forensics\latest-session.json"));
        let instance = programdata
            .components()
            .nth(5)
            .unwrap()
            .as_os_str()
            .to_string_lossy()
            .to_string();
        assert_eq!(instance.len(), 32);
        assert!(instance.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(programdata.starts_with(r"C:\ProgramData\VPNTE\runtime"));
    }

    #[test]
    fn marker_and_manifest_round_trip() {
        let dir = TempDir::new("manifest");
        assert_eq!(read_marker(dir.path()), None);
        write_marker(dir.path(), "2026-06-19T00-00-00-123Z").unwrap();
        assert_eq!(
            read_marker(dir.path()),
            Some(Some("2026-06-19T00-00-00-123Z".into()))
        );
        std::fs::write(dir.path().join(MARKER_FILE), r"..\..\x").unwrap();
        assert_eq!(read_marker(dir.path()), Some(None));
        remove_marker(dir.path()).unwrap();
        remove_marker(dir.path()).unwrap();

        let m = SessionManifest {
            schema_version: SCHEMA_VERSION,
            app_version: "2.0.0".into(),
            session_id: "s".into(),
            running: true,
            engine: Some("pktmon".into()),
            mode: Some(ConnectionMode::DirectVpn),
            target: Some("Example profile".into()),
            started_at: 1,
            stopped_at: None,
            max_size_mb: 512,
            stop_reason: None,
            last_error: None,
            pktmon: PktmonState::Unavailable("storage quota reached".into()),
            etw: EtwState::Running,
            etw_stats: None,
            warnings: vec![],
            app_events_dropped: 0,
        };
        write_manifest(dir.path(), &m).unwrap();
        assert_eq!(read_manifest(dir.path()), Some(m.clone()));
        let text = std::fs::read_to_string(dir.path().join(MANIFEST_FILE)).unwrap();
        assert!(text.contains(r#""mode": "directVpn""#), "{text}");
        assert!(text.contains(r#""state": "unavailable""#), "{text}");
        let newer = SessionManifest {
            schema_version: 3,
            ..m
        };
        write_manifest(dir.path(), &newer).unwrap();
        assert_eq!(read_manifest(dir.path()), None);
    }
}
