//! The app's own update (research §4.9): before the installer runs, `updates\pending.json`
//! records from which version to which and where the installer is; the next start reads it to
//! tell «Обновлено до 2.0.1» from «обновление не установилось» (the installer is then kept, so
//! the user can run it again).
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vpnte_base::types::UnixMs;

use crate::version::Version;

const PENDING_FILE: &str = "pending.json";
/// The installer's flags: silent, the update chain (shortcuts and data kept), start the app
/// again as the user afterwards (`installer/PROGRESS.md`).
pub const INSTALLER_ARGS: [&str; 3] = ["/S", "--updated", "--force-run"];

/// An update handed to the installer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pending {
    pub from: Version,
    pub to: Version,
    pub at: UnixMs,
    pub installer: PathBuf,
}

/// What the start after an update found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// This build is the version the installer was to put in place.
    Updated { to: Version },
    /// Still another version: the installer did not finish (it is kept).
    Failed { to: Version, installer: PathBuf },
}

/// Writes `<updates>\pending.json` atomically (before the installer starts).
pub fn write(updates: &Path, pending: &Pending) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(pending).map_err(std::io::Error::other)?;
    vpnte_core::store::write_atomic(&updates.join(PENDING_FILE), &bytes)
}

/// At start: reads and removes `pending.json` and says how the update went for the running
/// version `running`. A successful update's installer is deleted; a failed one is kept.
pub fn take(updates: &Path, running: Version) -> Option<Outcome> {
    let path = updates.join(PENDING_FILE);
    let pending: Option<Pending> = serde_json::from_slice(&std::fs::read(&path).ok()?).ok();
    let _ = std::fs::remove_file(&path);
    let pending = pending?;
    if running == pending.to {
        let _ = std::fs::remove_file(&pending.installer);
        Some(Outcome::Updated { to: pending.to })
    } else {
        tracing::warn!(from = %pending.from, to = %pending.to, %running, "update did not install");
        Some(Outcome::Failed {
            to: pending.to,
            installer: pending.installer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    /// pending.json: the start on the new version deletes the installer and reports success;
    /// a start on another version keeps it and reports the failure; the file is read once.
    #[test]
    fn pending_tells_success_from_failure() {
        let dir = TempDir::new("pending");
        let installer = dir.path().join("VPN-Tunnel-Enforcer-Setup-2.0.1.exe");
        let pending = Pending {
            from: Version(2, 0, 0),
            to: Version(2, 0, 1),
            at: 1,
            installer: installer.clone(),
        };
        std::fs::write(&installer, b"setup").unwrap();
        write(dir.path(), &pending).unwrap();
        assert_eq!(
            take(dir.path(), Version(2, 0, 0)),
            Some(Outcome::Failed {
                to: Version(2, 0, 1),
                installer: installer.clone()
            })
        );
        assert!(installer.is_file());
        assert_eq!(take(dir.path(), Version(2, 0, 1)), None, "read once");
        write(dir.path(), &pending).unwrap();
        assert_eq!(
            take(dir.path(), Version(2, 0, 1)),
            Some(Outcome::Updated {
                to: Version(2, 0, 1)
            })
        );
        assert!(!installer.exists());
        std::fs::write(dir.path().join(PENDING_FILE), b"junk").unwrap();
        assert_eq!(take(dir.path(), Version(2, 0, 1)), None);
        assert!(!dir.path().join(PENDING_FILE).exists());
    }
}
