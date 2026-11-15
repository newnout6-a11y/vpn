//! The last session a user started, kept in the service's private folder (ks-d, research
//! killswitch §5.3, §5.4): the service starts it again when its own crash left a held drop
//! behind, and at every start of its own while "Always" is in force (connect at Windows start:
//! the VPN is up before anyone signs in). It holds the upstream with its key, so only SYSTEM and
//! Administrators may read it (`PRIVATE_DIR_SDDL`).
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::proto::TunnelStart;

/// A started session and its user.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Remembered {
    /// SID of the Windows user whose start it was: only his app takes the session over.
    pub user: String,
    pub start: TunnelStart,
}

/// The kept session; `None` when there is none or it cannot be read (logged: nothing resumes).
pub fn load(path: &Path) -> Option<Remembered> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(error = %e, "last session unreadable");
            return None;
        }
    };
    serde_json::from_slice(&bytes)
        .inspect_err(|e| tracing::warn!(error = %e, "last session unreadable"))
        .ok()
}

/// Keeps `session` (a failed write only costs the resume: logged).
pub fn save(path: &Path, session: &Remembered) {
    let written = serde_json::to_vec(session)
        .map_err(io::Error::other)
        .and_then(|bytes| crate::paths::write_synced(path, &bytes));
    if let Err(e) = written {
        tracing::warn!(error = %e, "last session not kept");
    }
}

/// Drops the kept session (another user's app took the machine, the last user left).
pub fn forget(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(error = %e, "last session not removed"),
    }
}
