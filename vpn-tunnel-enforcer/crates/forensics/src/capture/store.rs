//! The forensics root: creation with a protected DACL, session listing, sizes, the storage quota
//! and the user's "clear" action. Nothing here deletes sessions on its own (owner decision
//! §10.6 «A»: sessions stay until the user clears them).
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;
use vpnte_base::types::UnixMs;

use super::manifest::{SESSIONS_DIR, SessionManifest, read_manifest, valid_session_id};

/// Default storage quota for all sessions together.
pub const DEFAULT_QUOTA_MB: u32 = 8192;
/// Clamp range of the quota.
pub const QUOTA_MB: (u32, u32) = (1024, 65_536);
const MIB: u64 = 1024 * 1024;

/// `%ProgramData%\VPN Tunnel Enforcer\forensics`.
pub fn default_root() -> Option<PathBuf> {
    let program_data = std::env::var_os("ProgramData").filter(|v| !v.is_empty())?;
    Some(
        PathBuf::from(program_data)
            .join(vpnte_core::paths::APP_DIR_NAME)
            .join("forensics"),
    )
}

/// Creates the root (and `sessions`) once. pktmon writes the ETL as an elevated caller, so the
/// root must not be user-writable (a junction planted there would redirect the write): it gets
/// `SYSTEM` and Administrators full control and the current user read-only, which keeps «Open
/// folder» working. An existing root must be a plain directory, not a reparse point.
pub fn ensure_root(root: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(root) {
        Ok(meta) => {
            if !meta.is_dir() || is_reparse_point(&meta) {
                return Err(io::Error::other("forensics root is not a plain directory"));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = root.parent() {
                std::fs::create_dir_all(parent)?;
            }
            create_protected_dir(root)?;
        }
        Err(e) => return Err(e),
    }
    match std::fs::create_dir(root.join(SESSIONS_DIR)) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => Err(e),
        _ => Ok(()),
    }
}

fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// `CreateDirectoryW` with `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;<user SID>)`.
fn create_protected_dir(path: &Path) -> io::Result<()> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::CreateDirectoryW;
    use windows::core::{HSTRING, PCWSTR};

    let sid = current_user_sid().map_err(io::Error::other)?;
    let sddl = HSTRING::from(format!(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;{sid})"
    ));
    let wide_path = HSTRING::from(path.as_os_str());
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl` is a NUL-terminated wide string; on success `sd` receives a LocalAlloc'ed
    // descriptor that is freed below.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
    }
    .map_err(io::Error::other)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };
    // SAFETY: `wide_path` is NUL-terminated; `sa` and the descriptor it points to outlive the call.
    let created = unsafe { CreateDirectoryW(PCWSTR(wide_path.as_ptr()), Some(&sa)) };
    // SAFETY: `sd` came from ConvertStringSecurityDescriptorToSecurityDescriptorW and is no longer used.
    unsafe { LocalFree(Some(HLOCAL(sd.0))) };
    created.map_err(|e| io::Error::from_raw_os_error(e.code().0 & 0xFFFF))
}

/// String SID (`S-1-5-21-…`) of this process's token user.
fn current_user_sid() -> windows::core::Result<String> {
    use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::{Owned, PWSTR};

    let mut raw = HANDLE::default();
    // SAFETY: the pseudo handle of this process is always valid; `raw` receives a token handle
    // that `Owned` closes.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) }?;
    // SAFETY: `raw` is a token handle we own from here on.
    let token = unsafe { Owned::new(raw) };
    let mut len = 0u32;
    // SAFETY: a size query without a buffer; it "fails" with ERROR_INSUFFICIENT_BUFFER by design.
    let _ = unsafe { GetTokenInformation(*token, TokenUser, None, 0, &mut len) };
    // `usize` elements keep the SID pointer inside TOKEN_USER aligned.
    let mut buf = vec![0usize; (len as usize).div_ceil(size_of::<usize>()).max(1)];
    let size = (buf.len() * size_of::<usize>()) as u32;
    // SAFETY: `buf` has `size` writable, pointer-aligned bytes.
    unsafe {
        GetTokenInformation(
            *token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            size,
            &mut len,
        )
    }?;
    // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points into `buf`.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut text = PWSTR::null();
    // SAFETY: `sid` is valid while `buf` lives; `text` is LocalAlloc'ed and freed below.
    unsafe { ConvertSidToStringSidW(sid, &mut text) }?;
    // SAFETY: `text` is a NUL-terminated wide string from ConvertSidToStringSidW.
    let out = unsafe { text.to_string() };
    // SAFETY: `text` is no longer used.
    unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    out.map_err(|_| windows::Win32::Foundation::E_FAIL.into())
}

/// One file of a session directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactFile {
    pub name: String,
    pub size: u64,
    pub mtime_ms: Option<UnixMs>,
}

/// One session directory under `<root>\sessions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionEntry {
    pub id: String,
    pub dir: PathBuf,
    /// Sum of the file sizes.
    pub bytes: u64,
    /// Sorted by name.
    pub files: Vec<ArtifactFile>,
    /// `None` when missing, unreadable or of a newer schema.
    pub manifest: Option<SessionManifest>,
}

/// Files of a session directory, sorted by name (sub-directories are not ours and are skipped).
pub fn list_artifacts(dir: &Path) -> Vec<ArtifactFile> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<ArtifactFile> = entries
        .flatten()
        .filter_map(|e| {
            let meta = e.metadata().ok().filter(|m| m.is_file())?;
            let mtime_ms = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as UnixMs);
            Some(ArtifactFile {
                name: e.file_name().to_string_lossy().into_owned(),
                size: meta.len(),
                mtime_ms,
            })
        })
        .collect();
    files.sort_by(|a, b| a.name.cmp(&b.name));
    files
}

/// `(id, dir)` of every session directory with a valid id, in directory order.
fn session_dirs(root: &Path) -> impl Iterator<Item = (String, PathBuf)> {
    std::fs::read_dir(root.join(SESSIONS_DIR))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| {
            let id = e
                .file_name()
                .to_str()
                .filter(|id| valid_session_id(id))?
                .to_string();
            Some((id, e.path()))
        })
}

/// Every session directory with a valid id, oldest first (ids sort by time).
pub fn list_sessions(root: &Path) -> Vec<SessionEntry> {
    let mut sessions: Vec<SessionEntry> = session_dirs(root)
        .map(|(id, dir)| {
            let files = list_artifacts(&dir);
            SessionEntry {
                bytes: files.iter().map(|f| f.size).sum(),
                manifest: read_manifest(&dir),
                id,
                dir,
                files,
            }
        })
        .collect();
    sessions.sort_by(|a, b| a.id.cmp(&b.id));
    sessions
}

/// Bytes used by all sessions except the directory `except` (no manifest is read).
pub fn total_bytes(root: &Path, except: Option<&Path>) -> u64 {
    session_dirs(root)
        .filter(|(_, dir)| Some(dir.as_path()) != except)
        .flat_map(|(_, dir)| list_artifacts(&dir))
        .map(|f| f.size)
        .sum()
}

/// Free bytes for the caller on the volume of `path`.
pub fn free_bytes(path: &Path) -> Option<u64> {
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    use windows::core::{HSTRING, PCWSTR};
    let wide = HSTRING::from(path.as_os_str());
    let mut free = 0u64;
    // SAFETY: `wide` is NUL-terminated and `free` is a valid out pointer.
    unsafe { GetDiskFreeSpaceExW(PCWSTR(wide.as_ptr()), Some(&mut free), None, None) }.ok()?;
    Some(free)
}

/// Whether a new packet capture of `max_size_mb` would break the quota or leave the volume with
/// less than twice its size free (§3.4.1). Over quota the session runs ETW-only; nothing is deleted.
pub fn quota_reached(total: u64, free: Option<u64>, max_size_mb: u32, quota_mb: u32) -> bool {
    let need = u64::from(max_size_mb) * MIB;
    total + need > u64::from(quota_mb) * MIB || free.is_some_and(|f| f < 2 * need)
}

/// Outcome of [`remove_sessions`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClearReport {
    pub removed: Vec<String>,
    pub failed: Vec<String>,
    pub freed_bytes: u64,
}

/// Deletes every session directory (the user's «clear diagnostics»).
pub fn remove_sessions(root: &Path) -> ClearReport {
    let mut report = ClearReport::default();
    for s in list_sessions(root) {
        match std::fs::remove_dir_all(&s.dir) {
            Ok(()) => {
                report.freed_bytes += s.bytes;
                report.removed.push(s.id);
            }
            Err(e) => {
                tracing::warn!("cannot remove forensics session {}: {e}", s.id);
                report.failed.push(s.id);
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    #[test]
    fn quota_rule() {
        // 7.5 GiB used + 512 MiB = exactly the 8 GiB quota: still fits.
        assert!(!quota_reached(7680 * MIB, None, 512, 8192));
        assert!(quota_reached(7681 * MIB, None, 512, 8192));
        assert!(quota_reached(0, Some(1023 * MIB), 512, 8192));
        assert!(!quota_reached(0, Some(1024 * MIB), 512, 8192));
    }

    #[test]
    fn lists_and_clears_sessions() {
        let root = TempDir::new("store-list");
        ensure_root(root.path()).unwrap();
        for (id, bytes) in [
            ("2026-01-02T00-00-00-000Z", 10),
            ("2026-01-01T00-00-00-000Z", 5),
        ] {
            let dir = root.path().join(SESSIONS_DIR).join(id);
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(dir.join("events.ndjson"), vec![b'x'; bytes]).unwrap();
            std::fs::write(dir.join("a.json"), b"{}").unwrap();
        }
        std::fs::create_dir(root.path().join(SESSIONS_DIR).join("not a session")).unwrap();
        let sessions = list_sessions(root.path());
        let ids: Vec<&str> = sessions.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            ["2026-01-01T00-00-00-000Z", "2026-01-02T00-00-00-000Z"]
        );
        assert_eq!(sessions[0].files[0].name, "a.json");
        assert_eq!(sessions[0].bytes, 7);
        assert_eq!(total_bytes(root.path(), None), 19);
        assert_eq!(total_bytes(root.path(), Some(&sessions[1].dir)), 7);
        assert!(free_bytes(root.path()).is_some_and(|f| f > 0));

        let mut report = remove_sessions(root.path());
        report.removed.sort();
        assert_eq!(
            report.removed,
            ["2026-01-01T00-00-00-000Z", "2026-01-02T00-00-00-000Z"]
        );
        assert_eq!(report.freed_bytes, 19);
        assert!(list_sessions(root.path()).is_empty());
    }

    /// The root gets a protected DACL: unelevated, the current user can read but not write.
    #[test]
    fn protected_root_is_read_only_for_the_user() {
        let parent = TempDir::new("store-dacl");
        let root = parent.path().join("forensics");
        create_protected_dir(&root).unwrap();
        assert!(std::fs::read_dir(&root).is_ok());
        let write = std::fs::write(root.join("probe.txt"), b"x");
        if vpnte_winnet::elevation::is_elevated() {
            assert!(write.is_ok());
        } else {
            assert_eq!(write.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        }
        // An existing plain directory is accepted as is.
        let plain = TempDir::new("store-plain");
        ensure_root(plain.path()).unwrap();
        assert!(plain.path().join(SESSIONS_DIR).is_dir());
    }
}
