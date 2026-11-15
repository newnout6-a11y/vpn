//! Names and folders of the installed service.
//!
//! Folders come from the known-folder registry (`SHGetKnownFolderPath`), never from environment
//! variables: the elevated install runs with the user's environment, and `%ProgramFiles%`
//! pointed at a user folder would make SYSTEM run a user-writable exe.
use std::io;
use std::path::{Path, PathBuf};

use windows::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::Storage::FileSystem::CreateDirectoryW;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::{
    FOLDERID_ProgramData, FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
};
use windows::core::{BOOL, GUID, HSTRING};

use crate::sddl::{self, SecurityDescriptor};

/// The Windows service name.
pub const SERVICE_NAME: &str = "VpnTunnelEnforcerService";
/// The name Services and Task Manager show.
pub const DISPLAY_NAME: &str = "VPN Tunnel Enforcer Service";
/// Folder under Program Files.
pub const INSTALL_DIR_NAME: &str = "VPN Tunnel Enforcer Service";
/// Folder under ProgramData (logs, users, kill-switch settings).
pub const DATA_DIR_NAME: &str = "VPN Tunnel Enforcer";
/// The service executable.
pub const EXE_NAME: &str = "vpnte-service.exe";

fn known_folder(id: &GUID) -> io::Result<PathBuf> {
    // SAFETY: valid GUID pointer; the returned string is freed with CoTaskMemFree below.
    unsafe {
        let raw = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).map_err(io::Error::other)?;
        let path = raw.to_string().map(PathBuf::from).map_err(io::Error::other);
        CoTaskMemFree(Some(raw.0 as *const _));
        path
    }
}

/// `%ProgramFiles%\VPN Tunnel Enforcer Service`.
pub fn install_dir() -> io::Result<PathBuf> {
    Ok(known_folder(&FOLDERID_ProgramFiles)?.join(INSTALL_DIR_NAME))
}

/// `%ProgramData%\VPN Tunnel Enforcer`.
pub fn data_dir() -> io::Result<PathBuf> {
    Ok(known_folder(&FOLDERID_ProgramData)?.join(DATA_DIR_NAME))
}

/// Files inside the data folder.
pub struct DataFiles {
    pub root: PathBuf,
    /// Engine logs of TUN sessions: SYSTEM and Administrators only (owner logs O-4: they name
    /// what a user reached through the tunnel); a user reads his own session's through the pipe.
    pub logs: PathBuf,
    /// SYSTEM and Administrators only: the users list, the kill-switch settings (exception paths
    /// name user folders) and the service log (client images) are no other user's business, and a
    /// user who could read them could also hold them open against the service (review service-b2).
    pub private: PathBuf,
    pub users: PathBuf,
    pub protection: PathBuf,
    /// The last session a user started (its upstream with the key): the service starts it
    /// again after its own crash while the drop is held, and at its start with "Always".
    pub session: PathBuf,
    pub service_log: PathBuf,
}

impl DataFiles {
    pub fn new(root: &Path) -> Self {
        let private = root.join("service");
        Self {
            root: root.to_owned(),
            logs: root.join("logs"),
            users: private.join("users.json"),
            protection: private.join("protection.json"),
            session: private.join("session.json"),
            service_log: private.join("service.log"),
            private,
        }
    }

    /// Creates or re-secures the data folder, its private part and the engine logs.
    pub fn secure(&self) -> io::Result<()> {
        secure_dir(&self.root)?;
        secure_dir_as(&self.private, sddl::PRIVATE_DIR_SDDL)?;
        // Best effort, as the logs folder always was: the tunnel runs without it and the next
        // start tries again (users cannot change it inside the secured root anyway).
        if let Err(err) = secure_dir_as(&self.logs, sddl::PRIVATE_DIR_SDDL) {
            tracing::warn!(error = %err, "engine logs folder not secured");
        }
        Ok(())
    }
}

/// Writes `bytes` through a sibling file that reaches the disk before it replaces `path`, so a
/// power loss leaves the old file or the new one, never half of one. One writer at a time.
pub fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let mut file = std::fs::File::create(&tmp)?;
    io::Write::write_all(&mut file, bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)
}

/// Creates `dir` with the admin-only DACL, or re-creates it when it exists but users can change
/// it (anyone may create folders in ProgramData: a folder planted before the install, with
/// junctions inside, would let SYSTEM write where a user chose).
pub fn secure_dir(dir: &Path) -> io::Result<()> {
    secure_dir_as(dir, sddl::ADMIN_ONLY_DIR_SDDL)
}

fn secure_dir_as(dir: &Path, folder_sddl: &str) -> io::Result<()> {
    if dir.exists() {
        if sddl::path_admin_only(dir) {
            // Users cannot change it. A private folder they may still read (the logs of builds
            // before 15.11 inherited «Users: read») gets its DACL in place: its files keep
            // their lines and take the new entries by inheritance.
            let private = folder_sddl == sddl::PRIVATE_DIR_SDDL;
            return if private && !sddl::path_private(dir) {
                set_dacl(dir, folder_sddl)
            } else {
                Ok(())
            };
        }
        tracing::warn!(dir = %dir.display(), "folder writable by users; recreated");
        // std removes junctions and symlinks themselves, never their targets.
        std::fs::remove_dir_all(dir)?;
    }
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let sd = SecurityDescriptor::from_sddl(folder_sddl).map_err(io::Error::other)?;
    let attributes = sd.attributes();
    // SAFETY: valid path and attributes (pointing at `sd`, alive for the call).
    unsafe { CreateDirectoryW(&HSTRING::from(dir.as_os_str()), Some(&attributes)) }
        .map_err(io::Error::other)
}

/// Puts the DACL of `folder_sddl` on `dir`, protected from the parent's; Windows passes its
/// inheritable entries on to everything inside (`SetNamedSecurityInfoW` propagates them).
fn set_dacl(dir: &Path, folder_sddl: &str) -> io::Result<()> {
    let sd = SecurityDescriptor::from_sddl(folder_sddl).map_err(io::Error::other)?;
    let (mut present, mut defaulted) = (BOOL(0), BOOL(0));
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `sd` is a valid descriptor that outlives `dacl`; out pointers are locals.
    unsafe { GetSecurityDescriptorDacl(sd.as_ptr(), &mut present, &mut dacl, &mut defaulted) }
        .map_err(io::Error::other)?;
    if !present.as_bool() || dacl.is_null() {
        return Err(io::Error::other("descriptor without a DACL"));
    }
    let info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    // SAFETY: valid path string; `dacl` points into `sd`, alive for the call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            &HSTRING::from(dir.as_os_str()),
            SE_FILE_OBJECT,
            info,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    status.ok().map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{DataFiles, set_dacl};
    use crate::sddl::{self, SecurityDescriptor};

    /// Owner logs O-4: the engine logs sit beside the private part, under a descriptor that
    /// grants users nothing (a user reads his own session's lines through the pipe).
    #[test]
    fn the_engine_logs_get_the_private_descriptor() {
        let files = DataFiles::new(Path::new(r"C:\data"));
        assert_eq!(files.logs, Path::new(r"C:\data\logs"));
        let sd = SecurityDescriptor::from_sddl(sddl::PRIVATE_DIR_SDDL).expect("valid SDDL");
        assert!(sd.admin_only_writes());
        assert!(
            !sddl::PRIVATE_DIR_SDDL.contains(";BU)") && !sddl::PRIVATE_DIR_SDDL.contains(";IU)")
        );
    }

    /// O-4 on a real folder: a fresh install creates the logs folder private, and the folder of
    /// an older install (users may read it, a log inside) is repaired in place at the next start,
    /// the log with it.
    #[test]
    #[ignore = "needs elevation"]
    fn elevated_the_engine_logs_are_private_and_repaired_in_place() {
        assert!(vpnte_winnet::elevation::is_elevated(), "run elevated");
        let root = std::env::temp_dir().join(format!("vpnte-logs-acl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let files = DataFiles::new(&root);
        let fresh = files.secure().map(|()| sddl::path_private(&files.logs));
        // As before 15.11: the folder inherited «Users: read», and so did its logs. The service
        // wrote them as SYSTEM; a file this elevated test wrote plainly would be owned by its own
        // user (Windows makes the creator the owner) and never read private, so the log is
        // created owned by Administrators, as trusted as SYSTEM (CI 15.11: «log false» came from
        // the owner, not the DACL; the staging folder's elevated test writes the same way).
        let old = set_dacl(&files.logs, sddl::ADMIN_ONLY_DIR_SDDL).and_then(|()| {
            let mut log = sddl::create_admin_owned(&files.logs.join("sing-box.log"))?;
            std::io::Write::write_all(
                &mut log, b"line
",
            )
        });
        let private_before = sddl::path_private(&files.logs.join("sing-box.log"));
        let repaired = files.secure().map(|()| {
            (
                sddl::path_private(&files.logs),
                sddl::path_private(&files.logs.join("sing-box.log")),
                std::fs::read(files.logs.join("sing-box.log")).ok(),
            )
        });
        let _ = std::fs::remove_dir_all(&root);
        assert!(fresh.expect("secured"), "a fresh logs folder is private");
        old.expect("an older install's folder");
        assert!(!private_before, "users could read the old log");
        let (folder, log, kept) = repaired.expect("repaired");
        assert!(folder && log, "repaired: folder {folder}, log {log}");
        assert_eq!(
            kept.as_deref(),
            Some(&b"line\n"[..]),
            "the log keeps its lines"
        );
    }
}
