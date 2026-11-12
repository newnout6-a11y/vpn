//! Names and folders of the installed service.
//!
//! Folders come from the known-folder registry (`SHGetKnownFolderPath`), never from environment
//! variables: the elevated install runs with the user's environment, and `%ProgramFiles%`
//! pointed at a user folder would make SYSTEM run a user-writable exe.
use std::io;
use std::path::{Path, PathBuf};

use windows::Win32::Storage::FileSystem::CreateDirectoryW;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::{
    FOLDERID_ProgramData, FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
};
use windows::core::{GUID, HSTRING};

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
    /// Engine logs of TUN sessions (users may read them).
    pub logs: PathBuf,
    /// SYSTEM and Administrators only: the users list, the kill-switch settings (exception paths
    /// name user folders) and the service log (client images) are no other user's business, and a
    /// user who could read them could also hold them open against the service (review service-b2).
    pub private: PathBuf,
    pub users: PathBuf,
    pub protection: PathBuf,
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
            service_log: private.join("service.log"),
            private,
        }
    }

    /// Creates or re-secures the data folder and its private part.
    pub fn secure(&self) -> io::Result<()> {
        secure_dir(&self.root)?;
        secure_dir_as(&self.private, sddl::PRIVATE_DIR_SDDL)
    }
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
            return Ok(());
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
