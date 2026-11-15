//! Where downloads and downloaded engines live: `%LOCALAPPDATA%\VPN Tunnel Enforcer\` (machine
//! local, not roaming; the installer removes it only on «удалить вместе с данными», never on an
//! upgrade). A development or test run on an overridden data dir (`VPNTE_DATA_DIR`) keeps
//! everything under `<data root>\local\` instead, so it never touches the real folders.
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use vpnte_base::{AppError, AppResult};
use vpnte_core::paths::APP_DIR_NAME;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_RoamingAppData, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
};
use windows::core::GUID;

/// The local root for the data root `data_root` (see the module docs).
pub fn local_root(data_root: &Path) -> AppResult<PathBuf> {
    let roaming = known_folder(&FOLDERID_RoamingAppData)?;
    if data_root.starts_with(&roaming) {
        Ok(known_folder(&FOLDERID_LocalAppData)?.join(APP_DIR_NAME))
    } else {
        Ok(data_root.join("local"))
    }
}

/// `<local>\engines`: downloaded engine versions and `state.json`.
pub fn engines_dir(local: &Path) -> PathBuf {
    local.join("engines")
}

/// `<local>\updates`: `.part` files, installers, engine archives, `pending.json`, the last feed.
pub fn updates_dir(local: &Path) -> PathBuf {
    local.join("updates")
}

fn known_folder(id: &GUID) -> AppResult<PathBuf> {
    // SAFETY: `id` is a static GUID; on success the returned string is CoTaskMemAlloc'ed, read
    // once while alive and freed exactly once below.
    unsafe {
        let raw = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).map_err(AppError::internal)?;
        let path = PathBuf::from(OsString::from_wide(raw.as_wide()));
        CoTaskMemFree(Some(raw.0 as *const _));
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A data root outside the roaming folder (VPNTE_DATA_DIR) keeps the local files with it.
    #[test]
    fn an_overridden_data_root_keeps_local_files_inside() {
        let root = std::env::temp_dir().join("vpnte-update-paths");
        assert_eq!(local_root(&root).unwrap(), root.join("local"));
        let roaming = known_folder(&FOLDERID_RoamingAppData)
            .unwrap()
            .join(APP_DIR_NAME);
        let local = local_root(&roaming).unwrap();
        assert!(local.ends_with(APP_DIR_NAME) && !local.starts_with(&roaming));
        assert_eq!(engines_dir(&local), local.join("engines"));
    }
}
