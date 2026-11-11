//! Where the app keeps its data, where the old Electron build kept its data, and where the engines are.
use std::ffi::OsString;
use std::fs::{File, OpenOptions, TryLockError};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use vpnte_base::{AppError, AppResult, Msg};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::{FOLDERID_RoamingAppData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};

/// Folder under `%APPDATA%` owned by this app.
pub const APP_DIR_NAME: &str = "VPN Tunnel Enforcer";
/// Folder under `%APPDATA%` of the old Electron build (read-only source of the one-time import).
pub const LEGACY_DIR_NAME: &str = "vpn-tunnel-enforcer";
/// Overrides the data root (tests, portable runs).
pub const ENV_DATA_DIR: &str = "VPNTE_DATA_DIR";
/// Overrides the legacy Electron data dir.
pub const ENV_LEGACY_DIR: &str = "VPNTE_LEGACY_DIR";
/// Overrides the engines / resources dir.
pub const ENV_RESOURCES_DIR: &str = "VPNTE_RESOURCES_DIR";

/// The app's directories (storage §6.1). Only `root` and its children are ever written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDirs {
    /// `%APPDATA%\VPN Tunnel Enforcer`: documents, `lock`, `migration.json`.
    pub root: PathBuf,
    /// `<root>\logs`.
    pub logs: PathBuf,
    /// `<root>\history`.
    pub history: PathBuf,
    /// `<root>\cache`.
    pub cache: PathBuf,
    /// `%APPDATA%\vpn-tunnel-enforcer`: never written, renamed or deleted by the app.
    pub legacy_electron: PathBuf,
    /// Engine binaries and bundled data (`sing-box.exe`, `xray.exe`, rule sets).
    pub resources: PathBuf,
}

impl DataDirs {
    /// Resolves the directories from the environment overrides, the Roaming AppData known folder and
    /// the executable's location. Creates nothing.
    pub fn resolve() -> AppResult<Self> {
        Self::resolve_with(|name| std::env::var_os(name), roaming_app_data, exe_dir)
    }

    /// Builds the layout from explicit locations.
    pub fn new(root: PathBuf, legacy_electron: PathBuf, resources: PathBuf) -> Self {
        Self {
            logs: root.join("logs"),
            history: root.join("history"),
            cache: root.join("cache"),
            root,
            legacy_electron,
            resources,
        }
    }

    fn resolve_with(
        env: impl Fn(&str) -> Option<OsString>,
        app_data: impl FnOnce() -> AppResult<PathBuf>,
        exe_dir: impl FnOnce() -> AppResult<PathBuf>,
    ) -> AppResult<Self> {
        let over = |name: &str| -> AppResult<Option<PathBuf>> {
            match env(name).filter(|v| !v.is_empty()) {
                Some(v) => Ok(Some(std::path::absolute(v)?)),
                None => Ok(None),
            }
        };
        let (data, legacy, resources) = (
            over(ENV_DATA_DIR)?,
            over(ENV_LEGACY_DIR)?,
            over(ENV_RESOURCES_DIR)?,
        );
        let (root, legacy) = match (data, legacy) {
            (Some(root), Some(legacy)) => (root, legacy),
            (root, legacy) => {
                let base = app_data()?;
                (
                    root.unwrap_or_else(|| base.join(APP_DIR_NAME)),
                    legacy.unwrap_or_else(|| base.join(LEGACY_DIR_NAME)),
                )
            }
        };
        let resources = match resources {
            Some(r) => r,
            None => exe_dir()?.join("resources"),
        };
        Ok(Self::new(root, legacy, resources))
    }

    /// Creates `root`, `logs`, `history` and `cache` if missing.
    pub fn ensure(&self) -> AppResult<()> {
        for dir in [&self.root, &self.logs, &self.history, &self.cache] {
            std::fs::create_dir_all(dir)?;
        }
        Ok(())
    }

    /// Takes the exclusive single-writer lock `<root>\lock` (storage B27). Held until the guard drops;
    /// a second instance gets [`vpnte_base::ErrorKind::Conflict`] and must not write anything.
    pub fn lock(&self) -> AppResult<DataLock> {
        std::fs::create_dir_all(&self.root)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.root.join("lock"))?;
        match file.try_lock() {
            Ok(()) => Ok(DataLock { _file: file }),
            Err(TryLockError::WouldBlock) => {
                Err(AppError::conflict(Msg::new("core.store.dataDirLocked")))
            }
            Err(TryLockError::Error(e)) => Err(e.into()),
        }
    }
}

/// Guard of the data-dir lock; the OS releases the lock when the handle closes (also on a crash).
#[derive(Debug)]
pub struct DataLock {
    _file: File,
}

fn roaming_app_data() -> AppResult<PathBuf> {
    // SAFETY: the GUID is a static constant; on success the returned string is CoTaskMemAlloc'ed,
    // read once while alive and freed exactly once below.
    unsafe {
        let raw = SHGetKnownFolderPath(&FOLDERID_RoamingAppData, KF_FLAG_DEFAULT, None)
            .map_err(AppError::internal)?;
        let path = PathBuf::from(OsString::from_wide(raw.as_wide()));
        CoTaskMemFree(Some(raw.0 as *const _));
        Ok(path)
    }
}

fn exe_dir() -> AppResult<PathBuf> {
    let exe = std::env::current_exe()?;
    exe.parent().map(Path::to_path_buf).ok_or_else(|| {
        AppError::internal(anyhow::anyhow!("executable path has no parent directory"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let owned: Vec<(String, OsString)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), OsString::from(v)))
            .collect();
        move |name| {
            owned
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        }
    }

    fn fixed(p: &str) -> impl FnOnce() -> AppResult<PathBuf> + use<> {
        let p = PathBuf::from(p);
        move || Ok(p)
    }

    #[test]
    fn defaults_come_from_app_data_and_exe_dir() {
        let d = DataDirs::resolve_with(env_of(&[]), fixed(r"C:\AD"), fixed(r"C:\App")).unwrap();
        assert_eq!(d.root, PathBuf::from(r"C:\AD\VPN Tunnel Enforcer"));
        assert_eq!(d.logs, PathBuf::from(r"C:\AD\VPN Tunnel Enforcer\logs"));
        assert_eq!(
            d.history,
            PathBuf::from(r"C:\AD\VPN Tunnel Enforcer\history")
        );
        assert_eq!(d.cache, PathBuf::from(r"C:\AD\VPN Tunnel Enforcer\cache"));
        assert_eq!(
            d.legacy_electron,
            PathBuf::from(r"C:\AD\vpn-tunnel-enforcer")
        );
        assert_eq!(d.resources, PathBuf::from(r"C:\App\resources"));
    }

    #[test]
    fn env_overrides_win_and_skip_the_known_folder() {
        let env = env_of(&[
            (ENV_DATA_DIR, r"D:\data"),
            (ENV_LEGACY_DIR, r"D:\old"),
            (ENV_RESOURCES_DIR, r"D:\res"),
        ]);
        let unreachable = || -> AppResult<PathBuf> { panic!("known folder must not be queried") };
        let d = DataDirs::resolve_with(env, unreachable, || panic!("exe dir not needed")).unwrap();
        assert_eq!(d.root, PathBuf::from(r"D:\data"));
        assert_eq!(d.logs, PathBuf::from(r"D:\data\logs"));
        assert_eq!(d.legacy_electron, PathBuf::from(r"D:\old"));
        assert_eq!(d.resources, PathBuf::from(r"D:\res"));
    }

    #[test]
    fn empty_override_is_ignored() {
        let env = env_of(&[(ENV_DATA_DIR, ""), (ENV_LEGACY_DIR, r"D:\old")]);
        let d = DataDirs::resolve_with(env, fixed(r"C:\AD"), fixed(r"C:\App")).unwrap();
        assert_eq!(d.root, PathBuf::from(r"C:\AD\VPN Tunnel Enforcer"));
        assert_eq!(d.legacy_electron, PathBuf::from(r"D:\old"));
    }

    /// A relative override is made absolute (the importer and the lock must not depend on the cwd).
    #[test]
    fn relative_override_is_made_absolute() {
        let env = env_of(&[(ENV_LEGACY_DIR, "old"), (ENV_DATA_DIR, "data")]);
        let d = DataDirs::resolve_with(env, fixed(r"C:\AD"), fixed(r"C:\App")).unwrap();
        assert!(d.legacy_electron.is_absolute() && d.legacy_electron.ends_with("old"));
        assert!(d.root.is_absolute() && d.logs.ends_with(r"data\logs"));
    }

    #[test]
    fn known_folder_resolves_on_this_machine() {
        // Read-only: only asks Windows where Roaming AppData is; nothing is created or opened.
        let dir = roaming_app_data().unwrap();
        assert!(dir.is_absolute() && dir.is_dir(), "{dir:?}");
    }

    /// B27: a second writer is refused while the first holds the lock, and admitted after release.
    #[test]
    fn data_dir_lock_is_exclusive() {
        let tmp = TempDir::new("paths");
        let dirs = DataDirs::new(
            tmp.path().join("root"),
            tmp.path().join("old"),
            tmp.path().into(),
        );
        let first = dirs.lock().unwrap();
        let err = dirs.lock().unwrap_err();
        assert_eq!(err.kind, vpnte_base::ErrorKind::Conflict);
        drop(first);
        dirs.lock().unwrap();
        dirs.ensure().unwrap();
        assert!(dirs.logs.is_dir() && dirs.history.is_dir() && dirs.cache.is_dir());
        assert!(!dirs.legacy_electron.exists());
    }
}
