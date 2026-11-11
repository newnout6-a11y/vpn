//! The Start-menu shortcut that binds an AUMID to our exe, and the heal for a stale dev Electron
//! shortcut that hijacked the production AUMID on machines that once ran an old dev build.
use std::ffi::OsString;
use std::mem::ManuallyDrop;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use vpnte_base::{AppError, AppResult, Msg};
use windows::Win32::Foundation::PROPERTYKEY;
use windows::Win32::System::Com::StructuredStorage::{
    PROPVARIANT, PROPVARIANT_0, PROPVARIANT_0_0, PROPVARIANT_0_0_0, PropVariantClear,
    PropVariantToStringAlloc,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, CoCreateInstance, CoTaskMemFree, IPersistFile, STGM_READ,
};
use windows::Win32::System::Variant::VT_LPWSTR;
use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
use windows::Win32::UI::Shell::{
    FOLDERID_CommonPrograms, FOLDERID_Programs, IShellLinkW, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    SHStrDupW, SLGP_RAWPATH, ShellLink,
};
use windows::core::{GUID, HSTRING, Interface, PWSTR};

use crate::win::{self, Apartment, Com};

/// `System.AppUserModel.ID` (propkey.h).
const PKEY_APP_USER_MODEL_ID: PROPERTYKEY = PROPERTYKEY {
    fmtid: GUID::from_u128(0x9f4c2855_9f79_4b39_a8d0_e1d42de1d5f3),
    pid: 5,
};

/// What a shortcut points at and which AUMID it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shortcut {
    /// `System.AppUserModel.ID` stamped on the link.
    pub aumid: String,
    /// Target exe.
    pub target: PathBuf,
    /// Command-line arguments (usually empty).
    pub args: String,
    /// Tooltip text.
    pub description: String,
}

/// The per-user Start-menu programs folder (`%APPDATA%\Microsoft\Windows\Start Menu\Programs`).
pub fn user_programs_dir() -> AppResult<PathBuf> {
    known_folder(&FOLDERID_Programs)
}

/// The all-users Start-menu programs folder (`%ProgramData%\Microsoft\Windows\Start Menu\Programs`),
/// where the installer puts the app's link.
pub fn common_programs_dir() -> AppResult<PathBuf> {
    known_folder(&FOLDERID_CommonPrograms)
}

fn known_folder(id: &GUID) -> AppResult<PathBuf> {
    // SAFETY: on success the path is CoTaskMem-allocated and owned by us; freed after copying.
    unsafe {
        let p = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).map_err(AppError::internal)?;
        let dir = PathBuf::from(OsString::from_wide(p.as_wide()));
        CoTaskMemFree(Some(p.0.cast_const().cast()));
        Ok(dir)
    }
}

/// Creates or rewrites the link at `path` so it matches `shortcut`; `Ok(true)` when it wrote.
///
/// Debug builds refuse the production AUMID: a dev shortcut owning it is exactly what once gave
/// the installed app's taskbar button a foreign icon.
pub fn ensure_shortcut(path: &Path, shortcut: &Shortcut) -> AppResult<bool> {
    if cfg!(debug_assertions) && shortcut.aumid == super::AUMID {
        return Err(AppError::validation(Msg::new(
            "winnet.toast.productionAumid",
        )));
    }
    let _com = Com::enter(Apartment::Sta);
    if read_link(path).is_ok_and(|current| current == *shortcut) {
        return Ok(false);
    }
    // Access denied (the all-users folder from a `--no-elevate` run) stays a Permission error.
    write_link(path, shortcut).map_err(|e| AppError::new(win::error_kind(&e)).with_source(e))?;
    Ok(true)
}

/// Reads target, arguments, description and AUMID of the link at `path`.
pub fn read_shortcut(path: &Path) -> AppResult<Shortcut> {
    let _com = Com::enter(Apartment::Sta);
    read_link(path).map_err(AppError::internal)
}

/// Deletes the link at `path`; `Ok(false)` when there was none.
pub fn remove_shortcut(path: &Path) -> AppResult<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn write_link(path: &Path, sc: &Shortcut) -> windows::core::Result<()> {
    // SAFETY: COM is initialised on this thread (`Com`); every string outlives its call.
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
        link.SetPath(&HSTRING::from(sc.target.as_os_str()))?;
        link.SetArguments(&HSTRING::from(sc.args.as_str()))?;
        link.SetDescription(&HSTRING::from(sc.description.as_str()))?;
        if let Some(dir) = sc.target.parent() {
            link.SetWorkingDirectory(&HSTRING::from(dir.as_os_str()))?;
        }
        let store: IPropertyStore = link.cast()?;
        store.SetValue(&PKEY_APP_USER_MODEL_ID, &lpwstr_variant(&sc.aumid)?.0)?;
        store.Commit()?;
        link.cast::<IPersistFile>()?
            .Save(&HSTRING::from(path.as_os_str()), true)
    }
}

fn read_link(path: &Path) -> windows::core::Result<Shortcut> {
    // SAFETY: COM is initialised on this thread (`Com`); buffers outlive the calls.
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
        link.cast::<IPersistFile>()?
            .Load(&HSTRING::from(path.as_os_str()), STGM_READ)?;
        let mut buf = vec![0u16; 32_768];
        link.GetPath(&mut buf, std::ptr::null_mut(), SLGP_RAWPATH.0 as u32)?;
        let target = PathBuf::from(OsString::from_wide(win::until_nul(&buf)));
        link.GetArguments(&mut buf)?;
        let args = win::from_wide(&buf);
        link.GetDescription(&mut buf)?;
        let description = win::from_wide(&buf);
        let store: IPropertyStore = link.cast()?;
        let value = Variant(store.GetValue(&PKEY_APP_USER_MODEL_ID)?);
        let text = PropVariantToStringAlloc(&value.0)?;
        let aumid = text.to_string().unwrap_or_default();
        CoTaskMemFree(Some(text.0.cast_const().cast()));
        Ok(Shortcut {
            aumid,
            target,
            args,
            description,
        })
    }
}

/// A raw `PROPVARIANT`, cleared on drop: the windows 0.62 struct has no `Drop` of its own.
struct Variant(PROPVARIANT);

impl Drop for Variant {
    fn drop(&mut self) {
        // SAFETY: the variant came from the property store or `lpwstr_variant` and is owned here;
        // PropVariantClear frees its CoTaskMem string once.
        let _ = unsafe { PropVariantClear(&mut self.0) };
    }
}

/// A `VT_LPWSTR` variant: the type the shell expects for `System.AppUserModel.ID`
/// (`PROPVARIANT::from(&str)` would make a `VT_BSTR`).
fn lpwstr_variant(text: &str) -> windows::core::Result<Variant> {
    // SAFETY: SHStrDupW allocates with CoTaskMemAlloc, which `Variant`'s PropVariantClear frees.
    let p: PWSTR = unsafe { SHStrDupW(&HSTRING::from(text)) }?;
    Ok(Variant(PROPVARIANT {
        Anonymous: PROPVARIANT_0 {
            Anonymous: ManuallyDrop::new(PROPVARIANT_0_0 {
                vt: VT_LPWSTR,
                wReserved1: 0,
                wReserved2: 0,
                wReserved3: 0,
                Anonymous: PROPVARIANT_0_0_0 { pwszVal: p },
            }),
        },
    }))
}

/// Deletes `<programs_dir>\Electron.lnk` when it still points into a `node_modules` Electron
/// dist: old dev builds made Electron stamp that shortcut with the production AUMID, and the
/// installed app's taskbar button then showed the Electron atom. A user's own `Electron.lnk`
/// pointing anywhere else is never touched. `Ok(true)` when it deleted the shortcut.
pub fn remove_hijacking_dev_shortcut(programs_dir: &Path) -> AppResult<bool> {
    let path = programs_dir.join("Electron.lnk");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    if !is_dev_electron_link(&bytes) {
        return Ok(false);
    }
    let removed = remove_shortcut(&path)?;
    if removed {
        tracing::info!("removed a stale dev Electron.lnk that hijacked the taskbar icon");
    }
    Ok(removed)
}

/// A `.lnk` keeps its target as UTF-16LE and often as ANSI too: search both decodings (UTF-16 at
/// both byte alignments, since the string may start at an odd offset).
fn is_dev_electron_link(bytes: &[u8]) -> bool {
    let wide = |skip: usize| {
        let units: Vec<u16> = bytes[skip.min(bytes.len())..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| u16::from_le_bytes(pair))
            .collect();
        String::from_utf16_lossy(&units)
    };
    let latin1: String = bytes.iter().map(|&b| char::from(b)).collect();
    [wide(0), wide(1), latin1]
        .iter()
        .any(|text| mentions_dev_electron(text))
}

/// `node_modules[\/]electron[\/]dist[\/]electron.exe`, case-insensitive.
fn mentions_dev_electron(text: &str) -> bool {
    text.to_ascii_lowercase()
        .replace('/', "\\")
        .contains(r"node_modules\electron\dist\electron.exe")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use crate::toast::{AUMID, DEV_AUMID};

    fn dev_shortcut(target: PathBuf) -> Shortcut {
        Shortcut {
            aumid: DEV_AUMID.into(),
            target,
            args: "--autostart".into(),
            description: "VPN Tunnel Enforcer".into(),
        }
    }

    #[test]
    fn shortcut_round_trips_and_is_idempotent() {
        let dir = TempDir::new("lnk");
        let link = dir.path().join("VPN Tunnel Enforcer.lnk");
        let wanted = dev_shortcut(std::env::current_exe().unwrap());
        assert!(ensure_shortcut(&link, &wanted).unwrap());
        assert_eq!(read_shortcut(&link).unwrap(), wanted);
        assert!(!ensure_shortcut(&link, &wanted).unwrap());
        let moved = Shortcut {
            args: String::new(),
            ..wanted
        };
        assert!(ensure_shortcut(&link, &moved).unwrap());
        assert_eq!(read_shortcut(&link).unwrap().args, "");
        assert!(remove_shortcut(&link).unwrap());
        assert!(!remove_shortcut(&link).unwrap());
    }

    /// A link made without an AUMID (as NSIS makes the installer's) reads with an empty AUMID;
    /// stamping it keeps target, arguments and description.
    #[test]
    fn unstamped_link_reads_empty_and_can_be_stamped() {
        let dir = TempDir::new("lnk");
        let link = dir.path().join("plain.lnk");
        let exe = std::env::current_exe().unwrap();
        {
            let _com = Com::enter(Apartment::Sta);
            // SAFETY: COM is initialised on this thread; every string outlives its call.
            unsafe {
                let plain: IShellLinkW =
                    CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).unwrap();
                plain.SetPath(&HSTRING::from(exe.as_os_str())).unwrap();
                plain.SetDescription(&HSTRING::from("plain")).unwrap();
                let file = plain.cast::<IPersistFile>().unwrap();
                file.Save(&HSTRING::from(link.as_os_str()), true).unwrap();
            }
        }
        let found = read_shortcut(&link).unwrap();
        assert_eq!(found.aumid, "");
        assert_eq!(found.target, exe);
        let stamped = Shortcut {
            aumid: DEV_AUMID.into(),
            ..found
        };
        assert!(ensure_shortcut(&link, &stamped).unwrap());
        assert_eq!(read_shortcut(&link).unwrap(), stamped);
    }

    /// Both Start-menu folders resolve (read only) and differ: per user vs. the installer's.
    #[test]
    fn programs_folders_resolve() {
        let (user, common) = (user_programs_dir().unwrap(), common_programs_dir().unwrap());
        for dir in [&user, &common] {
            assert!(
                dir.is_absolute() && dir.ends_with(r"Start Menu\Programs"),
                "{dir:?}"
            );
        }
        assert_ne!(user, common);
    }

    /// Debug builds refuse to stamp the production AUMID on any shortcut.
    #[test]
    fn debug_builds_never_write_the_production_aumid() {
        let dir = TempDir::new("lnk");
        let link = dir.path().join("x.lnk");
        let prod = Shortcut {
            aumid: AUMID.into(),
            ..dev_shortcut(std::env::current_exe().unwrap())
        };
        let err = ensure_shortcut(&link, &prod).unwrap_err();
        assert_eq!(err.user_msg().key, "winnet.toast.productionAumid");
        assert!(!link.exists());
    }

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// AT-00-004 (taskbarIdentity): the target path may sit in the bytes as UTF-16LE or ANSI.
    #[test]
    fn dev_electron_target_is_found_in_either_encoding() {
        let dev = r"C:\proj\node_modules\electron\dist\electron.exe";
        let mut odd = vec![0x4c];
        odd.extend(utf16(dev));
        for bytes in [utf16(dev), dev.as_bytes().to_vec(), odd] {
            assert!(is_dev_electron_link(&bytes));
        }
        assert!(mentions_dev_electron(
            "c:/p/NODE_MODULES/Electron/dist/ELECTRON.EXE"
        ));
        let user = r"C:\Program Files\Some Electron App\app.exe";
        assert!(!is_dev_electron_link(&utf16(user)));
        assert!(!is_dev_electron_link(user.as_bytes()));
    }

    /// AT-00-004 (taskbarIdentity): a dev Electron.lnk is deleted, a user's one stays, and an
    /// absent one is a no-op. Uses real `.lnk` files in a temp folder.
    #[test]
    fn hijacking_dev_shortcut_is_removed_and_others_stay() {
        let dir = TempDir::new("lnk");
        assert!(!remove_hijacking_dev_shortcut(dir.path()).unwrap());

        let electron = dir.path().join("Electron.lnk");
        let dev = dev_shortcut(PathBuf::from(
            r"C:\proj\node_modules\electron\dist\electron.exe",
        ));
        ensure_shortcut(&electron, &dev).unwrap();
        assert!(remove_hijacking_dev_shortcut(dir.path()).unwrap());
        assert!(!electron.exists());

        let user = dev_shortcut(PathBuf::from(r"C:\Program Files\Some Electron App\app.exe"));
        ensure_shortcut(&electron, &user).unwrap();
        assert!(!remove_hijacking_dev_shortcut(dir.path()).unwrap());
        assert!(electron.exists());
    }
}
