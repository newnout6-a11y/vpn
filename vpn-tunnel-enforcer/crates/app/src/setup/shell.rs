//! Shell work of the installer helper: the AUMID on the installer's links (`stamp-shortcuts`),
//! starting the installed client as the desktop user (`launch-as-user`), the jump list of our
//! AUMID (uninstall) and the known folders these need.
use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use vpnte_winnet::toast::{self, AUMID, Shortcut};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, CLSCTX_LOCAL_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, IDispatch, IServiceProvider,
};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::UI::Shell::{
    ApplicationDestinations, CSIDL_DESKTOP, FOLDERID_ProgramData, FOLDERID_PublicDesktop,
    IApplicationDestinations, IShellBrowser, IShellDispatch2, IShellFolderViewDual, IShellWindows,
    KF_FLAG_DEFAULT, SHGetKnownFolderPath, SID_STopLevelBrowser, SVGIO_BACKGROUND, SWC_DESKTOP,
    SWFO_NEEDDISPATCH, ShellWindows,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{BSTR, GUID, HSTRING, Interface};

use super::gate::{MAIN_EXE, same_path};

/// The name NSIS gives both links.
const LINK_NAME: &str = "VPN Tunnel Enforcer.lnk";

/// A single-threaded COM apartment for this thread, left again on drop.
struct Apartment {
    entered: bool,
}

impl Apartment {
    fn enter() -> Self {
        // SAFETY: plain call; balanced by `CoUninitialize` on drop when it succeeded (S_FALSE
        // included: already initialised on this thread).
        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
        Self {
            entered: hr.is_ok(),
        }
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.entered {
            // SAFETY: balances the successful `CoInitializeEx` of `enter` on this thread.
            unsafe { CoUninitialize() };
        }
    }
}

fn known_folder(id: &GUID) -> windows::core::Result<PathBuf> {
    // SAFETY: on success the path is CoTaskMem-allocated and ours; freed after copying.
    unsafe {
        let path = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None)?;
        let dir = PathBuf::from(OsString::from_wide(path.as_wide()));
        CoTaskMemFree(Some(path.0.cast_const().cast()));
        Ok(dir)
    }
}

/// `%ProgramData%\VPNTE\runtime`, where the Electron generation ran its engines (known folder,
/// not the environment variable).
pub fn legacy_runtime_dir() -> Option<PathBuf> {
    known_folder(&FOLDERID_ProgramData)
        .ok()
        .map(|dir| dir.join(r"VPNTE\runtime"))
}

/// `--setup stamp-shortcuts`: each of the installer's two links (all-users Start menu, public
/// desktop) that exists and targets `<dir>\VPN Tunnel Enforcer.exe` gets the app's AUMID and is
/// read back; nothing else is created. `Ok` lists what was done (stdout lines).
pub fn stamp_shortcuts(install_dir: &Path) -> Result<Vec<String>, String> {
    let exe = install_dir.join(MAIN_EXE);
    let folders = [
        ("start menu", toast::common_programs_dir().ok()),
        ("desktop", known_folder(&FOLDERID_PublicDesktop).ok()),
    ];
    let mut done = Vec::new();
    for (place, folder) in folders {
        let Some(folder) = folder else {
            return Err(format!(
                "Cannot locate the {place} folder; shortcut not stamped."
            ));
        };
        let link = folder.join(LINK_NAME);
        if !link.is_file() {
            done.push(format!("{place} link: absent"));
            continue;
        }
        let read = |link: &Path| {
            toast::read_shortcut(link)
                .map_err(|_| format!("Cannot read the {place} link; shortcut not stamped."))
        };
        let current = read(&link)?;
        if !same_path(&current.target, &exe) {
            done.push(format!("{place} link: points elsewhere, left alone"));
            continue;
        }
        if current.aumid != AUMID {
            let stamped = Shortcut {
                aumid: AUMID.to_owned(),
                ..current
            };
            toast::ensure_shortcut(&link, &stamped)
                .map_err(|_| format!("Cannot write the {place} link; shortcut not stamped."))?;
            if read(&link)?.aumid != AUMID {
                return Err(format!("The {place} link does not keep the AUMID."));
            }
        }
        done.push(format!("{place} link: stamped"));
    }
    Ok(done)
}

/// `--setup launch-as-user`: starts `<dir>\VPN Tunnel Enforcer.exe` without arguments through
/// the desktop's own shell (Explorer's `IShellDispatch2::ShellExecute`), so it runs as the
/// interactive user with Explorer's unelevated token, not the installer's; returns at once.
pub fn launch_as_user(install_dir: &Path) -> Result<(), String> {
    let exe = install_dir.join(MAIN_EXE);
    if !exe.is_file() {
        return Err("The installed client was not found; not started.".to_owned());
    }
    let _com = Apartment::enter();
    desktop_shell_execute(&exe, install_dir).map_err(|err| {
        format!(
            "Cannot start the client as the desktop user (0x{:08X}).",
            err.code().0.cast_unsigned()
        )
    })
}

/// Raymond Chen's "launch an unelevated process from an elevated one": `ShellExecute` runs
/// inside Explorer, with Explorer's token.
fn desktop_shell_execute(exe: &Path, dir: &Path) -> windows::core::Result<()> {
    let wide = |p: &Path| p.as_os_str().encode_wide().collect::<Vec<u16>>();
    let shell = desktop_shell()?;
    // SAFETY: COM is initialised on this thread (`Apartment`); every variant and string
    // outlives the call.
    unsafe {
        shell.ShellExecute(
            &BSTR::from_wide(&wide(exe)),
            &VARIANT::from(""),
            &VARIANT::from(BSTR::from_wide(&wide(dir))),
            &VARIANT::from(""),
            &VARIANT::from(SW_SHOWNORMAL.0),
        )
    }
}

/// Explorer's automation object, reached through the desktop window's folder view. Needs COM
/// on this thread and an interactive desktop with Explorer as its shell.
fn desktop_shell() -> windows::core::Result<IShellDispatch2> {
    // SAFETY: COM is initialised on this thread (`Apartment`); every variant outlives the call
    // it is passed to.
    unsafe {
        let windows: IShellWindows = CoCreateInstance(&ShellWindows, None, CLSCTX_LOCAL_SERVER)?;
        let mut hwnd = 0i32;
        let desktop = windows.FindWindowSW(
            &VARIANT::from(CSIDL_DESKTOP as i32),
            &VARIANT::default(),
            SWC_DESKTOP,
            &mut hwnd,
            SWFO_NEEDDISPATCH,
        )?;
        let browser: IShellBrowser = desktop
            .cast::<IServiceProvider>()?
            .QueryService(&SID_STopLevelBrowser)?;
        let background: IDispatch = browser
            .QueryActiveShellView()?
            .GetItemObject(SVGIO_BACKGROUND)?;
        background
            .cast::<IShellFolderViewDual>()?
            .Application()?
            .cast()
    }
}

/// Removes the jump-list entries (recent / frequent destinations) Windows keeps for our AUMID.
pub fn remove_jump_list() -> windows::core::Result<()> {
    let _com = Apartment::enter();
    // SAFETY: COM is initialised on this thread; the AUMID string outlives the call.
    unsafe {
        let list: IApplicationDestinations =
            CoCreateInstance(&ApplicationDestinations, None, CLSCTX_INPROC_SERVER)?;
        list.SetAppID(&HSTRING::from(AUMID))?;
        list.RemoveAllDestinations()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The folders the helper works in resolve (read only).
    #[test]
    fn known_folders_resolve() {
        let runtime = legacy_runtime_dir().expect("ProgramData");
        assert!(runtime.ends_with(r"VPNTE\runtime"));
        assert!(known_folder(&FOLDERID_PublicDesktop).is_ok_and(|d| d.is_absolute()));
    }

    /// The desktop's automation object is reachable: every step of `launch-as-user` except the
    /// final `ShellExecute`, which would start a program. Needs Explorer as the desktop shell,
    /// which a CI service session may not have.
    #[test]
    #[ignore = "needs an interactive desktop with Explorer"]
    fn desktop_shell_is_reachable() {
        let _com = Apartment::enter();
        desktop_shell().expect("IShellDispatch2 of the desktop");
    }
}
