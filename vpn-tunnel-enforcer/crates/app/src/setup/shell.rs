//! Shell work of the installer helper: the AUMID on the installer's per-user links
//! (`stamp-shortcuts`), starting the installed client unelevated (`launch-as-user`), the jump
//! list of our AUMID (uninstall) and the known folders these need.
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use vpnte_winnet::toast::{self, AUMID, Shortcut};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, CLSCTX_LOCAL_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, IDispatch, IServiceProvider,
};
use windows::Win32::System::Threading::{
    CreateProcessW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::UI::Shell::{
    ApplicationDestinations, CSIDL_DESKTOP, FOLDERID_Desktop, FOLDERID_ProgramData,
    IApplicationDestinations, IShellBrowser, IShellDispatch2, IShellFolderViewDual, IShellWindows,
    KF_FLAG_DEFAULT, SHGetKnownFolderPath, SID_STopLevelBrowser, SVGIO_BACKGROUND, SWC_DESKTOP,
    SWFO_NEEDDISPATCH, ShellWindows,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{BSTR, GUID, HSTRING, Interface, PCWSTR, PWSTR};

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

/// `--setup stamp-shortcuts`: each of the installer's two per-user links (the user's Start menu
/// and desktop) that exists and targets `<dir>\VPN Tunnel Enforcer.exe` gets the app's AUMID and
/// is read back; nothing else is created. All-users links (an old per-machine installation) are
/// never touched. `Ok` lists what was done (stdout lines).
pub fn stamp_shortcuts(install_dir: &Path) -> Result<Vec<String>, String> {
    let exe = install_dir.join(MAIN_EXE);
    let folders = [
        ("start menu", toast::user_programs_dir().ok()),
        ("desktop", known_folder(&FOLDERID_Desktop).ok()),
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

/// `--setup launch-as-user`: starts `<dir>\VPN Tunnel Enforcer.exe` without arguments and returns
/// at once. The per-user installer already runs as the user, so a plain start is enough; only a
/// helper that happens to be elevated (setup started "as administrator") goes through the
/// desktop's own shell, so that the app never inherits an elevated token by accident.
pub fn launch_as_user(install_dir: &Path) -> Result<(), String> {
    let exe = install_dir.join(MAIN_EXE);
    if !exe.is_file() {
        return Err("The installed client was not found; not started.".to_owned());
    }
    let started = if vpnte_winnet::elevation::is_elevated() {
        let _com = Apartment::enter();
        desktop_shell_execute(&exe, install_dir)
    } else {
        start_detached(&exe, install_dir)
    };
    started.map_err(|err| {
        format!(
            "Cannot start the client (0x{:08X}).",
            err.code().0.cast_unsigned()
        )
    })
}

/// A NUL-terminated wide string.
fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

/// The child's command line: the quoted exe path alone (argv[0]; the path has spaces).
fn command_line(exe: &Path) -> Vec<u16> {
    let mut line = OsString::from("\"");
    line.push(exe.as_os_str());
    line.push("\"");
    wide(&line)
}

/// Starts the app without handing it any handle: the installer reads this helper's output
/// through a pipe and would otherwise wait for the app to close its inherited copy.
fn start_detached(exe: &Path, dir: &Path) -> windows::core::Result<()> {
    let app = wide(exe.as_os_str());
    let cwd = wide(dir.as_os_str());
    let mut line = command_line(exe);
    let startup = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: every string is NUL-terminated and outlives the call; `line` is writable, as
    // CreateProcessW requires; the two returned handles are ours and closed once.
    unsafe {
        CreateProcessW(
            PCWSTR(app.as_ptr()),
            Some(PWSTR(line.as_mut_ptr())),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0),
            None,
            PCWSTR(cwd.as_ptr()),
            &startup,
            &mut info,
        )?;
        let _ = CloseHandle(info.hThread);
        let _ = CloseHandle(info.hProcess);
    }
    Ok(())
}

/// Raymond Chen's "launch an unelevated process from an elevated one": `ShellExecute` runs
/// inside Explorer, with Explorer's token.
fn desktop_shell_execute(exe: &Path, dir: &Path) -> windows::core::Result<()> {
    let bstr = |p: &Path| BSTR::from_wide(&p.as_os_str().encode_wide().collect::<Vec<u16>>());
    let shell = desktop_shell()?;
    // SAFETY: COM is initialised on this thread (`Apartment`); every variant and string
    // outlives the call.
    unsafe {
        shell.ShellExecute(
            &bstr(exe),
            &VARIANT::from(""),
            &VARIANT::from(bstr(dir)),
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
        assert!(known_folder(&FOLDERID_Desktop).is_ok_and(|d| d.is_absolute()));
        assert!(toast::user_programs_dir().is_ok_and(|d| d.is_absolute()));
    }

    /// The child gets its exe as one quoted argv[0], spaces and all, NUL-terminated.
    #[test]
    fn command_line_quotes_the_exe() {
        let exe = Path::new(r"C:\Users\A B\AppData\Local\Programs\VPN Tunnel Enforcer\x.exe");
        let line = command_line(exe);
        assert_eq!(line.last(), Some(&0));
        let text = String::from_utf16(&line[..line.len() - 1]).expect("UTF-16");
        assert_eq!(text, format!("\"{}\"", exe.display()));
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
