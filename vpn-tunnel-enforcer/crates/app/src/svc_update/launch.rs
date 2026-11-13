//! Starting the installer as the desktop user (research §4.9): an unelevated app starts it
//! directly, handing it no handle (the installer waits for this app to exit and must not keep
//! anything of ours open); an app that runs elevated goes through Explorer's own shell, so the
//! per-user installer never inherits an administrator token. The same technique as
//! `setup::shell::launch_as_user`, with arguments.
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Com::{
    CLSCTX_LOCAL_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance,
    CoInitializeEx, CoUninitialize, IDispatch, IServiceProvider,
};
use windows::Win32::System::Threading::{
    CreateProcessW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::UI::Shell::{
    CSIDL_DESKTOP, IShellBrowser, IShellDispatch2, IShellFolderViewDual, IShellWindows,
    SID_STopLevelBrowser, SVGIO_BACKGROUND, SWC_DESKTOP, SWFO_NEEDDISPATCH, ShellWindows,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{BSTR, Interface, PCWSTR, PWSTR};

/// Why the installer did not start.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LaunchError {
    /// Elevated and no desktop shell to start it unelevated: the user restarts the app normally.
    #[error("no desktop shell to start the installer without administrator rights")]
    NoShell,
    #[error("the installer did not start: {0}")]
    Failed(windows::core::Error),
}

/// Starts `exe` with `args` as the desktop user and returns at once.
pub(crate) fn run_unelevated(exe: &Path, args: &[&str]) -> Result<(), LaunchError> {
    let dir = exe.parent().unwrap_or(Path::new("."));
    if vpnte_winnet::elevation::is_elevated() {
        let _com = Apartment::enter();
        let shell = desktop_shell().map_err(|_| LaunchError::NoShell)?;
        let bstr = |s: &OsStr| BSTR::from_wide(&s.encode_wide().collect::<Vec<u16>>());
        // SAFETY: COM is initialised on this thread (`Apartment`); every variant and string
        // outlives the call.
        unsafe {
            shell.ShellExecute(
                &bstr(exe.as_os_str()),
                &VARIANT::from(bstr(OsStr::new(&args.join(" ")))),
                &VARIANT::from(bstr(dir.as_os_str())),
                &VARIANT::from(""),
                &VARIANT::from(SW_SHOWNORMAL.0),
            )
        }
        .map_err(LaunchError::Failed)
    } else {
        start_detached(exe, args, dir).map_err(LaunchError::Failed)
    }
}

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

/// CreateProcessW without inherited handles; the command line is the quoted exe and `args`.
fn start_detached(exe: &Path, args: &[&str], dir: &Path) -> windows::core::Result<()> {
    let app = wide(exe.as_os_str());
    let cwd = wide(dir.as_os_str());
    let mut line = std::ffi::OsString::from("\"");
    line.push(exe.as_os_str());
    line.push("\"");
    for arg in args {
        line.push(" ");
        line.push(arg);
    }
    let mut line = wide(&line);
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

/// A single-threaded COM apartment for this thread, left again on drop.
struct Apartment {
    entered: bool,
}

impl Apartment {
    fn enter() -> Self {
        // SAFETY: plain call; balanced by `CoUninitialize` on drop when it succeeded.
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

/// Explorer's automation object, reached through the desktop window's folder view (Raymond
/// Chen's "launch an unelevated process from an elevated one").
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
