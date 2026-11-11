//! The native Save dialog (`IFileSaveDialog`) on a thread of its own (a COM single-threaded
//! apartment), so the UI and the runtime keep running while it is open. A shell dialog of the
//! user's session: no elevation, no rights beyond the user's own.
use std::path::PathBuf;

use tokio::sync::oneshot;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use windows::Win32::Foundation::{ERROR_CANCELLED, HWND};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance,
    CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC;
use windows::Win32::UI::Shell::{
    FOLDERID_Desktop, FOS_FORCEFILESYSTEM, FOS_NOREADONLYRETURN, FOS_OVERWRITEPROMPT,
    FOS_PATHMUSTEXIST, FileSaveDialog, IFileSaveDialog, IShellItem, KF_FLAG_DEFAULT,
    SHGetKnownFolderItem, SIGDN_FILESYSPATH,
};
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};
use windows::core::{HRESULT, HSTRING, PCWSTR};

/// What the dialog shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SaveOptions {
    pub title: String,
    pub file_name: String,
    /// `(label, pattern)`; the first one is selected.
    pub filters: Vec<(String, String)>,
    /// Appended when the user types a name without one (no dot).
    pub extension: String,
}

/// Asks where to save; `None` when the user dismissed the dialog. Modal to our window when it is
/// in front (the user just clicked in it).
pub(super) async fn save(opts: SaveOptions) -> AppResult<Option<PathBuf>> {
    let owner = own_foreground_window();
    let (tx, rx) = oneshot::channel();
    std::thread::Builder::new()
        .name("save-dialog".into())
        .spawn(move || {
            let _ = tx.send(show(&opts, owner));
        })
        .map_err(failed)?;
    rx.await
        .map_err(|_| failed(anyhow::anyhow!("save dialog thread ended")))?
}

/// Our process's foreground window as a plain number (a window handle is not `Send`).
fn own_foreground_window() -> Option<isize> {
    // SAFETY: no arguments; a null result is handled.
    let hwnd = unsafe { GetForegroundWindow() };
    let mut pid = 0u32;
    // SAFETY: `hwnd` may be null or stale: the call then fails and leaves `pid` at 0.
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    // SAFETY: no arguments.
    let ours = pid != 0 && pid == unsafe { GetCurrentProcessId() };
    ours.then_some(hwnd.0 as isize)
}

fn show(opts: &SaveOptions, owner: Option<isize>) -> AppResult<Option<PathBuf>> {
    in_apartment(|| ask(&configure(opts)?, owner))
}

/// Runs `f` with COM initialised on the current (fresh) thread as a single-threaded apartment.
pub(super) fn in_apartment<T>(f: impl FnOnce() -> windows::core::Result<T>) -> AppResult<T> {
    // SAFETY: balanced by `CoUninitialize` below when it succeeded.
    let init = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
    if init.is_err() {
        return Err(failed(windows::core::Error::from(init)));
    }
    let result = f().map_err(failed);
    // SAFETY: matches the successful `CoInitializeEx` of this thread; `f` released its objects.
    unsafe { CoUninitialize() };
    result
}

/// A Save dialog set up for `opts`, not shown yet (COM must be initialised on this thread).
pub(super) fn configure(opts: &SaveOptions) -> windows::core::Result<IFileSaveDialog> {
    // SAFETY: COM is initialised on this thread; the CLSID / IID pair is the shell's own.
    let dialog: IFileSaveDialog =
        unsafe { CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER)? };
    let texts: Vec<(HSTRING, HSTRING)> = opts
        .filters
        .iter()
        .map(|(label, pattern)| (HSTRING::from(label), HSTRING::from(pattern)))
        .collect();
    let specs: Vec<COMDLG_FILTERSPEC> = texts
        .iter()
        .map(|(label, pattern)| COMDLG_FILTERSPEC {
            pszName: PCWSTR(label.as_ptr()),
            pszSpec: PCWSTR(pattern.as_ptr()),
        })
        .collect();
    // SAFETY: the strings behind `specs` (`texts`) and the HSTRING arguments outlive the calls.
    unsafe {
        dialog.SetFileTypes(&specs)?;
        dialog.SetFileTypeIndex(1)?;
        dialog.SetTitle(&HSTRING::from(&opts.title))?;
        dialog.SetFileName(&HSTRING::from(&opts.file_name))?;
        dialog.SetDefaultExtension(&HSTRING::from(&opts.extension))?;
        let options = dialog.GetOptions()?
            | FOS_OVERWRITEPROMPT
            | FOS_FORCEFILESYSTEM
            | FOS_PATHMUSTEXIST
            | FOS_NOREADONLYRETURN;
        dialog.SetOptions(options)?;
    }
    // The Desktop when Windows remembers no folder of ours yet.
    // SAFETY: a known-folder id constant; no token (the current user).
    if let Ok(desktop) =
        unsafe { SHGetKnownFolderItem::<IShellItem>(&FOLDERID_Desktop, KF_FLAG_DEFAULT, None) }
    {
        // SAFETY: a live shell item.
        unsafe { dialog.SetDefaultFolder(&desktop)? };
    }
    Ok(dialog)
}

/// Shows the dialog modal to `owner` and returns the chosen path; `None` = dismissed.
fn ask(dialog: &IFileSaveDialog, owner: Option<isize>) -> windows::core::Result<Option<PathBuf>> {
    // SAFETY: the owner is our own top-level window or none; the call blocks until it closes.
    match unsafe { dialog.Show(owner.map(|h| HWND(h as *mut _))) } {
        Err(err) if err.code() == HRESULT::from_win32(ERROR_CANCELLED.0) => return Ok(None),
        other => other?,
    }
    // SAFETY: the dialog returned OK, so it holds a result item.
    let path = unsafe { dialog.GetResult()?.GetDisplayName(SIGDN_FILESYSPATH)? };
    // SAFETY: `path` is a valid, NUL-terminated string the shell allocated for us.
    let text = unsafe { path.to_string() };
    // SAFETY: frees the shell's allocation exactly once, after the copy above.
    unsafe { CoTaskMemFree(Some(path.0 as *const _)) };
    Ok(text.ok().map(PathBuf::from))
}

fn failed(source: impl Into<anyhow::Error>) -> AppError {
    AppError::msg(ErrorKind::Internal, Msg::new("app.servers.dialog.failed")).with_source(source)
}
