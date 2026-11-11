//! Native Open / Save dialogs (`IFileOpenDialog` / `IFileSaveDialog`) on a thread of their own
//! (a COM single-threaded apartment), so the UI and the runtime keep running while one is open.
//! A shell dialog of the user's session: no elevation, no rights beyond the user's own.
use std::path::PathBuf;

use tokio::sync::oneshot;
use vpnte_base::i18n::Lang;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use windows::Win32::Foundation::{ERROR_CANCELLED, HWND};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance,
    CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC;
use windows::Win32::UI::Shell::{
    FOS_FILEMUSTEXIST, FOS_FORCEFILESYSTEM, FOS_NOREADONLYRETURN, FOS_OVERWRITEPROMPT,
    FOS_PATHMUSTEXIST, FileOpenDialog, FileSaveDialog, IFileDialog, SIGDN_FILESYSPATH,
};
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};
use windows::core::{HRESULT, HSTRING, PCWSTR};

use crate::services::Backend;

/// What a dialog shows (texts already rendered in the user's language).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDialog {
    pub title: String,
    /// `(label, pattern)`; the first one is selected.
    pub filters: Vec<(String, String)>,
    /// `Some((suggested file name, default extension))` = a Save dialog; `None` = Open.
    pub save: Option<(String, String)>,
}

impl FileDialog {
    /// An Open dialog; `filters` are `(label key, pattern)`.
    pub fn open(lang: Lang, title: &'static str, filters: &[(&'static str, &str)]) -> Self {
        Self {
            title: Msg::new(title).render(lang),
            filters: filters
                .iter()
                .map(|(label, pattern)| (Msg::new(*label).render(lang), (*pattern).to_owned()))
                .collect(),
            save: None,
        }
    }

    /// The same as a Save dialog suggesting `file_name` (`extension` is added to a typed name
    /// without one).
    #[must_use]
    pub fn save_as(mut self, file_name: String, extension: &str) -> Self {
        self.save = Some((file_name, extension.to_owned()));
        self
    }
}

/// The user's language for dialog texts: the stored one, else Windows'.
pub fn lang(backend: &Backend) -> Lang {
    backend
        .settings
        .read(|s| s.locale)
        .unwrap_or_else(vpnte_ui::lang::os_lang)
}

/// Shows the dialog; `None` when the user dismissed it. Modal to our window when it is in
/// front (the user just clicked in it).
pub async fn show(dialog: FileDialog) -> AppResult<Option<PathBuf>> {
    let owner = own_foreground_window();
    let (tx, rx) = oneshot::channel();
    std::thread::Builder::new()
        .name("file-dialog".into())
        .spawn(move || {
            let _ = tx.send(on_thread(&dialog, owner));
        })
        .map_err(failed)?;
    rx.await
        .map_err(|_| failed(anyhow::anyhow!("file dialog thread ended")))?
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

fn on_thread(dialog: &FileDialog, owner: Option<isize>) -> AppResult<Option<PathBuf>> {
    // SAFETY: a fresh thread; balanced by `CoUninitialize` below when it succeeded.
    let init = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
    if init.is_err() {
        return Err(failed(windows::core::Error::from(init)));
    }
    let result = run(dialog, owner).map_err(failed);
    // SAFETY: matches the successful `CoInitializeEx` of this thread.
    unsafe { CoUninitialize() };
    result
}

fn run(dialog: &FileDialog, owner: Option<isize>) -> windows::core::Result<Option<PathBuf>> {
    let clsid = if dialog.save.is_some() {
        &FileSaveDialog
    } else {
        &FileOpenDialog
    };
    // SAFETY: COM is initialised on this thread; both shell dialogs implement `IFileDialog`.
    let shell: IFileDialog = unsafe { CoCreateInstance(clsid, None, CLSCTX_INPROC_SERVER)? };
    let texts: Vec<(HSTRING, HSTRING)> = dialog
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
        shell.SetFileTypes(&specs)?;
        shell.SetFileTypeIndex(1)?;
        shell.SetTitle(&HSTRING::from(&dialog.title))?;
        let mut options = shell.GetOptions()? | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST;
        match &dialog.save {
            Some((file_name, extension)) => {
                shell.SetFileName(&HSTRING::from(file_name))?;
                shell.SetDefaultExtension(&HSTRING::from(extension))?;
                options |= FOS_OVERWRITEPROMPT | FOS_NOREADONLYRETURN;
            }
            None => options |= FOS_FILEMUSTEXIST,
        }
        shell.SetOptions(options)?;
    }
    // SAFETY: the owner is our own top-level window or none; the call blocks until it closes.
    match unsafe { shell.Show(owner.map(|h| HWND(h as *mut _))) } {
        Err(err) if err.code() == HRESULT::from_win32(ERROR_CANCELLED.0) => return Ok(None),
        other => other?,
    }
    // SAFETY: the dialog returned OK, so it holds a result item.
    let path = unsafe { shell.GetResult()?.GetDisplayName(SIGDN_FILESYSPATH)? };
    // SAFETY: `path` is a valid, NUL-terminated string the shell allocated for us.
    let text = unsafe { path.to_string() };
    // SAFETY: frees the shell's allocation exactly once, after the copy above.
    unsafe { CoTaskMemFree(Some(path.0 as *const _)) };
    Ok(text.ok().map(PathBuf::from))
}

fn failed(source: impl Into<anyhow::Error>) -> AppError {
    AppError::msg(ErrorKind::Internal, Msg::new("app.settings.dialog.failed")).with_source(source)
}
