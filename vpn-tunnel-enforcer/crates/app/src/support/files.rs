//! The native Save dialog (`IFileSaveDialog`) the export actions (logs, diagnostics, histories)
//! ask for a path. A shell window of the user's own session: no elevation, no rights beyond the
//! user's. The path the backend then writes is the user's answer in that window, never a string
//! that came from the page.
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

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
    FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Downloads, FOS_FORCEFILESYSTEM,
    FOS_NOREADONLYRETURN, FOS_OVERWRITEPROMPT, FOS_PATHMUSTEXIST, FileSaveDialog, IFileSaveDialog,
    IShellItem, KF_FLAG_DEFAULT, SHGetKnownFolderItem, SIGDN_FILESYSPATH,
};
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};
use windows::core::{GUID, HRESULT, HSTRING, PCWSTR, PWSTR};

/// Where the dialog opens while Windows remembers no folder of ours yet; afterwards it reopens
/// where the user saved last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StartFolder {
    #[default]
    Documents,
    Downloads,
    Desktop,
}

impl StartFolder {
    fn id(self) -> &'static GUID {
        match self {
            StartFolder::Documents => &FOLDERID_Documents,
            StartFolder::Downloads => &FOLDERID_Downloads,
            StartFolder::Desktop => &FOLDERID_Desktop,
        }
    }
}

/// What the Save dialog shows. Texts are keys, rendered in the language given to [`save_file`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveFile {
    pub title: Msg,
    /// Suggested name, made valid for Windows ([`file_name`]) before it is shown.
    pub file_name: String,
    /// Appended to a typed name without one; no leading dot (`"zip"`).
    pub extension: String,
    /// `(label, pattern)` such as `(Msg::new("app.x.zip"), "*.zip")`; the first is selected.
    pub filters: Vec<(Msg, String)>,
    pub folder: StartFolder,
}

impl SaveFile {
    /// A dialog titled `title` suggesting `file_name`, `extension` with or without its dot,
    /// opening in Documents, without file types yet.
    pub fn new(title: Msg, file_name: impl Into<String>, extension: &str) -> Self {
        Self {
            title,
            file_name: file_name.into(),
            extension: extension.trim_start_matches('.').to_owned(),
            filters: Vec::new(),
            folder: StartFolder::default(),
        }
    }

    /// Adds a file type; the first one added is selected.
    #[must_use]
    pub fn filter(mut self, label: Msg, pattern: &str) -> Self {
        self.filters.push((label, pattern.to_owned()));
        self
    }

    /// Opens in `folder` instead of Documents.
    #[must_use]
    pub fn in_folder(mut self, folder: StartFolder) -> Self {
        self.folder = folder;
        self
    }
}

/// `name` as a valid Windows file name: reserved and control characters become `_`, trailing
/// dots and spaces go (Windows would drop them silently), and a device name (`CON`, `nul.txt`,
/// `COM1`, ...) gets a `_` in front. Server names and times (`12:30`) end up in suggested names.
pub fn file_name(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_control() || r#"<>:"/\|?*"#.contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    let clean = clean.trim_start().trim_end_matches(['.', ' ']);
    if is_device(clean) {
        format!("_{clean}")
    } else {
        clean.to_owned()
    }
}

/// Windows opens a device instead of a file for these names, whatever the extension.
fn is_device(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or_default().trim_end();
    let upper = base.to_ascii_uppercase();
    let numbered = upper.len() == 4
        && (upper.starts_with("COM") || upper.starts_with("LPT"))
        && upper.as_bytes()[3].is_ascii_digit();
    numbered || ["CON", "PRN", "AUX", "NUL"].contains(&upper.as_str())
}

/// Asks where to save; `Ok(None)` = the user dismissed the dialog. Modal to our window when it is
/// in front (the user just clicked in it). Blocks until the dialog closes: call it from a blocking
/// thread (`spawn_blocking`), never from the UI thread, which must keep pumping messages while its
/// window is the dialog's owner.
pub fn save_file_blocking(req: &SaveFile, lang: Lang) -> AppResult<Option<PathBuf>> {
    let owner = own_foreground_window();
    // A thread of its own gets a fresh single-threaded apartment, whatever COM state the calling
    // (pool) thread was left in.
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("save-dialog".into())
            .spawn_scoped(scope, || in_sta(|| ask(&configure(req, lang)?, owner)))
            .map_err(failed)?
            .join()
            .unwrap_or_else(|_| Err(failed(anyhow::anyhow!("save dialog thread panicked"))))
    })
}

/// [`save_file_blocking`] on tokio's blocking pool.
pub async fn save_file(req: SaveFile, lang: Lang) -> AppResult<Option<PathBuf>> {
    super::blocking(move || save_file_blocking(&req, lang)).await
}

/// Our process's foreground window as a plain number (a window handle is not `Send`); a window
/// of another program never becomes the owner.
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

/// Runs `f` with COM initialised on this thread as a single-threaded apartment (the shell
/// dialogs need one).
pub(super) fn in_sta<T>(f: impl FnOnce() -> windows::core::Result<T>) -> AppResult<T> {
    // SAFETY: per-thread initialisation, balanced below whenever it succeeded (S_FALSE included).
    let init = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
    if init.is_err() {
        return Err(failed(windows::core::Error::from(init)));
    }
    let result = f().map_err(failed);
    // SAFETY: matches the successful `CoInitializeEx` above; `f` released its COM objects.
    unsafe { CoUninitialize() };
    result
}

/// The dialog set up for `req`, not shown (COM must be initialised on this thread).
pub(super) fn configure(req: &SaveFile, lang: Lang) -> windows::core::Result<IFileSaveDialog> {
    // SAFETY: COM is initialised on this thread; the CLSID / IID pair is the shell's own.
    let dialog: IFileSaveDialog =
        unsafe { CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER)? };
    let texts: Vec<(HSTRING, HSTRING)> = req
        .filters
        .iter()
        .map(|(label, pattern)| (HSTRING::from(label.render(lang)), HSTRING::from(pattern)))
        .collect();
    let specs: Vec<COMDLG_FILTERSPEC> = texts
        .iter()
        .map(|(label, pattern)| COMDLG_FILTERSPEC {
            pszName: PCWSTR(label.as_ptr()),
            pszSpec: PCWSTR(pattern.as_ptr()),
        })
        .collect();
    // SAFETY: the strings behind `specs` (`texts`) and every HSTRING argument outlive the calls.
    unsafe {
        if !specs.is_empty() {
            dialog.SetFileTypes(&specs)?;
            dialog.SetFileTypeIndex(1)?;
        }
        dialog.SetTitle(&HSTRING::from(req.title.render(lang)))?;
        dialog.SetFileName(&HSTRING::from(file_name(&req.file_name)))?;
        if !req.extension.is_empty() {
            dialog.SetDefaultExtension(&HSTRING::from(&req.extension))?;
        }
        let options = dialog.GetOptions()?
            | FOS_OVERWRITEPROMPT
            | FOS_FORCEFILESYSTEM
            | FOS_PATHMUSTEXIST
            | FOS_NOREADONLYRETURN;
        dialog.SetOptions(options)?;
    }
    // A redirected folder that is unavailable (OneDrive offline) leaves the shell's own choice.
    // SAFETY: a known-folder id constant; no token = the current user.
    let folder =
        unsafe { SHGetKnownFolderItem::<IShellItem>(req.folder.id(), KF_FLAG_DEFAULT, None) };
    if let Ok(folder) = folder {
        // SAFETY: a live shell item.
        unsafe { dialog.SetDefaultFolder(&folder)? };
    }
    Ok(dialog)
}

/// Shows `dialog` modal to `owner`: the chosen path, `None` when it was dismissed.
fn ask(dialog: &IFileSaveDialog, owner: Option<isize>) -> windows::core::Result<Option<PathBuf>> {
    // SAFETY: `owner` is a window of this process or none; the call blocks until the dialog closes.
    match unsafe { dialog.Show(owner.map(|h| HWND(h as *mut _))) } {
        Err(err) if err.code() == HRESULT::from_win32(ERROR_CANCELLED.0) => return Ok(None),
        other => other?,
    }
    // SAFETY: `Show` succeeded, so the dialog holds a result item.
    let path = unsafe { dialog.GetResult()?.GetDisplayName(SIGDN_FILESYSPATH)? };
    Ok(Some(take_path(path)))
}

/// Copies a string the shell allocated for us, losslessly (a name may hold unpaired surrogates),
/// and frees it.
pub(super) fn take_path(text: PWSTR) -> PathBuf {
    // SAFETY: a valid, non-null, NUL-terminated string returned by a successful shell call.
    let path = PathBuf::from(OsString::from_wide(unsafe { text.as_wide() }));
    // SAFETY: frees the shell's allocation exactly once, after the copy above.
    unsafe { CoTaskMemFree(Some(text.0 as *const _)) };
    path
}

fn failed(source: impl Into<anyhow::Error>) -> AppError {
    AppError::msg(
        ErrorKind::Internal,
        Msg::new("app.clickjack.saveDialog.failed"),
    )
    .with_source(source)
}
