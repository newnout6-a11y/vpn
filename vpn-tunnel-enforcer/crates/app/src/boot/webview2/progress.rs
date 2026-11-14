//! Windows' own progress window (IProgressDialog): the one progress line a start can show before WebView2
//! exists. It runs on a thread of its own, so the caller may block while it shows. If it cannot be shown, the
//! install runs without it.
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoUninitialize,
};
use windows::Win32::UI::Shell::{
    CLSID_ProgressDialog, IProgressDialog, PROGDLG_MARQUEEPROGRESS, PROGDLG_NOTIME,
};
use windows::core::{HSTRING, IUnknown};

/// A shown progress window; closed on drop.
pub struct Progress {
    dialog: Option<IProgressDialog>,
    /// This thread's COM initialisation succeeded and is balanced on drop.
    com: bool,
}

impl Progress {
    /// Shows `line` under `title` with an endless (marquee) bar and a Cancel button.
    pub fn show(title: &str, line: &str) -> Self {
        // Single-threaded apartment: WebView2 later initialises OLE on this same (main) thread.
        // SAFETY: plain COM initialisation of the calling thread, balanced in `drop`.
        let com = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.is_ok();
        let dialog = start(title, line).ok();
        Self { dialog, com }
    }

    /// `true` once the user pressed Cancel.
    pub fn cancelled(&self) -> bool {
        // SAFETY: a live dialog created on this thread.
        self.dialog
            .as_ref()
            .is_some_and(|dialog| unsafe { dialog.HasUserCancelled() }.as_bool())
    }
}

fn start(title: &str, line: &str) -> windows::core::Result<IProgressDialog> {
    let (title, line) = (HSTRING::from(title), HSTRING::from(line));
    // SAFETY: COM calls on this thread's apartment; the strings outlive the calls (the dialog copies them).
    unsafe {
        let dialog: IProgressDialog =
            CoCreateInstance(&CLSID_ProgressDialog, None, CLSCTX_INPROC_SERVER)?;
        dialog.SetTitle(&title)?;
        dialog.SetLine(1, &line, false, None)?;
        dialog.StartProgressDialog(
            None,
            None::<&IUnknown>,
            PROGDLG_MARQUEEPROGRESS | PROGDLG_NOTIME,
            None,
        )?;
        Ok(dialog)
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if let Some(dialog) = self.dialog.take() {
            // SAFETY: the dialog was started on this thread; stopping twice is harmless.
            let _ = unsafe { dialog.StopProgressDialog() };
        }
        if self.com {
            // SAFETY: balances the successful `CoInitializeEx` of `show` on this same thread.
            unsafe { CoUninitialize() };
        }
    }
}
