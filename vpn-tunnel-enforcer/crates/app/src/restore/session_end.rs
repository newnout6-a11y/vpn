//! Logoff and shutdown while the app runs (RU-2026 14c): Windows sends `WM_ENDSESSION` to every
//! top-level window and may end the process as soon as they have returned, so the rollback runs
//! inside the handler. A hidden top-level window on its own thread: a message-only window gets
//! no `WM_ENDSESSION`, and a console control handler never sees a logoff in a process that loads
//! user32 (Windows documents this), which ours does.
use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc as std_mpsc;

use vpnte_base::{AppError, AppResult};
use windows::Win32::Foundation::{
    ERROR_CLASS_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, WPARAM,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, MSG, RegisterClassExW,
    WM_CLOSE, WM_ENDSESSION, WNDCLASSEXW, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_POPUP,
};
use windows::core::{PCWSTR, w};

const CLASS_NAME: PCWSTR = w!("VPNTE.SessionEnd");

thread_local! {
    /// What runs when the session ends; set on the window's thread before the window exists.
    static ON_END: RefCell<Option<Box<dyn Fn()>>> = const { RefCell::new(None) };
}

/// Creates the window on its own thread; `on_end` runs there when the session ends. The window
/// lives as long as the process. Returns its handle as an integer (`HWND` is not `Send`).
pub fn start(on_end: impl Fn() + Send + 'static) -> AppResult<usize> {
    let (ready_tx, ready_rx) = std_mpsc::channel();
    std::thread::Builder::new()
        .name("vpnte-session-end".into())
        .spawn(move || run(Box::new(on_end), &ready_tx))?;
    ready_rx.recv().map_err(|_| {
        AppError::internal(std::io::Error::other(
            "session-end thread ended before its window existed",
        ))
    })?
}

fn run(on_end: Box<dyn Fn()>, ready: &std_mpsc::Sender<AppResult<usize>>) {
    ON_END.with_borrow_mut(|slot| *slot = Some(on_end));
    let hwnd = match create_window() {
        Ok(hwnd) => hwnd,
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    let _ = ready.send(Ok(hwnd.0 as usize));
    let mut msg = MSG::default();
    loop {
        // SAFETY: a standard message loop for the windows of this thread.
        let got = unsafe { GetMessageW(&mut msg, None, 0, 0) }.0;
        if got == 0 || got == -1 {
            break;
        }
        // SAFETY: `msg` was filled by GetMessageW.
        unsafe { DispatchMessageW(&msg) };
    }
}

fn create_window() -> AppResult<HWND> {
    // SAFETY: plain calls; the class lives for the process, the window for this thread.
    unsafe {
        let instance = GetModuleHandleW(PCWSTR::null()).map_err(AppError::internal)?;
        let class = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(wndproc),
            hInstance: instance.into(),
            lpszClassName: CLASS_NAME,
            ..Default::default()
        };
        if RegisterClassExW(&class) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS {
            return Err(AppError::internal(windows::core::Error::from_thread()));
        }
        // Top-level (no parent) so the session messages reach it; never shown, no taskbar or
        // Alt+Tab entry.
        CreateWindowExW(
            WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            CLASS_NAME,
            w!("VPN Tunnel Enforcer session end"),
            WS_POPUP,
            0,
            0,
            0,
            0,
            None,
            None,
            Some(instance.into()),
            None,
        )
        .map_err(AppError::internal)
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        // wParam FALSE: another program refused the logoff and the session goes on.
        WM_ENDSESSION if wparam.0 != 0 => {
            // A panic must not cross into Windows (that aborts with a crash report at logoff).
            let ran = catch_unwind(AssertUnwindSafe(|| {
                ON_END.with_borrow(|on_end| on_end.as_ref().map(|f| f()))
            }));
            if ran.is_err() {
                tracing::error!("session-end rollback panicked");
            }
            return LRESULT(0);
        }
        // `taskkill` without /f closes every top-level window of the process: the guard stays
        // for as long as the app runs.
        WM_CLOSE => return LRESULT(0),
        _ => {}
    }
    // SAFETY: default handling for our own window (WM_QUERYENDSESSION answers TRUE: the
    // session may end).
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}
