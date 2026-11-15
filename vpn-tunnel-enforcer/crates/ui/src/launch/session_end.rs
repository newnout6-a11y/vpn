//! Windows ending the session while the window runs (lab L9-3). tao (0.34) answers
//! `WM_ENDSESSION` on its hidden thread-target window by moving its event-loop runner to
//! `Destroyed`, yet the process runs on until Windows ends it; the next event dioxus sends (any
//! virtual-dom poll) then panics with «cannot move state from Destroyed». The frame subclasses
//! that window and keeps the message from tao: the event loop stays as it was until Windows ends
//! the process, which it does once every top-level window has answered. Nothing else needs the
//! message here: the rollback of the soft values has a window of its own (the app's `restore`),
//! and the helper service ends its session itself.
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Shell::{DefSubclassProc, SetWindowSubclass};
use windows::Win32::UI::WindowsAndMessaging::{EnumThreadWindows, GetClassNameW, WM_ENDSESSION};
use windows::core::BOOL;

/// The class tao registers for its thread-target window.
const TAO_TARGET: &str = "Tao Thread Event Target";
/// This module's subclass on that window (one per window: a second `hold` replaces it).
const SUBCLASS_ID: usize = 0x5650_4e54;

/// Keeps `WM_ENDSESSION` from tao's thread-target windows of the calling thread (call it on the
/// event loop's thread); returns how many it holds. Calling it again is harmless.
pub fn hold() -> usize {
    let mut held = 0;
    for window in targets() {
        // SAFETY: a window of this thread; the subclass procedure is a plain function and gets no
        // reference data.
        if unsafe { SetWindowSubclass(window, Some(keep_from_tao), SUBCLASS_ID, 0) }.as_bool() {
            held += 1;
        }
    }
    if held == 0 {
        // A tao update renamed its window class: a restart may log a panic again (lab L9-3).
        tracing::warn!("no event-loop window found: a Windows restart is not held from tao");
    }
    held
}

/// tao's thread-target windows of this thread.
fn targets() -> Vec<HWND> {
    let mut found: Vec<HWND> = Vec::new();
    let into = LPARAM(std::ptr::from_mut(&mut found) as isize);
    // SAFETY: `collect` gets a pointer to `found`, which outlives the call; it returns FALSE
    // only to stop early, which it never does, so the result says nothing worth checking.
    let _ = unsafe { EnumThreadWindows(GetCurrentThreadId(), Some(collect), into) };
    found
}

unsafe extern "system" fn collect(window: HWND, found: LPARAM) -> BOOL {
    let mut class = [0u16; 64];
    // SAFETY: `class` is a writable buffer of its own length.
    let len = unsafe { GetClassNameW(window, &mut class) };
    let len = usize::try_from(len).unwrap_or(0).min(class.len());
    if String::from_utf16_lossy(&class[..len]) == TAO_TARGET {
        // SAFETY: `targets` passes a pointer to its live `Vec<HWND>`.
        unsafe { &mut *(found.0 as *mut Vec<HWND>) }.push(window);
    }
    BOOL(1)
}

unsafe extern "system" fn keep_from_tao(
    window: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    // wParam FALSE: another program refused, the session goes on (tao does nothing then either).
    if msg == WM_ENDSESSION && wparam.0 != 0 {
        tracing::info!("Windows ends the session");
        return LRESULT(0);
    }
    // SAFETY: the next procedure of this window's subclass chain, with its own arguments.
    unsafe { DefSubclassProc(window, msg, wparam, lparam) }
}

#[cfg(test)]
mod tests;
