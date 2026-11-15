//! [`WindowBell`]: shows or hides the main window from any thread without the VirtualDom
//! (p-exit-gate). A later launch's `activate` or link, a click on a Windows toast and the
//! installer's shutdown arrive on other threads; carried through the VirtualDom they waited for it
//! (a hidden window's first render held every task, a dead page holds them for good). The bell
//! posts a registered message to the main window instead; the window's subclass answers it on the
//! UI thread inside `DispatchMessage`, whatever the VirtualDom and the page do. A plain posted
//! message would not do: tao turns only the messages it knows into events, so nothing of dioxus
//! would see it.
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicIsize, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};

use dioxus::desktop::tao::platform::windows::WindowExtWindows;
use dioxus::desktop::{DesktopContext, use_window};
use dioxus::prelude::*;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
use windows::Win32::UI::WindowsAndMessaging::{PostMessageW, RegisterWindowMessageW, WM_NCDESTROY};
use windows::core::w;

/// What the window is asked to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ask {
    /// Show, restore and focus it (also after a start in the tray).
    Show,
    /// Hide it to the tray.
    Hide,
}

impl Ask {
    fn code(self) -> u8 {
        match self {
            Ask::Show => 1,
            Ask::Hide => 2,
        }
    }

    fn from_code(code: u8) -> Option<Ask> {
        match code {
            1 => Some(Ask::Show),
            2 => Some(Ask::Hide),
            _ => None,
        }
    }
}

/// A handle to the main window that any thread may ring. Provide it as a root context: the tray
/// host answers it. An ask rung before the window answers waits for it; a newer ask replaces one
/// not carried out yet.
#[derive(Clone, Default)]
pub struct WindowBell(Arc<Shared>);

#[derive(Default)]
struct Shared {
    /// The ask not carried out yet ([`Ask::code`]; 0: none).
    ask: AtomicU8,
    /// The answering window's handle; 0 until one answers.
    hwnd: AtomicIsize,
}

impl WindowBell {
    /// Asks the window to show.
    pub fn show(&self) {
        self.ring(Ask::Show);
    }

    /// Asks the window to hide to the tray.
    pub fn hide(&self) {
        self.ring(Ask::Hide);
    }

    // SeqCst on both sides of `ask` and `hwnd`: a ring racing an attach must not leave both
    // seeing the other's old value (the ask would wait for the next ring).
    fn ring(&self, ask: Ask) {
        self.0.ask.store(ask.code(), Ordering::SeqCst);
        self.wake();
    }

    /// Posts the bell's message to the answering window, if there is one.
    fn wake(&self) {
        let hwnd = self.0.hwnd.load(Ordering::SeqCst);
        let message = message();
        if hwnd == 0 || message == 0 {
            return;
        }
        // SAFETY: plain call; a window that went away meanwhile only makes it fail.
        if let Err(err) =
            unsafe { PostMessageW(Some(HWND(hwnd as _)), message, WPARAM(0), LPARAM(0)) }
        {
            tracing::warn!(%err, "window bell not delivered");
        }
    }

    /// The ask waiting, taken.
    fn take(&self) -> Option<Ask> {
        Ask::from_code(self.0.ask.swap(0, Ordering::AcqRel))
    }

    /// `hwnd` answers from now on; an ask that waited for it is delivered.
    fn attach(&self, hwnd: isize) {
        self.0.hwnd.store(hwnd, Ordering::SeqCst);
        if self.0.ask.load(Ordering::SeqCst) != 0 {
            self.wake();
        }
    }

    /// `hwnd` goes away: the bell has no window until the next one answers.
    fn detach(&self, hwnd: isize) {
        let _ = self
            .0
            .hwnd
            .compare_exchange(hwnd, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
}

/// The bell's message, registered once per process (0 if Windows refused: the bell is silent).
fn message() -> u32 {
    static MESSAGE: OnceLock<u32> = OnceLock::new();
    // SAFETY: plain call with a NUL-terminated literal.
    *MESSAGE.get_or_init(|| unsafe { RegisterWindowMessageW(w!("VpnTunnelEnforcer.WindowBell")) })
}

/// This module's subclass on the answering windows.
const SUBCLASS_ID: usize = 0x5650_4e42;

/// What to do with an ask, per answering window of this thread.
type Answer = Rc<dyn Fn(Ask)>;

thread_local! {
    /// The answering windows of this (UI) thread; a subclass procedure has no other context.
    static ANSWERS: RefCell<Vec<(isize, WindowBell, Answer)>> = const { RefCell::new(Vec::new()) };
}

/// The calling component's window answers the root's [`WindowBell`] with `on` (nothing without
/// one: the demos). Call it once per window.
pub(super) fn use_answer(on: fn(&DesktopContext, Ask)) {
    let bell = try_use_context::<WindowBell>();
    let desktop = use_window();
    use_hook(move || {
        let Some(bell) = bell else {
            return;
        };
        let hwnd = HWND(desktop.window.hwnd() as _);
        // Weak: the answer lives outside the VirtualDom, and a strong handle would keep a closed
        // window (one replaced after a WebView2 crash) and its WebView2 alive for good.
        let window = Rc::downgrade(&desktop);
        let answer: Answer = Rc::new(move |ask| {
            if let Some(desktop) = window.upgrade() {
                on(&desktop, ask);
            }
        });
        if !answer_on(hwnd, &bell, answer) {
            tracing::warn!("window bell not attached: a later launch shows the window late");
        }
    });
}

/// Forgets the answers of window `key` and lets its bells go.
fn release(key: isize) {
    let gone = ANSWERS.with(|answers| {
        let mut answers = answers.borrow_mut();
        let gone: Vec<WindowBell> = answers
            .iter()
            .filter(|(k, ..)| *k == key)
            .map(|(_, bell, _)| bell.clone())
            .collect();
        answers.retain(|(k, ..)| *k != key);
        gone
    });
    for bell in gone {
        bell.detach(key);
    }
}

/// Subclasses `hwnd` (a window of the calling thread) to answer `bell` with `on`.
fn answer_on(hwnd: HWND, bell: &WindowBell, on: Answer) -> bool {
    let key = hwnd.0 as isize;
    ANSWERS.with(|answers| answers.borrow_mut().push((key, bell.clone(), on)));
    // SAFETY: a window of this thread; the procedure is a plain function without reference data.
    if !unsafe { SetWindowSubclass(hwnd, Some(on_message), SUBCLASS_ID, 0) }.as_bool() {
        ANSWERS.with(|answers| answers.borrow_mut().retain(|(k, ..)| *k != key));
        return false;
    }
    bell.attach(key);
    true
}

unsafe extern "system" fn on_message(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    let key = hwnd.0 as isize;
    let message = message();
    if message != 0 && msg == message {
        let entry = ANSWERS.with(|answers| {
            let answers = answers.borrow();
            let (_, bell, on) = answers.iter().find(|(k, ..)| *k == key)?;
            Some((bell.clone(), on.clone()))
        });
        // Outside the borrow: showing the window dispatches messages to it right away.
        if let Some((bell, on)) = entry
            && let Some(ask) = bell.take()
        {
            on(ask);
        }
        return LRESULT(0);
    }
    if msg == WM_NCDESTROY {
        release(key);
        // SAFETY: removes this module's own subclass from the window being destroyed.
        let _ = unsafe { RemoveWindowSubclass(hwnd, Some(on_message), SUBCLASS_ID) };
    }
    // SAFETY: the next procedure of this window's subclass chain, with its own arguments.
    unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) }
}

#[cfg(test)]
mod tests;
