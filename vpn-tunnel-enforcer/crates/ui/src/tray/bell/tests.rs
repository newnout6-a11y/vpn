//! The bell against a real (message-only, never shown) window of the test thread: asks rung on
//! another thread are answered on the window's thread inside `DispatchMessage`, with no dioxus at
//! all; the newest ask wins; an ask rung before the window answers waits for it; a destroyed
//! window lets go.
use std::cell::RefCell;

use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, DispatchMessageW, HWND_MESSAGE, MSG, PM_REMOVE, PeekMessageW,
    WINDOW_EX_STYLE, WINDOW_STYLE,
};

use super::*;

/// A message-only window of the calling thread.
fn window() -> HWND {
    // SAFETY: a system class, no creation data; the window is destroyed by the test.
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("STATIC"),
            w!(""),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            None,
            None,
        )
    }
    .expect("message-only window")
}

/// Dispatches what waits for `hwnd`, as the UI thread's message loop does.
fn pump(hwnd: HWND) {
    let mut msg = MSG::default();
    // SAFETY: `msg` outlives each call; the window belongs to this thread.
    while unsafe { PeekMessageW(&mut msg, Some(hwnd), 0, 0, PM_REMOVE) }.as_bool() {
        // SAFETY: a message just taken from this thread's queue.
        unsafe { DispatchMessageW(&msg) };
    }
}

/// The asks a window answered.
fn answering(hwnd: HWND, bell: &WindowBell) -> Rc<RefCell<Vec<Ask>>> {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let log = seen.clone();
    assert!(answer_on(
        hwnd,
        bell,
        Rc::new(move |ask| log.borrow_mut().push(ask))
    ));
    seen
}

/// p-exit-gate: a later launch's `activate` arrives on the pipe's thread and shows the window
/// through the window's own message queue; two asks before the window got to them are one (the
/// newest).
#[test]
fn asks_from_another_thread_are_answered_on_the_window_thread() {
    let hwnd = window();
    let bell = WindowBell::default();
    let seen = answering(hwnd, &bell);
    let from = bell.clone();
    std::thread::spawn(move || {
        from.hide();
        from.show();
    })
    .join()
    .unwrap();
    pump(hwnd);
    assert_eq!(*seen.borrow(), [Ask::Show]);
    bell.hide();
    pump(hwnd);
    assert_eq!(*seen.borrow(), [Ask::Show, Ask::Hide]);
    // SAFETY: the test's own window.
    unsafe { DestroyWindow(hwnd) }.unwrap();
}

/// An ask rung while no window answers (a start, a rebuilt window not mounted yet) is delivered
/// once one does; a destroyed window stops answering and leaves nothing behind.
#[test]
fn an_early_ask_waits_and_a_destroyed_window_lets_go() {
    let bell = WindowBell::default();
    bell.show();
    let hwnd = window();
    let seen = answering(hwnd, &bell);
    pump(hwnd);
    assert_eq!(*seen.borrow(), [Ask::Show]);
    // SAFETY: the test's own window.
    unsafe { DestroyWindow(hwnd) }.unwrap();
    assert!(ANSWERS.with(|answers| answers.borrow().is_empty()));
    assert_eq!(bell.0.hwnd.load(Ordering::Acquire), 0);
    bell.hide();
    assert_eq!(bell.take(), Some(Ask::Hide), "kept for the next window");
    assert_eq!(bell.take(), None);
}
