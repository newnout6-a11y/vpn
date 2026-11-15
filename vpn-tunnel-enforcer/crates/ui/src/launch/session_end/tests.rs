use dioxus::desktop::tao::event::Event;
use dioxus::desktop::tao::event_loop::{ControlFlow, EventLoopBuilder};
use dioxus::desktop::tao::platform::run_return::EventLoopExtRunReturn;
use dioxus::desktop::tao::platform::windows::EventLoopBuilderExtWindows;
use windows::Win32::UI::WindowsAndMessaging::SendMessageW;

use super::*;

/// A tao event loop on this thread (held from the session end when `held`) gets `WM_ENDSESSION`
/// as Windows sends it (from another thread, while the loop waits for messages), then an event
/// like the one dioxus sends on every virtual-dom poll; the event it handled.
fn session_end_then_event(held: bool) -> Option<u8> {
    let mut builder = EventLoopBuilder::<u8>::with_user_event();
    let mut event_loop = builder.with_any_thread(true).build();
    if held {
        assert_eq!(hold(), 1, "tao's thread-target window");
        assert_eq!(hold(), 1, "again: the same subclass");
    }
    let window = targets()[0].0 as isize;
    let proxy = event_loop.create_proxy();
    let windows_ends = std::thread::spawn(move || {
        let window = HWND(window as *mut std::ffi::c_void);
        // SAFETY: a live window of the test thread, which pumps messages in `run_return`.
        unsafe { SendMessageW(window, WM_ENDSESSION, Some(WPARAM(1)), Some(LPARAM(0))) };
        proxy.send_event(7).is_ok()
    });
    let mut got = None;
    event_loop.run_return(|event, _, flow| {
        *flow = ControlFlow::Wait;
        if let Event::UserEvent(n) = event {
            got = Some(n);
            *flow = ControlFlow::Exit;
        }
    });
    assert!(windows_ends.join().expect("sender"), "event sent");
    got
}

/// Lab L9-3: Windows ends the session while the window runs: `WM_ENDSESSION` no longer reaches
/// tao, so the next event is handled as usual.
#[test]
fn an_event_after_the_session_end_is_handled() {
    assert_eq!(session_end_then_event(true), Some(7));
}

/// What the lab saw, without the hold: tao's runner panics at the next event. Should a tao
/// update stop that, this test says so and the hold can go.
#[test]
#[should_panic(expected = "cannot move state from Destroyed")]
fn without_the_hold_tao_panics() {
    session_end_then_event(false);
}
