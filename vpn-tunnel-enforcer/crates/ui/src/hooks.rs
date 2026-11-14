//! Hooks shared by the pages: pushed backend state (`watch::Receiver`) as a Dioxus signal.
use dioxus::prelude::*;
use tokio::sync::watch;

/// Turns the receiver `subscribe` returns (called once, on the first render) into a signal that
/// follows every published value; equal values do not re-render. One pump task per call, owned by
/// the calling component.
pub fn use_watch<T: Clone + PartialEq + 'static>(
    subscribe: impl FnOnce() -> watch::Receiver<T>,
) -> Signal<T> {
    let rx = use_hook(subscribe);
    let mut value = use_signal(|| rx.borrow().clone());
    use_future(move || {
        let mut rx = rx.clone();
        async move {
            loop {
                // A value published between the first render and this task's first poll is
                // picked up here before waiting.
                let next = rx.borrow_and_update().clone();
                if *value.peek() != next {
                    value.set(next);
                }
                if rx.changed().await.is_err() {
                    break;
                }
            }
        }
    });
    value
}
