//! Helpers for the component tests that drive a `VirtualDom` without a webview.

use std::time::Duration;

use dioxus::core::NoOpMutations;
use dioxus::prelude::*;

/// Runs `rounds` rounds of "wait for work (at most `step_ms`), then render": enough for spawned
/// tasks and the state they publish to reach the DOM.
pub(crate) async fn settle(dom: &mut VirtualDom, rounds: usize, step_ms: u64) {
    for _ in 0..rounds {
        tokio::select! {
            () = dom.wait_for_work() => {}
            () = tokio::time::sleep(Duration::from_millis(step_ms)) => {}
        }
        dom.render_immediate(&mut NoOpMutations);
    }
}
