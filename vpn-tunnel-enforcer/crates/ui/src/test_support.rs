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

/// What a `VirtualDom` was asked to show: every text it created or set, and every dynamic
/// attribute with a text value (`data-*` markers), in order. Render tests read pages through it.
#[derive(Default)]
pub(crate) struct Shown {
    pub texts: Vec<String>,
    pub attrs: Vec<(&'static str, String)>,
}

impl Shown {
    /// A text node with exactly `text`.
    pub(crate) fn shows(&self, text: &str) -> bool {
        self.texts.iter().any(|t| t == text)
    }

    /// An attribute `name` with exactly `value`.
    pub(crate) fn has(&self, name: &str, value: &str) -> bool {
        self.attrs.iter().any(|(n, v)| *n == name && v == value)
    }
}

impl dioxus::core::WriteMutations for Shown {
    fn append_children(&mut self, _: dioxus::core::ElementId, _: usize) {}
    fn assign_node_id(&mut self, _: &'static [u8], _: dioxus::core::ElementId) {}
    fn create_placeholder(&mut self, _: dioxus::core::ElementId) {}
    fn create_text_node(&mut self, value: &str, _: dioxus::core::ElementId) {
        self.texts.push(value.to_owned());
    }
    fn load_template(&mut self, _: dioxus::core::Template, _: usize, _: dioxus::core::ElementId) {}
    fn replace_node_with(&mut self, _: dioxus::core::ElementId, _: usize) {}
    fn replace_placeholder_with_nodes(&mut self, _: &'static [u8], _: usize) {}
    fn insert_nodes_after(&mut self, _: dioxus::core::ElementId, _: usize) {}
    fn insert_nodes_before(&mut self, _: dioxus::core::ElementId, _: usize) {}
    fn set_attribute(
        &mut self,
        name: &'static str,
        _: Option<&'static str>,
        value: &dioxus::core::AttributeValue,
        _: dioxus::core::ElementId,
    ) {
        if let dioxus::core::AttributeValue::Text(text) = value {
            self.attrs.push((name, text.clone()));
        }
    }
    fn set_node_text(&mut self, value: &str, _: dioxus::core::ElementId) {
        self.texts.push(value.to_owned());
    }
    fn create_event_listener(&mut self, _: &'static str, _: dioxus::core::ElementId) {}
    fn remove_event_listener(&mut self, _: &'static str, _: dioxus::core::ElementId) {}
    fn remove_node(&mut self, _: dioxus::core::ElementId) {}
    fn push_root(&mut self, _: dioxus::core::ElementId) {}
}

/// Builds the whole tree and lets its tasks (signal pumps, pushed state) run a few rounds,
/// recording everything shown.
pub(crate) async fn shown(dom: &mut VirtualDom) -> Shown {
    let mut seen = Shown::default();
    dom.rebuild(&mut seen);
    for _ in 0..6 {
        tokio::select! {
            () = dom.wait_for_work() => {}
            () = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
        dom.render_immediate(&mut seen);
    }
    seen
}
