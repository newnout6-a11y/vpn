//! Toasts: one app-wide queue ([`Toasts`], in context) rendered once by [`ToastHost`] in the
//! shell: square paper cards with a state bar (ui-dashboard §2.9), newest at the bottom, at most
//! [`TOAST_LIMIT`], each gone after [`TOAST_TTL`] in view or on its close button.
use std::time::Duration;

use dioxus::prelude::*;
use tokio::time::Instant;
use vpnte_base::types::Level;
use vpnte_base::{AppError, ErrorKind, Msg};

use super::buttons::{Icon, IconGlyph};
use crate::lang::tr_now;

/// How long a toast stays (old global toasts: 4000 ms).
pub const TOAST_TTL: Duration = Duration::from_millis(4000);
/// How many toasts are kept; the oldest go first.
pub const TOAST_LIMIT: usize = 20;

/// Variant of a toast: the colour of its state bar (signal for error / warning, ink for
/// success, grey for info).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Success,
    Error,
    Warning,
    Info,
}

impl ToastKind {
    /// Class suffix (`is-error`) and stable name for tests.
    pub fn name(self) -> &'static str {
        match self {
            ToastKind::Success => "success",
            ToastKind::Error => "error",
            ToastKind::Warning => "warning",
            ToastKind::Info => "info",
        }
    }
}

impl From<Level> for ToastKind {
    fn from(level: Level) -> Self {
        match level {
            Level::Info => ToastKind::Info,
            Level::Success => ToastKind::Success,
            Level::Warn => ToastKind::Warning,
            Level::Error => ToastKind::Error,
        }
    }
}

/// One toast; the texts are already rendered by the caller.
#[derive(Debug, Clone, PartialEq)]
pub struct Toast {
    pub id: u64,
    pub kind: ToastKind,
    pub title: String,
    pub description: Option<String>,
    pub expires_at: Instant,
}

/// Handle of the app-wide toast queue (`Copy`; get it with [`Toasts::use_context`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Toasts {
    list: Signal<Vec<Toast>>,
    /// The window is in view ([`Toasts::set_seen`]). Out of view nothing expires: a notice
    /// that came while the window sat in the tray waits for the user (review exitgate-b3).
    seen: Signal<bool>,
}

impl Toasts {
    /// Creates the queue in the calling (root) component, provides it as context and expires
    /// toasts on time. Call once, unconditionally, at the top of the root component.
    pub fn use_provider() -> Self {
        let toasts = use_context_provider(|| Toasts {
            list: Signal::new(Vec::new()),
            seen: Signal::new(true),
        });
        let (mut list, seen) = (toasts.list, toasts.seen);
        // Re-armed whenever the list or the window's view changes; sleeps until the earliest
        // expiry, and not at all while the window is out of view.
        let _expiry = use_resource(move || {
            let next = due(&list.read(), *seen.read());
            async move {
                if let Some(at) = next {
                    tokio::time::sleep_until(at).await;
                    let now = Instant::now();
                    list.write().retain(|t| t.expires_at > now);
                }
            }
        });
        toasts
    }

    /// The queue provided by an ancestor.
    pub fn use_context() -> Self {
        dioxus::prelude::use_context()
    }

    /// Shows a toast; returns its id.
    pub fn push(
        &self,
        kind: ToastKind,
        title: impl Into<String>,
        description: Option<String>,
    ) -> u64 {
        let mut list = self.list;
        let id = super::next_serial();
        let toast = Toast {
            id,
            kind,
            title: title.into(),
            description,
            expires_at: Instant::now() + TOAST_TTL,
        };
        push_limited(&mut list.write(), toast);
        id
    }

    pub fn success(&self, title: impl Into<String>, description: Option<String>) -> u64 {
        self.push(ToastKind::Success, title, description)
    }
    pub fn error(&self, title: impl Into<String>, description: Option<String>) -> u64 {
        self.push(ToastKind::Error, title, description)
    }
    pub fn warning(&self, title: impl Into<String>, description: Option<String>) -> u64 {
        self.push(ToastKind::Warning, title, description)
    }
    pub fn info(&self, title: impl Into<String>, description: Option<String>) -> u64 {
        self.push(ToastKind::Info, title, description)
    }

    /// The toast of a failed action, the same on every page: nothing for a cancelled one (the
    /// user asked for it), otherwise a warning in the log and an error toast titled `title` with
    /// the error's own sentence.
    pub fn failed(&self, title: &Msg, err: &AppError) {
        if err.kind == ErrorKind::Cancelled {
            return;
        }
        tracing::warn!(target: "ui", error = %err, action = %title.key, "action failed");
        self.error(tr_now(title), Some(tr_now(&err.user_msg())));
    }

    /// The window came into view or left it (the shell tells). Back in view, every toast gets
    /// its full [`TOAST_TTL`] from now: the user has not seen it yet.
    pub fn set_seen(&self, in_view: bool) {
        let mut seen = self.seen;
        if *seen.peek() == in_view {
            return;
        }
        if in_view {
            let mut list = self.list;
            renew(&mut list.write(), Instant::now());
        }
        seen.set(in_view);
    }

    /// Removes a toast (its close button).
    pub fn dismiss(&self, id: u64) {
        let mut list = self.list;
        list.write().retain(|t| t.id != id);
    }

    /// The toasts on screen, oldest first (subscribes the caller; the dashboard's mascot reads
    /// new error / warning / success ids from here).
    pub fn list(&self) -> Vec<Toast> {
        self.list.read().clone()
    }
}

/// Appends `toast`, dropping the oldest beyond [`TOAST_LIMIT`].
fn push_limited(list: &mut Vec<Toast>, toast: Toast) {
    list.push(toast);
    let excess = list.len().saturating_sub(TOAST_LIMIT);
    list.drain(..excess);
}

fn next_expiry(list: &[Toast]) -> Option<Instant> {
    list.iter().map(|t| t.expires_at).min()
}

/// When the next toast goes: never while the window is out of view.
fn due(list: &[Toast], seen: bool) -> Option<Instant> {
    seen.then(|| next_expiry(list)).flatten()
}

/// Every toast stays at least a full [`TOAST_TTL`] from `now`.
fn renew(list: &mut [Toast], now: Instant) {
    let fresh = now + TOAST_TTL;
    for toast in list {
        toast.expires_at = toast.expires_at.max(fresh);
    }
}

/// The toast stack (top right, below the 36 px title strip). Rendered once, by the shell.
/// `close_label` names the close buttons (`common.close`).
#[component]
pub fn ToastHost(close_label: String) -> Element {
    let toasts = Toasts::use_context();
    rsx! {
        div { class: "c-swiss w-toasts", role: "status", aria_live: "polite",
            for toast in toasts.list() {
                div {
                    key: "{toast.id}",
                    class: "swiss-toast w-toast is-{toast.kind.name()}",
                    role: if toast.kind == ToastKind::Error { "alert" },
                    "data-kind": toast.kind.name(),
                    div { class: "w-toast-text",
                        p { class: "swiss-toast-title", "{toast.title}" }
                        if let Some(description) = toast.description {
                            p { class: "swiss-toast-desc", "{description}" }
                        }
                    }
                    button {
                        r#type: "button",
                        class: "swiss-toast-close",
                        aria_label: "{close_label}",
                        title: "{close_label}",
                        onclick: move |_| toasts.dismiss(toast.id),
                        Icon { glyph: IconGlyph::Close, size: 14 }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toast(id: u64, after_ms: u64) -> Toast {
        Toast {
            id,
            kind: ToastKind::Info,
            title: format!("t{id}"),
            description: None,
            expires_at: Instant::now() + Duration::from_millis(after_ms),
        }
    }

    /// Review exitgate-b3: out of view nothing is due; back in view a toast whose time ran out
    /// while hidden, and one with time left, both get a full TTL from then.
    #[test]
    fn toasts_wait_while_the_window_is_out_of_view() {
        let mut list = vec![toast(1, 0), toast(2, 6000)];
        assert_eq!(due(&list, false), None);
        assert_eq!(due(&list, true), Some(list[0].expires_at));
        let later = Instant::now() + Duration::from_secs(60);
        let kept = list[1].expires_at;
        renew(&mut list, later);
        assert_eq!(list[0].expires_at, later + TOAST_TTL);
        assert_eq!(list[1].expires_at, kept.max(later + TOAST_TTL));
    }

    /// At most 20 kept, the oldest dropped first (R/store.ts:461-481).
    #[test]
    fn queue_keeps_the_newest_twenty() {
        let mut list = Vec::new();
        for id in 0..25 {
            push_limited(&mut list, toast(id, 4000));
        }
        assert_eq!(list.len(), TOAST_LIMIT);
        assert_eq!(list.first().map(|t| t.id), Some(5));
        assert_eq!(list.last().map(|t| t.id), Some(24));
    }

    #[test]
    fn earliest_expiry_arms_the_timer() {
        assert_eq!(next_expiry(&[]), None);
        let list = vec![toast(1, 3000), toast(2, 1000), toast(3, 2000)];
        assert_eq!(next_expiry(&list), Some(list[1].expires_at));
    }

    #[test]
    fn levels_map_to_variants() {
        assert_eq!(ToastKind::from(Level::Warn), ToastKind::Warning);
        assert_eq!(ToastKind::from(Level::Error).name(), "error");
    }
}
