//! [`Load`]: what a list or a page section shows — loading, the data, or why it could not be
//! read, with a retry. A failed read is never shown as "empty" (ui-pages U-06).
use std::future::Future;

use dioxus::prelude::*;
use vpnte_base::AppResult;

use super::buttons::{Button, ButtonKind};
use super::feedback::Spinner;
use super::job::UiError;

/// State of a read.
#[derive(Debug, Clone, PartialEq)]
pub enum Load<T> {
    Loading,
    Ready(T),
    Failed(UiError),
}

impl<T> Load<T> {
    /// `Ready` for `Ok`, `Failed` for any error (a cancelled read is shown with its retry too:
    /// the user did not ask for it to stop).
    pub fn from_result(result: AppResult<T>) -> Self {
        match result {
            Ok(value) => Load::Ready(value),
            Err(err) => Load::Failed(UiError::from(&err)),
        }
    }

    /// The data, when ready.
    pub fn ready(&self) -> Option<&T> {
        match self {
            Load::Ready(value) => Some(value),
            _ => None,
        }
    }

    /// The error, when failed.
    pub fn error(&self) -> Option<&UiError> {
        match self {
            Load::Failed(err) => Some(err),
            _ => None,
        }
    }

    pub fn is_loading(&self) -> bool {
        matches!(self, Load::Loading)
    }

    /// Maps the data, keeping the state.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Load<U> {
        match self {
            Load::Loading => Load::Loading,
            Load::Ready(value) => Load::Ready(f(value)),
            Load::Failed(err) => Load::Failed(err),
        }
    }
}

/// A [`Load`] fed by a fetch closure; built on `use_resource`, so it re-runs when a signal read
/// by the closure changes, and keeps the previous outcome while it does ([`Loader::refreshing`]).
pub struct Loader<T: 'static> {
    resource: Resource<Load<T>>,
}

impl<T> Clone for Loader<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Loader<T> {}

impl<T> PartialEq for Loader<T> {
    fn eq(&self, other: &Self) -> bool {
        self.resource == other.resource
    }
}

/// Starts reading with `fetch` (in `Loading` until the first outcome). The read belongs to the
/// calling component: unmounting drops it.
pub fn use_load<T, F>(mut fetch: impl FnMut() -> F + 'static) -> Loader<T>
where
    T: 'static,
    F: Future<Output = AppResult<T>> + 'static,
{
    let resource = use_resource(move || {
        let read = fetch();
        async move { Load::from_result(read.await) }
    });
    Loader { resource }
}

impl<T: Clone + 'static> Loader<T> {
    /// The current state (subscribes the caller).
    pub fn state(&self) -> Load<T> {
        self.resource
            .read()
            .as_ref()
            .cloned()
            .unwrap_or(Load::Loading)
    }

    /// Reads again (the «Повторить» button, or after the data was changed).
    pub fn reload(&self) {
        let mut resource = self.resource;
        resource.restart();
    }

    /// A newer read is running while an older outcome is still shown.
    pub fn refreshing(&self) -> bool {
        self.resource.pending() && self.resource.read().is_some()
    }
}

/// The "still loading" line of a section.
#[component]
pub fn Loading(label: String) -> Element {
    rsx! {
        div { class: "w-load", role: "status",
            Spinner {}
            span { class: "w-load-text", "{label}" }
        }
    }
}

/// The "could not read" block: the message (rendered by the page) and a retry button.
#[component]
pub fn LoadError(text: String, retry_label: String, on_retry: EventHandler<()>) -> Element {
    rsx! {
        div { class: "w-load is-failed", role: "alert",
            span { class: "w-load-mark", aria_hidden: "true" }
            span { class: "w-load-text", "{text}" }
            Button {
                kind: ButtonKind::Ghost,
                small: true,
                onclick: move |_| on_retry.call(()),
                "{retry_label}"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use vpnte_base::{AppError, ErrorKind, Msg};

    use super::*;

    /// AT-00-008 (U-06): a failed read keeps its message, never turns into "empty".
    #[test]
    fn results_map_to_states() {
        assert_eq!(Load::from_result(Ok(3)), Load::Ready(3));
        let failed: Load<i32> =
            Load::from_result(Err(AppError::validation(Msg::new("servers.invalidKey"))));
        let err = failed.error().cloned();
        assert_eq!(err.as_ref().map(|e| e.kind), Some(ErrorKind::Validation));
        assert_eq!(err.map(|e| e.msg.key), Some("servers.invalidKey".into()));
        assert_eq!(failed.ready(), None);
        let cancelled: Load<i32> = Load::from_result(Err(AppError::cancelled()));
        assert_eq!(
            cancelled.error().map(|e| e.msg.key.clone()),
            Some("errors.cancelled".into())
        );
        assert!(Load::<i32>::Loading.is_loading());
        assert_eq!(Load::Ready(2).map(|v| v * 10), Load::Ready(20));
    }
}
