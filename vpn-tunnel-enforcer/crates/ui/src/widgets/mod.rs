//! Shared controls of every page except the start page, in the «Пломба» visual language: paper /
//! ink / rule / signal tokens, square corners, mono captions, hairline rules (styles:
//! `assets/css/widgets.css`, behaviour that must run inside the page: `assets/js/widgets.js`).
//!
//! Every text arrives through props, so the widgets never depend on the catalog; pages pass
//! `t!(…)` results. Plus the two async helpers every page uses: [`JobSlot`] (one run at a time,
//! cancelled with its owner) and [`Load`] (loading / ready / failed with retry).
use std::sync::atomic::{AtomicU64, Ordering};

mod buttons;
mod choice;
mod dialog;
mod feedback;
mod fields;
mod job;
mod layout;
mod load;
mod select;
mod table;
mod toast;

pub use buttons::{Button, ButtonKind, Icon, IconButton, IconGlyph};
pub use choice::{Checkbox, Segmented, Switch, Tabs, roving_index};
pub use dialog::{ConfirmDialog, Modal, ModalSize};
pub use feedback::{Badge, ProgressBar, Spinner, Tone};
pub use fields::{
    Field, FieldCtx, NumberCommit, NumberInput, TextArea, TextInput, TextKind, commit_number,
};
pub use job::{JobSlot, UiError, use_job};
pub use layout::{EmptyState, Panel, Row, SectionHeader, Trunc};
pub use load::{Load, LoadError, Loader, Loading, use_load};
pub use select::{
    Indicator, Select, SelectAction, SelectKey, SelectOption, SelectState, Size, initial_active,
    select_key,
};
pub use table::{Align, Cell, HeadCell, Sort, Table};
pub use toast::{TOAST_LIMIT, TOAST_TTL, Toast, ToastHost, ToastKind, Toasts};

/// A number unique in this process (DOM ids of widget instances).
pub(crate) fn next_serial() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// A DOM id unique in this process (`w-sel-7`): two open dialogs or two selects never share ids.
pub fn next_id(prefix: &str) -> String {
    format!("{prefix}-{}", next_serial())
}

/// A stable [`next_id`] for the calling component instance.
pub fn use_dom_id(prefix: &'static str) -> String {
    dioxus::prelude::use_hook(move || next_id(prefix))
}

/// `title` text of a control that may be disabled: the label, plus WHY it is disabled (there is no
/// tooltip component; the native `title` is the hover help everywhere).
pub fn title_with_reason(label: &str, disabled_reason: Option<&str>) -> String {
    match disabled_reason.map(str::trim).filter(|r| !r.is_empty()) {
        Some(reason) if label.is_empty() => reason.to_owned(),
        Some(reason) => format!("{label} — {reason}"),
        None => label.to_owned(),
    }
}

/// `title` for text that may be cut with an ellipsis: the full text when it is longer than `max`
/// characters, otherwise nothing (a title equal to the visible text is noise for screen readers).
pub fn title_if_long(text: &str, max: usize) -> Option<String> {
    (text.chars().count() > max).then(|| text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_prefixed() {
        let a = next_id("w-x");
        let b = next_id("w-x");
        assert_ne!(a, b);
        assert!(a.starts_with("w-x-"));
    }

    #[test]
    fn titles_explain_disabled_controls() {
        assert_eq!(title_with_reason("Удалить", None), "Удалить");
        assert_eq!(
            title_with_reason("Удалить", Some("Сначала отключитесь")),
            "Удалить — Сначала отключитесь"
        );
        assert_eq!(title_with_reason("", Some(" Нет данных ")), "Нет данных");
        assert_eq!(title_with_reason("Copy", Some("  ")), "Copy");
        assert_eq!(title_if_long("short", 10), None);
        assert_eq!(
            title_if_long("ДлинноеИмя", 4).as_deref(),
            Some("ДлинноеИмя")
        );
    }
}
