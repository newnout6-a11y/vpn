//! Table primitives: [`Table`], [`HeadCell`] (sortable through a real button: the old
//! `<th onClick>` was mouse-only, ui-pages U-15) and [`Cell`]. Pages write `thead` / `tbody` /
//! `tr` themselves.
use dioxus::prelude::*;

use super::buttons::{Icon, IconGlyph};

/// Horizontal alignment of a cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Align {
    #[default]
    Start,
    Center,
    /// Numbers.
    End,
}

impl Align {
    fn class(self) -> &'static str {
        match self {
            Align::Start => "",
            Align::Center => "is-center",
            Align::End => "is-end",
        }
    }
}

/// Sort direction of a column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sort {
    Asc,
    Desc,
}

/// `aria-sort` of a sortable column header.
fn aria_sort(sort: Option<Sort>) -> &'static str {
    match sort {
        Some(Sort::Asc) => "ascending",
        Some(Sort::Desc) => "descending",
        None => "none",
    }
}

/// A full-width table with hairline rows. `caption` is its accessible name (not shown).
#[component]
pub fn Table(
    #[props(default)] caption: Option<String>,
    /// 28 px rows instead of 36 px.
    #[props(default)]
    dense: bool,
    children: Element,
) -> Element {
    rsx! {
        div { class: "w-table-wrap",
            table { class: "w-table", class: if dense { "is-dense" },
                if let Some(caption) = caption {
                    caption { class: "w-sr", "{caption}" }
                }
                {children}
            }
        }
    }
}

/// A column header: a mono caption; with `on_sort` a button that toggles the sort, announced
/// through `aria-sort`.
#[component]
pub fn HeadCell(
    label: String,
    #[props(default)] align: Align,
    /// Current sort of this column (`None` = sorted by another column or not at all).
    #[props(default)]
    sort: Option<Sort>,
    #[props(default)] on_sort: Option<EventHandler<()>>,
    /// CSS width (`"120px"`, `"20%"`).
    #[props(default)]
    width: Option<String>,
) -> Element {
    let style = width.map(|w| format!("width:{w}"));
    rsx! {
        th {
            class: "w-th {align.class()}",
            scope: "col",
            style,
            aria_sort: on_sort.is_some().then(|| aria_sort(sort)),
            if let Some(on_sort) = on_sort {
                button {
                    r#type: "button",
                    class: "w-th-sort",
                    class: if sort.is_some() { "is-sorted" },
                    onclick: move |_| on_sort.call(()),
                    "{label}"
                    Icon {
                        glyph: if sort == Some(Sort::Asc) { IconGlyph::ChevronUp } else { IconGlyph::ChevronDown },
                        size: 12,
                    }
                }
            } else {
                "{label}"
            }
        }
    }
}

/// A body cell.
#[component]
pub fn Cell(
    #[props(default)] align: Align,
    #[props(default)] mono: bool,
    #[props(default)] muted: bool,
    /// Takes the free width of the table and cuts its text instead of widening the table.
    #[props(default)]
    grow: bool,
    #[props(default)] colspan: Option<u32>,
    children: Element,
) -> Element {
    rsx! {
        td {
            class: "w-td {align.class()}",
            class: if mono { "swiss-mono" },
            class: if muted { "is-muted" },
            class: if grow { "is-grow" },
            colspan: colspan.map(|c| c.to_string()),
            {children}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sort_states_are_announced() {
        assert_eq!(aria_sort(Some(Sort::Asc)), "ascending");
        assert_eq!(aria_sort(Some(Sort::Desc)), "descending");
        assert_eq!(aria_sort(None), "none");
    }
}
