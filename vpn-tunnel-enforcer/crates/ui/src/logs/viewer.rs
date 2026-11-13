//! «Технический»: live logs for support. Sources Приложение / sing-box / Xray / Служба; the
//! engine logs are the current session's wherever it runs (one calm line says which). Level
//! filter, search, follow / pause, copy a line or the visible lines (already redacted), open the
//! folder. At most the last 2 000 lines, newest first, keyed by their file offset: a re-read
//! keeps the expanded line, and the browser's scroll anchoring keeps the scroll position.
use dioxus::prelude::*;
use vpnte_base::ErrorKind;

use super::clear::{ClearButton, ClearTarget};
use super::journal::{JournalLine, LevelFilter, journal};
use super::model::{LogSource, LogTail, TailNote};
use super::state::use_remembered;
use super::table::use_tz;
use super::{COPIED_FLASH, JOURNAL_REFRESH, tr_now, use_api};
use crate::lang::{tr, translate_now};
use crate::pages::use_page_active;
use crate::t;
use crate::widgets::{
    Button, ButtonKind, EmptyState, Load, LoadError, Loader, Loading, Segmented, TextInput,
    TextKind, Toasts, use_job, use_load,
};

/// Catalog key of a source's label.
fn source_key(source: LogSource) -> &'static str {
    match source {
        LogSource::App => "logs.live.sourceApp",
        LogSource::SingBox => "logs.live.sourceSingBox",
        LogSource::Xray => "logs.live.sourceXray",
        LogSource::Service => "logs.tech.sourceService",
    }
}

/// Catalog key of a level filter's label.
fn level_key(filter: LevelFilter) -> &'static str {
    match filter {
        LevelFilter::All => "logs.live.levelAll",
        LevelFilter::Warnings => "logs.live.levelWarn",
        LevelFilter::Errors => "logs.live.levelError",
    }
}

/// The calm line over the lines, if any.
fn note_key(note: TailNote) -> Option<&'static str> {
    match note {
        TailNote::None => None,
        TailNote::ProxySession => Some("logs.tech.note.proxy"),
        TailNote::TunnelSession => Some("logs.tech.note.tunnel"),
        TailNote::ServiceSession => Some("logs.tech.note.service"),
        TailNote::ServiceLines => Some("logs.tech.note.serviceLines"),
        TailNote::NoService => Some("logs.tech.noService"),
        TailNote::OldService => Some("logs.tech.oldService"),
    }
}

/// The tab: the controls, the calm line, the lines.
#[component]
pub(super) fn TechnicalTab() -> Element {
    let api = use_api();
    let active = use_page_active();
    let tz = use_tz();
    let toasts = Toasts::use_context();
    let mut source = use_remembered(|s| s.tech.source, |s, v| s.tech.source = v);
    let mut level = use_remembered(|s| s.tech.level, |s, v| s.tech.level = v);
    let mut text = use_remembered(|s| s.tech.text.clone(), |s, v| s.tech.text = v);
    let mut follow = use_remembered(|s| s.tech.follow, |s, v| s.tech.follow = v);
    let mut reload = use_signal(|| 0u64);
    let expanded = use_signal(|| None::<u64>);
    let mut copied = use_signal(|| false);
    let open_job = use_job::<()>();
    let loader = use_load({
        let api = api.clone();
        move || {
            let api = api.clone();
            let src = source();
            let _ = reload();
            async move { api.read_log(src).await.map(|tail| (src, tail)) }
        }
    });
    // Follow: one read per period while the page is visible, never two at once.
    use_future(move || async move {
        loop {
            tokio::time::sleep(JOURNAL_REFRESH).await;
            if *active.peek()
                && *follow.peek()
                && !loader.refreshing()
                && !loader.state().is_loading()
            {
                loader.reload();
            }
        }
    });
    let current = source();
    let shown: Load<(LogTail, Vec<JournalLine>)> = match loader.state() {
        Load::Ready((src, tail)) if src == current => {
            let lines = journal(src, &tail, level(), &text.read(), &tz);
            Load::Ready((tail, lines))
        }
        Load::Ready(_) | Load::Loading => Load::Loading,
        Load::Failed(err) => Load::Failed(err),
    };
    let visible: Vec<String> = shown.ready().map_or_else(Vec::new, |(_, lines)| {
        lines.iter().rev().map(JournalLine::copy_text).collect()
    });
    let copy_visible = {
        let api = api.clone();
        move |_| {
            let (api, text) = (api.clone(), visible.join("\n"));
            spawn(async move {
                if api.copy_text(text).await.is_ok() {
                    copied.set(true);
                    tokio::time::sleep(COPIED_FLASH).await;
                    copied.set(false);
                }
            });
        }
    };
    let open_folder = move |_| {
        let api = api.clone();
        open_job.start(move |_token| async move {
            if let Err(err) = api.open_log_folder(current).await
                && err.kind != ErrorKind::Cancelled
            {
                tracing::warn!(error = %err, "logs folder not opened");
                toasts.error(
                    translate_now("logs.live.openFailed", &[]),
                    Some(tr_now(&err.user_msg())),
                );
            }
            Ok(())
        });
    };
    let sources: Vec<(LogSource, String)> = LogSource::ALL
        .iter()
        .map(|s| (*s, t!(source_key(*s))))
        .collect();
    let levels: Vec<(LevelFilter, String)> = LevelFilter::ALL
        .iter()
        .map(|l| (*l, t!(level_key(*l))))
        .collect();
    let note = shown
        .ready()
        .filter(|(tail, _)| tail.exists)
        .and_then(|(tail, _)| note_key(tail.note));
    let count = shown.ready().map(|(_, lines)| lines.len());
    rsx! {
        div { class: "lg-tab-bar",
            Segmented {
                options: sources,
                value: current,
                on_change: move |s| source.set(s),
                label: t!("logs.live.source"),
            }
            Segmented {
                options: levels,
                value: level(),
                on_change: move |l| level.set(l),
                label: t!("logs.level"),
            }
            div { class: "lg-search",
                TextInput {
                    kind: TextKind::Search,
                    value: text.read().clone(),
                    oninput: move |v| text.set(v),
                    placeholder: t!("logs.tech.search"),
                    aria_label: t!("logs.tech.search"),
                }
            }
        }
        div { class: "lg-tab-bar lg-tech-actions",
            Button {
                kind: ButtonKind::Ghost,
                small: true,
                onclick: move |_| follow.set(!follow()),
                if follow() {
                    {t!("logs.tech.pause")}
                } else {
                    {t!("logs.tech.follow")}
                }
            }
            Button {
                kind: ButtonKind::Ghost,
                small: true,
                busy: loader.refreshing(),
                onclick: move |_| loader.reload(),
                {t!("logs.live.refresh")}
            }
            Button {
                kind: ButtonKind::Ghost,
                small: true,
                disabled: count.unwrap_or(0) == 0,
                onclick: copy_visible,
                if copied() {
                    {t!("logs.copied")}
                } else {
                    {t!("logs.tech.copyVisible")}
                }
            }
            if current != LogSource::Service {
                Button {
                    kind: ButtonKind::Ghost,
                    small: true,
                    busy: open_job.running(),
                    onclick: open_folder,
                    {t!("logs.live.openFolder")}
                }
            }
            ClearButton { target: ClearTarget::Technical, on_done: move |()| *reload.write() += 1 }
            if let Some(count) = count {
                span { class: "lg-count swiss-mono", {t!("logs.live.lines", count = count)} }
            }
        }
        if let Some(note) = note {
            p { class: "lg-hint lg-note", {t!(note)} }
        }
        {lines_body(shown, level(), loader, expanded)}
    }
}

/// The lines, or why there are none.
fn lines_body(
    shown: Load<(LogTail, Vec<JournalLine>)>,
    level: LevelFilter,
    loader: Loader<(LogSource, LogTail)>,
    expanded: Signal<Option<u64>>,
) -> Element {
    match shown {
        Load::Loading => rsx! {
            Loading { label: t!("logs.live.loading") }
        },
        Load::Failed(err) => rsx! {
            LoadError {
                text: t!("logs.live.failed", message = tr(&err.msg)),
                retry_label: t!("common.retry"),
                on_retry: move |()| loader.reload(),
            }
        },
        Load::Ready((tail, _)) if !tail.exists => {
            let (title, detail) = match tail.note {
                TailNote::NoService => (t!("logs.tech.noService"), None),
                TailNote::OldService => (t!("logs.tech.oldService"), None),
                _ => (t!("logs.live.missing"), Some(t!("logs.live.missingHint"))),
            };
            rsx! {
                EmptyState { title, detail }
            }
        }
        Load::Ready((tail, lines)) if lines.is_empty() => {
            let title = if tail.lines.is_empty() {
                t!("logs.live.empty")
            } else if level == LevelFilter::All {
                t!("logs.tech.noMatches")
            } else {
                t!("logs.live.noLevel")
            };
            rsx! {
                EmptyState { title }
            }
        }
        Load::Ready((tail, lines)) => rsx! {
            ol { class: "lg-lines swiss-mono", aria_label: t!("logs.live.title"),
                for line in lines {
                    TechLine {
                        key: "{line.key}",
                        open: expanded() == Some(line.key),
                        line,
                        expanded,
                    }
                }
            }
            if tail.truncated {
                p { class: "lg-hint lg-journal-more", {t!("logs.live.truncated")} }
            }
        },
    }
}

/// One line: time, level, short scope, text; a click shows its fields and «Скопировать строку».
#[component]
fn TechLine(line: JournalLine, open: bool, mut expanded: Signal<Option<u64>>) -> Element {
    let api = use_api();
    let mut copied = use_signal(|| false);
    let key = line.key;
    let detail_id = format!("lg-line-{key}");
    let copy = {
        let text = line.copy_text();
        move |_| {
            let (api, text) = (api.clone(), text.clone());
            spawn(async move {
                if api.copy_text(text).await.is_ok() {
                    copied.set(true);
                    tokio::time::sleep(COPIED_FLASH).await;
                    copied.set(false);
                }
            });
        }
    };
    rsx! {
        li { class: "lg-line", "data-level": line.level.name(),
            button {
                r#type: "button",
                class: "lg-line-head",
                aria_expanded: if open { "true" } else { "false" },
                aria_controls: "{detail_id}",
                onclick: move |_| expanded.set(if open { None } else { Some(key) }),
                span { class: "lg-line-time", {line.time.clone().unwrap_or_default()} }
                span { class: "lg-line-level", {line.level.name()} }
                if let Some(scope) = &line.scope {
                    span { class: "lg-line-scope", "{scope}" }
                }
                span { class: "lg-line-text", "{line.text}" }
            }
            if open {
                div { class: "lg-line-detail", id: "{detail_id}",
                    if !line.fields.is_empty() {
                        dl { class: "lg-fields",
                            for (name, value) in line.fields.iter() {
                                div { class: "lg-field",
                                    dt { "{name}" }
                                    dd { "{value}" }
                                }
                            }
                        }
                    }
                    Button { kind: ButtonKind::Link, onclick: copy,
                        if copied() {
                            {t!("logs.copied")}
                        } else {
                            {t!("logs.tech.copyLine")}
                        }
                    }
                }
            }
        }
    }
}
