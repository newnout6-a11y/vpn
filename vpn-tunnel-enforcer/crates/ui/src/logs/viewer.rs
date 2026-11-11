//! The journal viewer: app.log or an engine log, level filter, newest first, following the tail
//! while the page is visible (replaces the old 10 s poll of a re-parsed app.log, U-19).
use dioxus::prelude::*;
use vpnte_base::ErrorKind;

use super::journal::{JournalLine, LevelFilter, journal};
use super::model::{LogSource, LogTail};
use super::table::use_tz;
use super::{JOURNAL_REFRESH, tr_now, use_api};
use crate::lang::tr;
use crate::lang::translate_now;
use crate::pages::use_page_active;
use crate::t;
use crate::widgets::{
    Button, ButtonKind, Checkbox, EmptyState, Load, LoadError, Loading, Panel, Segmented, Toasts,
    use_job, use_load,
};

/// Catalog key of a source's tab label.
fn source_key(source: LogSource) -> &'static str {
    match source {
        LogSource::App => "logs.live.sourceApp",
        LogSource::SingBox => "logs.live.sourceSingBox",
        LogSource::Xray => "logs.live.sourceXray",
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

/// The journal panel. `reload` changes after a cleanup (the files were truncated).
#[component]
pub(super) fn JournalPanel(reload: ReadSignal<u64>) -> Element {
    let api = use_api();
    let active = use_page_active();
    let tz = use_tz();
    let toasts = Toasts::use_context();
    let mut source = use_signal(|| LogSource::App);
    let mut level = use_signal(LevelFilter::default);
    let mut follow = use_signal(|| true);
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
    // Follow the tail: one read per period while the page is visible, never two at once.
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
    let open_folder = move |_| {
        let api = api.clone();
        open_job.start(move |_token| async move {
            if let Err(err) = api.open_log_folder().await
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

    let current = source();
    let filter = level();
    let shown: Load<(LogTail, Vec<JournalLine>)> = match loader.state() {
        Load::Ready((src, tail)) if src == current => {
            let lines = journal(src, &tail, filter, &tz);
            Load::Ready((tail, lines))
        }
        Load::Ready(_) | Load::Loading => Load::Loading,
        Load::Failed(err) => Load::Failed(err),
    };
    let count = shown
        .ready()
        .map(|(_, lines)| t!("logs.live.lines", count = lines.len()));
    let sources: Vec<(LogSource, String)> = LogSource::ALL
        .iter()
        .map(|s| (*s, t!(source_key(*s))))
        .collect();
    let levels: Vec<(LevelFilter, String)> = LevelFilter::ALL
        .iter()
        .map(|l| (*l, t!(level_key(*l))))
        .collect();
    rsx! {
        Panel {
            title: t!("logs.live.title"),
            flush: true,
            actions: rsx! {
                Button {
                    kind: ButtonKind::Link,
                    busy: loader.refreshing(),
                    onclick: move |_| loader.reload(),
                    {t!("logs.live.refresh")}
                }
                Button {
                    kind: ButtonKind::Link,
                    busy: open_job.running(),
                    onclick: open_folder,
                    {t!("logs.live.openFolder")}
                }
            },
            div { class: "lg-journal-bar",
                Segmented {
                    options: sources,
                    value: current,
                    on_change: move |s| source.set(s),
                    label: t!("logs.live.source"),
                }
                Segmented {
                    options: levels,
                    value: filter,
                    on_change: move |l| level.set(l),
                    label: t!("logs.level"),
                }
                Checkbox {
                    label: t!("logs.live.follow"),
                    checked: follow(),
                    on_change: move |on| follow.set(on),
                }
                if let Some(count) = count {
                    span { class: "lg-count swiss-mono", "{count}" }
                }
            }
            p { class: "lg-hint lg-journal-hint", {t!("logs.live.hint")} }
            {journal_body(shown, filter, loader)}
        }
    }
}

/// The lines, or why there are none.
fn journal_body(
    shown: Load<(LogTail, Vec<JournalLine>)>,
    filter: LevelFilter,
    loader: crate::widgets::Loader<(LogSource, LogTail)>,
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
        Load::Ready((tail, _)) if !tail.exists => rsx! {
            EmptyState { title: t!("logs.live.missing"), detail: t!("logs.live.missingHint") }
        },
        Load::Ready((tail, lines)) if lines.is_empty() => {
            let title =
                if tail.lines.iter().all(|l| l.trim().is_empty()) || filter == LevelFilter::All {
                    t!("logs.live.empty")
                } else {
                    t!("logs.live.noLevel")
                };
            rsx! {
                EmptyState { title }
            }
        }
        Load::Ready((tail, lines)) => rsx! {
            ol { class: "lg-lines swiss-mono", aria_label: t!("logs.live.title"),
                for (i, line) in lines.into_iter().enumerate() {
                    li { key: "{i}", class: "lg-line", "data-level": line.level.name(),
                        span { class: "lg-line-time", {line.time.unwrap_or_default()} }
                        span { class: "lg-line-level", {line.level.name()} }
                        if let Some(scope) = line.scope {
                            span { class: "lg-line-scope", "[{scope}]" }
                        }
                        span { class: "lg-line-text", {line.text} }
                    }
                }
            }
            if tail.truncated {
                p { class: "lg-hint lg-journal-more", {t!("logs.live.truncated")} }
            }
        },
    }
}
