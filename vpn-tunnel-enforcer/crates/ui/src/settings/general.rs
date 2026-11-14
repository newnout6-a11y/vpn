//! «Интерфейс»: language and theme, both applied at once (ui-pages §2.2, §3.1.1).
use dioxus::prelude::*;

use super::model::{Lang, ThemeMode};
use super::{ActionError, use_api, use_ctx};
use crate::lang::{LANG, tr};
use crate::t;
use crate::widgets::{Button, ButtonKind, Panel, Row, Segmented, UiError, use_job};

/// Id of the first built-in theme of `mode` (the old segmented control picked it the same way).
fn builtin_id(themes: &[super::ThemeChoice], mode: ThemeMode) -> String {
    themes
        .iter()
        .find(|t| t.builtin && t.mode == mode)
        .map(|t| t.id.clone())
        .unwrap_or_else(|| format!("builtin-{}", mode.name()))
}

#[component]
pub(super) fn General() -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let lang_job = use_job::<()>();
    let theme_job = use_job::<()>();
    let state = ctx.state.read();
    let themes = state.themes.clone();
    let active = state.active_theme_id.clone();
    // A custom theme shows the segment of its own mode (§3.1.1).
    let mode = themes
        .iter()
        .find(|t| t.id == active)
        .map_or(ThemeMode::System, |t| t.mode);
    drop(state);
    let custom: Vec<_> = themes.iter().filter(|t| !t.builtin).cloned().collect();
    let lang_api = api.clone();
    let pick_lang = move |lang: Lang| {
        if *LANG.peek() == lang {
            return;
        }
        // The UI switches first; persisting follows (a failure is shown, the switch stays).
        *LANG.write() = lang;
        let api = lang_api.clone();
        lang_job.start(move |_| async move { api.set_language(lang).await });
    };
    let theme_api = api.clone();
    let set_theme = move |id: String| {
        let api = theme_api.clone();
        theme_job.start(move |_| async move { api.set_theme(id).await });
    };
    let lang_error = match lang_job.last() {
        Some(Err(err)) => Some(UiError {
            kind: err.kind,
            msg: vpnte_base::Msg::new("ui.settings.general.languageNotSaved")
                .arg("reason", tr(&err.msg)),
        }),
        _ => None,
    };
    let theme_error = match theme_job.last() {
        Some(Err(err)) => Some(err),
        _ => None,
    };
    let on_mode = {
        let set_theme = set_theme.clone();
        let themes = themes.clone();
        move |mode: ThemeMode| set_theme(builtin_id(&themes, mode))
    };
    rsx! {
        Panel { title: t!("ui.settings.general.title"), id: "set-general",
            Row {
                label: t!("settings.language"),
                hint: t!("settings.languageDescription"),
                Segmented {
                    label: t!("settings.language"),
                    options: vec![
                        (Lang::Ru, t!("ui.settings.general.langRu")),
                        (Lang::En, t!("ui.settings.general.langEn")),
                    ],
                    value: *LANG.read(),
                    // a switch while the previous one persists would show but never be saved
                    disabled: lang_job.running(),
                    on_change: pick_lang,
                }
            }
            ActionError { error: lang_error }
            Row {
                label: t!("settings.theme"),
                hint: t!("settings.themeDescription"),
                Segmented {
                    label: t!("settings.theme"),
                    options: vec![
                        (ThemeMode::Light, t!("settings.themeLight")),
                        (ThemeMode::Dark, t!("settings.themeDark")),
                        (ThemeMode::System, t!("settings.themeSystem")),
                    ],
                    value: mode,
                    disabled: theme_job.running(),
                    on_change: on_mode,
                }
            }
            if !custom.is_empty() {
                div { class: "set-chips", role: "group", aria_label: t!("themes.custom"),
                    for theme in custom {
                        Button {
                            key: "{theme.id}",
                            kind: if theme.id == active { ButtonKind::Primary } else { ButtonKind::Ghost },
                            small: true,
                            title: t!("themes.custom"),
                            disabled: theme_job.running(),
                            onclick: {
                                let set_theme = set_theme.clone();
                                let id = theme.id.clone();
                                move |_| set_theme(id.clone())
                            },
                            "{theme.name}"
                        }
                    }
                }
            }
            ActionError { error: theme_error }
        }
    }
}
