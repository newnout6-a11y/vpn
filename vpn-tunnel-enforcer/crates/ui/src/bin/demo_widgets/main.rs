//! `demo_widgets`: every shared control of `vpnte_ui::widgets` with fake data, in light and dark,
//! Russian and English. Flags: `--theme light|dark|system`, `--lang ru|en`, `--size WxH`,
//! `--scene modal|confirm|toasts` (opens that state on start, for screenshots).
#![windows_subsystem = "windows"]

use dioxus::prelude::*;
use vpnte_ui::lang::{LANG, Lang, init_locales};
use vpnte_ui::launch::{DemoArgs, LaunchOptions, launch};
use vpnte_ui::t;
use vpnte_ui::theme::{THEME, Theme, ThemeMode, scheme};
use vpnte_ui::widgets::*;

mod controls;
mod views;

use controls::*;
use views::*;

/// Demo-only layout; inline so it never ships in another binary's index page.
const DEMO_CSS: &str = "
.wd{position:fixed;inset:0;display:flex;flex-direction:column;background:var(--paper);color:var(--ink)}
.wd-strip{height:36px;flex:none;display:flex;align-items:center;gap:16px;padding-left:16px;border-bottom:1px solid var(--rule)}
.wd-drag{flex:1;align-self:stretch;display:flex;align-items:center;app-region:drag;-webkit-app-region:drag}
.wd-strip .w-seg-item{height:26px;padding:0 10px;font-size:12px}
.wd-close{width:46px;height:36px;display:flex;align-items:center;justify-content:center;color:var(--ink)}
.wd-close:hover{background:#c42b1c;color:#fff}
.wd-body{flex:1;overflow:auto;padding:24px 24px 48px}
.wd-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:24px;align-items:start}
.wd-stack{display:flex;flex-direction:column;gap:14px}
.wd-line{display:flex;flex-wrap:wrap;align-items:center;gap:10px}
.wd-note{font-size:12px;color:var(--mute)}
.wd-clip{height:64px;overflow:hidden;border:1px dashed var(--rule-strong);padding:12px}
@media (max-width:1000px){.wd-grid{grid-template-columns:minmax(0,1fr)}}
";

fn main() {
    let args = DemoArgs::parse();
    // The canonical error texts (`errors.*`) live in vpnte-base; the app registers them the same way.
    init_locales(&[(
        include_str!("../../../../base/locales/base.ru.json"),
        include_str!("../../../../base/locales/base.en.json"),
    )]);
    let options = LaunchOptions::demo("demo_widgets", &args);
    launch(options, App, move || vec![Box::new(args)]);
}

#[component]
fn App() -> Element {
    let toasts = Toasts::use_provider();
    let args = use_context::<DemoArgs>();
    let scene = args.scene.clone().unwrap_or_default();
    use_hook(move || {
        if scene == "toasts" {
            push_all_toasts(toasts);
        }
    });
    let desktop = dioxus::desktop::use_window();
    let mode = if scheme().is_dark() {
        ThemeMode::Dark
    } else {
        ThemeMode::Light
    };
    let lang = *LANG.read();
    rsx! {
        style { {DEMO_CSS} }
        div { class: "c-swiss wd",
            header { class: "wd-strip",
                div { class: "wd-drag",
                    span { class: "swiss-label", id: "demo-title", {t!("ui.widgets.demo.title")} }
                }
                Segmented {
                    options: vec![(ThemeMode::Light, t!("ui.widgets.demo.light")), (ThemeMode::Dark, t!("ui.widgets.demo.dark"))],
                    value: mode,
                    on_change: move |m| *THEME.write() = Theme::builtin(m),
                    label: t!("ui.widgets.demo.theme"),
                }
                Segmented {
                    options: vec![(Lang::Ru, "RU".to_string()), (Lang::En, "EN".to_string())],
                    value: lang,
                    on_change: move |l| *LANG.write() = l,
                    label: "Language / Язык",
                }
                button {
                    r#type: "button",
                    class: "wd-close",
                    aria_label: t!("ui.widgets.demo.close"),
                    title: t!("ui.widgets.demo.close"),
                    onclick: move |_| desktop.close(),
                    Icon { glyph: IconGlyph::Close }
                }
            }
            main { class: "wd-body", tabindex: "-1", "data-w-focus-fallback": "true",
                SectionHeader {
                    number: "00",
                    title: t!("ui.widgets.demo.title"),
                    description: t!("ui.widgets.demo.intro"),
                    Badge { tone: Tone::Neutral, "ui-widgets" }
                }
                div { class: "wd-grid",
                    ButtonsDemo {}
                    StatusDemo {}
                    FormDemo {}
                    ChoicesDemo {}
                    TableDemo {}
                    StatesDemo {}
                    DialogsDemo {}
                    JobDemo {}
                }
            }
            ToastHost { close_label: t!("common.close") }
        }
    }
}

fn push_all_toasts(toasts: Toasts) {
    toasts.success(t!("ui.widgets.demo.toastSuccess"), None);
    toasts.error(
        t!("ui.widgets.demo.toastError"),
        Some(t!("ui.widgets.demo.toastErrorDesc")),
    );
    toasts.warning(t!("ui.widgets.demo.toastWarning"), None);
    toasts.info(t!("ui.widgets.demo.toastInfo"), None);
}
