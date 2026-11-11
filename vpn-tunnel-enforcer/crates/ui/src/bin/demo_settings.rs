//! `demo_settings`: the Settings page inside the shell, on the fake backend
//! ([`DemoSettingsApi`]). Flags: `--theme light|dark|system`, `--lang ru|en`, `--size WxH`,
//! `--page <id>` (start page, default settings), `--scene default|fresh|blocked|failures|advanced`.
#![windows_subsystem = "windows"]

use std::rc::Rc;

use dioxus::prelude::*;
use vpnte_ui::lang::init_locales;
use vpnte_ui::launch::{DemoArgs, LaunchOptions, launch};
use vpnte_ui::pages::{Page, PageRegistry};
use vpnte_ui::settings::demo::DemoSettingsApi;
use vpnte_ui::settings::{SettingsApi, SettingsPage};
use vpnte_ui::shell::Shell;
use vpnte_ui::t;
use vpnte_ui::widgets::{ToastHost, Toasts};

fn main() {
    // canonical error texts (errors.*) live in the base crate's fragment
    init_locales(&[(
        include_str!("../../../base/locales/base.ru.json"),
        include_str!("../../../base/locales/base.en.json"),
    )]);
    let args = DemoArgs::parse();
    let options = LaunchOptions::demo("demo_settings", &args);
    let scene = args.scene.clone().unwrap_or_default();
    let theme = args.theme.unwrap_or_default();
    launch(options, App, move || {
        let api: Rc<dyn SettingsApi> = DemoSettingsApi::new(&scene, theme);
        vec![Box::new(args), Box::new(api)]
    });
}

#[component]
fn App() -> Element {
    Toasts::use_provider();
    let args = use_context::<DemoArgs>();
    let api = use_context::<Rc<dyn SettingsApi>>();
    // The sidebar's «Починка» follows the SAVED advanced mode, as in the app.
    let rx = use_hook(|| api.state());
    let first = rx.borrow().settings.advanced_mode;
    let mut advanced = use_signal(move || first);
    use_future(move || {
        let mut rx = rx.clone();
        async move {
            loop {
                let saved = rx.borrow_and_update().settings.advanced_mode;
                if *advanced.peek() != saved {
                    advanced.set(saved);
                }
                if rx.changed().await.is_err() {
                    break;
                }
            }
        }
    });
    let start = args
        .page
        .as_deref()
        .and_then(Page::from_id)
        .unwrap_or(Page::Settings);
    let registry = use_hook(|| {
        let mut registry = PageRegistry::new();
        registry.register(Page::Settings, SettingsPage);
        registry
    });
    rsx! {
        Shell {
            version: env!("CARGO_PKG_VERSION"),
            advanced,
            registry,
            start,
            toasts: rsx! {
                ToastHost { close_label: t!("common.close") }
            },
        }
    }
}
