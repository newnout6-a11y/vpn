//! `demo_servers`: the Servers page inside the real shell over `DemoServersApi` (fake store,
//! realistic delays, no network). Flags: `--theme light|dark|system`, `--lang ru|en`,
//! `--size WxH`, `--scene normal|empty|loading|foreign|link` (`link`: a link handed over at start
//! opens the add dialog).
#![windows_subsystem = "windows"]

use std::rc::Rc;

use dioxus::prelude::*;
use vpnte_ui::lang::init_locales;
use vpnte_ui::launch::{DemoArgs, LaunchOptions, launch};
use vpnte_ui::pages::{Page, PageRegistry};
use vpnte_ui::servers::{DemoScene, DemoServersApi, ServersApi, ServersPage};
use vpnte_ui::shell::Shell;
use vpnte_ui::t;
use vpnte_ui::widgets::{ToastHost, Toasts};

fn main() {
    let args = DemoArgs::parse();
    // The canonical error texts (`errors.*`) live in vpnte-base; the app registers them the same way.
    init_locales(&[(
        include_str!("../../../base/locales/base.ru.json"),
        include_str!("../../../base/locales/base.en.json"),
    )]);
    let options = LaunchOptions::demo("demo_servers", &args);
    launch(options, App, move || vec![Box::new(args)]);
}

#[component]
fn App() -> Element {
    let args = use_context::<DemoArgs>();
    let scene = DemoScene::from_name(args.scene.as_deref().unwrap_or_default());
    Toasts::use_provider();
    use_context_provider(|| -> Rc<dyn ServersApi> { Rc::new(DemoServersApi::new(scene)) });
    let advanced = use_signal(|| false);
    let registry = use_hook(|| {
        let mut registry = PageRegistry::new();
        registry.register(Page::Servers, ServersPage);
        registry
    });
    rsx! {
        Shell {
            version: env!("CARGO_PKG_VERSION"),
            advanced,
            registry,
            start: Page::Servers,
            toasts: rsx! {
                ToastHost { close_label: t!("common.close") }
            },
        }
    }
}
