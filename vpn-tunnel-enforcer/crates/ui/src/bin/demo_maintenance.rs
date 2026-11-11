//! `demo_maintenance`: the Maintenance page inside the shell (advanced mode on), on the fake
//! backend ([`DemoMaintenanceApi`]). Flags: `--theme light|dark|system`, `--lang ru|en`,
//! `--size WxH`, `--page <id>` (start page, default maintenance),
//! `--scene default|off|problems|leak|inconclusive`.
#![windows_subsystem = "windows"]

use std::rc::Rc;

use dioxus::prelude::*;
use vpnte_ui::lang::init_locales;
use vpnte_ui::launch::{DemoArgs, LaunchOptions, launch};
use vpnte_ui::maintenance::demo::{DemoMaintenanceApi, Scene};
use vpnte_ui::maintenance::{MaintenanceApi, MaintenancePage};
use vpnte_ui::pages::{Page, PageRegistry};
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
    let options = LaunchOptions::demo("demo_maintenance", &args);
    let scene = Scene::parse(args.scene.as_deref().unwrap_or_default());
    launch(options, App, move || {
        let api: Rc<dyn MaintenanceApi> = DemoMaintenanceApi::new(scene);
        vec![Box::new(args), Box::new(api)]
    });
}

#[component]
fn App() -> Element {
    Toasts::use_provider();
    let args = use_context::<DemoArgs>();
    // The page lives in advanced mode only; the demo keeps it on.
    let advanced = use_signal(|| true);
    let start = args
        .page
        .as_deref()
        .and_then(Page::from_id)
        .unwrap_or(Page::Maintenance);
    let registry = use_hook(|| {
        let mut registry = PageRegistry::new();
        registry.register(Page::Maintenance, MaintenancePage);
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
