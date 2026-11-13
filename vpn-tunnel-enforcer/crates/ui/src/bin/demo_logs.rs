//! `demo_logs`: the «Журнал» page in the shell with a fake backend. Flags: `--theme
//! light|dark|system`, `--lang ru|en`, `--size WxH`, `--scene
//! full|empty|loading|failed|service|partial` (see `vpnte_ui::logs::demo`). The maintenance demo
//! backs «Сохранить для поддержки».
#![windows_subsystem = "windows"]

use std::rc::Rc;

use dioxus::prelude::*;
use vpnte_base::types::now_ms;
use vpnte_ui::lang::init_locales;
use vpnte_ui::launch::{DemoArgs, LaunchOptions, launch};
use vpnte_ui::logs::demo::DemoLogs;
use vpnte_ui::logs::{LogsApi, LogsPage};
use vpnte_ui::maintenance::MaintenanceApi;
use vpnte_ui::maintenance::demo::{DemoMaintenanceApi, Scene};
use vpnte_ui::pages::{Page, PageRegistry};
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
    let options = LaunchOptions::demo("demo_logs", &args);
    launch(options, App, move || vec![Box::new(args)]);
}

#[component]
fn App() -> Element {
    let args = use_context::<DemoArgs>();
    let scene = args.scene.clone().unwrap_or_default();
    use_context_provider(|| Rc::new(DemoLogs::new(&scene, now_ms())) as Rc<dyn LogsApi>);
    use_context_provider(|| DemoMaintenanceApi::new(Scene::Default) as Rc<dyn MaintenanceApi>);
    Toasts::use_provider();
    let advanced = use_signal(|| false);
    let registry = use_hook(|| {
        let mut registry = PageRegistry::new();
        registry.register(Page::Logs, LogsPage);
        registry
    });
    rsx! {
        Shell {
            version: env!("CARGO_PKG_VERSION"),
            advanced,
            registry,
            start: Page::Logs,
            toasts: rsx! {
                ToastHost { close_label: t!("common.close") }
            },
        }
    }
}
