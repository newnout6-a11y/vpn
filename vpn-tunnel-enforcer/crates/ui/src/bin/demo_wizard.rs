//! `demo_wizard`: the first-run wizard over the shell, with a stand-in start page whose power
//! button counts presses (proof that nothing underneath can be toggled while the wizard is open)
//! and shows what the fake backend was asked to do. Flags: `--theme light|dark|system`,
//! `--lang ru|en`, `--size WxH`, `--scene first-run|no-proxy|rerun|finish-fails|restore-fails|
//! skip-fails` with an optional helper state `+installed|+missing|+older|+elevated` (default
//! installed).
#![windows_subsystem = "windows"]

use std::rc::Rc;

use dioxus::prelude::*;
use vpnte_ui::helper::HelperApi;
use vpnte_ui::helper::demo::{DemoHelper, split_scene};
use vpnte_ui::launch::{DemoArgs, LaunchOptions, launch};
use vpnte_ui::pages::{Page, PageRegistry};
use vpnte_ui::shell::Shell;
use vpnte_ui::t;
use vpnte_ui::wizard::{DemoScene, DemoWizardApi, Wizard, WizardApi};

/// Demo-only layout; inline so it never ships in another binary's index page.
const DEMO_CSS: &str = "
.wz-demo{display:flex;flex-direction:column;gap:16px;max-width:560px}
.wz-demo .row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.wz-demo .swiss-power{width:auto;padding:0 20px;height:56px}
.wz-demo ol{margin:0;padding-left:20px;font-size:12px;color:var(--mute)}
";

fn main() {
    let args = DemoArgs::parse();
    let options = LaunchOptions::demo("demo_wizard", &args);
    launch(options, App, move || vec![Box::new(args)]);
}

#[component]
fn App() -> Element {
    let args = use_context::<DemoArgs>();
    let (scene, helper) = split_scene(args.scene.as_deref().unwrap_or_default());
    use_context_provider(|| Rc::new(DemoHelper::new(helper)) as Rc<dyn HelperApi>);
    let api = use_context_provider(|| {
        let scene = DemoScene::from_name(scene);
        Rc::new(DemoWizardApi::new(scene.unwrap_or_default()))
    });
    use_context_provider(|| api.clone() as Rc<dyn WizardApi>);
    let registry = use_hook(|| {
        let mut registry = PageRegistry::new();
        registry.register(Page::Dashboard, DemoHome);
        registry
    });
    rsx! {
        style { {DEMO_CSS} }
        Shell {
            version: env!("CARGO_PKG_VERSION"),
            advanced: false,
            registry,
            overlays: rsx! {
                Wizard {}
            },
        }
    }
}

/// Stand-in start page: a power button that counts presses (click or Ctrl+Enter through
/// `dashboard.js`), «open the wizard again», and the fake backend's log.
#[component]
fn DemoHome() -> Element {
    let api = use_context::<Rc<DemoWizardApi>>();
    let mut presses = use_signal(|| 0u32);
    let mut log = use_signal(Vec::<String>::new);
    let rx = use_hook({
        let api = api.clone();
        move || api.log()
    });
    use_future(move || {
        let mut rx = rx.clone();
        async move {
            while rx.changed().await.is_ok() {
                let lines = rx.borrow_and_update().clone();
                log.set(lines);
            }
        }
    });
    rsx! {
        div { class: "c-swiss swiss-skin",
            div { class: "wz-demo",
                p { class: "swiss-label", "demo_wizard" }
                div { class: "row",
                    button {
                        id: "demo-power",
                        class: "swiss-power",
                        onclick: move |_| presses += 1,
                        {t!("ui.wizard.demo.power")}
                    }
                    span { id: "demo-presses", class: "swiss-mono",
                        {t!("ui.wizard.demo.presses", count = presses())}
                    }
                }
                button {
                    id: "demo-reopen",
                    class: "w-btn is-ghost",
                    onclick: move |_| api.reopen(),
                    {t!("ui.wizard.demo.reopen")}
                }
                ol { id: "demo-log",
                    for (i , line) in log().into_iter().enumerate() {
                        li { key: "{i}", "{line}" }
                    }
                }
            }
        }
    }
}
