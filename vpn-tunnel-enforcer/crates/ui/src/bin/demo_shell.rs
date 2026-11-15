//! `demo_shell`: the shell with stand-in pages (start page, two draft forms, Schedule failing
//! once, the rest as placeholders). Flags: `--theme light|dark|system`, `--lang ru|en`,
//! `--size WxH`, `--page <id>` (start page), `--scene reference|advanced` (`reference`: the
//! version string of the reference capture, 1.1.24; `advanced`: advanced mode on).
#![windows_subsystem = "windows"]

use std::sync::atomic::{AtomicBool, Ordering};

use dioxus::prelude::*;
use vpnte_ui::launch::{DemoArgs, LaunchOptions, launch};
use vpnte_ui::pages::{Page, PageRegistry, use_nav, use_page_active};
use vpnte_ui::shell::Shell;
use vpnte_ui::t;

/// Demo-only layout; inline so it never ships in another binary's index page.
const DEMO_CSS: &str = "
.shell-demo{display:flex;flex-direction:column;gap:16px;max-width:520px}
.shell-demo h1{margin:0}
.shell-demo .row{display:flex;gap:8px;flex-wrap:wrap}
.shell-demo button{padding:6px 14px;box-shadow:inset 0 0 0 1px currentColor;font-size:13px;font-weight:600}
.shell-demo button.on{background:var(--ink);color:var(--paper)}
.shell-demo input{padding:6px 8px;border:1px solid var(--rule-strong);background:transparent;color:var(--ink);font:14px 'Inter Tight'}
";

/// Advanced mode of the demo, shared with its start page.
#[derive(Clone, Copy)]
struct DemoAdvanced(Signal<bool>);

fn main() {
    let args = DemoArgs::parse();
    let options = LaunchOptions::demo("demo_shell", &args);
    launch(options, App, move || vec![Box::new(args)]);
}

#[component]
fn App() -> Element {
    let args = use_context::<DemoArgs>();
    let scene = args.scene.clone().unwrap_or_default();
    let advanced = use_signal(|| scene == "advanced");
    use_context_provider(|| DemoAdvanced(advanced));
    let start = args
        .page
        .as_deref()
        .and_then(Page::from_id)
        .unwrap_or(Page::Dashboard);
    let version = if scene == "reference" {
        "1.1.24"
    } else {
        env!("CARGO_PKG_VERSION")
    };
    let registry = use_hook(|| {
        let mut registry = PageRegistry::new();
        registry
            .register(Page::Dashboard, DemoHome)
            .register(Page::Schedule, DemoBroken)
            .register(Page::Settings, DemoSettings)
            .register(Page::Logs, DemoLogs);
        registry
    });
    rsx! {
        style { {DEMO_CSS} }
        Shell {
            version,
            advanced,
            registry,
            start,
            // the old app's empty global toast stack, as in the reference DOM
            toasts: rsx! {
                div { class: "c-swiss fixed z-[100] flex flex-col gap-2 top-[52px] right-4" }
            },
        }
    }
}

/// Stand-in start page: navigation from a deep component, advanced mode, page activity.
#[component]
fn DemoHome() -> Element {
    let nav = use_nav();
    let active = use_page_active();
    let DemoAdvanced(mut advanced) = use_context::<DemoAdvanced>();
    rsx! {
        div { class: "c-swiss swiss-skin",
            div { class: "shell-demo",
                h1 { class: "swiss-label", "demo_shell" }
                p { id: "demo-active-dashboard", class: "swiss-mono",
                    {t!("ui.shell.demo.active", value = active())}
                }
                div { class: "row",
                    button {
                        id: "demo-advanced",
                        class: if advanced() { "on" },
                        onclick: move |_| advanced.toggle(),
                        {t!("ui.shell.demo.advanced")}
                    }
                    button {
                        id: "demo-go-servers",
                        onclick: move |_| nav.go(Page::Servers),
                        {t!("ui.shell.demo.openServers")}
                    }
                    button {
                        id: "demo-go-maintenance",
                        onclick: move |_| nav.go(Page::Maintenance),
                        {t!("ui.shell.demo.openMaintenance")}
                    }
                }
            }
        }
    }
}

/// Stand-in Settings page: a draft that survives navigation (the page stays mounted).
#[component]
fn DemoSettings() -> Element {
    draft_page(Page::Settings)
}

/// Stand-in Logs page: active-only, so its draft is gone after leaving.
#[component]
fn DemoLogs() -> Element {
    draft_page(Page::Logs)
}

/// Stand-in Schedule page that fails on its first render (the shell's error boundary shows its
/// fallback) and renders after «Повторить».
#[component]
fn DemoBroken() -> Element {
    static FAILED_ONCE: AtomicBool = AtomicBool::new(false);
    if !FAILED_ONCE.swap(true, Ordering::Relaxed) {
        return Err(dioxus::CapturedError::from_display("demo page failure").into());
    }
    draft_page(Page::Schedule)
}

/// The draft input is uncontrolled (like the old test's `defaultValue` input): what survives is
/// the mounted DOM itself.
fn draft_page(page: Page) -> Element {
    let active = use_page_active();
    rsx! {
        div { class: "c-swiss swiss-skin",
            div { class: "shell-demo",
                h1 { class: "swiss-label", {t!(page.label_key())} }
                p { id: "demo-active-{page.id()}", class: "swiss-mono",
                    {t!("ui.shell.demo.active", value = active())}
                }
                label { class: "swiss-label", r#for: "demo-draft-{page.id()}",
                    {t!("ui.shell.demo.draft")}
                }
                input { id: "demo-draft-{page.id()}" }
            }
        }
    }
}
