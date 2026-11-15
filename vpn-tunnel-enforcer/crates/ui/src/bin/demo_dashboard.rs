//! `demo_dashboard`: the start page (`ui-dashboard`) inside the shell, over the reference
//! fixtures. Flags: `--scene <name>` (`disconnected`, `connecting`, `connected`, `verify`,
//! `closing`, `cancelling`, `switching`, `reconnecting`, `restart`, `leak`, `error-killswitch`,
//! `unknown-killswitch`, `tunnel-blocked`, `proxy-down`, `competing-tun`, `foreign-vpn`,
//! `servers-empty`, `connected-soft`, `mascot-alert`, `live`; a reference id
//! such as `connected-dark-860x600` also sets theme and size; an optional helper state
//! `+installed|+missing|+older|+elevated`, default installed: `disconnected+missing` shows the
//! strip of a saved Tunnel mode that waits for the helper service), `--theme`, `--lang`,
//! `--size WxH`.
#![windows_subsystem = "windows"]

use std::rc::Rc;

use dioxus::prelude::*;
use vpnte_ui::dashboard::Dashboard;
use vpnte_ui::dashboard::demo::{DashScene, DemoDashboard, DemoStart};
use vpnte_ui::helper::HelperApi;
use vpnte_ui::helper::demo::{DemoHelper, split_scene};
use vpnte_ui::launch::{DemoArgs, LaunchOptions, launch};
use vpnte_ui::pages::{Page, PageRegistry};
use vpnte_ui::shell::Shell;
use vpnte_ui::t;
use vpnte_ui::theme::ThemeMode;
use vpnte_ui::widgets::{ToastHost, Toasts};

/// A reference scene id (`connected-dark-860x600`) also names a theme and a window size; flags
/// given on the command line win.
fn apply_scene_id(args: &mut DemoArgs) {
    let Some(scene) = args.scene.clone() else {
        return;
    };
    let parts: Vec<&str> = scene.split('-').collect();
    if args.theme.is_none() {
        args.theme = parts.iter().find_map(|p| ThemeMode::from_name(p));
    }
    if args.size.is_none() {
        args.size = parts.last().and_then(|p| {
            let (w, h) = p.split_once('x')?;
            Some((w.parse().ok()?, h.parse().ok()?))
        });
    }
}

fn main() {
    let mut args = DemoArgs::parse();
    let (page, helper) = split_scene(args.scene.as_deref().unwrap_or_default());
    let page = page.to_owned();
    args.scene = (!page.is_empty()).then_some(page);
    apply_scene_id(&mut args);
    let scene = args
        .scene
        .as_deref()
        .and_then(DashScene::from_name)
        .unwrap_or(DashScene::Connected);
    // The page renders view.* keys (labels, traffic read-out), the engine's reasons (the identity
    // column's «Xray · REALITY») and the canonical errors.* texts: the app registers the same layers.
    let mut layers = vec![
        (
            include_str!("../../../base/locales/base.ru.json"),
            include_str!("../../../base/locales/base.en.json"),
        ),
        (
            include_str!("../../../engine/locales/engine-xray-config.ru.json"),
            include_str!("../../../engine/locales/engine-xray-config.en.json"),
        ),
    ];
    layers.extend_from_slice(vpnte_view::LOCALES);
    vpnte_ui::lang::init_locales(&layers);
    let options = LaunchOptions::demo("demo_dashboard", &args);
    launch(options, App, move || {
        let (api, panels, start) = DemoDashboard::handle(scene);
        let helper: Rc<dyn HelperApi> = Rc::new(DemoHelper::new(helper));
        vec![
            Box::new(args),
            Box::new(api),
            Box::new(panels),
            Box::new(start),
            Box::new(helper),
        ]
    });
}

#[component]
fn App() -> Element {
    let start = use_context::<DemoStart>();
    Toasts::use_provider();
    let advanced = use_signal(|| false);
    let registry = use_hook(|| {
        let mut registry = PageRegistry::new();
        registry.register(Page::Dashboard, Dashboard);
        registry
    });
    use_future(move || {
        let start = start.clone();
        async move {
            // after the first paint, like the reference timelines after boot
            let painted = document::eval(
                "await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r))); return 1;",
            );
            let _ = painted.join::<u8>().await;
            start.start();
        }
    });
    rsx! {
        Shell {
            // the reference capture's version line
            version: "1.1.24",
            advanced,
            registry,
            toasts: rsx! {
                ToastHost { close_label: t!("common.close") }
            },
        }
    }
}
