//! `demo_panels`: the panel row (`ui-panels`) with the reference fixtures, inside a skeleton of
//! the start page that puts `.swiss-panels` at the reference box (x, y, width, height) of the
//! chosen scene and window size, so `diff.mjs` matches it with the reference capture.
//!
//! Flags: `--scene connected|disconnected|servers-empty|proxy-picker-open|live` (a reference id
//! such as `connected-dark-860x600` also sets theme and size), `--theme`, `--lang`, `--size WxH`.
#![windows_subsystem = "windows"]

use std::time::Duration;

use dioxus::prelude::*;
use vpnte_ui::launch::{DemoArgs, LaunchOptions, launch};
use vpnte_ui::panels::SwissPanels;
use vpnte_ui::panels::demo::{DemoFeed, DemoPanels, DemoScene};
use vpnte_ui::t;
use vpnte_ui::theme::ThemeMode;

/// Demo-only chrome: a close button in the title strip and a blank sidebar.
const DEMO_CSS: &str = "
.panels-demo-close{position:absolute;top:0;right:0;width:46px;height:36px;border:0;background:transparent;color:var(--ink);font:16px 'Inter Tight';app-region:no-drag;-webkit-app-region:no-drag}
.panels-demo-close:hover{background:#c42b1c;color:#fff}
.panels-demo-slab{display:flex;align-items:flex-end;padding:16px 24px}
";

/// Reference panel-row tops (CSS px) minus the skin's content top (60 px): the height of the
/// placeholder that stands for the facts strip and the slab. Window heights 600 / 720 / 900.
fn slab_height(scene: DemoScene, window_h: u32) -> f64 {
    let disconnected = scene == DemoScene::Disconnected;
    match (window_h, disconnected) {
        (..=660, _) => 492.5,
        (661..=810, false) => 363.8,
        (661..=810, true) => 384.3,
        (_, false) => 397.3,
        (_, true) => 417.8,
    }
}

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

#[derive(Clone, Copy)]
struct Scene {
    data: DemoScene,
    picker_open: bool,
    window_h: u32,
}

fn main() {
    let mut args = DemoArgs::parse();
    apply_scene_id(&mut args);
    let name = args.scene.clone().unwrap_or_else(|| "connected".into());
    let data = DemoScene::from_name(&name).unwrap_or(DemoScene::Connected);
    let scene = Scene {
        data,
        picker_open: name.starts_with("proxy-picker-open"),
        window_h: args.size.map_or(720, |(_, h)| h),
    };
    // the panels render view.* keys (traffic hover read-out)
    vpnte_ui::lang::init_locales(vpnte_view::LOCALES);
    let options = LaunchOptions::demo("demo_panels", &args);
    launch(options, App, move || {
        let (api, feed) = DemoPanels::handle(data);
        vec![
            Box::new(args),
            Box::new(scene),
            Box::new(api),
            Box::new(feed),
        ]
    });
}

#[component]
fn App() -> Element {
    let desktop = dioxus::desktop::use_window();
    let scene = use_context::<Scene>();
    let feed = use_context::<DemoFeed>();
    use_future(move || {
        let feed = feed.clone();
        async move {
            // after the first paint the UI thread is free to take every sample of the burst
            let painted = document::eval(
                "await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r))); return 1;",
            );
            let _ = painted.join::<u8>().await;
            feed.start();
        }
    });
    use_future(move || async move {
        if scene.picker_open {
            // as the reference scene: open the picker once the data is in
            tokio::time::sleep(Duration::from_millis(2_500)).await;
            let _ = document::eval(
                "document.querySelector('.swiss-proxy-select [role=\"combobox\"]')?.click()",
            );
        }
    });
    let slab = slab_height(scene.data, scene.window_h);
    rsx! {
        style { {DEMO_CSS} }
        div { class: "flex h-screen gradient-bg pt-9",
            div { class: "c-swiss swiss-titlebar",
                button {
                    class: "panels-demo-close",
                    title: t!("ui.frame.demo.close"),
                    onclick: move |_| desktop.close(),
                    "✕"
                }
            }
            aside { class: "c-swiss swiss-sidebar flex h-full shrink-0 flex-col border-r border-[var(--rule)] bg-[var(--paper)] p-5 text-[var(--ink)]" }
            div { class: "flex-1 min-w-0 relative",
                main {
                    aria_hidden: "false",
                    class: "absolute inset-0 overflow-y-auto p-6 tabular pointer-events-auto",
                    div { class: "c-swiss swiss-skin",
                        div { class: "space-y-6",
                            div {
                                class: "swiss-slab panels-demo-slab",
                                style: "height: {slab}px;",
                                span { class: "swiss-label", {t!("ui.panels.demo.slab")} }
                            }
                            SwissPanels {}
                        }
                    }
                }
            }
        }
    }
}
