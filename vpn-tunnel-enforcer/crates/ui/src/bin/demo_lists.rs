//! `demo_lists`: the Schedule, Apps (split tunnel) and Traffic pages in the shell over fake
//! backends. Flags: `--theme light|dark|system`, `--lang ru|en`, `--size WxH`,
//! `--page schedule|apps|trafficHistory` (start page, default `apps`), `--scene
//! full|empty|loading|failed|errors|many` (applies to every page; see each page's `demo`) with an
//! optional helper state `+installed|+missing|+older|+elevated` (default installed: the
//! Schedule's Tunnel entries connect; `+missing` marks them and offers the service's install).
#![windows_subsystem = "windows"]

use std::rc::Rc;

use dioxus::prelude::*;
use vpnte_base::types::now_ms;
use vpnte_ui::helper::HelperApi;
use vpnte_ui::helper::demo::{DemoHelper, split_scene};
use vpnte_ui::lang::init_locales;
use vpnte_ui::launch::{DemoArgs, LaunchOptions, launch};
use vpnte_ui::pages::{Page, PageRegistry};
use vpnte_ui::schedule::demo::DemoSchedule;
use vpnte_ui::schedule::{ScheduleApi, SchedulePage};
use vpnte_ui::shell::Shell;
use vpnte_ui::split_tunnel::demo::DemoSplitTunnel;
use vpnte_ui::split_tunnel::{SplitTunnelApi, SplitTunnelPage};
use vpnte_ui::t;
use vpnte_ui::traffic_history::demo::DemoTrafficHistory;
use vpnte_ui::traffic_history::{TrafficHistoryApi, TrafficHistoryPage};
use vpnte_ui::widgets::{ToastHost, Toasts};

fn main() {
    let args = DemoArgs::parse();
    // The canonical error texts (`errors.*`) live in vpnte-base; the app registers them the same way.
    init_locales(&[(
        include_str!("../../../base/locales/base.ru.json"),
        include_str!("../../../base/locales/base.en.json"),
    )]);
    let options = LaunchOptions::demo("demo_lists", &args);
    launch(options, App, move || vec![Box::new(args)]);
}

#[component]
fn App() -> Element {
    let args = use_context::<DemoArgs>();
    let (scene, helper) = split_scene(args.scene.as_deref().unwrap_or_default());
    use_context_provider(|| Rc::new(DemoHelper::new(helper)) as Rc<dyn HelperApi>);
    use_context_provider(|| Rc::new(DemoSchedule::new(scene)) as Rc<dyn ScheduleApi>);
    use_context_provider(|| Rc::new(DemoSplitTunnel::new(scene)) as Rc<dyn SplitTunnelApi>);
    use_context_provider(|| {
        Rc::new(DemoTrafficHistory::new(scene, now_ms())) as Rc<dyn TrafficHistoryApi>
    });
    Toasts::use_provider();
    let advanced = use_signal(|| false);
    let registry = use_hook(|| {
        let mut registry = PageRegistry::new();
        registry
            .register(Page::Apps, SplitTunnelPage)
            .register(Page::Schedule, SchedulePage)
            .register(Page::TrafficHistory, TrafficHistoryPage);
        registry
    });
    let start = args
        .page
        .as_deref()
        .and_then(Page::from_id)
        .unwrap_or(Page::Apps);
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
