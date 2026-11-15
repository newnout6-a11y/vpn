//! `demo_tools`: the Availability and Speed test pages inside the shell, over the demo APIs.
//! Flags: `--theme light|dark|system`, `--lang ru|en`, `--size WxH`, `--page availability|
//! speedtest` (start page, default availability), `--scene <name>`: `connected` (default: tunnel
//! up, saved history), `off` (tunnel down), `empty` (no history), `history-error` (the saved
//! history could not be read), `mismatch` (the next speed test sees another exit IP), `fail`
//! (the next speed test fails during the download).
#![windows_subsystem = "windows"]

use std::rc::Rc;

use dioxus::prelude::*;
use vpnte_base::Msg;
use vpnte_ui::availability::demo::DemoAvailability;
use vpnte_ui::availability::{AvailabilityApi, AvailabilityPage, AvailabilityState};
use vpnte_ui::lang::init_locales;
use vpnte_ui::launch::{DemoArgs, LaunchOptions, launch};
use vpnte_ui::pages::{Page, PageRegistry};
use vpnte_ui::shell::Shell;
use vpnte_ui::speedtest::demo::{DemoOutcome, DemoSpeedTest};
use vpnte_ui::speedtest::{SpeedTestApi, SpeedTestPage, SpeedTestState};

fn main() {
    let args = DemoArgs::parse();
    // The canonical error texts (`errors.*`) live in vpnte-base; the app registers them the same way.
    init_locales(&[(
        include_str!("../../../base/locales/base.ru.json"),
        include_str!("../../../base/locales/base.en.json"),
    )]);
    let options = LaunchOptions::demo("demo_tools", &args);
    let scene = args.scene.clone().unwrap_or_default();
    launch(options, App, move || {
        let (availability, speed) = demo_apis(&scene);
        vec![Box::new(args), Box::new(availability), Box::new(speed)]
    });
}

/// The two fake backends for a scene.
fn demo_apis(scene: &str) -> (Rc<dyn AvailabilityApi>, Rc<dyn SpeedTestApi>) {
    let tunnel = scene != "off";
    let (availability, speed) = match scene {
        "empty" => (
            DemoAvailability::with_state(AvailabilityState {
                tunnel_running: true,
                ..Default::default()
            }),
            DemoSpeedTest::with_state(SpeedTestState {
                tunnel_running: true,
                ..Default::default()
            }),
        ),
        "history-error" => {
            let error = Some(Msg::new("ui.tools.demo.historyError"));
            (
                DemoAvailability::with_state(AvailabilityState {
                    tunnel_running: true,
                    history: Vec::new(),
                    history_error: error.clone(),
                }),
                DemoSpeedTest::with_state(SpeedTestState {
                    tunnel_running: true,
                    history: Vec::new(),
                    history_error: error,
                }),
            )
        }
        "mismatch" => (
            DemoAvailability::new(tunnel),
            DemoSpeedTest::new(tunnel).with_outcome(DemoOutcome::Mismatch),
        ),
        "fail" => (
            DemoAvailability::new(tunnel),
            DemoSpeedTest::new(tunnel).with_outcome(DemoOutcome::Fail),
        ),
        _ => (DemoAvailability::new(tunnel), DemoSpeedTest::new(tunnel)),
    };
    (Rc::new(availability), Rc::new(speed))
}

#[component]
fn App() -> Element {
    let args = use_context::<DemoArgs>();
    let start = args
        .page
        .as_deref()
        .and_then(Page::from_id)
        .filter(|page| matches!(page, Page::SpeedTest | Page::Availability))
        .unwrap_or(Page::Availability);
    let advanced = use_signal(|| false);
    let registry = use_hook(|| {
        let mut registry = PageRegistry::new();
        registry
            .register(Page::Availability, AvailabilityPage)
            .register(Page::SpeedTest, SpeedTestPage);
        registry
    });
    rsx! {
        Shell { version: env!("CARGO_PKG_VERSION"), advanced, registry, start }
    }
}
