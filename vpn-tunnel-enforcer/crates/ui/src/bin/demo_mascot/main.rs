//! `demo_mascot`: «Пломбик» over a stand-in start page (the real one is the dashboard package's):
//! the reference shell, facts strip, slab and panel row with every `data-perch` spot the brain
//! uses, on paper, signal (the orange slab when connected) and inverse (the ink power button)
//! surfaces. Flags: `--theme light|dark|system`, `--lang ru|en`, `--size WxH`, `--scene <name>`:
//! `bench` (default: phase and event buttons in the traffic panel), `mascot-bubble`, `mascot-sleep`,
//! `mascot-alert` (the reference scenes: greeting at 12:34, disconnected; asleep after 30 s;
//! a leak 4 s after start). CDP hook: `window.mascotDemo('<action>')`, actions as in [`act`].
#![windows_subsystem = "windows"]

use std::time::Duration;

use dioxus::prelude::*;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_ui::launch::{DemoArgs, LaunchOptions, launch};
use vpnte_ui::mascot::{MascotBus, MascotEvent, MascotPhase, use_mascot_bus_provider};
use vpnte_ui::theme::{THEME, Theme, ThemeMode};

mod page;
mod panels;

use page::*;
use panels::*;

/// Bench controls only (the stand-in page uses the shipped stylesheets).
const DEMO_CSS: &str = "
.mascot-bench{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:4px;padding:12px 20px}
.mascot-bench .swiss-label{grid-column:1/-1;margin-top:4px}
.mascot-bench button{height:22px;border:1px solid var(--rule-strong);background:var(--paper);color:var(--ink);
  font:500 10px 'JetBrains Mono';text-transform:uppercase;white-space:nowrap;overflow:hidden}
.mascot-bench button:hover{background:var(--ink);color:var(--paper)}
";

fn main() {
    let args = DemoArgs::parse();
    vpnte_ui::lang::init_locales(vpnte_view::LOCALES);
    let options = LaunchOptions::demo("demo_mascot", &args);
    launch(options, App, move || vec![Box::new(args)]);
}

/// What the stand-in page shows (one per mascot phase).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Look {
    Exposed,
    Linking,
    Secure,
    Leak,
}

impl Look {
    fn phase(self) -> MascotPhase {
        match self {
            Look::Exposed => MascotPhase::Off,
            Look::Linking => MascotPhase::Connecting,
            Look::Secure => MascotPhase::On,
            Look::Leak => MascotPhase::Alert,
        }
    }
    fn connected(self) -> bool {
        matches!(self, Look::Secure | Look::Leak)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scene {
    Bench,
    Bubble,
    Sleep,
    Alert,
}

impl Scene {
    fn from_arg(arg: Option<&str>) -> Scene {
        match arg {
            Some("mascot-bubble") => Scene::Bubble,
            Some("mascot-sleep") => Scene::Sleep,
            Some("mascot-alert") => Scene::Alert,
            _ => Scene::Bench,
        }
    }
}

/// The reference scenes were captured at 12:34:56 local time (a day greeting).
const REFERENCE_TIME: Duration = Duration::from_secs(12 * 3600 + 34 * 60 + 56);

#[component]
fn App() -> Element {
    let args = use_context::<DemoArgs>();
    let scene = Scene::from_arg(args.scene.as_deref());
    let bus = use_mascot_bus_provider();
    let mut look = use_signal(|| match scene {
        Scene::Alert => Look::Secure,
        _ => Look::Exposed,
    });
    let state = Bench {
        look,
        smart: use_signal(|| true),
        proxies: use_signal(|| 0u32),
        session: use_signal(|| now_ms() - 5_000),
    };
    // Idempotent: cheap on every render.
    bus.phase(look().phase());
    bus.session_started(look().connected().then(|| (state.session)()));

    // The leak of the mascot-alert scene comes 4 s after start (the greeting is over by then).
    use_future(move || async move {
        if scene == Scene::Alert {
            tokio::time::sleep(Duration::from_secs(4)).await;
            look.set(Look::Leak);
        }
    });
    // CDP hook: window.mascotDemo('<action>').
    let hook_bus = bus.clone();
    use_future(move || {
        let bus = hook_bus.clone();
        async move {
            let mut js = document::eval(
                "window.mascotDemo = (a) => dioxus.send(a); await new Promise(() => {});",
            );
            while let Ok(action) = js.recv::<String>().await {
                act(&bus, state, &action);
            }
        }
    });

    let greet_time = (scene != Scene::Bench).then_some(REFERENCE_TIME);
    rsx! {
        style { {DEMO_CSS} }
        div { class: "flex h-screen gradient-bg pt-9",
            div { class: "c-swiss swiss-titlebar", aria_hidden: "true" }
            {sidebar()}
            div { class: "flex-1 min-w-0 relative",
                main { class: "absolute inset-0 overflow-y-auto p-6 tabular pointer-events-auto",
                    div { class: "c-swiss swiss-skin",
                        div { class: "space-y-6",
                            div { class: "c-swiss fixed z-[100] flex flex-col gap-2 top-[52px] right-4" }
                            if look() == Look::Leak {
                                {leak_banner()}
                            }
                            {facts(&bus, state)}
                            {slab(&bus, look(), greet_time)}
                            {panels(&bus, state, scene == Scene::Bench)}
                        }
                    }
                }
            }
            div { class: "c-swiss fixed z-[100] flex flex-col gap-2 top-[52px] right-4" }
        }
    }
}

/// Bench state shared by the stand-in controls.
#[derive(Clone, Copy)]
struct Bench {
    look: Signal<Look>,
    smart: Signal<bool>,
    proxies: Signal<u32>,
    /// Start of the stand-in tunnel session.
    session: Signal<UnixMs>,
}

/// One bench action (the buttons and the CDP hook use the same names).
fn act(bus: &MascotBus, mut b: Bench, action: &str) {
    let ev = match action {
        "off" => return b.look.set(Look::Exposed),
        "connecting" => return b.look.set(Look::Linking),
        "on" => return b.look.set(Look::Secure),
        "alert" => return b.look.set(Look::Leak),
        "fast" => return bus.speed_band(80.0),
        "slow" => return bus.speed_band(1.5),
        "idle" => return bus.speed_band(0.0),
        // A session that reaches its 10-minute mark in 2 s.
        "milestone" => return b.session.set(now_ms() - 598_000),
        "theme" => {
            let dark = THEME.read().mode == ThemeMode::Dark;
            let mode = if dark {
                ThemeMode::Light
            } else {
                ThemeMode::Dark
            };
            *THEME.write() = Theme::builtin(mode);
            return;
        }
        "page" => {
            let bus = bus.clone();
            bus.page_active(false);
            spawn(async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                bus.page_active(true);
            });
            return;
        }
        "smart" => {
            let on = !(b.smart)();
            b.smart.set(on);
            if on {
                MascotEvent::SmartOn
            } else {
                MascotEvent::SmartOff
            }
        }
        "proxy-start" => {
            b.proxies += 1;
            MascotEvent::ProxyStart
        }
        "proxy-stop" | "proxy-stop-all" => {
            let all = action == "proxy-stop-all";
            let n = (b.proxies)();
            b.proxies.set(if all { 0 } else { n.saturating_sub(1) });
            if all {
                MascotEvent::ProxyStopAll
            } else {
                MascotEvent::ProxyStop
            }
        }
        "proxy-rotate" => MascotEvent::ProxyRotate,
        "leak-start" => MascotEvent::LeakStart,
        "leak-ok" => MascotEvent::LeakOk,
        "leak-warn" => MascotEvent::LeakWarn,
        "leak-fail" => MascotEvent::LeakFail,
        "notice-error" => MascotEvent::NoticeError,
        "notice-warn" => MascotEvent::NoticeWarn,
        "notice-ok" => MascotEvent::NoticeOk,
        "hover-in" => MascotEvent::HoverIn,
        "hover-out" => MascotEvent::HoverOut,
        "poke" => MascotEvent::Poke,
        "pet" => MascotEvent::Pet,
        other => {
            tracing::warn!(action = other, "unknown demo action");
            return;
        }
    };
    bus.send(ev);
}
