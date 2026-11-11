//! `demo_tray`: the tray on fake data. The page shows the menu as the model has it, the tooltip,
//! the four icon variants and what the native tray holds (read back from muda, with the count of
//! Win32 updates); the × of the strip is the app's close path. Flags: `--theme light|dark|system`,
//! `--lang ru|en`, `--size WxH`, `--scene <status key>|quit-fails` (e.g. `protected`, `leak`,
//! `proxyDown`, `killSwitch`, `restarting`; default `off`).
#![windows_subsystem = "windows"]

use std::rc::Rc;

use dioxus::prelude::*;
use vpnte_ui::lang::tr;
use vpnte_ui::launch::{DemoArgs, LaunchOptions, launch};
use vpnte_ui::t;
use vpnte_ui::tray::{
    Badge, DemoTray, TrayApi, TrayContext, TrayHost, TrayStatus, data_uri, fit_tooltip,
    tray_icon_size, variant_png,
};

/// Demo-only layout; inline so it never ships in another binary's index page.
const DEMO_CSS: &str = "
.tray-demo{position:fixed;inset:0;display:flex;flex-direction:column;background:var(--paper);color:var(--ink)}
.tray-demo-strip{height:36px;flex:none;display:flex;align-items:center;border-bottom:1px solid var(--rule)}
.tray-demo-drag{flex:1;align-self:stretch;display:flex;align-items:center;padding-left:16px;app-region:drag;-webkit-app-region:drag}
.tray-demo-x{width:46px;height:36px;border:0;background:transparent;color:var(--ink);font:16px 'Inter Tight';app-region:no-drag;-webkit-app-region:no-drag}
.tray-demo-x:hover{background:#c42b1c;color:#fff}
.tray-demo-body{flex:1;overflow:auto;padding:20px 24px;display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:22px 36px;align-content:start}
.tray-demo section{display:flex;flex-direction:column;gap:10px;min-width:0}
.tray-demo h2{margin:0}
.tray-demo .row{display:flex;gap:6px;flex-wrap:wrap}
.tray-demo button.pick{padding:5px 10px;border:1px solid var(--rule-strong);background:transparent;color:var(--ink);font:600 12px 'Inter Tight'}
.tray-demo button.pick.on{background:var(--ink);color:var(--paper)}
.tray-demo label.opt{display:flex;align-items:center;gap:8px;font-size:13px}
.tray-demo-menu{margin:0;padding:4px 0;list-style:none;border:1px solid var(--rule-strong);font-size:13px}
.tray-demo-menu li{padding:5px 12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tray-demo-menu li.off{color:var(--mute)}
.tray-demo-menu li.sep{padding:0;margin:4px 0;border-top:1px solid var(--rule)}
.tray-demo-tip{margin:0;padding:10px 12px;border:1px solid var(--rule);font-size:12px;line-height:1.5;white-space:pre-wrap}
.tray-demo-icons{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.tray-demo-icon{display:flex;flex-direction:column;align-items:flex-start;gap:6px;padding:8px;border:1px solid var(--rule)}
.tray-demo-icon.on{border-color:var(--signal);box-shadow:inset 0 0 0 1px var(--signal)}
.tray-demo-icon .big{width:64px;height:64px;image-rendering:pixelated}
.tray-demo-icon .real{width:16px;height:16px}
.tray-demo-native{margin:0;font-size:11px;line-height:1.6}
";

fn main() {
    let args = DemoArgs::parse();
    let options = LaunchOptions::demo("demo_tray", &args);
    let demo = Rc::new(DemoTray::new(args.scene.as_deref()));
    launch(options, App, move || {
        demo.spawn_traffic();
        let api: Rc<dyn TrayApi> = demo.clone();
        vec![Box::new(args), Box::new(api), Box::new(demo)]
    });
}

#[component]
fn App() -> Element {
    rsx! {
        style { {DEMO_CSS} }
        TrayHost { DemoPage {} }
    }
}

/// The icon variants as `data:` URIs at the tray's pixel size.
fn icon_uris() -> Vec<(Badge, String)> {
    [Badge::Off, Badge::Green, Badge::Amber, Badge::Red]
        .into_iter()
        .filter_map(|b| Some((b, data_uri("image/png", &variant_png(b, tray_icon_size())?))))
        .collect()
}

#[component]
fn DemoPage() -> Element {
    let tray = use_context::<TrayContext>();
    let demo = use_context::<Rc<DemoTray>>();
    let desktop = dioxus::desktop::use_window();
    let icons = use_hook(icon_uris);
    let model = tray.model.read();
    let status = model.status;
    let mut tip: Vec<String> = model.tooltip.iter().map(tr).collect();
    tip.extend(model.tooltip_speed.as_ref().map(tr));
    let native = tray.native.read();
    let state = demo.state().borrow().clone();
    let set = |change: fn(&mut vpnte_ui::tray::TrayState)| {
        let demo = demo.clone();
        move |_| demo.update(change)
    };
    rsx! {
        div { class: "c-swiss tray-demo",
            header { class: "tray-demo-strip",
                div { class: "tray-demo-drag",
                    span { class: "swiss-label", {t!("ui.tray.demo.title")} }
                }
                button {
                    class: "tray-demo-x",
                    id: "close",
                    title: t!("ui.tray.demo.closeWindow"),
                    onclick: move |_| desktop.close(),
                    "×"
                }
            }
            main { class: "tray-demo-body",
                section {
                    h2 { class: "swiss-label", {t!("ui.tray.demo.scene")} }
                    div { class: "row",
                        for s in TrayStatus::ALL {
                            button {
                                id: "scene-{s.key()}",
                                class: if s == status { "pick on" } else { "pick" },
                                onclick: {
                                    let demo = demo.clone();
                                    move |_| {
                                        let keep = demo.state().borrow().minimize_to_tray;
                                        demo.update(|st| {
                                            *st = vpnte_ui::tray::TrayState {
                                                minimize_to_tray: keep,
                                                ..DemoTray::scene(s)
                                            };
                                        });
                                    }
                                },
                                {t!(& format!("ui.tray.demo.status.{}", s.key()))}
                            }
                        }
                    }
                    h2 { class: "swiss-label", {t!("ui.tray.demo.options")} }
                    label { class: "opt",
                        input {
                            r#type: "checkbox",
                            id: "opt-tray",
                            checked: state.minimize_to_tray,
                            onchange: set(|s| s.minimize_to_tray = !s.minimize_to_tray),
                        }
                        {t!("ui.tray.demo.minimizeToTray")}
                    }
                    label { class: "opt",
                        input {
                            r#type: "checkbox",
                            id: "opt-ks",
                            checked: state.kill_switch,
                            onchange: set(|s| s.kill_switch = !s.kill_switch),
                        }
                        {t!("ui.tray.demo.killSwitch")}
                    }
                    label { class: "opt",
                        input {
                            r#type: "checkbox",
                            id: "opt-leak",
                            checked: state.leak,
                            onchange: set(|s| s.leak = !s.leak),
                        }
                        {t!("ui.tray.demo.leak")}
                    }
                }
                section {
                    h2 { class: "swiss-label", {t!("ui.tray.demo.menu")} }
                    ul { class: "tray-demo-menu", id: "menu",
                        for item in model.items.iter() {
                            li {
                                key: "{item.id.menu_id()}",
                                class: if item.enabled { "on" } else { "off" },
                                "data-id": item.id.menu_id(),
                                {tr(&item.label)}
                            }
                            if item.id.separator_after() {
                                li { class: "sep", role: "separator" }
                            }
                        }
                    }
                }
                section {
                    h2 { class: "swiss-label", {t!("ui.tray.demo.tooltip")} }
                    pre { class: "tray-demo-tip swiss-mono", id: "tooltip", {fit_tooltip(&tip)} }
                    h2 { class: "swiss-label", {t!("ui.tray.demo.icons")} }
                    div { class: "tray-demo-icons",
                        for (badge , uri) in icons.iter() {
                            div {
                                class: if status.badge() == *badge { "tray-demo-icon on" } else { "tray-demo-icon" },
                                id: "icon-{badge:?}",
                                img { class: "big", src: "{uri}", alt: "{badge:?}" }
                                img { class: "real", src: "{uri}", alt: "" }
                            }
                        }
                    }
                }
                section {
                    h2 { class: "swiss-label", {t!("ui.tray.demo.native")} }
                    match native.as_ref() {
                        Some(report) => rsx! {
                            p { class: "tray-demo-native swiss-mono", id: "native-calls",
                                {t!("ui.tray.demo.calls", text = report.calls.text, enabled = report.calls.enabled, tooltip = report.calls.tooltip, icon = report.calls.icon)}
                            }
                            ul { class: "tray-demo-menu", id: "native-menu",
                                for (text , enabled) in report.items.iter() {
                                    li { class: if *enabled { "on" } else { "off" }, {text.clone()} }
                                }
                            }
                            pre { class: "tray-demo-tip swiss-mono", id: "native-tooltip", {report.tooltip.clone()} }
                        },
                        None => rsx! {
                            p { class: "tray-demo-native", id: "native-calls", {t!("ui.tray.demo.noTray")} }
                        },
                    }
                }
            }
        }
    }
}
