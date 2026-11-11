//! `demo_frame`: the frame on its own: bundled fonts, the «Пломба» and legacy palettes, theme and
//! language switches. Flags: `--theme light|dark|system`, `--lang ru|en`, `--size WxH`.
#![windows_subsystem = "windows"]

use dioxus::prelude::*;
use vpnte_ui::lang::{LANG, Lang};
use vpnte_ui::launch::{DemoArgs, LaunchOptions, launch};
use vpnte_ui::t;
use vpnte_ui::theme::{self, LEVELS, THEME, Theme, ThemeMode};

/// Demo-only layout; inline so it never ships in another binary's index page.
const DEMO_CSS: &str = "
.frame-demo{position:fixed;inset:0;display:flex;flex-direction:column;background:var(--paper);color:var(--ink)}
.frame-demo-strip{height:36px;flex:none;display:flex;align-items:center;padding-left:16px;border-bottom:1px solid var(--rule)}
.frame-demo-drag{flex:1;align-self:stretch;display:flex;align-items:center;app-region:drag;-webkit-app-region:drag}
.frame-demo-close{width:46px;height:36px;border:0;background:transparent;color:var(--ink);font:16px 'Inter Tight';app-region:no-drag;-webkit-app-region:no-drag}
.frame-demo-close:hover{background:#c42b1c;color:#fff}
.frame-demo-body{flex:1;overflow:auto;padding:24px;display:grid;grid-template-columns:1fr 1fr;gap:24px 40px;align-content:start}
.frame-demo section{display:flex;flex-direction:column;gap:10px}
.frame-demo h2{margin:0}
.frame-demo .row{display:flex;gap:8px;flex-wrap:wrap}
.frame-demo button.pick{padding:6px 14px;border:1px solid var(--rule-strong);background:transparent;color:var(--ink);font:600 13px 'Inter Tight'}
.frame-demo button.pick.on{background:var(--ink);color:var(--paper)}
.frame-demo .sans{font-family:'Inter Tight';font-size:22px;margin:0}
.frame-demo .mono{font-size:15px;margin:0}
.frame-demo .sw{display:flex;align-items:center;gap:8px;font:11px 'JetBrains Mono'}
.frame-demo .sw i{width:28px;height:18px;border:1px solid var(--rule)}
";

fn main() {
    let args = DemoArgs::parse();
    let options = LaunchOptions::demo("demo_frame", &args);
    launch(options, App, move || vec![Box::new(args)]);
}

fn theme_key(mode: ThemeMode) -> &'static str {
    match mode {
        ThemeMode::Light => "themes.light",
        ThemeMode::Dark => "themes.dark",
        ThemeMode::System => "themes.system",
    }
}

#[component]
fn App() -> Element {
    let desktop = dioxus::desktop::use_window();
    let mode = THEME.read().mode;
    let lang = *LANG.read();
    let scheme = theme::scheme();
    rsx! {
        style { {DEMO_CSS} }
        div { class: "c-swiss frame-demo",
            header { class: "frame-demo-strip",
                div { class: "frame-demo-drag",
                    span { class: "swiss-label", id: "demo-title", {t!("ui.frame.demo.title")} }
                }
                button {
                    class: "frame-demo-close",
                    title: t!("ui.frame.demo.close"),
                    onclick: move |_| desktop.close(),
                    "×"
                }
            }
            main { class: "frame-demo-body",
                section {
                    h2 { class: "swiss-label", {t!("ui.frame.demo.theme")} }
                    div { class: "row",
                        for m in [ThemeMode::Light, ThemeMode::Dark, ThemeMode::System] {
                            button {
                                id: format!("theme-{}", m.name()),
                                class: if mode == m { "pick on" } else { "pick" },
                                onclick: move |_| *THEME.write() = Theme::builtin(m),
                                {t!(theme_key(m))}
                            }
                        }
                    }
                    p { id: "scheme", class: "swiss-mono",
                        {t!("ui.frame.demo.scheme", scheme = scheme.name())}
                    }
                }
                section {
                    h2 { class: "swiss-label", {t!("ui.frame.demo.language")} }
                    div { class: "row",
                        for (l , label) in [(Lang::Ru, "Русский"), (Lang::En, "English")] {
                            button {
                                id: format!("lang-{}", l.code()),
                                class: if lang == l { "pick on" } else { "pick" },
                                onclick: move |_| *LANG.write() = l,
                                {label}
                            }
                        }
                    }
                    p { id: "plural", class: "swiss-mono",
                        {t!("servers.groups.serverCount", count = 5)}
                    }
                }
                section {
                    h2 { class: "swiss-label", {t!("ui.frame.demo.fonts")} }
                    p { id: "sans-400", class: "sans", style: "font-weight:400", {t!("ui.frame.demo.sample")} }
                    p { id: "sans-800", class: "sans", style: "font-weight:800", "SECURE · 01:23:45" }
                    p { id: "mono", class: "mono swiss-mono", "0123456789 · 198.51.100.7 · 42 мс" }
                }
                section {
                    h2 { class: "swiss-label", {t!("ui.frame.demo.palette")} }
                    div { class: "row",
                        for var in ["--paper", "--ink", "--mute", "--rule", "--signal"] {
                            span { class: "sw",
                                i { style: "background:var({var})" }
                                {var}
                            }
                        }
                    }
                    h2 { class: "swiss-label", {t!("ui.frame.demo.legacyPalette")} }
                    div { class: "row",
                        for (_ , var) in LEVELS {
                            span { class: "sw",
                                i { style: "background:rgb(var({var}))" }
                                {var.trim_start_matches("--rgb-")}
                            }
                        }
                    }
                }
            }
        }
    }
}
