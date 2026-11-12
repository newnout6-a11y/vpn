//! The window shell around every page: the title-bar strip with HTML caption buttons (the window
//! is frameless), the «Пломба» sidebar (wordmark, version, numbered navigation, clock) and the
//! page area, plus slots for the global toasts and the overlays.
use std::time::Duration;

use dioxus::desktop::tao::event::{Event, WindowEvent};
use dioxus::desktop::tao::window::ResizeDirection;
use dioxus::desktop::{use_window, use_wry_event_handler};
use dioxus::html::input_data::MouseButton;
use dioxus::prelude::*;

use crate::pages::{Page, PageHost, PageRegistry, nav_number, use_nav, use_nav_provider};
use crate::t;

/// Everything the shell needs from the app.
#[derive(Props, Clone, PartialEq)]
pub struct ShellProps {
    /// Version under the wordmark, without the `v` (the app passes its `CARGO_PKG_VERSION`).
    pub version: String,
    /// Settings → advanced mode: shows and allows the Maintenance page.
    pub advanced: ReadSignal<bool>,
    /// The page components.
    pub registry: PageRegistry,
    /// The page shown at launch.
    #[props(default = Page::Dashboard)]
    pub start: Page,
    /// Overlays above the pages (first-run wizard, shutdown overlay).
    #[props(default = VNode::empty())]
    pub overlays: Element,
    /// The global toast stack (fixed, top right, below the title bar).
    #[props(default = VNode::empty())]
    pub toasts: Element,
}

/// The app shell (old `App.tsx` layout): title-bar strip, sidebar, page area, overlays, toasts,
/// caption buttons. Provides [`crate::pages::Nav`] and [`WindowState`] as context.
#[component]
pub fn Shell(props: ShellProps) -> Element {
    use_nav_provider(props.start, props.advanced);
    let window = use_window_state_provider();
    rsx! {
        // pt-9 = the 36 px title bar
        div { class: "flex h-screen gradient-bg pt-9",
            div { class: "c-swiss swiss-titlebar", aria_hidden: "true" }
            Sidebar { version: props.version }
            div { class: "flex-1 min-w-0 relative",
                PageHost { registry: props.registry }
            }
            {props.overlays}
            {props.toasts}
            CaptionButtons {}
            if !window.maximized() {
                ResizeHandles {}
            }
        }
    }
}

/// Live state of the main window, in context under the shell.
#[derive(Clone, Copy, PartialEq)]
pub struct WindowState {
    minimized: Signal<bool>,
    maximized: Signal<bool>,
    /// `document.hidden`: the tray hides the window together with the WebView.
    page_hidden: Signal<bool>,
    focused: Signal<bool>,
}

impl WindowState {
    /// Neither minimised nor hidden (subscribes the caller).
    pub fn visible(&self) -> bool {
        !*self.minimized.read() && !*self.page_hidden.read()
    }

    /// Maximised (subscribes the caller).
    pub fn maximized(&self) -> bool {
        *self.maximized.read()
    }

    /// The window is active (its WebView has the focus; subscribes the caller).
    pub fn focused(&self) -> bool {
        *self.focused.read()
    }
}

/// Reports `[document.hasFocus(), document.hidden]` on every change. WebView2 keeps
/// `document.hidden` false while the window is minimised (wry does not hide the controller then),
/// hence the native minimised flag as well.
const WINDOW_JS: &str = r#"
const send = () => dioxus.send([document.hasFocus(), document.hidden]);
window.addEventListener('focus', send);
window.addEventListener('blur', send);
document.addEventListener('visibilitychange', send);
send();
await new Promise(() => {});
"#;

fn set_if_changed(mut signal: Signal<bool>, value: bool) {
    if *signal.peek() != value {
        signal.set(value);
    }
}

fn use_window_state_provider() -> WindowState {
    let desktop = use_window();
    let state = use_context_provider(|| WindowState {
        minimized: Signal::new(desktop.window.is_minimized()),
        maximized: Signal::new(desktop.window.is_maximized()),
        page_hidden: Signal::new(false),
        focused: Signal::new(true),
    });
    // Snap, Win+arrows, a double click on the strip and the taskbar all resize the window.
    use_wry_event_handler(move |event, _| {
        if let Event::WindowEvent {
            window_id,
            event: WindowEvent::Resized(_),
            ..
        } = event
            && *window_id == desktop.window.id()
        {
            set_if_changed(state.minimized, desktop.window.is_minimized());
            set_if_changed(state.maximized, desktop.window.is_maximized());
        }
    });
    use_future(move || async move {
        let mut events = document::eval(WINDOW_JS);
        while let Ok((focused, hidden)) = events.recv::<(bool, bool)>().await {
            set_if_changed(state.focused, focused);
            set_if_changed(state.page_hidden, hidden);
        }
    });
    state
}

/// «Пломба» navigation: wordmark, version, numbered index, clock.
#[component]
fn Sidebar(version: String) -> Element {
    let nav = use_nav();
    let current = nav.current();
    let platform = t!("sidebar.platform", "win-x64");
    rsx! {
        aside { class: "c-swiss swiss-sidebar flex h-full shrink-0 flex-col border-r border-[var(--rule)] bg-[var(--paper)] p-5 text-[var(--ink)]",
            // the wordmark is literal, never translated
            div { class: "swiss-brand",
                "Tunnel"
                br {}
                "Enforcer"
            }
            div { class: "swiss-mono mt-1.5 text-[10px] text-[var(--mute)]",
                "v{version} / {platform}"
            }
            nav { class: "mt-10 flex flex-col",
                for (i , page) in Page::nav(nav.advanced()).enumerate() {
                    button {
                        key: "{page.id()}",
                        r#type: "button",
                        class: "swiss-nav-item",
                        aria_current: (page == current).then_some("page"),
                        "data-perch": "nav-{page.id()}",
                        "data-perch-y": "bottom",
                        "data-perch-x": "0.85",
                        "data-perch-scale": "0.3",
                        "data-perch-fit": "gap",
                        onclick: move |_| nav.go(page),
                        span { class: "swiss-nav-num swiss-mono", {nav_number(i)} }
                        span { class: "swiss-nav-label", {t!(page.label_key())} }
                        span { class: "swiss-nav-mark", aria_hidden: "true" }
                    }
                }
            }
            // just the clock: the slab already says whether protection is on
            div {
                class: "mt-auto pt-3",
                "data-perch": "clock",
                "data-perch-x": "0.55",
                "data-perch-scale": "0.5",
                span { class: "swiss-mono text-[15px] font-medium text-[var(--mute)]",
                    Clock {}
                }
            }
        }
    }
}

/// Local wall-clock time of the sidebar clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ClockTime {
    hour: u16,
    minute: u16,
    second: u16,
    millis: u16,
}

impl ClockTime {
    /// Now, in the local zone through jiff (CONTRACT §3.6): the same zone source as the mascot's
    /// greeting and the timestamps of the Logs page, so the sidebar never disagrees with them.
    fn now() -> ClockTime {
        let t = jiff::Zoned::now().time();
        // jiff's civil fields are bounded (hour < 24, minute and second < 60, ms < 1000).
        let field = |v: i16| u16::try_from(v).unwrap_or_default();
        ClockTime {
            hour: field(t.hour().into()),
            minute: field(t.minute().into()),
            second: field(t.second().into()),
            millis: field(t.millisecond()),
        }
    }

    /// `("HH", colon dimmed, "MM")`: the colon dims on every odd second.
    fn parts(self) -> (String, bool, String) {
        (
            format!("{:02}", self.hour),
            self.second % 2 == 1,
            format!("{:02}", self.minute),
        )
    }

    /// Time until the next whole second, so the colon flips on the second.
    fn until_next_second(self) -> Duration {
        Duration::from_millis(1000 - u64::from(self.millis.min(999)))
    }
}

/// `HH:MM` with a blinking colon; a leaf, so only it re-renders every second. It ticks only
/// while the window is visible (D-14: the old interval also ran minimised and in the tray);
/// showing the window again restarts the loop, which corrects the time at once.
#[component]
fn Clock() -> Element {
    let window = use_context::<WindowState>();
    let mut now = use_signal(ClockTime::now);
    use_resource(move || async move {
        if !window.visible() {
            return;
        }
        loop {
            let fresh = ClockTime::now();
            if now.peek().parts() != fresh.parts() {
                now.set(fresh);
            }
            // a few ms past the boundary, never just before it
            tokio::time::sleep(fresh.until_next_second() + Duration::from_millis(5)).await;
        }
    });
    let (hh, dim, mm) = now().parts();
    rsx! {
        span { class: "tabular-nums",
            {hh}
            span { class: if dim { "opacity-30" }, ":" }
            {mm}
        }
    }
}

const GLYPH_MINIMIZE: &str = "\u{E921}";
const GLYPH_MAXIMIZE: &str = "\u{E922}";
const GLYPH_RESTORE: &str = "\u{E923}";
const GLYPH_CLOSE: &str = "\u{E8BB}";

/// Minimise / maximise-restore / close, drawn in HTML where the old app had the native window
/// controls overlay (46 × 36 each, Segoe Fluent Icons). Not in the tab order, like the native
/// buttons (Alt+Space, Alt+F4 and Win+arrows stay); named for screen readers. Close goes through
/// the window's close behaviour, exactly like Alt+F4 (the tray switches it to hide).
#[component]
fn CaptionButtons() -> Element {
    let desktop = use_window();
    let window = use_context::<WindowState>();
    let maximized = window.maximized();
    let (minimize, toggle, close) = (desktop.clone(), desktop.clone(), desktop);
    let (minimize_label, maximize_label, close_label) = (
        t!("ui.shell.minimize"),
        if maximized {
            t!("ui.shell.restore")
        } else {
            t!("ui.shell.maximize")
        },
        t!("ui.shell.close"),
    );
    rsx! {
        div { class: "c-swiss shell-caption", class: if !window.focused() { "is-inactive" },
            button {
                r#type: "button",
                class: "shell-caption-btn",
                tabindex: "-1",
                title: "{minimize_label}",
                aria_label: "{minimize_label}",
                onclick: move |_| minimize.window.set_minimized(true),
                {GLYPH_MINIMIZE}
            }
            button {
                r#type: "button",
                class: "shell-caption-btn",
                tabindex: "-1",
                title: "{maximize_label}",
                aria_label: "{maximize_label}",
                onclick: move |_| toggle.toggle_maximized(),
                if maximized { {GLYPH_RESTORE} } else { {GLYPH_MAXIMIZE} }
            }
            button {
                r#type: "button",
                class: "shell-caption-btn is-close",
                tabindex: "-1",
                title: "{close_label}",
                aria_label: "{close_label}",
                onclick: move |_| close.close(),
                {GLYPH_CLOSE}
            }
        }
    }
}

/// Top-edge resize handles. The WebView covers the whole client area, so natively only the
/// outermost pixel row resizes, and none above the caption buttons. Hidden while maximised.
#[component]
fn ResizeHandles() -> Element {
    let desktop = use_window();
    let drag = move |direction: ResizeDirection| {
        let desktop = desktop.clone();
        move |evt: MouseEvent| {
            // a native border resizes with the primary button only
            if evt.trigger_button() != Some(MouseButton::Primary) {
                return;
            }
            if let Err(err) = desktop.window.drag_resize_window(direction) {
                tracing::debug!(%err, "window resize drag not started");
            }
        }
    };
    rsx! {
        div { class: "shell-resize is-n", onmousedown: drag(ResizeDirection::North) }
        div { class: "shell-resize is-nw", onmousedown: drag(ResizeDirection::NorthWest) }
        div { class: "shell-resize is-ne", onmousedown: drag(ResizeDirection::NorthEast) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(hour: u16, minute: u16, second: u16, millis: u16) -> ClockTime {
        ClockTime {
            hour,
            minute,
            second,
            millis,
        }
    }

    /// Sidebar clock (`Sidebar.tsx` `Clock`): zero-padded `HH` `:` `MM`, the colon dimmed on odd
    /// seconds.
    #[test]
    fn clock_pads_and_blinks() {
        assert_eq!(at(9, 5, 7, 0).parts(), ("09".into(), true, "05".into()));
        assert_eq!(at(23, 59, 58, 0).parts(), ("23".into(), false, "59".into()));
        assert_eq!(at(0, 0, 0, 0).parts(), ("00".into(), false, "00".into()));
    }

    #[test]
    fn clock_ticks_on_the_second() {
        assert_eq!(
            at(1, 2, 3, 0).until_next_second(),
            Duration::from_millis(1000)
        );
        assert_eq!(
            at(1, 2, 3, 250).until_next_second(),
            Duration::from_millis(750)
        );
        assert_eq!(
            at(1, 2, 3, 999).until_next_second(),
            Duration::from_millis(1)
        );
        // a leap-second style overflow never yields a zero or negative wait
        assert_eq!(
            at(1, 2, 3, 1000).until_next_second(),
            Duration::from_millis(1)
        );
        let now = ClockTime::now();
        assert!(now.hour < 24 && now.minute < 60 && now.second < 61);
    }

    /// Every key the shell renders exists in both languages.
    #[test]
    fn rendered_keys_exist() {
        crate::test_locales::assert_resolve(
            &crate::test_locales::catalogs(&[]),
            [
                "ui.shell.minimize",
                "ui.shell.maximize",
                "ui.shell.restore",
                "ui.shell.close",
                "ui.shell.placeholder",
                "ui.shell.pageFailed",
            ],
        );
    }
}
