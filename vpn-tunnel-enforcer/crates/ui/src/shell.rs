//! The window shell around every page: the title-bar strip with HTML caption buttons (the window
//! is frameless), the «Пломба» sidebar (wordmark, version, numbered navigation, clock) and the
//! page area, plus slots for the global toasts and the overlays.
use std::time::{Duration, Instant};

use dioxus::desktop::tao::event::{Event, WindowEvent};
use dioxus::desktop::tao::window::ResizeDirection;
use dioxus::desktop::{DesktopContext, use_window, use_wry_event_handler};
use dioxus::html::input_data::MouseButton;
use dioxus::prelude::*;

use crate::pages::{Page, PageHost, PageRegistry, nav_number, use_nav, use_nav_provider};
use crate::t;
use crate::widgets::Toasts;

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
    // Toasts wait while the window is in the tray or minimised (review exitgate-b3).
    let toasts = try_use_context::<Toasts>();
    use_effect(move || {
        let in_view = window.visible();
        if let Some(toasts) = toasts {
            toasts.set_seen(in_view);
        }
    });
    let desktop = use_window();
    rsx! {
        // pt-9 = the 36 px title bar
        div { class: "flex h-screen gradient-bg pt-9",
            WindowChrome {
                maximized: window.maximized,
                focused: window.focused,
                act: move |act| apply(&desktop, act),
                Sidebar { version: props.version }
                div { class: "c-swiss flex-1 min-w-0 relative shell-pages",
                    PageHost { registry: props.registry }
                }
                {props.overlays}
                {props.toasts}
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

/// What the frameless window's own chrome asks of the window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WindowAct {
    /// A press on the title strip: Windows' own move loop (Aero Snap, drag out of maximised).
    Move,
    /// A double click on the strip, or the middle caption button.
    ToggleMaximize,
    /// The first caption button.
    Minimize,
    /// The window's close behaviour, the same path as Alt+F4 (the tray switches it to hide).
    Close,
    /// A press on a top-edge handle: Windows' own resize loop.
    Resize(ResizeDirection),
}

/// Carries a chrome action out on the real window.
fn apply(desktop: &DesktopContext, act: WindowAct) {
    let started = match act {
        WindowAct::Move => desktop.window.drag_window(),
        WindowAct::Resize(direction) => desktop.window.drag_resize_window(direction),
        WindowAct::ToggleMaximize => {
            desktop.toggle_maximized();
            Ok(())
        }
        WindowAct::Minimize => {
            desktop.window.set_minimized(true);
            Ok(())
        }
        WindowAct::Close => {
            desktop.close();
            Ok(())
        }
    };
    if let Err(err) = started {
        tracing::debug!(%err, ?act, "window move or resize not started");
    }
}

/// Windows' default double-click time and distance (`GetDoubleClickTime`, `SM_CXDOUBLECLK`).
const DOUBLE_CLICK_TIME: Duration = Duration::from_millis(500);
const DOUBLE_CLICK_SLOP: f64 = 4.0;

/// Tells the second press of a double click on the strip from a fresh press. The page never sees
/// the release of a press that started a move (Windows' move loop takes it), so the WebView's own
/// `dblclick` cannot be relied on; the second press decides, as on a native caption, where
/// `WM_NCLBUTTONDBLCLK` also arrives on the press.
#[derive(Default)]
struct StripPresses {
    last: Option<(Instant, f64, f64)>,
}

impl StripPresses {
    /// The act for a primary press at screen point `(x, y)` (CSS px) at `now`.
    fn press(&mut self, now: Instant, (x, y): (f64, f64)) -> WindowAct {
        let double = self.last.is_some_and(|(at, px, py)| {
            now.saturating_duration_since(at) <= DOUBLE_CLICK_TIME
                && (x - px).abs() <= DOUBLE_CLICK_SLOP
                && (y - py).abs() <= DOUBLE_CLICK_SLOP
        });
        // a third press starts afresh, as on a native caption
        self.last = (!double).then_some((now, x, y));
        if double {
            WindowAct::ToggleMaximize
        } else {
            WindowAct::Move
        }
    }
}

/// The frameless window's chrome around `children` (sidebar, pages, overlays, toasts): the title
/// strip first, then the caption buttons and, unless maximised, the top-edge resize handles. The
/// strip moves the window through Windows' move loop instead of WebView2's CSS `app-region`,
/// which the installed build never honoured (15.11.2026: the window did not move at all).
#[component]
fn WindowChrome(
    maximized: ReadSignal<bool>,
    focused: ReadSignal<bool>,
    act: EventHandler<WindowAct>,
    children: Element,
) -> Element {
    let mut presses = use_signal(StripPresses::default);
    rsx! {
        div {
            class: "c-swiss swiss-titlebar",
            aria_hidden: "true",
            onmousedown: move |evt: MouseEvent| {
                // a native caption moves with the primary button only
                if evt.trigger_button() != Some(MouseButton::Primary) {
                    return;
                }
                let at = evt.screen_coordinates();
                let press = presses.write().press(Instant::now(), (at.x, at.y));
                act.call(press);
            },
        }
        {children}
        CaptionButtons { maximized, focused, act }
        if !maximized() {
            ResizeHandles { act }
        }
    }
}

const GLYPH_MINIMIZE: &str = "\u{E921}";
const GLYPH_MAXIMIZE: &str = "\u{E922}";
const GLYPH_RESTORE: &str = "\u{E923}";
const GLYPH_CLOSE: &str = "\u{E8BB}";

/// Minimise / maximise-restore / close, drawn in HTML where the old app had the native window
/// controls overlay (46 × 36 each, Segoe Fluent Icons). Not in the tab order, like the native
/// buttons (Alt+Space, Alt+F4 and Win+arrows stay); named for screen readers. Siblings of the
/// strip, never inside it, so a press on them never starts a move.
#[component]
fn CaptionButtons(
    maximized: ReadSignal<bool>,
    focused: ReadSignal<bool>,
    act: EventHandler<WindowAct>,
) -> Element {
    let maximized = maximized();
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
        div { class: "c-swiss shell-caption", class: if !focused() { "is-inactive" },
            button {
                r#type: "button",
                class: "shell-caption-btn",
                tabindex: "-1",
                title: "{minimize_label}",
                aria_label: "{minimize_label}",
                onclick: move |_| act.call(WindowAct::Minimize),
                {GLYPH_MINIMIZE}
            }
            button {
                r#type: "button",
                class: "shell-caption-btn",
                tabindex: "-1",
                title: "{maximize_label}",
                aria_label: "{maximize_label}",
                onclick: move |_| act.call(WindowAct::ToggleMaximize),
                if maximized { {GLYPH_RESTORE} } else { {GLYPH_MAXIMIZE} }
            }
            button {
                r#type: "button",
                class: "shell-caption-btn is-close",
                tabindex: "-1",
                title: "{close_label}",
                aria_label: "{close_label}",
                onclick: move |_| act.call(WindowAct::Close),
                {GLYPH_CLOSE}
            }
        }
    }
}

/// Top-edge resize handles. The WebView covers the whole client area, so natively only the
/// outermost pixel row resizes, and none above the caption buttons. Hidden while maximised.
#[component]
fn ResizeHandles(act: EventHandler<WindowAct>) -> Element {
    let drag = move |direction: ResizeDirection| {
        move |evt: MouseEvent| {
            // a native border resizes with the primary button only
            if evt.trigger_button() == Some(MouseButton::Primary) {
                act.call(WindowAct::Resize(direction));
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
    use std::cell::RefCell;
    use std::rc::Rc;

    use dioxus::core::{ElementId, NoOpMutations, WriteMutations};
    use dioxus::html::geometry::{ClientPoint, Coordinates, ElementPoint, PagePoint, ScreenPoint};
    use dioxus::html::{Modifiers, PlatformEventData, SerializedMouseData};

    use super::*;

    type Acts = Rc<RefCell<Vec<WindowAct>>>;

    /// The chrome as the shell renders it, its acts recorded instead of carried out.
    fn chrome_root() -> Element {
        let acts = use_context::<Acts>();
        let maximized = use_signal(|| false);
        let focused = use_signal(|| true);
        rsx! {
            WindowChrome {
                maximized,
                focused,
                act: move |act| acts.borrow_mut().push(act),
                div { "page" }
            }
        }
    }

    /// Every element that got a listener, with the event name, in render order.
    #[derive(Default)]
    struct Listeners(Vec<(&'static str, ElementId)>);

    impl WriteMutations for Listeners {
        fn append_children(&mut self, _: ElementId, _: usize) {}
        fn assign_node_id(&mut self, _: &'static [u8], _: ElementId) {}
        fn create_placeholder(&mut self, _: ElementId) {}
        fn create_text_node(&mut self, _: &str, _: ElementId) {}
        fn load_template(&mut self, _: dioxus::core::Template, _: usize, _: ElementId) {}
        fn replace_node_with(&mut self, _: ElementId, _: usize) {}
        fn replace_placeholder_with_nodes(&mut self, _: &'static [u8], _: usize) {}
        fn insert_nodes_after(&mut self, _: ElementId, _: usize) {}
        fn insert_nodes_before(&mut self, _: ElementId, _: usize) {}
        fn set_attribute(
            &mut self,
            _: &'static str,
            _: Option<&'static str>,
            _: &dioxus::core::AttributeValue,
            _: ElementId,
        ) {
        }
        fn set_node_text(&mut self, _: &str, _: ElementId) {}
        fn create_event_listener(&mut self, name: &'static str, id: ElementId) {
            self.0.push((name, id));
        }
        fn remove_event_listener(&mut self, _: &'static str, _: ElementId) {}
        fn remove_node(&mut self, _: ElementId) {}
        fn push_root(&mut self, _: ElementId) {}
    }

    /// A mouse event on `id` as the WebView sends it: `button` at screen point `at`.
    fn mouse(dom: &VirtualDom, name: &str, id: ElementId, button: MouseButton, at: (f64, f64)) {
        let point = |x, y| (ScreenPoint::new(x, y), ClientPoint::new(x, y));
        let (screen, client) = point(at.0, at.1);
        let data = SerializedMouseData::new(
            Some(button),
            Default::default(),
            Coordinates::new(
                screen,
                client,
                ElementPoint::new(0.0, 0.0),
                PagePoint::new(at.0, at.1),
            ),
            Modifiers::empty(),
        );
        let data = PlatformEventData::new(Box::new(data));
        let event = dioxus::core::Event::new(Rc::new(data) as Rc<dyn std::any::Any>, true);
        dom.runtime().handle_event(name, event, id);
    }

    /// The title strip moves the window (the installed build of 15.11.2026 did not move at all):
    /// it carries the press handler, a second press on the same spot maximises or restores, a
    /// secondary press does nothing, and neither a caption button nor a resize handle starts a
    /// move (they are the strip's siblings, so their presses never reach it).
    #[test]
    fn only_the_strip_moves_the_window() {
        // the desktop renderer installs it; the handlers read the button and the point
        dioxus::html::set_event_converter(Box::new(dioxus::html::SerializedHtmlEventConverter));
        let acts = Acts::default();
        let mut dom = VirtualDom::new(chrome_root).with_root_context(acts.clone());
        let mut listeners = Listeners::default();
        dom.rebuild(&mut listeners);
        let ids = |name: &str| -> Vec<ElementId> {
            listeners
                .0
                .iter()
                .filter(|(n, _)| *n == name)
                .map(|(_, id)| *id)
                .collect()
        };
        let (presses, clicks) = (ids("mousedown"), ids("click"));
        // the strip and the three resize handles take presses; the caption buttons take clicks
        assert_eq!((presses.len(), clicks.len()), (4, 3), "{:?}", listeners.0);
        let take = || std::mem::take(&mut *acts.borrow_mut());

        let strip = presses[0];
        mouse(
            &dom,
            "mousedown",
            strip,
            MouseButton::Primary,
            (300.0, 120.0),
        );
        assert_eq!(take(), [WindowAct::Move]);
        mouse(
            &dom,
            "mousedown",
            strip,
            MouseButton::Primary,
            (301.0, 121.0),
        );
        assert_eq!(take(), [WindowAct::ToggleMaximize]);
        mouse(
            &dom,
            "mousedown",
            strip,
            MouseButton::Primary,
            (301.0, 121.0),
        );
        assert_eq!(take(), [WindowAct::Move], "a third press starts afresh");
        mouse(
            &dom,
            "mousedown",
            strip,
            MouseButton::Secondary,
            (500.0, 120.0),
        );
        assert_eq!(take(), []);

        for &id in &clicks {
            mouse(&dom, "mousedown", id, MouseButton::Primary, (900.0, 10.0));
        }
        assert_eq!(take(), [], "a caption button never starts a move");
        for &id in &clicks {
            mouse(&dom, "click", id, MouseButton::Primary, (900.0, 10.0));
        }
        assert_eq!(
            take(),
            [
                WindowAct::Minimize,
                WindowAct::ToggleMaximize,
                WindowAct::Close
            ]
        );
        for &id in &presses[1..] {
            mouse(&dom, "mousedown", id, MouseButton::Primary, (4.0, 2.0));
        }
        assert_eq!(
            take(),
            [
                WindowAct::Resize(ResizeDirection::North),
                WindowAct::Resize(ResizeDirection::NorthWest),
                WindowAct::Resize(ResizeDirection::NorthEast),
            ]
        );
        dom.render_immediate(&mut NoOpMutations);
    }

    /// A double click is two presses within Windows' default time and distance; a slow second
    /// press, or one after the window moved, starts a move again.
    #[test]
    fn strip_double_click_by_time_and_distance() {
        let t0 = Instant::now();
        let mut strip = StripPresses::default();
        assert_eq!(strip.press(t0, (10.0, 10.0)), WindowAct::Move);
        let late = t0 + DOUBLE_CLICK_TIME + Duration::from_millis(1);
        assert_eq!(strip.press(late, (10.0, 10.0)), WindowAct::Move);
        let moved = late + Duration::from_millis(100);
        assert_eq!(strip.press(moved, (40.0, 10.0)), WindowAct::Move);
        let quick = moved + Duration::from_millis(300);
        assert_eq!(strip.press(quick, (43.0, 13.0)), WindowAct::ToggleMaximize);
        assert_eq!(strip.press(quick, (43.0, 13.0)), WindowAct::Move);
    }

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
