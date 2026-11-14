//! [`TrayHost`]: the Dioxus side of the tray. It pumps the app's [`TrayState`] into a signal,
//! keeps the native tray in sync, answers menu clicks and tray clicks, decides what a window close
//! does (lifecycle §3.7) and runs the quit flow: the window is hidden first and only closed after
//! the cleanup succeeded; a refused cleanup brings it back with the choice (A-12, H-06).
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Instant;

use dioxus::desktop::tao::event::{Event, WindowEvent};
use dioxus::desktop::trayicon::{MouseButton, MouseButtonState, TrayIconEvent};
use dioxus::desktop::{
    DesktopContext, WindowCloseBehaviour, use_muda_event_handler, use_tray_icon_event_handler,
    use_window, use_wry_event_handler,
};
use dioxus::prelude::*;
use tokio::sync::watch;
use vpnte_base::{AppResult, Msg};

use super::model::{CloseAction, TrayExtras, TrayItemId, TrayModel, TrayState};
use super::native::{ALWAYS_MENU_ID, NativeReport, NativeTray, SPEED_REFRESH, UPDATE_MENU_ID};
use crate::helper::{Capability, HelperApi};
use crate::hooks::use_watch;
use crate::lang::{LANG, tr, translate};
use crate::settings::{KillSwitchLevel, KillSwitchView, SettingsApi};
use crate::t;
use crate::updates::{UpdatesApi, UpdatesView};
use crate::widgets::{Button, ButtonKind, Modal, ModalSize};

/// How the quit cleanup treats a failed rollback of the Proxy-mode tweaks (system proxy, variables).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuitMode {
    /// Restore everything; a failed rollback refuses the exit and the user is asked.
    Restore,
    /// «Выйти без восстановления»: exit anyway; the tweak journal rolls back at the next start.
    SkipRestore,
}

/// Backend side of the tray, implemented by the app ([`super::DemoTray`] in the demo).
#[async_trait::async_trait(?Send)]
pub trait TrayApi: 'static {
    /// The tray inputs, pushed on every change.
    fn state(&self) -> watch::Receiver<TrayState>;
    /// «Включить защиту»: the connect the settings describe (owner `manual`, source `tray`).
    async fn start(&self) -> AppResult<()>;
    /// «Выключить защиту».
    async fn stop(&self) -> AppResult<()>;
    /// «Проверить маршрут»: the leak check as a registry operation; the verdict is a notice.
    async fn check_route(&self) -> AppResult<()>;
    /// «Открыть логи»: the log folder in Explorer.
    async fn open_logs(&self) -> AppResult<()>;
    /// The bounded shutdown cleanup. `Ok`: the process may exit now. `Err`: the exit is refused
    /// (a failed Proxy-mode rollback under [`QuitMode::Restore`]); its message is shown to the user.
    async fn quit(&self, mode: QuitMode) -> AppResult<()>;
}

/// Shows, restores and focuses the window (tray click, «Показать окно», a second launch).
pub fn show_window(desktop: &DesktopContext) {
    set_webview_hidden(desktop, false);
    desktop.window.set_visible(true);
    if desktop.window.is_minimized() {
        desktop.window.set_minimized(false);
    }
    desktop.window.set_focus();
}

/// Hides the window to the tray.
pub fn hide_to_tray(desktop: &DesktopContext) {
    desktop.window.set_visible(false);
    set_webview_hidden(desktop, true);
}

/// Hiding the window alone keeps the page "visible" and rendering. With the WebView2 controller
/// hidden too, rAF stops and the working set drops from ~370 MB to ~57 MB (cookbook §9); the
/// VirtualDom keeps running, so the tray menu still updates. A start in the tray needs it too:
/// wry creates the controller visible whatever the window is.
pub(crate) fn set_webview_hidden(desktop: &DesktopContext, hidden: bool) {
    use dioxus::desktop::wry::{MemoryUsageLevel, WebViewExtWindows};
    let level = if hidden {
        MemoryUsageLevel::Low
    } else {
        MemoryUsageLevel::Normal
    };
    if let Err(err) = desktop.webview.set_visible(!hidden) {
        tracing::warn!(%err, "WebView2 visibility not changed");
    }
    if let Err(err) = desktop.webview.set_memory_usage_level(level) {
        tracing::warn!(%err, "WebView2 memory level not changed");
    }
}

/// A modal question of the tray host, shown over the page.
#[derive(Clone, Debug, PartialEq)]
enum TrayDialog {
    /// The quit cleanup was refused; `reason` comes from the backend.
    QuitFailed { reason: Msg },
}

/// What [`TrayHost`] shares with the page below it.
#[derive(Clone, Copy)]
pub struct TrayContext {
    /// The current model (what the tray shows, before rendering).
    pub model: Memo<TrayModel>,
    /// The native tray as Win32 holds it; `None` when no tray icon could be created.
    pub native: Signal<Option<NativeReport>>,
}

/// A button of a [`TrayDialog`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Choice {
    Cancel,
    Retry,
    ExitAnyway,
}

/// Pushes `model` to the native tray and publishes what it holds.
fn sync(
    native: &RefCell<Option<NativeTray>>,
    model: &TrayModel,
    lang: crate::lang::Lang,
    mut report: Signal<Option<NativeReport>>,
) {
    let mut native = native.borrow_mut();
    let Some(tray) = native.as_mut() else {
        return;
    };
    tray.apply(model, lang, Instant::now());
    let next = tray.report();
    if report.peek().as_ref() != Some(&next) {
        report.set(Some(next));
    }
}

/// Whether `value`'s debug form is exactly `expected`, without building it: formatting stops at
/// the first difference. dioxus keeps its `UserWindowEvent` type private, so the event behind
/// `DesktopContext::close()` (the HTML title-bar ×) is only recognisable by its debug form
/// `CloseWindow(<id>)` (dioxus is pinned at =0.7.10). The early stop also keeps `Ipc` events,
/// which can carry what the user typed, from being copied into a string on every event.
fn debug_equals(value: &impl std::fmt::Debug, expected: &str) -> bool {
    struct Rest<'a>(&'a str);
    impl std::fmt::Write for Rest<'_> {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            self.0 = self.0.strip_prefix(s).ok_or(std::fmt::Error)?;
            Ok(())
        }
    }
    let mut rest = Rest(expected);
    std::fmt::write(&mut rest, format_args!("{value:?}")).is_ok() && rest.0.is_empty()
}

/// The window's crash watch (`launch`) sets it while the window is lost after a WebView2 crash;
/// it lives as long as that window's VirtualDom (a new window starts with its own, unset).
#[derive(Clone, Copy)]
pub(crate) struct WindowLost(pub(crate) Signal<bool>);

/// What the tray reads from the root's Settings and Updates backends (none in the demo): "Always"
/// in force and the app version on offer; and from the window's crash watch: the window is lost.
fn use_extras() -> (Option<Rc<dyn SettingsApi>>, Memo<TrayExtras>) {
    let settings = try_use_context::<Rc<dyn SettingsApi>>();
    let updates = try_use_context::<Rc<dyn UpdatesApi>>();
    let lost = try_use_context::<WindowLost>();
    let source = settings.clone();
    let kill = use_watch(move || match source {
        Some(api) => api.kill_switch(),
        None => watch::channel(KillSwitchView::default()).1,
    });
    let offer = use_watch(move || match updates {
        Some(api) => api.state(),
        None => watch::channel(UpdatesView::default()).1,
    });
    let helper = try_use_context::<Rc<dyn HelperApi>>();
    let capability = use_watch(move || match helper {
        Some(api) => api.capability(),
        None => watch::channel(Capability::default()).1,
    });
    let extras = use_memo(move || {
        let kill = kill.read();
        TrayExtras {
            // As the start page reads it: a stored "Always" nothing keeps works as "If the VPN
            // drops", where the disconnect gives the internet back.
            always: kill.level == KillSwitchLevel::Strict && kill.always_available,
            update: offer.read().app.as_ref().map(|app| app.version.clone()),
            window_lost: lost.is_some_and(|WindowLost(lost)| lost()),
            service_note: capability.read().service.pause_key().map(Msg::new),
        }
    });
    (settings, extras)
}

/// The tray. Mount it once around the app's root; it needs `Rc<dyn TrayApi>` in context and
/// provides [`TrayContext`] to its children.
#[component]
pub fn TrayHost(children: Element) -> Element {
    let api = use_context::<Rc<dyn TrayApi>>();
    let desktop = use_window();
    let state = use_watch(|| api.state());
    let (settings, extras) = use_extras();
    let mut quitting = use_signal(|| false);
    let mut dialog = use_signal(|| None::<TrayDialog>);
    let model = use_memo(move || TrayModel::build_with(&state.read(), &extras.read(), quitting()));
    let native = use_hook(|| Rc::new(RefCell::new(NativeTray::new(&model.peek(), *LANG.peek()))));
    let report = use_signal(|| native.borrow().as_ref().map(NativeTray::report));
    use_hook({
        let desktop = desktop.clone();
        // The window always hides on close; the close handler below decides what else happens
        // (with dioxus' default the window is destroyed and the loop ends before any cleanup).
        move || desktop.set_close_behavior(WindowCloseBehaviour::WindowHides)
    });
    use_effect({
        let native = native.clone();
        move || sync(&native, &model.read(), *LANG.read(), report)
    });
    // Speed-only changes are held back for a second; this brings the latest figures out.
    use_future({
        let native = native.clone();
        move || {
            let native = native.clone();
            async move {
                let mut tick = tokio::time::interval(SPEED_REFRESH);
                loop {
                    tick.tick().await;
                    sync(&native, &model.peek(), *LANG.peek(), report);
                }
            }
        }
    });
    let start_quit = use_callback({
        let (api, desktop) = (api.clone(), desktop.clone());
        move |mode: QuitMode| {
            if *quitting.peek() {
                return;
            }
            quitting.set(true);
            dialog.set(None);
            hide_to_tray(&desktop);
            let (api, desktop) = (api.clone(), desktop.clone());
            spawn(async move {
                match api.quit(mode).await {
                    Ok(()) => {
                        tracing::info!(?mode, "shutdown cleanup done; closing the window");
                        desktop.set_close_behavior(WindowCloseBehaviour::WindowCloses);
                        desktop.close();
                    }
                    Err(err) => {
                        tracing::error!(error = %err, ?mode, "shutdown refused; window shown again");
                        quitting.set(false);
                        dialog.set(Some(TrayDialog::QuitFailed {
                            reason: err.user_msg(),
                        }));
                        show_window(&desktop);
                    }
                }
            });
        }
    });
    let on_close = use_callback({
        let (native, desktop) = (native.clone(), desktop.clone());
        move |()| {
            if *quitting.peek() {
                return;
            }
            // Without a tray icon a hidden window could never come back.
            let has_tray = native.borrow().is_some();
            match state.peek().close_action() {
                // dioxus hides the window right after this handler
                CloseAction::Hide if has_tray => set_webview_hidden(&desktop, true),
                CloseAction::Hide | CloseAction::Quit => start_quit(QuitMode::Restore),
            }
        }
    });
    use_wry_event_handler({
        let id = desktop.window.id();
        let close_window = format!("CloseWindow({id:?})");
        move |event, _| {
            let close = match event {
                Event::WindowEvent {
                    window_id,
                    event: WindowEvent::CloseRequested,
                    ..
                } => *window_id == id,
                Event::UserEvent(user) => debug_equals(user, &close_window),
                _ => false,
            };
            if close {
                on_close(());
            }
        }
    });
    use_tray_icon_event_handler({
        let desktop = desktop.clone();
        move |event| match event {
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            }
            | TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            } => show_window(&desktop),
            _ => {}
        }
    });
    use_muda_event_handler({
        let (api, desktop) = (api.clone(), desktop.clone());
        move |event| {
            let Some(click) = click(&event.id().0) else {
                return;
            };
            if click
                .entry()
                .is_some_and(|id| !model.peek().item(id).enabled)
            {
                return;
            }
            match click {
                // The offer and its buttons are on the start page and in Settings.
                Click::Window | Click::Item(TrayItemId::Show) => show_window(&desktop),
                Click::TurnOffAlways => {
                    if let Some(settings) = settings.clone() {
                        spawn(turn_off_always(settings, desktop.clone()));
                    }
                }
                Click::Item(TrayItemId::Quit) => start_quit(QuitMode::Restore),
                Click::Item(
                    id @ (TrayItemId::Start
                    | TrayItemId::Stop
                    | TrayItemId::CheckRoute
                    | TrayItemId::OpenLogs),
                ) => {
                    let (api, desktop) = (api.clone(), desktop.clone());
                    spawn(async move { run_action(api.as_ref(), id, &desktop).await });
                }
                Click::Item(_) => {}
            }
        }
    });
    use_context_provider(|| TrayContext {
        model,
        native: report,
    });
    let on_choice = move |choice: Choice| match choice {
        Choice::Retry => start_quit(QuitMode::Restore),
        Choice::ExitAnyway => start_quit(QuitMode::SkipRestore),
        Choice::Cancel => dialog.set(None),
    };
    let open = use_memo(move || dialog.read().is_some());
    rsx! {
        {children}
        Question { open, dialog, on_choice }
    }
}

/// Runs a menu action. Errors are logged, never dropped silently (`tray.ts:133-141`); a failed
/// start and every route check end with the window shown, where the details are (§3.11).
/// What a menu click asks for, read from the id its entry was built with, never from a newer
/// state: the label the user read belongs to that id (pfollow-b2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Click {
    /// The update line.
    Window,
    /// «Выключить «Всегда»» (the Stop entry while "Always" holds a pause).
    TurnOffAlways,
    Item(TrayItemId),
}

impl Click {
    /// The entry whose enabled flag gates the click (none for the update line).
    fn entry(self) -> Option<TrayItemId> {
        match self {
            Click::Window => None,
            Click::TurnOffAlways => Some(TrayItemId::Stop),
            Click::Item(id) => Some(id),
        }
    }
}

fn click(id: &str) -> Option<Click> {
    match id {
        UPDATE_MENU_ID => Some(Click::Window),
        ALWAYS_MENU_ID => Some(Click::TurnOffAlways),
        id => TrayItemId::from_menu_id(id).map(Click::Item),
    }
}

async fn run_action(api: &dyn TrayApi, id: TrayItemId, desktop: &DesktopContext) {
    let result = match id {
        TrayItemId::Start => api.start().await,
        TrayItemId::Stop => api.stop().await,
        TrayItemId::CheckRoute => api.check_route().await,
        _ => api.open_logs().await,
    };
    if let Err(err) = &result {
        tracing::error!(target: "tray", action = id.menu_id(), error = %err, "tray action failed");
    }
    let show = match id {
        TrayItemId::Start => result.is_err(),
        TrayItemId::CheckRoute => true,
        _ => false,
    };
    if show {
        show_window(desktop);
    }
}

/// «Выключить «Всегда»» in the paused menu: the level goes to "If the VPN drops", as the start
/// page's button does (the pause then offers «Продолжить без VPN»). A failure shows the window,
/// where the pause offers the same button.
async fn turn_off_always(settings: Rc<dyn SettingsApi>, desktop: DesktopContext) {
    if let Err(err) = settings
        .set_kill_switch_level(KillSwitchLevel::Standard)
        .await
    {
        tracing::error!(target: "tray", error = %err, "\"Always\" not turned off");
        show_window(&desktop);
    }
}

/// Texts and buttons of a dialog: `(title, message, detail, [(choice, label key)])`; the first
/// button is the default one.
type Content = (String, String, String, Vec<(Choice, &'static str)>);

fn dialog_content(dialog: &TrayDialog) -> Content {
    match dialog {
        TrayDialog::QuitFailed { reason } => (
            t!("ui.tray.quitFailed.title"),
            tr(reason),
            t!("ui.tray.quitFailed.note"),
            vec![
                (Choice::Retry, "ui.tray.quitFailed.retry"),
                (Choice::ExitAnyway, "ui.tray.quitFailed.exitAnyway"),
            ],
        ),
    }
}

/// The open question as a [`Modal`]: the page behind is inert, Tab stays inside, the focus starts
/// on the default (first) button and returns afterwards. Escape is «Отмена»; on the refused quit it
/// dismisses the question and keeps the app open, as the old «Оставить открытым» did.
#[component]
fn Question(
    open: ReadSignal<bool>,
    dialog: ReadSignal<Option<TrayDialog>>,
    on_choice: EventHandler<Choice>,
) -> Element {
    let (title, message, detail, buttons) = dialog
        .read()
        .as_ref()
        .map(dialog_content)
        .unwrap_or_default();
    rsx! {
        Modal {
            open,
            title,
            description: message,
            on_close: move |()| on_choice.call(Choice::Cancel),
            close_label: t!("common.cancel"),
            show_close: false,
            // three buttons with these labels overflow the 420 px confirmation width
            size: ModalSize::Md,
            footer: rsx! {
                for (i , (choice , key)) in buttons.into_iter().enumerate() {
                    Button {
                        key: "{key}",
                        kind: if i == 0 { ButtonKind::Primary } else { ButtonKind::Ghost },
                        initial_focus: i == 0,
                        onclick: move |_| on_choice.call(choice),
                        {translate(key, &[], None)}
                    }
                }
            },
            p { class: "w-confirm-text", "{detail}" }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    #[derive(Debug)]
    enum Event {
        Poll(u32),
        CloseWindow(u32),
        Ipc { msg: String },
    }

    #[test]
    fn close_window_is_recognised_by_its_debug_form() {
        assert!(debug_equals(&Event::CloseWindow(7), "CloseWindow(7)"));
        assert!(!debug_equals(&Event::CloseWindow(70), "CloseWindow(7)"));
        assert!(!debug_equals(&Event::CloseWindow(7), "CloseWindow(70)"));
        assert!(!debug_equals(&Event::Poll(7), "CloseWindow(7)"));
        let typed = Event::Ipc {
            msg: "x".repeat(10_000),
        };
        assert!(!debug_equals(&typed, "CloseWindow(7)"));
    }

    /// fix-follow (pfollow-b2): a click does what its entry said when it was drawn: «Выключить
    /// «Всегда»» and the disconnect have their own ids, nothing is read from a newer state.
    #[test]
    fn a_click_does_what_its_entry_said() {
        assert_eq!(click(ALWAYS_MENU_ID), Some(Click::TurnOffAlways));
        let stop = TrayItemId::Stop.menu_id();
        assert_eq!(click(stop), Some(Click::Item(TrayItemId::Stop)));
        assert_eq!(click(UPDATE_MENU_ID), Some(Click::Window));
        assert_eq!(click("tray.unknown"), None);
        assert_eq!(Click::TurnOffAlways.entry(), Some(TrayItemId::Stop));
        assert_eq!(Click::Window.entry(), None);
    }
}
