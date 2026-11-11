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

use super::model::{CloseAction, TrayItemId, TrayModel, TrayState};
use super::native::{NativeReport, NativeTray, SPEED_REFRESH};
use crate::lang::LANG;

/// How the quit cleanup treats a failed rollback of the Soft-mode system proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuitMode {
    /// Restore everything; a failed Soft env rollback refuses the exit and the user is asked.
    Restore,
    /// «Выйти без восстановления»: exit anyway; the env backup is restored at the next start.
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
    /// (a failed Soft env rollback under [`QuitMode::Restore`]); its message is shown to the user.
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
/// VirtualDom keeps running, so the tray menu still updates.
fn set_webview_hidden(desktop: &DesktopContext, hidden: bool) {
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
    /// Close requested while protection is on (§3.7).
    CloseProtected { offer_tray: bool },
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
    ToTray,
    StopAndClose,
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

/// The tray. Mount it once around the app's root; it needs `Rc<dyn TrayApi>` in context and
/// provides [`TrayContext`] to its children.
#[component]
pub fn TrayHost(children: Element) -> Element {
    let api = use_context::<Rc<dyn TrayApi>>();
    let desktop = use_window();
    let mut state = use_signal({
        let rx = api.state();
        move || rx.borrow().clone()
    });
    use_future({
        let api = api.clone();
        move || {
            let mut rx = api.state();
            async move {
                while rx.changed().await.is_ok() {
                    let next = rx.borrow_and_update().clone();
                    if *state.peek() != next {
                        state.set(next);
                    }
                }
            }
        }
    });
    let mut quitting = use_signal(|| false);
    let mut dialog = use_signal(|| None::<TrayDialog>);
    let model = use_memo(move || TrayModel::build(&state.read(), quitting()));
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
            let action = match state.peek().close_action() {
                CloseAction::Hide if !has_tray => CloseAction::Quit,
                CloseAction::Ask { offer_tray } => CloseAction::Ask {
                    offer_tray: offer_tray && has_tray,
                },
                action => action,
            };
            match action {
                // dioxus hides the window right after this handler
                CloseAction::Hide => set_webview_hidden(&desktop, true),
                CloseAction::Quit => start_quit(QuitMode::Restore),
                CloseAction::Ask { offer_tray } => {
                    dialog.set(Some(TrayDialog::CloseProtected { offer_tray }));
                    // dioxus hides the window right after this handler; a task runs after
                    // that and brings it back with the question.
                    let desktop = desktop.clone();
                    spawn(async move { show_window(&desktop) });
                }
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
            let Some(id) = TrayItemId::from_menu_id(&event.id().0) else {
                return;
            };
            if !model.peek().item(id).enabled {
                return;
            }
            match id {
                TrayItemId::Show => show_window(&desktop),
                TrayItemId::Quit => start_quit(QuitMode::Restore),
                TrayItemId::Start
                | TrayItemId::Stop
                | TrayItemId::CheckRoute
                | TrayItemId::OpenLogs => {
                    let (api, desktop) = (api.clone(), desktop.clone());
                    spawn(async move { run_action(api.as_ref(), id, &desktop).await });
                }
                TrayItemId::Status | TrayItemId::Ip | TrayItemId::Proxy | TrayItemId::Speed => {}
            }
        }
    });
    use_context_provider(|| TrayContext {
        model,
        native: report,
    });
    let on_choice = {
        let desktop = desktop.clone();
        move |choice: Choice| match choice {
            Choice::ToTray => {
                dialog.set(None);
                hide_to_tray(&desktop);
            }
            Choice::StopAndClose | Choice::Retry => start_quit(QuitMode::Restore),
            Choice::ExitAnyway => start_quit(QuitMode::SkipRestore),
            Choice::Cancel => dialog.set(None),
        }
    };
    rsx! {
        {children}
        if let Some(open) = dialog() {
            DialogView { dialog: open, on_choice }
        }
    }
}

/// Runs a menu action. Errors are logged, never dropped silently (`tray.ts:133-141`); a failed
/// start and every route check end with the window shown, where the details are (§3.11).
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

/// Texts and buttons of a dialog: `(title, message, detail, [(choice, label key)])`; the first
/// button is the default one, Esc is «Отмена» (or dismisses the refused-quit question, which
/// keeps the app open as the old «Оставить открытым» did).
fn dialog_content(dialog: &TrayDialog) -> (String, String, String, Vec<(Choice, &'static str)>) {
    use crate::t;
    match dialog {
        TrayDialog::CloseProtected { offer_tray } => {
            let mut buttons = Vec::new();
            if *offer_tray {
                buttons.push((Choice::ToTray, "ui.tray.close.toTray"));
            }
            buttons.push((Choice::StopAndClose, "ui.tray.close.stopAndClose"));
            buttons.push((Choice::Cancel, "ui.tray.close.cancel"));
            let detail = if *offer_tray {
                t!("ui.tray.close.detailTray")
            } else {
                t!("ui.tray.close.detailStop")
            };
            (
                t!("ui.tray.close.title"),
                t!("ui.tray.close.message"),
                detail,
                buttons,
            )
        }
        TrayDialog::QuitFailed { reason } => (
            t!("ui.tray.quitFailed.title"),
            crate::lang::tr(reason),
            t!("ui.tray.quitFailed.note"),
            vec![
                (Choice::Retry, "ui.tray.quitFailed.retry"),
                (Choice::ExitAnyway, "ui.tray.quitFailed.exitAnyway"),
            ],
        ),
    }
}

/// The modal card over the page: paper, hairline frame, mono caption, square buttons.
#[component]
fn DialogView(dialog: TrayDialog, on_choice: EventHandler<Choice>) -> Element {
    let (title, message, detail, buttons) = dialog_content(&dialog);
    rsx! {
        div { class: "c-swiss tray-dialog-backdrop",
            div {
                class: "tray-dialog",
                id: "tray-dialog",
                role: "alertdialog",
                aria_modal: "true",
                aria_labelledby: "tray-dialog-title",
                aria_describedby: "tray-dialog-message",
                onkeydown: move |evt| {
                    if evt.key() == Key::Escape {
                        on_choice.call(Choice::Cancel);
                    }
                },
                span { class: "swiss-label", {crate::launch::APP_NAME} }
                h2 { class: "tray-dialog-title", id: "tray-dialog-title", {title} }
                p { class: "tray-dialog-message", id: "tray-dialog-message", {message} }
                p { class: "tray-dialog-detail swiss-mono", {detail} }
                div { class: "tray-dialog-actions",
                    for (i , (choice , key)) in buttons.into_iter().enumerate() {
                        button {
                            key: "{key}",
                            r#type: "button",
                            class: if i == 0 { "tray-dialog-btn is-default" } else { "tray-dialog-btn" },
                            "data-choice": "{choice:?}",
                            onmounted: move |evt| async move {
                                if i == 0 {
                                    let _ = evt.set_focus(true).await;
                                }
                            },
                            onclick: move |_| on_choice.call(choice),
                            {crate::lang::translate(key, &[], None)}
                        }
                    }
                }
            }
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
}
