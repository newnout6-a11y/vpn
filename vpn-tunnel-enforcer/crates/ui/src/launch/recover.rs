//! WebView2 process failures (`ICoreWebView2::ProcessFailed`). WebView2 restarts its helper
//! processes by itself. A dead page renderer or browser process leaves dioxus-desktop 0.7.10
//! without a page: its edit queue stalls and the VirtualDom stops (tray actions, Quit, a second
//! launch's activation). So the window is rebuilt ([`super::remount`]): a new window with a new
//! VirtualDom over the same root contexts, in the old one's place and state. After a dead browser
//! process the new window waits until its processes are gone (WebView2 asks for that before a new
//! environment on the same user-data folder).
//!
//! The crashed window hides at once; a dead renderer's window opens the [`stand_in`] page, so its
//! VirtualDom keeps running (tray, Quit with its cleanup) until the new window has mounted and the
//! old one closes. At most [`MAX_REBUILDS`] automatic rebuilds per [`REBUILD_SPAN`]; beyond that,
//! or when a new window does not come up, the old one stays hidden as the crash left it and the
//! next request to show it (the tray, a second launch) builds a new one.
use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};

use dioxus::desktop::tao::event::{Event, WindowEvent};
use dioxus::desktop::wry::WebViewExtWindows;
use dioxus::desktop::{DesktopContext, use_muda_event_handler, use_window, use_wry_event_handler};
use dioxus::prelude::*;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    COREWEBVIEW2_PROCESS_FAILED_KIND, COREWEBVIEW2_PROCESS_FAILED_KIND_BROWSER_PROCESS_EXITED,
    COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_EXITED,
    COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_UNRESPONSIVE, ICoreWebView2Environment5,
    ICoreWebView2ProcessFailedEventArgs, ICoreWebView2ProcessFailedEventArgs2,
};
use webview2_com::{
    AddScriptToExecuteOnDocumentCreatedCompletedHandler, BrowserProcessExitedEventHandler,
    NavigationCompletedEventHandler, NavigationStartingEventHandler, ProcessFailedEventHandler,
    take_pwstr,
};
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::{KillTimer, SetTimer};
use windows_core_061::{BOOL, HSTRING, Interface, PWSTR};

use super::remount::{MAX_REBUILDS, REBUILD_SPAN, Rebuild, Shape};
use super::stand_in::{self, OPEN_DELAY_MS, StandIn};
use crate::tray::{TrayItemId, WindowLost, hide_to_tray, show_window};

/// How long a rebuild after a dead browser process waits for `BrowserProcessExited` before it
/// opens the new window anyway (a new environment too early can fail, and dioxus panics then).
const BROWSER_WAIT_MS: u32 = 10_000;
/// How long a new window may take to mount (its page loads in about a second); one that did not
/// is closed and the old one waits for the user, as after the rebuild limit.
const MOUNT_WAIT_MS: u32 = 30_000;

/// What a process failure means for the window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The page's renderer died: the page is gone, the controller lives.
    Renderer,
    /// The renderer hangs; it may come back.
    Unresponsive,
    /// The browser process died, and the controller with it.
    Browser,
    /// A helper (GPU, utility, sandbox, plugin, an iframe's renderer): WebView2 restarts it.
    Helper,
}

impl Failure {
    pub(crate) fn of(kind: COREWEBVIEW2_PROCESS_FAILED_KIND) -> Failure {
        match kind {
            COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_EXITED => Failure::Renderer,
            COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_UNRESPONSIVE => Failure::Unresponsive,
            COREWEBVIEW2_PROCESS_FAILED_KIND_BROWSER_PROCESS_EXITED => Failure::Browser,
            _ => Failure::Helper,
        }
    }
}

/// Where a window is in its crash handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Live,
    /// The browser process died: the rebuild waits for its processes to end.
    Waiting,
    /// A new window is on its way; this one closes when it has mounted.
    Replaced,
    /// Left as the crash left it (rebuild limit): the next request to show it builds a new one.
    Lost,
    /// Left as the crash left it for good (a single-use root context).
    Stuck,
}

/// What a timer of [`later`] is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Due {
    /// The next attempt to open the stand-in page.
    StandIn,
    /// The dead browser's processes had their time to end.
    BrowserWait,
    /// The new window had its time to mount.
    MountCheck,
}

thread_local! {
    /// Pending thread timers, the watch and the purpose of each (a timer callback has no context).
    static TIMERS: RefCell<Vec<(usize, Weak<CrashWatch>, Due)>> = const { RefCell::new(Vec::new()) };
}

/// A thread timer of [`later`]: runs on the UI thread while it dispatches messages, also while
/// the VirtualDom stands still (a dead page never acknowledges its edits).
unsafe extern "system" fn on_timer(_: HWND, _: u32, id: usize, _: u32) {
    // SAFETY: a one-shot timer this thread set; a second kill is harmless.
    let _ = unsafe { KillTimer(None, id) };
    let due = TIMERS.with(|timers| {
        let mut timers = timers.borrow_mut();
        let at = timers.iter().position(|(timer, ..)| *timer == id)?;
        let (_, watch, due) = timers.swap_remove(at);
        Some((watch.upgrade()?, due))
    });
    if let Some((watch, due)) = due {
        watch.on_timer(due);
    }
}

/// Calls [`CrashWatch::on_timer`] with `due` after `ms`; `false` when no timer could be set.
fn later(watch: &Rc<CrashWatch>, ms: u32, due: Due) -> bool {
    // SAFETY: a thread timer with a plain callback; this thread runs the message loop.
    let id = unsafe { SetTimer(None, 0, ms, Some(on_timer)) };
    if id == 0 {
        return false;
    }
    TIMERS.with(|timers| timers.borrow_mut().push((id, Rc::downgrade(watch), due)));
    true
}

/// One window's crash watch.
pub(crate) struct CrashWatch {
    desktop: DesktopContext,
    rebuild: Rc<Rebuild>,
    stand_in: StandIn,
    phase: Phase,
    /// The window as the crash found it, for the new one.
    shape: Cell<Option<Shape>>,
    /// What took the page.
    failure: Cell<Option<Failure>>,
}

/// Watches the window's WebView2 for process failures. Call it once, in the root component.
pub(crate) fn use_crash_watch(rebuild: Rc<Rebuild>) {
    let desktop = use_window();
    let lost = use_signal(|| false);
    use_context_provider(|| WindowLost(lost));
    let watch = use_hook(|| {
        let home = desktop
            .webview
            .url()
            .inspect_err(|err| tracing::warn!(%err, "page address unknown"))
            .ok();
        let watch = Rc::new(CrashWatch {
            desktop: desktop.clone(),
            rebuild,
            stand_in: StandIn::new(home),
            phase: Phase::new(lost),
            shape: Cell::new(None),
            failure: Cell::new(None),
        });
        watch.register();
        watch
    });
    // A lost window is hidden; whatever shows it again (the tray, a second launch, a toast
    // click) focuses it, which is the request for a new one. Runs inside the event loop's tick,
    // so also while a dead page keeps the VirtualDom still.
    let id = desktop.window.id();
    let shown = watch.clone();
    use_wry_event_handler(move |event, _| {
        if let Event::WindowEvent {
            window_id,
            event: WindowEvent::Focused(true),
            ..
        } = event
            && *window_id == id
        {
            shown.on_shown();
        }
    });
    use_muda_event_handler(move |event| match event.id().0.as_str() {
        id if id == TrayItemId::Quit.menu_id() => watch.on_quit(),
        id if id == TrayItemId::Show.menu_id() => watch.on_open(),
        _ => {}
    });
}

/// The watch's [`State`], mirrored into the tray's [`WindowLost`] flag: set exactly while the
/// window is `Lost`, so the tray offers «Открыть окно». The window that replaces it starts with
/// its own flag, unset.
struct Phase {
    state: Cell<State>,
    lost: Signal<bool>,
}

impl Phase {
    fn new(lost: Signal<bool>) -> Phase {
        Phase {
            state: Cell::new(State::Live),
            lost,
        }
    }

    fn get(&self) -> State {
        self.state.get()
    }

    /// Callers run outside the VirtualDom (WebView2 events, thread timers): a flag whose dom is
    /// gone is skipped, and an unchanged one is not written (a write wakes its readers).
    fn set(&self, state: State) {
        self.state.set(state);
        let lost = state == State::Lost;
        let mut flag = self.lost;
        if flag.try_peek().is_ok_and(|now| *now != lost)
            && let Ok(mut value) = flag.try_write()
        {
            *value = lost;
        }
    }
}

impl CrashWatch {
    /// Registers the handlers and the stand-in script for the life of the webview.
    fn register(self: &Rc<Self>) {
        let webview = self.desktop.webview.webview();
        let this = Rc::downgrade(self);
        let failed = ProcessFailedEventHandler::create(Box::new(move |_, args| {
            if let (Some(this), Some(args)) = (this.upgrade(), args) {
                this.on_failure(&args);
            }
            Ok(())
        }));
        let this = Rc::downgrade(self);
        let completed = NavigationCompletedEventHandler::create(Box::new(move |_, args| {
            if let (Some(this), Some(args)) = (this.upgrade(), args) {
                let mut ok = BOOL(0);
                // SAFETY: COM getter on the event's live arguments, UI thread; `ok` is live.
                let read = unsafe { args.IsSuccess(&mut ok) };
                this.on_navigated(read.is_ok() && ok.as_bool());
            }
            Ok(())
        }));
        // dioxus-desktop lets its own page load only once (its navigation handler cancels every
        // later load of it, a reload included). Added after it, this one lets exactly the
        // stand-in page through, and only while it is being opened.
        let this = Rc::downgrade(self);
        let starting = NavigationStartingEventHandler::create(Box::new(move |_, args| {
            if let (Some(this), Some(args)) = (this.upgrade(), args) {
                let mut uri = PWSTR::null();
                // SAFETY: COM getter on the event's live arguments, UI thread; `take_pwstr`
                // frees the string.
                let uri = unsafe { args.Uri(&mut uri) }.map(|()| take_pwstr(uri));
                if uri.is_ok_and(|uri| this.stand_in.lets_through(&uri)) {
                    // SAFETY: COM setter on the event's live arguments, UI thread.
                    unsafe { args.SetCancel(false) }?;
                }
            }
            Ok(())
        }));
        let script = HSTRING::from(stand_in::STAND_IN_JS);
        let added =
            AddScriptToExecuteOnDocumentCreatedCompletedHandler::create(Box::new(|added, _| {
                if let Err(err) = added {
                    tracing::warn!(%err, "renderer crash stand-in not prepared");
                }
                Ok(())
            }));
        let mut token = 0;
        // SAFETY: COM calls on the UI (STA) thread on a live interface; `token` outlives each
        // call and WebView2 copies the script.
        let registered = unsafe {
            webview
                .add_ProcessFailed(&failed, &mut token)
                .and_then(|()| webview.add_NavigationCompleted(&completed, &mut token))
                .and_then(|()| webview.add_NavigationStarting(&starting, &mut token))
                .and_then(|()| webview.AddScriptToExecuteOnDocumentCreated(&script, &added))
        };
        if let Err(err) = registered {
            tracing::warn!(%err, "WebView2 process failures not fully watched");
        }
        self.watch_browser_exit();
    }

    /// `BrowserProcessExited` of the window's environment: every process of a dead browser has
    /// ended, a new environment on the same user-data folder can start.
    fn watch_browser_exit(self: &Rc<Self>) {
        let this = Rc::downgrade(self);
        let exited = BrowserProcessExitedEventHandler::create(Box::new(move |_, _| {
            if let Some(this) = this.upgrade() {
                this.on_browser_gone();
            }
            Ok(())
        }));
        let mut token = 0;
        let environment = self.desktop.webview.environment();
        // SAFETY: COM calls on the UI (STA) thread on a live interface; `token` outlives the call.
        let registered =
            environment
                .cast::<ICoreWebView2Environment5>()
                .and_then(|environment| unsafe {
                    environment.add_BrowserProcessExited(&exited, &mut token)
                });
        if let Err(err) = registered {
            tracing::warn!(%err, "WebView2 browser exit not watched; a rebuild waits for its timer");
        }
    }
}

impl CrashWatch {
    fn on_failure(self: &Rc<Self>, args: &ICoreWebView2ProcessFailedEventArgs) {
        let mut kind = COREWEBVIEW2_PROCESS_FAILED_KIND::default();
        // SAFETY: COM getters on the event's live arguments, UI thread; out pointers are live.
        let exit_code = unsafe {
            if let Err(err) = args.ProcessFailedKind(&mut kind) {
                tracing::warn!(%err, "WebView2 process failure of unknown kind");
                return;
            }
            let mut code = 0;
            args.cast::<ICoreWebView2ProcessFailedEventArgs2>()
                .and_then(|args| args.ExitCode(&mut code))
                .ok()
                .map(|()| code)
        };
        match Failure::of(kind) {
            Failure::Helper => tracing::info!(
                kind = kind.0,
                ?exit_code,
                "WebView2 helper process exited; WebView2 restarts it"
            ),
            Failure::Unresponsive => tracing::warn!("WebView2 renderer unresponsive"),
            failure => self.on_page_lost(failure, exit_code),
        }
    }

    /// The page's renderer or the browser process died.
    fn on_page_lost(self: &Rc<Self>, failure: Failure, exit_code: Option<i32>) {
        match self.phase.get() {
            State::Live => {}
            // The stand-in page's own renderer died: open it again (bounded by the stand-in).
            _ if failure == Failure::Renderer => return self.open_stand_in(),
            _ => return,
        }
        // Before the window hides: the new one takes this state over.
        self.shape.set(Some(Shape::of(&self.desktop.window)));
        self.failure.set(Some(failure));
        self.shelve(failure);
        if !self.rebuild.reusable {
            tracing::error!(
                ?failure,
                ?exit_code,
                "WebView2 page lost; the window cannot be rebuilt (a root context is single-use), the tray keeps working"
            );
            return self.phase.set(State::Stuck);
        }
        if !self.rebuild.allow() {
            tracing::error!(
                ?failure,
                ?exit_code,
                max = MAX_REBUILDS,
                minutes = REBUILD_SPAN.as_secs() / 60,
                "WebView2 crashed too often; the window stays closed until it is opened from the tray"
            );
            return self.phase.set(State::Lost);
        }
        if failure == Failure::Browser {
            tracing::warn!(
                ?exit_code,
                "WebView2 browser process exited; a new window opens once its processes are gone"
            );
            self.phase.set(State::Waiting);
            if !later(self, BROWSER_WAIT_MS, Due::BrowserWait) {
                self.replace();
            }
        } else {
            tracing::warn!(?exit_code, "WebView2 renderer exited; opening a new window");
            self.replace();
        }
    }

    /// Hides the window as the crash left it. A dead renderer's window gets the stand-in page,
    /// so its VirtualDom (the tray, Quit with its cleanup) keeps running until it is replaced; a
    /// dead browser took the controller with it.
    fn shelve(self: &Rc<Self>, failure: Failure) {
        if failure == Failure::Renderer {
            hide_to_tray(&self.desktop);
            self.open_stand_in();
        } else {
            self.desktop.window.set_visible(false);
        }
    }

    fn open_stand_in(self: &Rc<Self>) {
        if self.stand_in.start() && !later(self, OPEN_DELAY_MS, Due::StandIn) {
            tracing::error!("renderer crash stand-in not opened: no timer");
        }
    }

    /// A new window replaces this one, in the state the crash found it in.
    fn replace(self: &Rc<Self>) {
        let shape = self
            .shape
            .get()
            .unwrap_or_else(|| Shape::of(&self.desktop.window));
        if !self.rebuild.open(&self.desktop, shape) {
            tracing::warn!("another window rebuild is under way; this window stays closed");
            return self.phase.set(State::Lost);
        }
        self.phase.set(State::Replaced);
        if !later(self, MOUNT_WAIT_MS, Due::MountCheck) {
            tracing::warn!("no timer to check that the new window comes up");
        }
    }

    /// Every process of the dead browser has ended.
    fn on_browser_gone(self: &Rc<Self>) {
        if self.phase.get() == State::Waiting {
            self.replace();
        }
    }

    fn on_timer(self: &Rc<Self>, due: Due) {
        match due {
            Due::StandIn => self.stand_in.open(&self.desktop),
            Due::BrowserWait if self.phase.get() == State::Waiting => {
                tracing::warn!("no WebView2 browser exit report in time; opening the new window");
                self.replace();
            }
            Due::MountCheck
                if self.phase.get() == State::Replaced && self.rebuild.abandon(&self.desktop) =>
            {
                tracing::error!(
                    "the new WebView2 window did not come up; the window stays closed until it is opened from the tray"
                );
                self.phase.set(State::Lost);
            }
            Due::BrowserWait | Due::MountCheck => {}
        }
    }

    /// The window was focused, which a lost (hidden) window only is when something shows it: a
    /// new window replaces it now, in the state it is shown in.
    fn on_shown(self: &Rc<Self>) {
        if self.phase.get() == State::Lost {
            tracing::info!("window opened again after a WebView2 crash");
            self.shape.set(Some(Shape::of(&self.desktop.window)));
            self.replace();
        }
    }

    /// The tray's «Открыть окно» (or «Показать окно») on a lost window: shown first, so the new
    /// window comes up shown, then rebuilt at once instead of waiting for the focus Windows may
    /// not give. The tray shows the window as well; its focus finds the rebuild under way.
    fn on_open(self: &Rc<Self>) {
        if self.phase.get() == State::Lost {
            show_window(&self.desktop);
            self.on_shown();
        }
    }

    /// The tray's Quit while a new window is on its way. This window's VirtualDom runs the quit
    /// (the stand-in keeps it running after a dead renderer) and closes this window at its end;
    /// a new window would keep the process alive past it, or drop this one mid-quit when it
    /// mounts. So the new window goes; a refused quit shows this window, which then rebuilds.
    /// After a dead browser this VirtualDom stands still: the rebuild goes on, the new tray quits.
    fn on_quit(&self) {
        if self.phase.get() == State::Replaced
            && self.failure.get() == Some(Failure::Renderer)
            && self.rebuild.abandon(&self.desktop)
        {
            tracing::info!("quit while the window was being rebuilt; the new window is closed");
            self.phase.set(State::Lost);
        }
    }

    /// A navigation ended: a failed attempt to open the stand-in page is retried.
    fn on_navigated(self: &Rc<Self>, ok: bool) {
        if self.stand_in.on_navigated(ok) && !later(self, OPEN_DELAY_MS, Due::StandIn) {
            tracing::error!("renderer crash stand-in not opened: no timer");
        }
    }
}

#[cfg(test)]
mod tests {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        COREWEBVIEW2_PROCESS_FAILED_KIND_FRAME_RENDER_PROCESS_EXITED,
        COREWEBVIEW2_PROCESS_FAILED_KIND_GPU_PROCESS_EXITED,
        COREWEBVIEW2_PROCESS_FAILED_KIND_UTILITY_PROCESS_EXITED,
    };

    use super::*;

    /// p-uiperf: a dead page renderer or browser process loses the page (the window is rebuilt);
    /// a hang is reported, helpers are left to WebView2.
    #[test]
    fn failures_are_told_apart() {
        let of = Failure::of;
        assert_eq!(
            of(COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_EXITED),
            Failure::Renderer
        );
        assert_eq!(
            of(COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_UNRESPONSIVE),
            Failure::Unresponsive
        );
        assert_eq!(
            of(COREWEBVIEW2_PROCESS_FAILED_KIND_BROWSER_PROCESS_EXITED),
            Failure::Browser
        );
        for helper in [
            COREWEBVIEW2_PROCESS_FAILED_KIND_GPU_PROCESS_EXITED,
            COREWEBVIEW2_PROCESS_FAILED_KIND_UTILITY_PROCESS_EXITED,
            COREWEBVIEW2_PROCESS_FAILED_KIND_FRAME_RENDER_PROCESS_EXITED,
        ] {
            assert_eq!(of(helper), Failure::Helper);
        }
    }

    /// p-tails-a: the tray's «Открыть окно» flag follows the watch: set exactly while the window
    /// is lost (rebuild limit, a new window that did not come up), unset once a new window is on
    /// its way; a flag whose VirtualDom is gone is skipped, not a panic in a WebView2 callback.
    #[test]
    fn the_tray_flag_follows_a_lost_window() {
        let dom = VirtualDom::new(|| rsx! {});
        let phase = dom.in_scope(ScopeId::ROOT, || Phase::new(Signal::new(false)));
        let lost = |phase: &Phase| dom.in_scope(ScopeId::ROOT, || *phase.lost.peek());
        assert!(!lost(&phase));
        for (state, flag) in [
            (State::Waiting, false),
            (State::Replaced, false),
            (State::Lost, true),
            (State::Lost, true),
            (State::Replaced, false),
            (State::Lost, true),
            (State::Stuck, false),
        ] {
            phase.set(state);
            assert_eq!(phase.get(), state);
            assert_eq!(lost(&phase), flag, "{state:?}");
        }
        drop(dom);
        phase.set(State::Lost);
        assert_eq!(phase.get(), State::Lost);
    }
}
