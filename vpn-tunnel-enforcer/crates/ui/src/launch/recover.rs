//! Renderer crash handling (`ICoreWebView2::ProcessFailed`). WebView2 restarts its helper
//! processes by itself. When the page's renderer dies, dioxus-desktop 0.7.10 has no page to send
//! its edit batches to: the queue stalls and the VirtualDom stops (tray menu actions, Quit and a
//! second launch's activation never run). The page cannot be built again either: dioxus keeps its
//! template ids and string caches per webview and resends none of them to a new page.
//!
//! So the window opens a stand-in page (the app's page with [`MARKER`]): a script registered at
//! start acknowledges every edit batch there and never announces the page, so the VirtualDom keeps
//! its tree and keeps running. The window stays empty until the app restarts; the tray and the
//! quit cleanup keep working. A dead browser process takes the controller with it and is only
//! logged.
use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};

use dioxus::desktop::wry::WebViewExtWindows;
use dioxus::desktop::{DesktopContext, use_window};
use dioxus::prelude::*;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    COREWEBVIEW2_PROCESS_FAILED_KIND, COREWEBVIEW2_PROCESS_FAILED_KIND_BROWSER_PROCESS_EXITED,
    COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_EXITED,
    COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_UNRESPONSIVE,
    ICoreWebView2ProcessFailedEventArgs, ICoreWebView2ProcessFailedEventArgs2,
};
use webview2_com::{
    AddScriptToExecuteOnDocumentCreatedCompletedHandler, NavigationCompletedEventHandler,
    NavigationStartingEventHandler, ProcessFailedEventHandler, take_pwstr,
};
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::{KillTimer, SetTimer};
use windows_core_061::{BOOL, HSTRING, Interface, PWSTR};

/// Stand-in pages per process: a renderer that keeps dying must not become a reload loop.
const MAX_STAND_INS: u32 = 3;
/// Query of the stand-in page; nothing else opens the page with it.
const MARKER: &str = "?recover";
/// Attempts to open the stand-in page, one per [`OPEN_DELAY_MS`].
const OPEN_TRIES: u32 = 20;
/// Pause before each attempt (measured: navigations started within 40 ms of the crash were
/// cancelled while WebView2 was still taking it in).
const OPEN_DELAY_MS: u32 = 250;

/// Registered at start (`AddScriptToExecuteOnDocumentCreated` waits for a live renderer, so it
/// cannot be added after the crash); acts on the stand-in page only. It wraps dioxus'
/// interpreter (`native.ts` of 0.7.10: `rafEdits`, `markEditsFinished`, `sendIpcMessage`) when
/// the page creates it: every batch is acknowledged, applied or not (they name nodes of the page
/// that died), and `initialize` is never sent (dioxus would rebuild the tree as new scopes next
/// to the old ones, against a template cache the page does not have).
const STAND_IN_JS: &str = r#"(() => {
  if (location.search !== "?recover") return;
  let interpreter;
  Object.defineProperty(window, "interpreter", {
    configurable: true,
    get: () => interpreter,
    set(value) {
      interpreter = value;
      const apply = value.rafEdits.bind(value);
      value.rafEdits = (bytes) => {
        try { apply(bytes); } catch (err) { value.markEditsFinished(); }
      };
      const send = value.sendIpcMessage.bind(value);
      value.sendIpcMessage = (...args) => { if (args[0] !== "initialize") send(...args); };
    },
  });
})();"#;

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

thread_local! {
    /// The watch a delayed open belongs to (a thread timer callback carries no context).
    static OPENING: RefCell<Weak<CrashWatch>> = const { RefCell::new(Weak::new()) };
}

/// The timer callback of [`CrashWatch::open_later`]: runs on the UI thread while it dispatches
/// messages.
unsafe extern "system" fn open_now(_: HWND, _: u32, id: usize, _: u32) {
    // SAFETY: the one-shot timer this thread set; a second kill is harmless.
    let _ = unsafe { KillTimer(None, id) };
    if let Some(watch) = OPENING.with(|opening| opening.borrow().upgrade()) {
        watch.open();
    }
}

/// The main window's crash watch: the `ProcessFailed` handler and the stand-in page.
pub(crate) struct CrashWatch {
    desktop: DesktopContext,
    /// The page's address, read at start (the stand-in is this address with [`MARKER`]).
    home: Option<String>,
    /// Stand-in pages opened so far.
    count: Cell<u32>,
    /// Attempts left to open the stand-in page; 0 while none is being opened.
    opening: Cell<u32>,
}

/// Watches the window's WebView2 for process failures. Call it once, in the root component.
pub(crate) fn use_crash_watch() {
    let desktop = use_window();
    use_hook(|| {
        let home = desktop
            .webview
            .url()
            .inspect_err(|err| tracing::warn!(%err, "page address unknown"))
            .ok();
        let watch = Rc::new(CrashWatch {
            desktop,
            home,
            count: Cell::new(0),
            opening: Cell::new(0),
        });
        watch.register();
        watch
    });
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
                if uri.is_ok_and(|uri| this.lets_through(&uri)) {
                    // SAFETY: COM setter on the event's live arguments, UI thread.
                    unsafe { args.SetCancel(false) }?;
                }
            }
            Ok(())
        }));
        let script = HSTRING::from(STAND_IN_JS);
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
    }

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
            Failure::Browser => tracing::error!(
                ?exit_code,
                "WebView2 browser process exited; the window stays empty until the app restarts"
            ),
            Failure::Renderer => self.stand_in(exit_code),
        }
    }
}

impl CrashWatch {
    /// The page's renderer died: open the stand-in page, so the VirtualDom keeps running.
    fn stand_in(self: &Rc<Self>, exit_code: Option<i32>) {
        if self.opening.get() > 0 {
            return;
        }
        let count = self.count.get() + 1;
        self.count.set(count);
        if self.home.is_none() || count > MAX_STAND_INS {
            tracing::error!(
                ?exit_code,
                count,
                "WebView2 renderer exited; the app needs a restart"
            );
            return;
        }
        tracing::warn!(
            ?exit_code,
            count,
            "WebView2 renderer exited; the window stays empty until the app restarts, the tray keeps working"
        );
        self.opening.set(OPEN_TRIES);
        self.open_later();
    }

    /// Opens the stand-in page.
    fn open(&self) {
        let Some(home) = &self.home else {
            return;
        };
        if let Err(err) = self.desktop.webview.load_url(&format!("{home}{MARKER}")) {
            tracing::error!(%err, "renderer crash stand-in not opened");
            self.opening.set(0);
        }
    }

    /// Whether a navigation to `uri` is the stand-in page while it is being opened.
    fn lets_through(&self, uri: &str) -> bool {
        self.opening.get() > 0
            && self
                .home
                .as_deref()
                .is_some_and(|home| uri.strip_suffix(MARKER) == Some(home))
    }

    /// [`CrashWatch::open`] after [`OPEN_DELAY_MS`], on this (UI) thread.
    fn open_later(self: &Rc<Self>) {
        OPENING.with(|opening| *opening.borrow_mut() = Rc::downgrade(self));
        // SAFETY: a thread timer with a plain callback; this thread runs the message loop.
        if unsafe { SetTimer(None, 0, OPEN_DELAY_MS, Some(open_now)) } == 0 {
            tracing::error!("renderer crash stand-in not opened: no timer");
            self.opening.set(0);
        }
    }

    /// A navigation ended: while the stand-in is being opened, a failed attempt is retried.
    fn on_navigated(self: &Rc<Self>, ok: bool) {
        let left = self.opening.get();
        if left == 0 {
            return;
        }
        if ok {
            self.opening.set(0);
            return;
        }
        self.opening.set(left - 1);
        if left > 1 {
            self.open_later();
        } else {
            tracing::error!("renderer crash stand-in not opened: every attempt was cancelled");
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

    /// p-uiperf: only the page's own renderer gets the stand-in page; a dead browser process and a
    /// hang are reported, helpers are left to WebView2.
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

    /// The script acts on the stand-in page only and wraps exactly the interpreter members
    /// dioxus-desktop 0.7.10 uses for the edit queue and the IPC (`native.ts`).
    #[test]
    fn the_script_wraps_the_pinned_interpreter() {
        assert!(STAND_IN_JS.contains(&format!("location.search !== \"{MARKER}\"")));
        for member in [
            "\"interpreter\"",
            "value.rafEdits",
            "value.markEditsFinished()",
            "value.sendIpcMessage",
            "\"initialize\"",
        ] {
            assert!(STAND_IN_JS.contains(member), "{member}");
        }
    }
}
