//! The stand-in page. When a window stays as a dead renderer left it (rebuild limit, see
//! [`super::recover`]), dioxus-desktop 0.7.10 has no page to send its edit batches to: the queue
//! stalls and the VirtualDom stops (tray actions, Quit and its cleanup never run). So the window
//! opens the app's page with [`MARKER`]: a script registered at start acknowledges every edit batch
//! there and never announces the page, so the VirtualDom keeps its tree and keeps running.
use std::cell::Cell;

use dioxus::desktop::DesktopContext;

/// Query of the stand-in page; nothing else opens the page with it.
pub(super) const MARKER: &str = "?recover";
/// Stand-in pages per window: a stand-in renderer that keeps dying must not become a reload loop.
const MAX_STAND_INS: u32 = 3;
/// Attempts to open the stand-in page, one per [`OPEN_DELAY_MS`].
const OPEN_TRIES: u32 = 20;
/// Pause before each attempt (measured: navigations started within 40 ms of the crash were
/// cancelled while WebView2 was still taking it in).
pub(super) const OPEN_DELAY_MS: u32 = 250;

/// Registered at start (`AddScriptToExecuteOnDocumentCreated` waits for a live renderer, so it
/// cannot be added after the crash); acts on the stand-in page only. It wraps dioxus'
/// interpreter (`native.ts` of 0.7.10: `rafEdits`, `markEditsFinished`, `sendIpcMessage`) when
/// the page creates it: every batch is acknowledged, applied or not (they name nodes of the page
/// that died), and `initialize` is never sent (dioxus would rebuild the tree as new scopes next
/// to the old ones, against a template cache the page does not have).
pub(super) const STAND_IN_JS: &str = r#"(() => {
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

/// One window's stand-in page.
pub(super) struct StandIn {
    /// The page's address, read at start (the stand-in is this address with [`MARKER`]).
    home: Option<String>,
    /// Stand-in pages started so far.
    count: Cell<u32>,
    /// Attempts left to open the stand-in page; 0 while none is being opened.
    opening: Cell<u32>,
}

impl StandIn {
    pub(super) fn new(home: Option<String>) -> StandIn {
        StandIn {
            home,
            count: Cell::new(0),
            opening: Cell::new(0),
        }
    }

    /// Starts opening the stand-in page; `false` when it will not be opened (one is already on
    /// its way, the page's address is unknown, or too many were opened).
    pub(super) fn start(&self) -> bool {
        if self.opening.get() > 0 {
            return false;
        }
        let count = self.count.get() + 1;
        self.count.set(count);
        if self.home.is_none() || count > MAX_STAND_INS {
            tracing::error!(
                count,
                "renderer crash stand-in not opened; this window's VirtualDom stops until a new window opens"
            );
            return false;
        }
        self.opening.set(OPEN_TRIES);
        true
    }

    /// Whether an attempt is due (the timer of [`OPEN_DELAY_MS`] belongs to the stand-in).
    pub(super) fn opening(&self) -> bool {
        self.opening.get() > 0
    }

    /// One attempt to open the stand-in page.
    pub(super) fn open(&self, desktop: &DesktopContext) {
        let Some(home) = self.home.as_deref().filter(|_| self.opening()) else {
            return;
        };
        if let Err(err) = desktop.webview.load_url(&format!("{home}{MARKER}")) {
            tracing::error!(%err, "renderer crash stand-in not opened");
            self.opening.set(0);
        }
    }

    /// Whether a navigation to `uri` is the stand-in page while it is being opened.
    pub(super) fn lets_through(&self, uri: &str) -> bool {
        self.opening()
            && self
                .home
                .as_deref()
                .is_some_and(|home| uri.strip_suffix(MARKER) == Some(home))
    }

    /// A navigation ended while the stand-in is being opened; `true`: try again after
    /// [`OPEN_DELAY_MS`].
    pub(super) fn on_navigated(&self, ok: bool) -> bool {
        let left = self.opening.get();
        if left == 0 {
            return false;
        }
        if ok {
            self.opening.set(0);
            return false;
        }
        self.opening.set(left - 1);
        if left == 1 {
            tracing::error!("renderer crash stand-in not opened: every attempt was cancelled");
        }
        left > 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// At most three stand-ins per window, one at a time; a cancelled attempt is retried, a
    /// loaded page ends the attempts, and only the stand-in address is let through meanwhile.
    #[test]
    fn stand_ins_are_bounded() {
        let page = StandIn::new(Some("http://dioxus.index.html/".into()));
        assert!(!page.lets_through("http://dioxus.index.html/?recover"));
        assert!(page.start());
        assert!(!page.start(), "one at a time");
        assert!(page.lets_through("http://dioxus.index.html/?recover"));
        assert!(!page.lets_through("http://dioxus.index.html/"));
        assert!(page.on_navigated(false), "a cancelled attempt is retried");
        assert!(!page.on_navigated(true));
        assert!(!page.opening());
        assert!(page.start());
        assert!(!page.on_navigated(true));
        assert!(page.start());
        assert!(!page.on_navigated(true));
        assert!(!page.start(), "the fourth stand-in is refused");
        assert!(!StandIn::new(None).start(), "no address, no stand-in");
    }
}
