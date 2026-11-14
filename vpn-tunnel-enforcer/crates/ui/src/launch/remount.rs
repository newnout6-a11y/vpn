//! Rebuilding the window after a WebView2 crash. dioxus-desktop 0.7.10 cannot build a page again
//! in a webview whose page died (its template ids and string caches belong to that page), so a
//! crash gets a NEW window with a NEW VirtualDom over the same root contexts, in the old window's
//! place and state. The old window (hidden, its VirtualDom and tray still running) closes when the
//! new one has mounted, so the tray hands over within one turn of the event loop. The backend and
//! its session live outside the VirtualDom and keep running.
use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::{Duration, Instant};

use dioxus::desktop::tao::dpi::{PhysicalPosition, PhysicalSize};
use dioxus::desktop::tao::window::Window;
use dioxus::desktop::{DesktopContext, PendingDesktopContext, WindowCloseBehaviour};
use dioxus::prelude::*;
use futures_util::FutureExt;
use vpnte_base::i18n::Lang;

use super::{Frame, FrameProps, LaunchOptions};
use crate::lang::LANG;
use crate::theme::{THEME, Theme};

/// Automatic rebuilds allowed within [`REBUILD_SPAN`]; a WebView2 that keeps crashing must not
/// become a window that keeps reappearing.
pub(crate) const MAX_REBUILDS: usize = 3;
/// The sliding span of [`MAX_REBUILDS`].
pub(crate) const REBUILD_SPAN: Duration = Duration::from_secs(10 * 60);

/// A root context. Each VirtualDom the window gets (the first one and one per rebuild) receives
/// its own value, so a context must be a cheap handle to something built once (`Rc`, `Arc`, a
/// small value). `use_context` clones contexts anyway: every `Clone + 'static` value is one.
pub trait RootContext: 'static {
    /// The value for the next VirtualDom; `None` once a [`once`] context is used up.
    fn provide(&self) -> Option<Box<dyn Any>>;
    /// Whether every VirtualDom can get a value (`false` only for [`once`]).
    fn reusable(&self) -> bool {
        true
    }
}

impl<T: Clone + 'static> RootContext for T {
    fn provide(&self) -> Option<Box<dyn Any>> {
        Some(Box::new(self.clone()))
    }
}

/// A context whose type the caller cannot name: the first VirtualDom gets it, and the window can
/// then not be rebuilt after a crash (it stays as the crash left it, the tray keeps working).
pub fn once(context: Box<dyn Any>) -> Box<dyn RootContext> {
    Box::new(Once(RefCell::new(Some(context))))
}

struct Once(RefCell<Option<Box<dyn Any>>>);

impl RootContext for Once {
    fn provide(&self) -> Option<Box<dyn Any>> {
        self.0.borrow_mut().take()
    }

    fn reusable(&self) -> bool {
        false
    }
}

/// The automatic rebuilds of the last [`REBUILD_SPAN`].
#[derive(Debug, Default)]
pub(crate) struct Recoveries {
    times: VecDeque<Instant>,
}

impl Recoveries {
    /// Whether one more automatic rebuild is allowed at `now`; an allowed one is counted.
    pub(crate) fn allow(&mut self, now: Instant) -> bool {
        while self
            .times
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= REBUILD_SPAN)
        {
            self.times.pop_front();
        }
        if self.times.len() >= MAX_REBUILDS {
            return false;
        }
        self.times.push_back(now);
        true
    }
}

/// The old window as a rebuilt one takes it over.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Shape {
    pub(crate) visible: bool,
    pub(crate) minimized: bool,
    pub(crate) maximized: bool,
    pub(crate) focused: bool,
    /// Outer position and inner size; `None` while minimised (Windows parks a minimised window
    /// at -32000 with no client area): the new window then opens at the start size.
    pub(crate) place: Option<(PhysicalPosition<i32>, PhysicalSize<u32>)>,
}

impl Shape {
    pub(crate) fn of(window: &Window) -> Shape {
        let minimized = window.is_minimized();
        Shape {
            visible: window.is_visible(),
            minimized,
            maximized: window.is_maximized(),
            focused: window.is_focused(),
            place: window
                .outer_position()
                .ok()
                .filter(|_| !minimized)
                .map(|position| (position, window.inner_size())),
        }
    }
}

/// How a VirtualDom's window starts.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Mount {
    /// The window of the start: in the tray (`hidden`) or shown once painted.
    First { hidden: bool },
    /// A rebuilt window: the old one's state, the language and theme shown before the crash.
    Again {
        shape: Shape,
        lang: Lang,
        theme: Theme,
    },
}

impl Mount {
    /// The page starts hidden: the WebView2 controller is hidden at the first render.
    pub(crate) fn hidden(&self) -> bool {
        match self {
            Mount::First { hidden } => *hidden,
            Mount::Again { shape, .. } => !shape.visible,
        }
    }
}

/// What every window of the process is built from; one per [`super::launch`].
pub(crate) struct Rebuild {
    pub(crate) options: LaunchOptions,
    root: fn() -> Element,
    contexts: Vec<Box<dyn RootContext>>,
    /// Every context can be provided to another VirtualDom.
    pub(crate) reusable: bool,
    recoveries: RefCell<Recoveries>,
    /// The language and theme shown now (the frame mirrors its signals here).
    lang: Cell<Lang>,
    theme: Cell<Theme>,
    /// The rebuild under way, until the new window mounts.
    swap: RefCell<Option<Swap>>,
}

/// A window being replaced and its replacement on the way.
struct Swap {
    old: DesktopContext,
    new: PendingDesktopContext,
}

impl Rebuild {
    pub(crate) fn new(
        options: LaunchOptions,
        root: fn() -> Element,
        contexts: Vec<Box<dyn RootContext>>,
    ) -> Rc<Rebuild> {
        // Through the trait object: `&Box<dyn RootContext>` is itself `Clone`, so method
        // resolution would pick the blanket impl for the reference.
        let reusable = contexts.iter().all(|context| (**context).reusable());
        if !reusable {
            tracing::error!(
                "a root context can be provided once only: the window cannot be rebuilt after a WebView2 crash"
            );
        }
        Rc::new(Rebuild {
            root,
            reusable,
            recoveries: RefCell::default(),
            lang: Cell::new(options.lang),
            theme: Cell::new(options.theme),
            swap: RefCell::new(None),
            contexts,
            options,
        })
    }

    /// The frame around the root, with a value of every context.
    pub(crate) fn dom(self: &Rc<Self>, mount: Mount) -> VirtualDom {
        let props = FrameProps {
            root: self.root,
            min_size: self.options.min_size,
            mount,
            rebuild: self.clone(),
        };
        let mut dom = VirtualDom::new_with_props(Frame, props);
        for context in self
            .contexts
            .iter()
            .filter_map(|context| (**context).provide())
        {
            dom.insert_any_root_context(context);
        }
        dom
    }

    /// Mirrors the language and theme shown (the frame calls it on every change).
    pub(crate) fn carry(&self, lang: Lang, theme: Theme) {
        self.lang.set(lang);
        self.theme.set(theme);
    }

    /// Whether one more automatic rebuild is allowed now (counted when it is).
    pub(crate) fn allow(&self) -> bool {
        self.recoveries.borrow_mut().allow(Instant::now())
    }

    /// Opens a new window with a new VirtualDom in the place and state `shape` describes; `old`
    /// closes once the new one has mounted ([`Rebuild::mounted`]). `false` while another rebuild
    /// is under way.
    pub(crate) fn open(self: &Rc<Self>, old: &DesktopContext, shape: Shape) -> bool {
        if self.swap.borrow().is_some() {
            return false;
        }
        let mount = Mount::Again {
            shape,
            lang: self.lang.get(),
            theme: self.theme.get(),
        };
        let config = super::window_config(&self.options, &mount);
        let new = old.new_window(self.dom(mount), config);
        *self.swap.borrow_mut() = Some(Swap {
            old: old.clone(),
            new,
        });
        true
    }

    /// A frame mounted: the window it replaces closes now (with its VirtualDom, tray icon and
    /// tasks). Closing it earlier would leave no tray while the new page loads, and none at all
    /// if it never came up; closing the last window would end dioxus' event loop.
    pub(crate) fn mounted(&self) {
        let swap = self.swap.borrow_mut().take();
        if let Some(swap) = swap {
            close(&swap.old);
        }
    }

    /// The replacement of `old` did not mount in time: it is closed, `old` stays. `false` when
    /// `old` was not waiting for one.
    pub(crate) fn abandon(&self, old: &DesktopContext) -> bool {
        let swap = self
            .swap
            .borrow_mut()
            .take_if(|swap| Rc::ptr_eq(&swap.old, old));
        let Some(swap) = swap else {
            return false;
        };
        // Resolved long ago when dioxus created the window; nothing to close otherwise.
        if let Some(Ok(new)) = swap.new.try_resolve().now_or_never() {
            close(&new);
        }
        true
    }
}

/// Closes a window for good (the tray switches windows to hide on close).
fn close(window: &DesktopContext) {
    window.set_close_behavior(WindowCloseBehaviour::WindowCloses);
    window.close();
}

/// `LANG` and `THEME` are per-VirtualDom signals that start from the launch values: a rebuilt
/// window takes over the ones shown before the crash (first render, before any page reads them),
/// and every window mirrors its current ones into `rebuild` for the next.
pub(crate) fn use_carry(rebuild: &Rc<Rebuild>, mount: Mount) {
    use_hook(|| {
        if let Mount::Again { lang, theme, .. } = mount {
            if *LANG.peek() != lang {
                *LANG.write() = lang;
            }
            if *THEME.peek() != theme {
                *THEME.write() = theme;
            }
        }
    });
    let rebuild = rebuild.clone();
    use_effect(move || rebuild.carry(*LANG.read(), *THEME.read()));
}

/// A rebuilt window once its page has announced itself (dioxus has then given the window the
/// start's visibility): the old window's visibility, minimised state and focus; the cloak goes
/// once the page is painted.
pub(crate) async fn settle(desktop: &DesktopContext, shape: Shape) {
    let window = &desktop.window;
    if !shape.visible {
        // The controller is hidden since the first render (as a start in the tray).
        window.set_visible(false);
        super::set_cloaked(window, false);
        return;
    }
    window.set_visible(true);
    if shape.minimized {
        window.set_minimized(true);
    } else {
        super::painted().await;
    }
    super::set_cloaked(window, false);
    if shape.focused && !shape.minimized {
        window.set_focus();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// p-webview-recover: three automatic rebuilds per ten minutes, counted over a sliding span;
    /// a refused one is not counted.
    #[test]
    fn rebuilds_are_limited_per_ten_minutes() {
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        let mut recoveries = Recoveries::default();
        assert!(recoveries.allow(at(0)));
        assert!(recoveries.allow(at(60)));
        assert!(recoveries.allow(at(120)));
        assert!(!recoveries.allow(at(130)), "the fourth within ten minutes");
        assert!(!recoveries.allow(at(599)));
        // the first one leaves the span at 600 s
        assert!(recoveries.allow(at(600)));
        assert!(!recoveries.allow(at(601)));
        assert!(recoveries.allow(at(660)));
        // long after: only this one counts
        assert!(recoveries.allow(at(2_000)));
        assert_eq!(recoveries.times.len(), 1);
    }

    #[derive(Clone)]
    struct Probe(Rc<Cell<u32>>);

    fn probe_root() -> Element {
        let Probe(mounts) = use_context::<Probe>();
        let name = use_context::<&'static str>();
        use_hook(|| mounts.set(mounts.get() + 1));
        rsx! { "{name}" }
    }

    /// Every VirtualDom built from the same contexts gets a clone of each (the same `Rc`), so a
    /// rebuilt window works on the backend the first one used; a single-use context makes the
    /// window not rebuildable.
    #[test]
    fn every_dom_gets_the_same_contexts() {
        let mounts = Rc::new(Cell::new(0));
        let contexts: Vec<Box<dyn RootContext>> =
            vec![Box::new(Probe(mounts.clone())), Box::new("api")];
        let rebuild = Rebuild::new(LaunchOptions::default(), probe_root, contexts);
        assert!(rebuild.reusable);
        for _ in 0..2 {
            let dom = rebuild.dom(Mount::First { hidden: true });
            let probe = dom.in_scope(ScopeId::ROOT, consume_context::<Probe>);
            assert!(Rc::ptr_eq(&probe.0, &mounts));
            assert_eq!(dom.in_scope(ScopeId::ROOT, consume_context::<&str>), "api");
        }
        assert_eq!(
            Rc::strong_count(&mounts),
            2,
            "the stored context and this test"
        );
        let single: Vec<Box<dyn RootContext>> = vec![once(Box::new(Probe(mounts.clone())))];
        let rebuild = Rebuild::new(LaunchOptions::default(), probe_root, single);
        assert!(!rebuild.reusable);
        let dom = rebuild.dom(Mount::First { hidden: true });
        assert!(
            dom.in_scope(ScopeId::ROOT, try_consume_context::<Probe>)
                .is_some()
        );
        let dom = rebuild.dom(Mount::First { hidden: true });
        assert!(
            dom.in_scope(ScopeId::ROOT, try_consume_context::<Probe>)
                .is_none()
        );
    }

    /// A rebuilt window's page starts hidden exactly when the old window was hidden; the first
    /// window's follows `start_hidden`.
    #[test]
    fn mounts_say_when_the_page_starts_hidden() {
        let shape = |visible| Shape {
            visible,
            minimized: false,
            maximized: false,
            focused: false,
            place: None,
        };
        let again = |visible| Mount::Again {
            shape: shape(visible),
            lang: Lang::Ru,
            theme: Theme::default(),
        };
        assert!(Mount::First { hidden: true }.hidden());
        assert!(!Mount::First { hidden: false }.hidden());
        assert!(again(false).hidden());
        assert!(!again(true).hidden());
    }
}
