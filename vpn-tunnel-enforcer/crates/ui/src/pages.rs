//! The pages of the main window: ids in sidebar order, the navigation state behind [`Nav`], the
//! [`PageRegistry`] page packages plug into, and the [`PageHost`] that keeps visited pages
//! mounted.
use dioxus::prelude::*;

use crate::shell::WindowState;
use crate::t;

/// A page of the main window, in sidebar order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Page {
    /// The start page.
    Dashboard,
    /// Split tunnelling (the old id `apps`).
    Apps,
    Servers,
    SpeedTest,
    Availability,
    TrafficHistory,
    Schedule,
    Logs,
    Settings,
    /// Repair tools; only in advanced mode.
    Maintenance,
}

impl Page {
    /// Every page in sidebar order.
    pub const ALL: [Page; 10] = [
        Page::Dashboard,
        Page::Apps,
        Page::Servers,
        Page::SpeedTest,
        Page::Availability,
        Page::TrafficHistory,
        Page::Schedule,
        Page::Logs,
        Page::Settings,
        Page::Maintenance,
    ];

    /// The old string id (`nav.ts` `AppPage`, `data-perch="nav-<id>"`, the demos' `--page`).
    pub const fn id(self) -> &'static str {
        match self {
            Page::Dashboard => "dashboard",
            Page::Apps => "apps",
            Page::Servers => "servers",
            Page::SpeedTest => "speedtest",
            Page::Availability => "availability",
            Page::TrafficHistory => "trafficHistory",
            Page::Schedule => "schedule",
            Page::Logs => "logs",
            Page::Settings => "settings",
            Page::Maintenance => "maintenance",
        }
    }

    /// Parses [`Page::id`].
    pub fn from_id(id: &str) -> Option<Page> {
        Page::ALL.into_iter().find(|page| page.id() == id)
    }

    /// i18n key of the sidebar label (the old keys; `availability` and `maintenance` only had
    /// call-site defaults, this package's fragment adds them).
    pub const fn label_key(self) -> &'static str {
        match self {
            Page::Dashboard => "sidebar.dashboard",
            Page::Apps => "sidebar.apps",
            Page::Servers => "sidebar.servers",
            Page::SpeedTest => "sidebar.speedTest",
            Page::Availability => "sidebar.availability",
            Page::TrafficHistory => "sidebar.trafficHistory",
            Page::Schedule => "sidebar.schedule",
            Page::Logs => "sidebar.logs",
            Page::Settings => "sidebar.settings",
            Page::Maintenance => "sidebar.maintenance",
        }
    }

    /// Shown and reachable only in advanced mode.
    pub const fn advanced_only(self) -> bool {
        matches!(self, Page::Maintenance)
    }

    /// Mounted only while current: these pages read and render potentially large log files, so
    /// their work stays scoped to the page the user is looking at.
    pub const fn active_only(self) -> bool {
        matches!(self, Page::TrafficHistory | Page::Logs)
    }

    /// The sidebar entries in order: every page, Maintenance only in advanced mode.
    pub fn nav(advanced: bool) -> impl Iterator<Item = Page> {
        Page::ALL
            .into_iter()
            .filter(move |page| advanced || !page.advanced_only())
    }

    /// `self`, or the start page when `self` needs advanced mode and it is off.
    pub const fn allowed(self, advanced: bool) -> Page {
        if self.advanced_only() && !advanced {
            Page::Dashboard
        } else {
            self
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Two-digit sidebar number of the entry at `index` (0-based): `01`…`10`.
pub fn nav_number(index: usize) -> String {
    format!("{:02}", index + 1)
}

/// How a page appears when it is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Entry {
    /// No animation: the start page at launch.
    Still,
    /// First mount while current: fade in and rise 8 px (`.page-enter`).
    Slide,
    /// Shown again after being hidden: fade in only (`.page-fade`).
    Fade,
}

impl Entry {
    /// CSS class of the `<main>` element. A hidden page has `display: none`, which cancels its
    /// animation, so the same class replays every time the page is shown again.
    const fn class(self) -> &'static str {
        match self {
            Entry::Still => "",
            Entry::Slide => "page-enter",
            Entry::Fade => "page-fade",
        }
    }
}

/// Which page is current and which pages stay mounted (pure; the shell keeps it in a signal).
#[derive(Clone, Debug, PartialEq, Eq)]
struct NavState {
    current: Page,
    start: Page,
    /// Pages in the order of their first visit, the current one included.
    visited: Vec<Page>,
    /// Pages that were current and then left at least once.
    left: Vec<Page>,
}

impl NavState {
    /// Starts on `start`, the only visited page.
    fn new(start: Page) -> NavState {
        NavState {
            current: start,
            start,
            visited: vec![start],
            left: Vec::new(),
        }
    }

    /// Makes `page` current, redirected by [`Page::allowed`]; returns whether the current page
    /// changed.
    fn go(&mut self, page: Page, advanced: bool) -> bool {
        let page = page.allowed(advanced);
        if page == self.current {
            return false;
        }
        if !self.left.contains(&self.current) {
            self.left.push(self.current);
        }
        if !self.visited.contains(&page) {
            self.visited.push(page);
        }
        self.current = page;
        true
    }

    /// Advanced mode was switched off: leaves an advanced-only page and forgets every visit to
    /// one, so none stays mounted and the next visit mounts it afresh (D-26: the old app kept a
    /// hidden second Dashboard under the Maintenance id).
    fn leave_advanced(&mut self) {
        self.go(self.current, false);
        self.visited.retain(|page| !page.advanced_only());
        self.left.retain(|page| !page.advanced_only());
    }

    /// Pages to keep in the DOM, in first-visit order: the current page and every visited page
    /// except active-only ones.
    fn mounted(&self) -> Vec<Page> {
        self.visited
            .iter()
            .copied()
            .filter(|&page| page == self.current || !page.active_only())
            .collect()
    }

    /// How `page` enters when shown: the start page not at launch, a page on its first visit
    /// (and an active-only page on every visit, it is mounted afresh) slides, a page shown again
    /// fades.
    fn entry(&self, page: Page) -> Entry {
        let left = self.left.contains(&page);
        if page == self.start && !left {
            Entry::Still
        } else if page.active_only() || !left {
            Entry::Slide
        } else {
            Entry::Fade
        }
    }
}

/// Navigation handle, in context under the shell (`use_nav()`): deep components request a page
/// with [`Nav::go`] instead of the old `vpnte:navigate` window event.
#[derive(Clone, Copy, PartialEq)]
pub struct Nav {
    state: Signal<NavState>,
    advanced: ReadSignal<bool>,
}

impl Nav {
    /// The current page (subscribes the caller).
    pub fn current(&self) -> Page {
        self.state.read().current
    }

    /// Whether advanced mode is on (subscribes the caller).
    pub fn advanced(&self) -> bool {
        *self.advanced.read()
    }

    /// Opens `page`; an advanced-only page opens the start page while advanced mode is off.
    pub fn go(&self, page: Page) {
        let advanced = *self.advanced.peek();
        let mut state = self.state;
        if state.peek().current != page.allowed(advanced) {
            state.write().go(page, advanced);
        }
    }

    /// Pages to keep mounted and the entry of each (subscribes the caller).
    fn mounted(&self) -> Vec<(Page, Entry)> {
        let state = self.state.read();
        state
            .mounted()
            .into_iter()
            .map(|page| (page, state.entry(page)))
            .collect()
    }
}

/// Creates the navigation state on `start` and provides [`Nav`] as context; leaves (and
/// forgets) advanced-only pages when advanced mode is switched off.
pub(crate) fn use_nav_provider(start: Page, advanced: ReadSignal<bool>) -> Nav {
    let nav = use_context_provider(|| Nav {
        state: Signal::new(NavState::new(start.allowed(*advanced.peek()))),
        advanced,
    });
    use_effect(move || {
        let mut state = nav.state;
        if !*advanced.read() && state.peek().visited.iter().any(|page| page.advanced_only()) {
            state.write().leave_advanced();
        }
    });
    nav
}

/// The [`Nav`] provided by the shell. Panics outside it, like `use_context`.
pub fn use_nav() -> Nav {
    use_context::<Nav>()
}

/// The page a component belongs to, provided by the page host around each page.
#[derive(Clone, Copy, PartialEq)]
struct PageScope(Page);

/// `usePageActive`: a page is active while it is current and the window is visible.
fn is_active(page: Option<Page>, current: Option<Page>, window_visible: bool) -> bool {
    let current_page = match (page, current) {
        (Some(page), Some(current)) => page == current,
        // Outside a page (or without the shell) only the window decides, as the old default.
        _ => true,
    };
    current_page && window_visible
}

/// True while the caller's page is current and the window is neither minimised nor hidden:
/// visited pages stay mounted (drafts survive), only their background readers pause.
pub fn use_page_active() -> Memo<bool> {
    let scope = try_use_context::<PageScope>();
    let nav = try_use_context::<Nav>();
    let window = try_use_context::<WindowState>();
    use_memo(move || {
        is_active(
            scope.map(|PageScope(page)| page),
            nav.map(|nav| nav.current()),
            window.is_none_or(|window| window.visible()),
        )
    })
}

/// Page components by page: each page package registers its root component (no props), so
/// pages plug in without editing this module. Unregistered pages show a neutral placeholder.
#[derive(Clone, Copy, Default)]
pub struct PageRegistry {
    pages: [Option<fn() -> Element>; Page::ALL.len()],
}

impl PageRegistry {
    /// An empty registry.
    pub fn new() -> PageRegistry {
        PageRegistry::default()
    }

    /// Sets the component of `page`, replacing an earlier registration.
    pub fn register(&mut self, page: Page, component: fn() -> Element) -> &mut PageRegistry {
        self.pages[page.index()] = Some(component);
        self
    }

    /// The component registered for `page`.
    pub fn get(&self, page: Page) -> Option<fn() -> Element> {
        self.pages[page.index()]
    }
}

impl PartialEq for PageRegistry {
    fn eq(&self, other: &Self) -> bool {
        self.pages.iter().zip(&other.pages).all(|pair| match pair {
            (Some(a), Some(b)) => std::ptr::fn_addr_eq(*a, *b),
            (None, None) => true,
            _ => false,
        })
    }
}

impl std::fmt::Debug for PageRegistry {
    /// The ids of the registered pages.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let registered = Page::ALL
            .into_iter()
            .filter(|&page| self.get(page).is_some());
        f.debug_set().entries(registered.map(Page::id)).finish()
    }
}

/// The page area: each mounted page in its own `<main>`; hidden pages keep their state under
/// `display: none` and `aria-hidden`, the shown page plays its [`Entry`].
#[component]
pub(crate) fn PageHost(registry: PageRegistry) -> Element {
    let nav = use_nav();
    let current = nav.current();
    rsx! {
        for (page , entry) in nav.mounted() {
            main {
                key: "{page.id()}",
                aria_hidden: if page == current { "false" } else { "true" },
                class: "absolute inset-0 overflow-y-auto p-6 tabular",
                class: if page == current { "pointer-events-auto" } else { "pointer-events-none" },
                class: "{entry.class()}",
                style: if page != current { "display:none" },
                PageView { page, registry }
            }
        }
    }
}

/// One page: provides its [`PageScope`], renders the registered component inside an error
/// boundary (a failing page must not take the shell down), or a neutral placeholder when no
/// package registered the page (yet).
#[component]
fn PageView(page: Page, registry: PageRegistry) -> Element {
    use_context_provider(|| PageScope(page));
    let Some(Body) = registry.get(page) else {
        return rsx! {
            PageNotice { page, text: t!("ui.shell.placeholder") }
        };
    };
    rsx! {
        ErrorBoundary {
            handle_error: move |errors: ErrorContext| {
                if let Some(error) = errors.error() {
                    tracing::error!(page = page.id(), %error, "page failed to render");
                }
                rsx! {
                    PageNotice { page, text: t!("ui.shell.pageFailed"),
                        button {
                            r#type: "button",
                            class: "shell-placeholder-retry",
                            onclick: move |_| errors.clear_errors(),
                            {t!("common.retry")}
                        }
                    }
                }
            },
            Body {}
        }
    }
}

/// A «Пломба» paper page with the page's number and name, a line of text and optional actions.
#[component]
fn PageNotice(page: Page, text: String, children: Element) -> Element {
    let number = nav_number(page.index());
    let label = t!(page.label_key());
    rsx! {
        div { class: "c-swiss swiss-skin",
            div { class: "shell-placeholder",
                span { class: "swiss-label", "{number} / {label}" }
                p { class: "shell-placeholder-text", "{text}" }
                {children}
            }
        }
    }
}

#[cfg(test)]
mod tests;
