//! What the page remembers between visits (owner, 13.11.2026: the chosen tab and the filters
//! survive leaving the page). The page stays active-only (its readers stop while it is away);
//! its controls start from this state and write every change back.
use dioxus::prelude::*;

use super::events::EventQuery;
use super::history::{Filters, Period, SortState};
use super::journal::LevelFilter;
use super::model::LogSource;

/// The tabs of «Журнал».
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Tab {
    /// «События»: the timeline (the default).
    #[default]
    Events,
    /// «Подключения»: the sessions table.
    Connections,
    /// «Технический»: the logs for support.
    Technical,
}

impl Tab {
    pub const ALL: [Tab; 3] = [Tab::Events, Tab::Connections, Tab::Technical];

    /// Tab label key (`logs.tabs.events`).
    pub fn label_key(self) -> &'static str {
        match self {
            Tab::Events => "logs.tabs.events",
            Tab::Connections => "logs.tabs.connections",
            Tab::Technical => "logs.tabs.technical",
        }
    }

    /// DOM id stem of the tab and its panel.
    pub fn id(self) -> &'static str {
        match self {
            Tab::Events => "events",
            Tab::Connections => "connections",
            Tab::Technical => "technical",
        }
    }
}

/// The technical tab's controls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TechQuery {
    pub source: LogSource,
    pub level: LevelFilter,
    pub text: String,
    /// Re-read the log while the page is visible («Пауза» stops it).
    pub follow: bool,
}

impl Default for TechQuery {
    fn default() -> Self {
        Self {
            source: LogSource::App,
            level: LevelFilter::All,
            text: String::new(),
            follow: true,
        }
    }
}

/// The page's remembered state.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PageState {
    pub tab: Tab,
    pub events: EventQuery,
    pub filters: Filters,
    pub period: Period,
    pub sort: SortState,
    pub tech: TechQuery,
}

/// One per app (Dioxus keeps globals per window runtime, so tests do not share it).
pub(super) static STATE: GlobalSignal<PageState> = Signal::global(PageState::default);

/// A local signal that starts from the remembered `get` and writes every change back with `set`.
pub(super) fn use_remembered<T: Clone + PartialEq + 'static>(
    get: fn(&PageState) -> T,
    set: fn(&mut PageState, T),
) -> Signal<T> {
    let local = use_signal(|| get(&STATE.peek()));
    use_effect(move || {
        let value = local();
        if get(&STATE.peek()) != value {
            set(&mut STATE.write(), value);
        }
    });
    local
}
