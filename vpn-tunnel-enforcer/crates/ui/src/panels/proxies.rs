//! External proxies column: running count and countries, picker + start, one row per slot
//! with rotate / stop, «stop all», inline error.
use std::rc::Rc;

use dioxus::prelude::*;
use vpnte_base::types::{Level, Notice};
use vpnte_base::{AppResult, Msg};
use vpnte_view::mascot::MascotEvent;

use super::icons::{Plus, RefreshCw, Spinner, Square};
use super::model::{ProxiesView, ProxyRowView};
use super::picker::{Picker, PickerOption};
use super::rules::{
    Indicator, choice_label, country_summary, first_free_slot, keep_selection, proxy_dot_class,
    proxy_dot_title, proxy_meta, refresh_interval, running_count,
};
use super::{PanelHead, PanelsApi, notify};
use crate::lang::tr;
use crate::t;

/// The action in flight (all controls wait for it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Start,
    Stop,
    Rotate,
    StopAll,
}

impl Action {
    /// The mascot's nudge before the call; «stop all» nudges only after it succeeded (§3.9).
    fn nudge(self) -> Option<MascotEvent> {
        match self {
            Action::Start => Some(MascotEvent::ProxyStart),
            Action::Stop => Some(MascotEvent::ProxyStop),
            Action::Rotate => Some(MascotEvent::ProxyRotate),
            Action::StopAll => None,
        }
    }
}

/// Which action runs, and on which slot (`None` for «stop all»).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Busy {
    slot: Option<u16>,
    action: Action,
}

/// A command of the column.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Request {
    Start { slot: u16, profile: String },
    Stop(u16),
    Rotate(u16),
    StopAll,
}

impl Request {
    fn busy(&self) -> Busy {
        let (slot, action) = match self {
            Request::Start { slot, .. } => (Some(*slot), Action::Start),
            Request::Stop(slot) => (Some(*slot), Action::Stop),
            Request::Rotate(slot) => (Some(*slot), Action::Rotate),
            Request::StopAll => (None, Action::StopAll),
        };
        Busy { slot, action }
    }
}

/// A user-visible detail line that is data, not a sentence (an address, a server name).
fn detail(text: &str) -> Msg {
    Msg::new("ui.panels.proxy.detail").arg("text", text)
}

/// The column.
#[component]
pub(super) fn ProxiesPanel(
    view: Signal<ProxiesView>,
    active: Option<Memo<bool>>,
    on_mascot: Option<EventHandler<MascotEvent>>,
    on_notice: Option<EventHandler<Notice>>,
) -> Element {
    let api = use_context::<Rc<dyn PanelsApi>>();
    let mut busy = use_signal(|| None::<Busy>);
    let mut error = use_signal(|| None::<Msg>);
    let mut chosen = use_signal(|| keep_selection(None, &view.peek().choices));
    // the picker keeps its server while it stays usable
    use_effect(move || {
        let next = keep_selection(chosen.peek().as_deref(), &view.read().choices);
        if *chosen.peek() != next {
            chosen.set(next);
        }
    });
    // Health refresh on the policy's cadence while the page is shown (the old column paused while
    // the window was hidden); restarts when the cadence or the page activity changes.
    let cadence = use_memo(move || refresh_interval(&view.read()));
    let refresher = api.clone();
    use_resource(move || {
        let api = refresher.clone();
        let wait = cadence();
        let shown = active.is_none_or(|active| active());
        async move {
            if !shown {
                return;
            }
            loop {
                tokio::time::sleep(wait).await;
                if let Err(err) = api.proxy_refresh().await {
                    // advisory: the controls report actionable failures
                    tracing::debug!(%err, "external proxy refresh failed");
                }
            }
        }
    });
    let mascot = move |ev: MascotEvent| {
        if let Some(h) = on_mascot {
            h.call(ev);
        }
    };

    let run = use_callback(move |request: Request| {
        // a second click can arrive before the re-render has disabled the controls
        if busy.peek().is_some() {
            return;
        }
        let Busy { slot, action } = request.busy();
        tracing::info!(?slot, ?action, "external proxy action");
        if let Some(nudge) = action.nudge() {
            mascot(nudge);
        }
        busy.set(Some(Busy { slot, action }));
        error.set(None);
        let before = running_count(&view.peek().rows);
        let api = api.clone();
        spawn(async move {
            let result: AppResult<ProxiesView> = match request {
                Request::Start { slot, profile } => api.proxy_start(slot, &profile).await,
                Request::Stop(slot) => api.proxy_stop(slot).await,
                Request::Rotate(slot) => api.proxy_rotate(slot).await,
                Request::StopAll => api.proxy_stop_all().await,
            };
            match result {
                // `next` is already published through `proxies()`: applying it here could
                // overwrite a newer push that the pump delivered first.
                Ok(next) => {
                    if action == Action::StopAll {
                        mascot(MascotEvent::ProxyStopAll);
                    }
                    if let Some(notice) = done_notice(action, slot, before, &next) {
                        notify(on_notice, notice);
                    }
                }
                Err(err) => {
                    tracing::warn!(?slot, ?action, %err, "external proxy action failed");
                    let title = if action == Action::StopAll {
                        "ui.panels.proxy.stopAllFailed"
                    } else {
                        "ui.panels.proxy.failed"
                    };
                    let msg = err.user_msg();
                    notify(
                        on_notice,
                        Notice::new(Level::Error, title).body(msg.clone()),
                    );
                    error.set(Some(msg));
                }
            }
            busy.set(None);
        });
    });
    let add = move |_| {
        let usable = {
            let v = view.read();
            chosen()
                .filter(|id| v.choices.iter().any(|c| &c.id == id && c.usable()))
                .map(|id| (id, first_free_slot(&v.rows)))
        };
        let Some((profile, slot)) = usable else {
            error.set(Some(Msg::new("ui.panels.proxy.pickFirst")));
            return;
        };
        run.call(Request::Start { slot, profile });
    };
    let stop_all = move |_| run.call(Request::StopAll);

    let snapshot = view.read();
    let running = running_count(&snapshot.rows);
    let summary = country_summary(&snapshot.rows);
    let busy_now = busy();
    let is_busy = busy_now.is_some();
    let options: Vec<PickerOption> = snapshot
        .choices
        .iter()
        .map(|c| {
            let indicator = Indicator::of(c.health);
            PickerOption {
                id: c.id.clone(),
                label: choice_label(c, tr),
                indicator,
                indicator_label: tr(&indicator.label()),
                disabled: !c.usable(),
            }
        })
        .collect();
    let placeholder = if options.is_empty() {
        t!("ui.panels.proxy.pickerNone")
    } else {
        t!("ui.panels.proxy.pickerPlaceholder")
    };
    let rows = snapshot.rows.clone();
    drop(snapshot);
    rsx! {
        section { class: "swiss-panel",
            PanelHead { title: t!("ui.panels.proxy.title"), perch: "proxies",
                button {
                    r#type: "button",
                    class: "swiss-fact-action",
                    disabled: is_busy || running == 0,
                    title: t!("ui.panels.proxy.stopAllTitle"),
                    onclick: stop_all,
                    if busy_now.is_some_and(|b| b.action == Action::StopAll) {
                        Spinner { class: "mr-1 inline h-3 w-3 animate-spin" }
                    }
                    {t!("ui.panels.proxy.stopAll")}
                }
            }
            div { class: "swiss-proxy-top",
                div { class: "swiss-proxy-summary",
                    span { class: "swiss-proxy-count", "{running}" }
                    span { class: "swiss-label", {t!("ui.panels.proxy.running")} }
                    if let Some(s) = summary {
                        span { class: "swiss-mono swiss-proxy-countries", title: "{s.title}", "{s.text}" }
                    }
                }
                div { class: "swiss-proxy-add",
                    Picker {
                        id: "proxy-picker",
                        label: t!("ui.panels.proxy.pickerLabel"),
                        placeholder,
                        options,
                        value: chosen(),
                        disabled: is_busy,
                        on_change: move |id: String| chosen.set(Some(id)),
                    }
                    button {
                        r#type: "button",
                        class: "swiss-proxy-start",
                        disabled: is_busy || chosen().is_none(),
                        aria_label: t!("ui.panels.proxy.start"),
                        title: t!("ui.panels.proxy.startTitle"),
                        onclick: add,
                        if busy_now.is_some_and(|b| b.action == Action::Start) {
                            Spinner { class: "h-4 w-4 animate-spin" }
                        } else {
                            Plus { class: "h-4 w-4" }
                        }
                    }
                }
            }
            div { class: "swiss-panel-body",
                if rows.is_empty() {
                    p { class: "swiss-empty swiss-proxy-empty", {t!("ui.panels.proxy.empty")} }
                }
                for row in rows {
                    ProxyRow {
                        key: "{row.slot}",
                        row: row.clone(),
                        busy: is_busy,
                        spinning: busy_now.filter(|b| b.slot == Some(row.slot)).map(|b| b.action),
                        on_rotate: move |slot: u16| run.call(Request::Rotate(slot)),
                        on_stop: move |slot: u16| run.call(Request::Stop(slot)),
                    }
                }
                if let Some(msg) = error() {
                    p { class: "swiss-panel-error", {tr(&msg)} }
                }
            }
        }
    }
}

/// Feedback for a finished action: a start or rotation only when the slot's process runs; a
/// stop always; «stop all» with the count running before the call.
fn done_notice(
    action: Action,
    slot: Option<u16>,
    before: usize,
    next: &ProxiesView,
) -> Option<Notice> {
    let row = slot.and_then(|s| next.rows.iter().find(|r| r.slot == s));
    let slot_no = slot.unwrap_or_default();
    match action {
        Action::Start => row.filter(|r| r.process_running).map(|r| {
            let n = Notice::new(
                Level::Success,
                Msg::new("ui.panels.proxy.started").arg("slot", slot_no),
            );
            match &r.proxy_url {
                Some(url) => n.body(detail(url)),
                None => n,
            }
        }),
        Action::Rotate => row.filter(|r| r.process_running).map(|r| {
            let n = Notice::new(
                Level::Success,
                Msg::new("ui.panels.proxy.rotated").arg("slot", slot_no),
            );
            match &r.profile_name {
                Some(name) => n.body(detail(name)),
                None => n,
            }
        }),
        Action::Stop => Some(Notice::new(
            Level::Info,
            Msg::new("ui.panels.proxy.stopped").arg("slot", slot_no),
        )),
        Action::StopAll => Some(Notice::new(
            Level::Info,
            Msg::new("ui.panels.proxy.stoppedAll").arg("n", before),
        )),
    }
}

/// One proxy slot.
#[component]
fn ProxyRow(
    row: ProxyRowView,
    busy: bool,
    spinning: Option<Action>,
    on_rotate: EventHandler<u16>,
    on_stop: EventHandler<u16>,
) -> Element {
    let slot = row.slot;
    let name = row
        .profile_name
        .clone()
        .unwrap_or_else(|| t!("ui.panels.proxy.unnamed"));
    let (head, tail) = proxy_meta(&row, tr);
    let rotate = t!("ui.panels.proxy.rotate", slot = slot);
    let stop = t!("ui.panels.proxy.stop", slot = slot);
    rsx! {
        div { class: "swiss-proxy-row",
            div { class: "min-w-0",
                div { class: "swiss-proxy-name",
                    span { class: proxy_dot_class(&row), title: tr(&proxy_dot_title(&row)) }
                    span { class: "truncate", "{name}" }
                    if let Some(cc) = row.country.clone().filter(|c| !c.is_empty()) {
                        span { class: "swiss-mono swiss-proxy-cc", "{cc}" }
                    }
                }
                div { class: "swiss-mono swiss-proxy-meta", title: row.proxy_url.clone(),
                    "{head}"
                    if let Some(tail) = tail {
                        "{tail}"
                    }
                }
            }
            div { class: "swiss-proxy-actions",
                button {
                    r#type: "button",
                    class: "swiss-icon-btn",
                    disabled: busy,
                    aria_label: "{rotate}",
                    title: "{rotate}",
                    onclick: move |_| on_rotate.call(slot),
                    if spinning == Some(Action::Rotate) {
                        Spinner { class: "h-3.5 w-3.5 animate-spin" }
                    } else {
                        RefreshCw { class: "h-3.5 w-3.5" }
                    }
                }
                button {
                    r#type: "button",
                    class: "swiss-icon-btn is-danger",
                    disabled: busy,
                    aria_label: "{stop}",
                    title: "{stop}",
                    onclick: move |_| on_stop.call(slot),
                    if spinning == Some(Action::Stop) {
                        Spinner { class: "h-3.5 w-3.5 animate-spin" }
                    } else {
                        Square { class: "h-3.5 w-3.5" }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(rows: Vec<ProxyRowView>) -> ProxiesView {
        ProxiesView {
            rows,
            choices: Vec::new(),
        }
    }

    /// Feedback of §3.9 (`ExternalProxyCard.tsx:242-299`): start and rotate toast only when the
    /// slot's process runs (URL / profile name as the body), stop always, «stop all» with the
    /// count running before the call.
    #[test]
    fn done_notices_follow_the_old_column() {
        let up = ProxyRowView {
            slot: 3,
            process_running: true,
            profile_name: Some("Sweden · Stockholm".into()),
            proxy_url: Some("socks5://127.0.0.1:18003".into()),
            ..ProxyRowView::default()
        };
        let down = ProxyRowView {
            process_running: false,
            ..up.clone()
        };
        let started = done_notice(Action::Start, Some(3), 2, &view(vec![up.clone()]));
        assert_eq!(
            started,
            Some(
                Notice::new(
                    Level::Success,
                    Msg::new("ui.panels.proxy.started").arg("slot", 3)
                )
                .body(detail("socks5://127.0.0.1:18003"))
            )
        );
        assert_eq!(
            done_notice(Action::Start, Some(3), 2, &view(vec![down])),
            None
        );
        assert_eq!(done_notice(Action::Rotate, Some(3), 2, &view(vec![])), None);
        let rotated = done_notice(Action::Rotate, Some(3), 2, &view(vec![up]));
        assert_eq!(
            rotated.and_then(|n| n.body),
            Some(detail("Sweden · Stockholm"))
        );
        assert_eq!(
            done_notice(Action::Stop, Some(3), 2, &view(vec![])),
            Some(Notice::new(
                Level::Info,
                Msg::new("ui.panels.proxy.stopped").arg("slot", 3)
            ))
        );
        let all = done_notice(Action::StopAll, None, 2, &view(vec![]));
        assert_eq!(
            all.map(|n| n.title),
            Some(Msg::new("ui.panels.proxy.stoppedAll").arg("n", 2))
        );
    }
}
