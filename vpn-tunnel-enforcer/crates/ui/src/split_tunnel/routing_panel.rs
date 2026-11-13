//! «Маршрутизация Happ»: paste a `happ://routing/…` link or pick the profile a subscription sent,
//! see what it would add, add it to your own rules with one click. Nothing changes before the
//! click; the rules then live in Settings → domain routing, editable and removable.
use dioxus::prelude::*;
use vpnte_base::{ErrorKind, Msg};

use super::routing::{RoutingImported, RoutingOffer, RoutingPreview, RoutingSource};
use super::routing_preview::PreviewView;
use super::{tr_now, use_api};
use crate::lang::tr;
use crate::t;
use crate::widgets::{Button, ButtonKind, Panel, TextInput, use_job};

/// The panel; `offers` come with the page state.
#[component]
pub fn RoutingPanel(offers: Vec<RoutingOffer>) -> Element {
    let api = use_api();
    let preview_job = use_job::<()>();
    let import_job = use_job::<()>();
    let mut text = use_signal(String::new);
    let mut preview = use_signal(|| None::<RoutingPreview>);
    // A calm result line, or the reason a value was not read.
    let mut outcome = use_signal(|| None::<Result<String, Msg>>);

    let show = {
        let api = api.clone();
        move |source: RoutingSource| {
            let api = api.clone();
            preview_job.start(move |_| async move {
                match api.preview_routing(source).await {
                    Ok(next) => {
                        outcome.set(None);
                        preview.set(Some(next));
                    }
                    Err(err) if err.kind == ErrorKind::Cancelled => {}
                    Err(err) => {
                        preview.set(None);
                        outcome.set(Some(Err(err.user_msg())));
                    }
                }
                Ok(())
            });
        }
    };
    let import = {
        let api = api.clone();
        move |token: u64| {
            let api = api.clone();
            import_job.start(move |_| async move {
                match api.import_routing(token).await {
                    Ok(done) => {
                        preview.set(None);
                        text.set(String::new());
                        let line: Vec<String> = done_msgs(done).iter().map(tr_now).collect();
                        outcome.set(Some(Ok(line.join(" "))));
                    }
                    Err(err) if err.kind == ErrorKind::Cancelled => {}
                    Err(err) => {
                        // A stale preview is gone; any other failure keeps it for a retry.
                        if err.kind == ErrorKind::Conflict {
                            preview.set(None);
                        }
                        outcome.set(Some(Err(err.user_msg())));
                    }
                }
                Ok(())
            });
        }
    };

    let pasted = {
        let show = show.clone();
        move || {
            let raw = text.peek().trim().to_owned();
            if !raw.is_empty() {
                show(RoutingSource::Pasted(raw));
            }
        }
    };
    let enter = pasted.clone();
    let blank = text.read().trim().is_empty();
    let busy = preview_job.running() || import_job.running();
    let input_id = crate::widgets::use_dom_id("apps-routing");
    rsx! {
        Panel { title: t!("splitTunneling.routing.title"),
            div { class: "apps-routing",
                label { class: "apps-cmd-hint", r#for: "{input_id}", {t!("splitTunneling.routing.hint")} }
                div { class: "apps-cmd-row",
                    TextInput {
                        id: input_id.clone(),
                        value: text(),
                        mono: true,
                        placeholder: t!("splitTunneling.routing.placeholder"),
                        // A failed subscription preview is not about the (blank) input.
                        invalid: !blank && matches!(&*outcome.read(), Some(Err(_))),
                        oninput: move |v: String| {
                            text.set(v);
                            outcome.set(None);
                        },
                        on_enter: move |()| enter(),
                    }
                    Button {
                        kind: ButtonKind::Ghost,
                        busy: preview_job.running(),
                        disabled: blank || busy,
                        onclick: move |_| pasted(),
                        {t!("splitTunneling.routing.show")}
                    }
                }
                for offer in offers {
                    OfferRow { key: "{offer.group_id}", offer, busy, on_show: show.clone() }
                }
                if let Some(shown) = preview() {
                    PreviewView {
                        preview: shown,
                        busy: import_job.running(),
                        on_import: import.clone(),
                        on_cancel: move |()| preview.set(None),
                    }
                }
                match outcome() {
                    Some(Ok(line)) => rsx! {
                        p { class: "apps-cmd-result", role: "status", {line} }
                    },
                    Some(Err(msg)) => rsx! {
                        p { class: "apps-cmd-result is-error", role: "alert", {tr(&msg)} }
                    },
                    None => rsx! {},
                }
            }
        }
    }
}

/// A subscription whose provider sent a profile: its name, the profile's name, «Посмотреть».
#[component]
fn OfferRow(offer: RoutingOffer, busy: bool, on_show: EventHandler<RoutingSource>) -> Element {
    let line = match &offer.profile {
        Some(profile) => t!(
            "splitTunneling.routing.offerNamed",
            group = offer.group,
            profile = profile
        ),
        None => t!("splitTunneling.routing.offer", group = offer.group),
    };
    let id = offer.group_id.clone();
    rsx! {
        div { class: "apps-routing-offer",
            span { class: "apps-routing-offer-text", {line} }
            Button {
                kind: ButtonKind::Ghost,
                small: true,
                disabled: busy,
                onclick: move |_| on_show.call(RoutingSource::Subscription(id.clone())),
                {t!("splitTunneling.routing.show")}
            }
        }
    }
}

/// The sentences of an import's result line: what was added, Smart RU, what did not fit, where
/// the rules live and when they apply.
pub(super) fn done_msgs(done: RoutingImported) -> Vec<Msg> {
    let mut parts: Vec<Msg> = Vec::new();
    if done.added > 0 {
        parts.push(Msg::new("splitTunneling.routing.added").arg("count", done.added));
    }
    if done.smart_ru_on {
        parts.push(Msg::new("splitTunneling.routing.smartRuOn"));
    }
    if done.over_limit > 0 {
        parts.push(Msg::new("splitTunneling.routing.overLimit").arg("count", done.over_limit));
    }
    if parts.is_empty() {
        parts.push(Msg::new("splitTunneling.routing.nothingAdded"));
    } else {
        if done.added > 0 {
            parts.push(Msg::new("splitTunneling.routing.whereRules"));
        }
        parts.push(Msg::new("splitTunneling.routing.nextConnect"));
    }
    parts
}
