//! The six screens. Each one has its own heading, focused when the screen appears (screen readers
//! announce it, Tab starts at the top), and its controls; choices are radio cards (`role=radio`,
//! arrow keys move and select, Tab enters at the selected card).
use std::rc::Rc;

use dioxus::prelude::*;
use vpnte_base::i18n::Lang;
use vpnte_base::types::{KillSwitchLevel, ProxyKind};

use super::model::{Detect, KeyStatus, Step};
use super::view::{Ctx, start_check, start_detection};
use super::{Connection, LocalProxy, Routing, WizardApi};
use crate::helper::{Feature, HelperLine, use_capability};
use crate::lang::{LANG, tr};
use crate::t;
use crate::widgets::{
    Button, ButtonKind, Checkbox, Field, Spinner, TextArea, roving_index, use_dom_id,
};

/// The screen of the current step.
#[component]
pub(super) fn StepBody(ctx: Ctx, title_id: String) -> Element {
    match ctx.model.read().step {
        Step::Welcome => rsx! { Welcome { ctx, title_id } },
        Step::Connect => rsx! { Connect { ctx, title_id } },
        Step::Routing => rsx! { RoutingStep { ctx, title_id } },
        Step::SmartRu => rsx! { SmartRuStep { ctx, title_id } },
        Step::Protection => rsx! { Protection { ctx, title_id } },
        Step::Done => rsx! { Done { ctx, title_id } },
    }
}

/// Number, heading and lead of a screen; takes the focus when it mounts.
#[component]
fn StepHead(step: Step, title_id: String, title: String, lead: String) -> Element {
    rsx! {
        div { class: "wz-step-head",
            p { class: "wz-step-num swiss-mono", aria_hidden: "true", "{step.index() + 1:02} /" }
            h2 {
                id: "{title_id}",
                class: "wz-title",
                tabindex: "-1",
                onmounted: move |evt| async move {
                    let _ = evt.set_focus(true).await;
                },
                "{title}"
            }
            p { class: "wz-lead", "{lead}" }
        }
    }
}

/// One radio card.
#[derive(Clone, PartialEq)]
struct Card<T> {
    value: T,
    title: String,
    text: Option<String>,
    /// Mono status line under the text (detection result, servers in the list).
    meta: Option<String>,
    /// Language of the title when it differs from the UI (`ru` / `en` endonyms).
    lang: Option<&'static str>,
}

impl<T> Card<T> {
    fn new(value: T, title: String) -> Self {
        Self {
            value,
            title,
            text: None,
            meta: None,
            lang: None,
        }
    }
    fn text(mut self, text: String) -> Self {
        self.text = Some(text);
        self
    }
}

/// `aria-describedby` of a card: its text and its status line.
fn described_by<T>(base: &str, i: usize, card: &Card<T>) -> Option<String> {
    let ids: Vec<String> = [(card.text.is_some(), "d"), (card.meta.is_some(), "m")]
        .into_iter()
        .filter(|(present, _)| *present)
        .map(|(_, part)| format!("{base}-{i}-{part}"))
        .collect();
    (!ids.is_empty()).then(|| ids.join(" "))
}

/// A radio group of cards.
#[component]
fn Cards<T: Clone + PartialEq + 'static>(
    label: String,
    cards: Vec<Card<T>>,
    value: T,
    on_change: EventHandler<T>,
    #[props(default = 2)] columns: u8,
) -> Element {
    let base = use_dom_id("wz-card");
    let mut handles = use_signal(Vec::<Option<Rc<MountedData>>>::new);
    let selected = cards.iter().position(|c| c.value == value);
    let values: Vec<T> = cards.iter().map(|c| c.value.clone()).collect();
    let tab_stop = selected.unwrap_or(0);
    rsx! {
        div {
            class: "wz-cards",
            class: if columns == 3 { "is-three" },
            role: "radiogroup",
            aria_label: "{label}",
            onkeydown: move |evt| {
                let Some(next) = roving_index(values.len(), tab_stop, &evt.key()) else {
                    return;
                };
                evt.prevent_default();
                evt.stop_propagation();
                if Some(next) != selected {
                    on_change.call(values[next].clone());
                }
                if let Some(Some(el)) = handles.peek().get(next).cloned() {
                    spawn(async move {
                        let _ = el.set_focus(true).await;
                    });
                }
            },
            for (i , card) in cards.into_iter().enumerate() {
                button {
                    key: "{i}",
                    r#type: "button",
                    class: "wz-card",
                    class: if Some(i) == selected { "is-on" },
                    role: "radio",
                    aria_checked: if Some(i) == selected { "true" } else { "false" },
                    aria_labelledby: "{base}-{i}-t",
                    aria_describedby: described_by(&base, i, &card),
                    tabindex: if i == tab_stop { "0" } else { "-1" },
                    onmounted: move |evt| {
                        let mut list = handles.write();
                        if list.len() <= i {
                            list.resize(i + 1, None);
                        }
                        list[i] = Some(evt.data());
                    },
                    onclick: {
                        let value = card.value.clone();
                        move |_| on_change.call(value.clone())
                    },
                    span { class: "wz-card-mark", aria_hidden: "true" }
                    span { class: "wz-card-title", id: "{base}-{i}-t", lang: card.lang, "{card.title}" }
                    if let Some(text) = &card.text {
                        span { class: "wz-card-text", id: "{base}-{i}-d", "{text}" }
                    }
                    if let Some(meta) = &card.meta {
                        span { class: "wz-card-meta swiss-mono", id: "{base}-{i}-m", "{meta}" }
                    }
                }
            }
        }
    }
}

/// Language names in their own language: findable whatever the UI shows now.
const LANGS: [(Lang, &str, &str); 2] = [(Lang::Ru, "Русский", "ru"), (Lang::En, "English", "en")];

/// Step 1: what the wizard does, and the language (switched live, saved by finish or skip).
#[component]
fn Welcome(ctx: Ctx, title_id: String) -> Element {
    let mut model = ctx.model;
    let lang = model.read().lang;
    let cards = LANGS
        .iter()
        .map(|&(l, name, code)| Card {
            lang: Some(code),
            ..Card::new(l, name.to_owned())
        })
        .collect::<Vec<_>>();
    rsx! {
        StepHead {
            step: Step::Welcome,
            title_id,
            title: t!("onboarding.welcome"),
            lead: t!("ui.wizard.welcome.lead"),
        }
        p { class: "wz-group-label", {t!("onboarding.selectLanguage")} }
        Cards {
            label: t!("onboarding.selectLanguage"),
            cards,
            value: lang,
            on_change: move |l: Lang| {
                model.write().lang = l;
                *LANG.write() = l;
            },
        }
        p { class: "wz-note", {t!("ui.wizard.welcome.note")} }
    }
}

/// `127.0.0.1:2080 · SOCKS5`.
fn proxy_text(proxy: &LocalProxy) -> String {
    let kind = match proxy.kind {
        ProxyKind::Socks5 => "SOCKS5",
        ProxyKind::Http => "HTTP",
    };
    format!("{}:{} · {kind}", proxy.host, proxy.port)
}

/// Status line of the local proxy card.
fn detect_meta(detect: &Detect) -> String {
    match detect {
        Detect::NotRun => t!("ui.wizard.connect.metaNotRun"),
        Detect::Running => t!("ui.wizard.connect.metaSearching"),
        Detect::Found(proxy) => t!("ui.wizard.connect.metaFound", proxy = proxy_text(proxy)),
        Detect::NotFound => t!("ui.wizard.connect.metaNotFound"),
        Detect::Failed(_) => t!("ui.wizard.connect.metaFailed"),
    }
}

/// Step 2: our own servers from a key / subscription, or another client's local proxy.
#[component]
fn Connect(ctx: Ctx, title_id: String) -> Element {
    let mut model = ctx.model;
    let (connection, servers, meta) = {
        let m = model.read();
        (m.connection, m.servers, detect_meta(&m.detect))
    };
    let mut key = Card::new(Connection::Key, t!("ui.wizard.connect.key"))
        .text(t!("ui.wizard.connect.keyText"));
    if servers > 0 {
        key.meta = Some(t!("ui.wizard.connect.metaServers", count = servers));
    }
    let mut proxy = Card::new(Connection::LocalProxy, t!("ui.wizard.connect.proxy"))
        .text(t!("ui.wizard.connect.proxyText"));
    proxy.meta = Some(meta);
    rsx! {
        StepHead {
            step: Step::Connect,
            title_id,
            title: t!("ui.wizard.connect.title"),
            lead: t!("ui.wizard.connect.lead"),
        }
        Cards {
            label: t!("ui.wizard.connect.title"),
            cards: vec![key, proxy],
            value: connection,
            on_change: move |c| model.write().connection = c,
        }
        div { class: "wz-sub",
            if connection == Connection::Key {
                KeyPanel { ctx }
            } else {
                ProxyPanel { ctx }
            }
        }
    }
}

/// The key field, «Проверить» and the result. An edit cancels a running check.
#[component]
fn KeyPanel(ctx: Ctx) -> Element {
    let api = use_context::<Rc<dyn WizardApi>>();
    let mut model = ctx.model;
    let (text, status, servers) = {
        let m = model.read();
        (m.key_text().to_owned(), m.key_status().clone(), m.servers)
    };
    let checking = status == KeyStatus::Checking;
    let hwid_offer = model.read().hwid_offer();
    let blank = text.trim().is_empty();
    let hint = if servers > 0 {
        t!("ui.wizard.connect.keyHintHasServers", count = servers)
    } else {
        t!("ui.wizard.connect.keyHint")
    };
    let check = {
        let api = api.clone();
        move || start_check(api.clone(), ctx)
    };
    let on_submit = check.clone();
    let on_hwid = check.clone();
    let on_click = check;
    rsx! {
        Field { label: t!("ui.wizard.connect.keyLabel"), hint,
            TextArea {
                value: text,
                rows: 2,
                mono: true,
                placeholder: t!("onboarding.importKeyPlaceholder"),
                invalid: matches!(status, KeyStatus::Invalid | KeyStatus::Failed(_)),
                oninput: move |v: String| {
                    ctx.check.cancel();
                    model.write().edit_key(v);
                },
                on_submit: move |_| on_submit(),
            }
        }
        div { class: "wz-check-row",
            Button {
                kind: ButtonKind::Ghost,
                small: true,
                busy: checking,
                disabled: blank,
                disabled_reason: blank.then(|| t!("ui.wizard.connect.keyEmpty")),
                onclick: move |_| on_click(),
                {t!("ui.wizard.connect.check")}
            }
            div { class: "wz-status-slot", role: "status",
                match &status {
                    KeyStatus::Valid(found) => rsx! {
                        p { class: "wz-status is-ok",
                            span { class: "wz-status-mark" }
                            if found.subscription {
                                {t!("ui.wizard.connect.foundSubscription", count = found.servers)}
                            } else {
                                {t!("ui.wizard.connect.found", count = found.servers)}
                            }
                        }
                    },
                    KeyStatus::Checking => rsx! {
                        p { class: "wz-status", {t!("ui.wizard.connect.checking")} }
                    },
                    _ => rsx! {},
                }
            }
        }
        match &status {
            KeyStatus::Invalid => rsx! {
                p { class: "wz-status is-fail", role: "alert",
                    span { class: "wz-status-mark" }
                    {t!("onboarding.keyInvalid")}
                }
            },
            KeyStatus::Failed(msg) => rsx! {
                p { class: "wz-status is-fail", role: "alert",
                    span { class: "wz-status-mark" }
                    {tr(msg)}
                }
            },
            _ => rsx! {},
        }
        // The HWID goes to the provider only after this click (as in the Add dialog).
        if hwid_offer {
            Button {
                kind: ButtonKind::Ghost,
                small: true,
                onclick: move |_| {
                    model.write().allow_hwid();
                    on_hwid();
                },
                {t!("ui.servers.add.hwidRetry")}
            }
        }
    }
}

/// What the proxy search found, and «Искать снова».
#[component]
fn ProxyPanel(ctx: Ctx) -> Element {
    let api = use_context::<Rc<dyn WizardApi>>();
    let detect = ctx.model.read().detect.clone();
    let again = move |_| start_detection(api.clone(), ctx);
    rsx! {
        div { class: "wz-status-slot", role: "status",
            match &detect {
                Detect::Running | Detect::NotRun => rsx! {
                    p { class: "wz-status", Spinner {} {t!("ui.wizard.connect.searching")} }
                },
                Detect::Found(proxy) => rsx! {
                    p { class: "wz-status is-ok",
                        span { class: "wz-status-mark" }
                        {t!("ui.wizard.connect.proxyFound", proxy = proxy_text(proxy))}
                    }
                },
                Detect::NotFound => rsx! {
                    p { class: "wz-status", {t!("ui.wizard.connect.proxyNotFound")} }
                },
                Detect::Failed(msg) => rsx! {
                    p { class: "wz-status is-fail",
                        span { class: "wz-status-mark" }
                        {tr(msg)}
                    }
                },
            }
        }
        if matches!(detect, Detect::NotFound | Detect::Failed(_) | Detect::Found(_)) {
            Button { kind: ButtonKind::Ghost, small: true, onclick: again,
                {t!("ui.wizard.connect.searchAgain")}
            }
        }
    }
}

/// Step 3: Tunnel (TUN, through the helper service) or Proxy; both work with either upstream
/// (NOADMIN §2). Without the service the helper line under the cards offers its install.
#[component]
fn RoutingStep(ctx: Ctx, title_id: String) -> Element {
    let mut model = ctx.model;
    let routing = model.read().routing;
    let hard = Card::new(Routing::Hard, t!("ui.wizard.routing.hard"))
        .text(t!("ui.wizard.routing.hardText"));
    let soft = Card::new(Routing::Soft, t!("ui.wizard.routing.soft"))
        .text(t!("ui.wizard.routing.softText"));
    rsx! {
        StepHead {
            step: Step::Routing,
            title_id,
            title: t!("ui.wizard.routing.title"),
            lead: t!("ui.wizard.routing.lead"),
        }
        Cards {
            label: t!("ui.wizard.routing.title"),
            cards: vec![hard, soft],
            value: routing,
            on_change: move |r| model.write().routing = r,
        }
        HelperLine { feature: Feature::Tunnel }
    }
}

/// Step 4: Smart RU, preselected on for a first run (owner answer 18); one line for each choice.
#[component]
fn SmartRuStep(ctx: Ctx, title_id: String) -> Element {
    let mut model = ctx.model;
    let on = model.read().smart_ru;
    let cards = vec![
        Card::new(true, t!("ui.wizard.smartRu.on")).text(t!("ui.wizard.smartRu.onText")),
        Card::new(false, t!("ui.wizard.smartRu.off")).text(t!("ui.wizard.smartRu.offText")),
    ];
    rsx! {
        StepHead {
            step: Step::SmartRu,
            title_id,
            title: t!("ui.wizard.smartRu.title"),
            lead: t!("ui.wizard.smartRu.lead"),
        }
        Cards {
            label: t!("ui.wizard.smartRu.title"),
            cards,
            value: on,
            on_change: move |v| model.write().smart_ru = v,
        }
    }
}

/// Catalog key of a kill-switch level's name.
fn level_key(level: KillSwitchLevel) -> &'static str {
    match level {
        KillSwitchLevel::Off => "ui.settings.killSwitch.off",
        KillSwitchLevel::Standard => "ui.settings.killSwitch.onDrop",
        KillSwitchLevel::Strict => "ui.settings.killSwitch.always",
    }
}

/// Step 5: kill-switch level (Off unless picked, D-15) and autostart. Two choices with one line
/// each (research killswitch 5.2); "Always" needs the helper service and lives in Settings, so a
/// first run never picks it. In Proxy mode "If the VPN drops" adds its one neutral sentence.
#[component]
fn Protection(ctx: Ctx, title_id: String) -> Element {
    let mut model = ctx.model;
    let (level, autostart, soft) = {
        let m = model.read();
        (m.kill_switch, m.autostart, m.routing == Routing::Soft)
    };
    let on_drop = match soft {
        true => format!(
            "{} {}",
            t!("ui.settings.killSwitch.onDropLine"),
            t!("ui.settings.killSwitch.onDropProxy")
        ),
        false => t!("ui.settings.killSwitch.onDropLine"),
    };
    let cards = vec![
        Card::new(KillSwitchLevel::Off, t!(level_key(KillSwitchLevel::Off)))
            .text(t!("ui.settings.killSwitch.offLine")),
        Card::new(
            KillSwitchLevel::Standard,
            t!(level_key(KillSwitchLevel::Standard)),
        )
        .text(on_drop),
    ];
    rsx! {
        StepHead {
            step: Step::Protection,
            title_id,
            title: t!("ui.wizard.protection.title"),
            lead: t!("ui.wizard.protection.lead"),
        }
        p { class: "wz-group-label", {t!("settings.killSwitch")} }
        Cards {
            label: t!("settings.killSwitch"),
            cards,
            value: level,
            on_change: move |l| model.write().kill_switch = l,
        }
        div { class: "wz-autostart",
            Checkbox {
                label: t!("onboarding.autostartEnable"),
                hint: t!("ui.wizard.protection.autostartHint"),
                checked: autostart,
                on_change: move |on| model.write().autostart = on,
            }
        }
    }
}

/// Step 6: what «Завершить» will apply.
#[component]
fn Done(ctx: Ctx, title_id: String) -> Element {
    let m = ctx.model.read().clone();
    let lang_name = LANGS
        .iter()
        .find(|(l, ..)| *l == m.lang)
        .map_or("", |(_, name, _)| name);
    let connection = match (m.connection, m.key_status(), &m.detect) {
        (Connection::Key, KeyStatus::Valid(found), _) => {
            t!("ui.wizard.done.keyAdds", count = found.servers)
        }
        (Connection::Key, ..) if m.servers > 0 => {
            t!("ui.wizard.done.keyExisting", count = m.servers)
        }
        (Connection::Key, ..) => t!("ui.wizard.done.keyLater"),
        (Connection::LocalProxy, _, Detect::Found(proxy)) => {
            t!("ui.wizard.done.proxyFound", proxy = proxy_text(proxy))
        }
        (Connection::LocalProxy, ..) => t!("ui.wizard.done.proxyNotFound"),
    };
    // Tunnel mode where it cannot run yet is saved as Proxy (the app says so after «Завершить»):
    // the summary shows what will be saved, and the helper line its install.
    let tunnel_waits = use_capability().is_some_and(|c| !c.tunnel.works());
    let tunnel = m.routing == Routing::Hard && !tunnel_waits;
    let routing = if tunnel {
        t!("ui.wizard.routing.hard")
    } else {
        t!("ui.wizard.routing.soft")
    };
    let rows = [
        (t!("ui.wizard.done.language"), lang_name.to_owned()),
        (t!("ui.wizard.done.connection"), connection),
        (t!("ui.wizard.done.routing"), routing),
        (
            t!("ui.wizard.smartRu.title"),
            t!(if m.smart_ru {
                "common.on"
            } else {
                "common.off"
            }),
        ),
        (t!("settings.killSwitch"), t!(level_key(m.kill_switch))),
        (
            t!("ui.wizard.done.autostart"),
            t!(if m.autostart {
                "common.on"
            } else {
                "common.off"
            }),
        ),
    ];
    rsx! {
        StepHead {
            step: Step::Done,
            title_id,
            title: t!("ui.wizard.done.title"),
            lead: t!("ui.wizard.done.lead"),
        }
        dl { class: "wz-summary",
            for (i , (term , value)) in rows.into_iter().enumerate() {
                div { key: "{i}", class: "wz-summary-row",
                    dt { class: "swiss-label", "{term}" }
                    dd { "{value}" }
                }
            }
        }
        if m.routing == Routing::Hard {
            HelperLine { feature: Feature::Tunnel }
        }
        if m.key_left_unchecked() {
            p { class: "wz-status is-warn",
                span { class: "wz-status-mark" }
                {t!("ui.wizard.done.keyUnchecked")}
            }
        }
    }
}
