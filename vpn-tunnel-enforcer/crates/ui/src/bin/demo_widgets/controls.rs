//! Buttons, status marks, form fields and choice controls with fake data.
use std::time::Duration;

use vpnte_ui::t;

use super::*;

pub(super) const GLYPHS: [IconGlyph; 15] = [
    IconGlyph::Close,
    IconGlyph::Plus,
    IconGlyph::Minus,
    IconGlyph::Check,
    IconGlyph::ChevronDown,
    IconGlyph::ChevronUp,
    IconGlyph::ArrowRight,
    IconGlyph::Refresh,
    IconGlyph::Copy,
    IconGlyph::Trash,
    IconGlyph::Edit,
    IconGlyph::More,
    IconGlyph::Search,
    IconGlyph::Info,
    IconGlyph::Warning,
];

#[component]
pub(super) fn ButtonsDemo() -> Element {
    let toasts = Toasts::use_context();
    let mut pressed = use_signal(|| false);
    rsx! {
        Panel {
            id: "demo-buttons",
            title: t!("ui.widgets.demo.buttons"),
            actions: rsx! {
                Button {
                    kind: ButtonKind::Link,
                    onclick: move |_| {
                        toasts.info(t!("ui.widgets.demo.toastInfo"), None);
                    },
                    {t!("ui.widgets.demo.pingAll")}
                }
            },
            div { class: "wd-stack",
                div { class: "wd-line",
                    Button { id: "btn-primary", {t!("ui.widgets.demo.connect")} }
                    Button { kind: ButtonKind::Ghost, {t!("ui.widgets.demo.checkNow")} }
                    Button { kind: ButtonKind::Danger, {t!("ui.widgets.demo.deleteAll")} }
                    Button { kind: ButtonKind::Link, {t!("ui.widgets.demo.pingAll")} }
                }
                div { class: "wd-line",
                    Button { small: true, {t!("ui.widgets.demo.connect")} }
                    Button { small: true, kind: ButtonKind::Ghost, {t!("ui.widgets.demo.checkNow")} }
                    Button { busy: true, id: "btn-busy", {t!("ui.widgets.demo.saving")} }
                    Button {
                        kind: ButtonKind::Ghost,
                        disabled: true,
                        disabled_reason: t!("ui.widgets.demo.disabledReason"),
                        id: "btn-disabled",
                        {t!("ui.widgets.demo.deleteAll")}
                    }
                }
                Button { wide: true, kind: ButtonKind::Primary,
                    {t!("ui.widgets.demo.connect")}
                    Icon { glyph: IconGlyph::ArrowRight }
                }
                div { class: "wd-line",
                    for glyph in GLYPHS {
                        IconButton { glyph, label: format!("{glyph:?}") }
                    }
                }
                div { class: "wd-line",
                    IconButton { glyph: IconGlyph::Plus, label: "Add", solid: true }
                    IconButton { glyph: IconGlyph::Trash, label: "Delete", danger: true }
                    IconButton { glyph: IconGlyph::Refresh, label: "Refresh", busy: true }
                    IconButton {
                        glyph: IconGlyph::Search,
                        label: "Filter",
                        pressed: pressed(),
                        onclick: move |_| pressed.toggle(),
                    }
                    IconButton {
                        glyph: IconGlyph::Copy,
                        label: "Copy",
                        disabled: true,
                        disabled_reason: t!("ui.widgets.demo.disabledReason"),
                    }
                }
            }
        }
    }
}

#[component]
pub(super) fn StatusDemo() -> Element {
    let mut progress = use_signal(|| 0.45_f64);
    use_future(move || async move {
        loop {
            tokio::time::sleep(Duration::from_millis(700)).await;
            let next = (progress() + 0.07) % 1.05;
            progress.set(next);
        }
    });
    rsx! {
        Panel { id: "demo-status", title: t!("ui.widgets.demo.status"),
            div { class: "wd-stack",
                div { class: "wd-line",
                    Badge { tone: Tone::Ok, {t!("ui.widgets.demo.ok")} }
                    Badge { tone: Tone::Warn, {t!("ui.widgets.demo.warn")} }
                    Badge { tone: Tone::Fail, {t!("ui.widgets.demo.fail")} }
                    Badge { tone: Tone::Neutral, {t!("ui.widgets.demo.neutral")} }
                    Badge { tone: Tone::Unknown, {t!("ui.widgets.notChecked")} }
                }
                Field { label: t!("ui.widgets.demo.progress"),
                    ProgressBar { value: Some(0.45), label: t!("ui.widgets.demo.progress"), show_value: true }
                }
                ProgressBar { value: Some(progress()), label: t!("ui.widgets.demo.progress"), show_value: true }
                ProgressBar { value: None, label: t!("ui.widgets.demo.waiting") }
                div { class: "wd-line wd-note",
                    Spinner {}
                    {t!("ui.widgets.demo.waiting")}
                }
            }
        }
    }
}

pub(super) fn server_options() -> Vec<SelectOption<&'static str>> {
    let (on, off, unknown) = (
        t!("ui.widgets.demo.online"),
        t!("ui.widgets.demo.offline"),
        t!("ui.widgets.demo.unchecked"),
    );
    vec![
        SelectOption::new("nl", "Netherlands · Amsterdam").indicator(Indicator::Ok, on.clone()),
        SelectOption::new("de", "Germany · Frankfurt").indicator(Indicator::Ok, on.clone()),
        SelectOption::new("fi", "Finland · Helsinki").indicator(Indicator::Muted, unknown.clone()),
        SelectOption::new("us", "USA · New York")
            .indicator(Indicator::Fail, off)
            .disabled(true),
        SelectOption::new("pl", "Poland · Warsaw · PL · HYSTERIA2 · reality")
            .indicator(Indicator::Ok, on.clone()),
        SelectOption::new("se", "Sweden · Stockholm").indicator(Indicator::Muted, unknown),
        SelectOption::new("lv", "Latvia · Riga").indicator(Indicator::Signal, on.clone()),
        SelectOption::new("ch", "Switzerland · Zürich").indicator(Indicator::Ok, on),
    ]
}

#[component]
pub(super) fn FormDemo() -> Element {
    let toasts = Toasts::use_context();
    let mut name = use_signal(|| "Riga-2".to_string());
    let mut url = use_signal(String::new);
    let mut notes = use_signal(String::new);
    let mut interval = use_signal(|| 30_i64);
    let mut server = use_signal(|| Some("nl"));
    let mut refresh = use_signal(|| "off");
    let name_error = name
        .read()
        .trim()
        .is_empty()
        .then(|| t!("ui.widgets.demo.serverError"));
    let refresh_options = vec![
        SelectOption::new("off", t!("ui.widgets.demo.refreshOff")),
        SelectOption::new("hour", t!("ui.widgets.demo.refreshHour")),
        SelectOption::new("day", t!("ui.widgets.demo.refreshDay")),
    ];
    rsx! {
        Panel { id: "demo-form", title: t!("ui.widgets.demo.form"),
            div { class: "wd-stack",
                Field {
                    label: t!("ui.widgets.demo.serverName"),
                    hint: t!("ui.widgets.demo.serverHint"),
                    error: name_error,
                    TextInput { value: name(), oninput: move |v| name.set(v) }
                }
                Field { label: t!("ui.widgets.demo.subscription"),
                    TextInput {
                        value: url(),
                        oninput: move |v| url.set(v),
                        kind: TextKind::Url,
                        mono: true,
                        placeholder: "https://example.com/sub/…",
                        on_enter: move |_| {
                            toasts.info(t!("ui.widgets.demo.toastInfo"), Some(url()));
                        },
                    }
                }
                Field { label: t!("ui.widgets.demo.server"),
                    Select {
                        options: server_options(),
                        value: server(),
                        on_change: move |v| server.set(Some(v)),
                        placeholder: t!("ui.widgets.choose"),
                    }
                }
                Row { label: t!("ui.widgets.demo.interval"), hint: t!("ui.widgets.demo.intervalHint"),
                    NumberInput {
                        value: interval(),
                        min: 5,
                        max: 300,
                        unit: t!("ui.widgets.demo.unit"),
                        on_commit: move |v| interval.set(v),
                    }
                }
                Field { label: t!("ui.widgets.demo.notes"),
                    TextArea { value: notes(), oninput: move |v| notes.set(v), rows: 3 }
                }
                div { class: "wd-clip", id: "demo-clip",
                    Select {
                        options: refresh_options,
                        value: Some(refresh()),
                        on_change: move |v| refresh.set(v),
                        size: Size::Sm,
                        aria_label: t!("ui.widgets.demo.refresh"),
                    }
                }
            }
        }
    }
}

#[component]
pub(super) fn ChoicesDemo() -> Element {
    let mut kill = use_signal(|| true);
    let mut autostart = use_signal(|| false);
    let mut applying = use_signal(|| false);
    let mut agree = use_signal(|| true);
    let mut mode = use_signal(|| "hard");
    let mut tab = use_signal(|| 0_usize);
    let tab_names = [
        t!("ui.widgets.demo.tabSessions"),
        t!("ui.widgets.demo.tabEvents"),
        t!("ui.widgets.demo.tabErrors"),
    ];
    let current = tab_names[tab()].clone();
    rsx! {
        Panel { id: "demo-choices", title: t!("ui.widgets.demo.choices"),
            Switch {
                label: t!("ui.widgets.demo.killSwitch"),
                hint: t!("ui.widgets.demo.killSwitchHint"),
                checked: kill(),
                on_change: move |v| kill.set(v),
            }
            Switch {
                label: t!("ui.widgets.demo.autostart"),
                checked: autostart(),
                busy: applying(),
                on_change: move |v| {
                    applying.set(true);
                    spawn(async move {
                        tokio::time::sleep(Duration::from_millis(1200)).await;
                        autostart.set(v);
                        applying.set(false);
                    });
                },
            }
            Switch {
                label: t!("ui.widgets.demo.stealth"),
                checked: false,
                disabled: true,
                disabled_reason: t!("ui.widgets.demo.disabledReason"),
                on_change: move |_| {},
            }
            Checkbox {
                label: t!("ui.widgets.demo.agree"),
                hint: t!("ui.widgets.demo.agreeHint"),
                checked: agree(),
                on_change: move |v| agree.set(v),
            }
            Row { label: t!("ui.widgets.demo.mode"),
                Segmented {
                    options: vec![("hard", "Hard".to_string()), ("soft", "Soft".to_string()), ("direct", "Direct".to_string())],
                    value: mode(),
                    on_change: move |v| mode.set(v),
                    label: t!("ui.widgets.demo.mode"),
                }
            }
            Tabs {
                tabs: tab_names.iter().cloned().enumerate().collect::<Vec<_>>(),
                value: tab(),
                on_change: move |v| tab.set(v),
                label: t!("ui.widgets.demo.tabs"),
                p { class: "wd-note", {t!("ui.widgets.demo.tabBody", tab = current)} }
            }
        }
    }
}
