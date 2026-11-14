//! The add dialog: a key, a key list, JSON or a subscription URL, the target group and the device
//! persona the subscription is fetched as; then the import report. The import belongs to the
//! page: closing the dialog does not stop it (its outcome then arrives as a toast).
use dioxus::prelude::*;
use vpnte_base::types::ClientDevice;

use super::actions::{Actions, fetch_error_text};
use super::links::AddSources;
use super::model::{AddTarget, GroupSource, ImportReport};
use super::present::{DEVICES, device_label, sort_groups};
use crate::lang::tr;
use crate::t;
use crate::widgets::{
    Badge, Button, ButtonKind, Checkbox, Field, Modal, ModalSize, ProgressBar, Segmented, Select,
    SelectOption, TextArea, Tone,
};

#[component]
pub(crate) fn AddDialog() -> Element {
    let actions = use_context::<Actions>();
    let store = actions.store;
    let mut open = store.add_open;
    let mut form = store.add;
    let f = form();
    let mut groups = store.view.read().groups.clone();
    sort_groups(&mut groups);
    let options: Vec<SelectOption<AddTarget>> = std::iter::once(SelectOption::new(
        AddTarget::Auto,
        t!("ui.servers.add.targetAuto"),
    ))
    .chain(groups.into_iter().map(|g| {
        let tag = if g.source == GroupSource::Subscription {
            "SUB"
        } else {
            "KEYS"
        };
        SelectOption::new(AddTarget::Group(g.id), format!("{} · {tag}", g.name))
    }))
    .collect();
    let devices: Vec<(ClientDevice, String)> = DEVICES
        .iter()
        .map(|&d| (d, device_label(d).to_owned()))
        .collect();
    let error = f.error.as_ref().map(|e| tr(&e.msg));
    let help = f
        .error
        .as_ref()
        .and_then(|e| help_for(&e.msg.key, f.request.send_hwid));
    let blank = f.input.trim().is_empty();
    let mut close = move || {
        open.set(false);
        form.write().closed();
    };
    let (a_submit, a_enter) = (actions.clone(), actions.clone());
    let (a_copy, a_retry) = (actions.clone(), actions.clone());
    let footer = if f.report.is_some() {
        rsx! {
            Button { kind: ButtonKind::Ghost, onclick: move |_| form.write().report = None,
                {t!("ui.servers.add.more")}
            }
            Button { initial_focus: true, onclick: move |_| close(), {t!("ui.servers.add.done")} }
        }
    } else {
        rsx! {
            Button { kind: ButtonKind::Ghost, onclick: move |_| close(), {t!("common.cancel")} }
            Button {
                busy: f.busy,
                disabled: blank || f.reading,
                onclick: move |_| a_submit.add(),
                {t!("servers.addServer")}
            }
        }
    };
    rsx! {
        Modal {
            open,
            title: t!("ui.servers.add.title"),
            description: t!("ui.servers.add.description"),
            on_close: move |_| close(),
            close_label: t!("common.close"),
            size: ModalSize::Md,
            footer,
            if let Some(report) = f.report.clone() {
                Report { report }
            } else {
                div { class: "srv-add",
                    if f.from_link {
                        p { class: "srv-strip is-info", role: "status", {t!("ui.servers.phones.fromLink")} }
                    }
                    AddSources {}
                    Field { label: t!("ui.servers.add.keyLabel"), hint: t!("ui.servers.add.hint"), error,
                        TextArea {
                            value: f.input.clone(),
                            oninput: move |text: String| {
                                let mut f = form.write();
                                f.input = text;
                                f.error = None;
                                f.from_link = false;
                                // Edited by hand: the user vouches for the address now.
                                f.request.from_outside = false;
                            },
                            rows: 4,
                            placeholder: t!("servers.addPlaceholder"),
                            disabled: f.busy || f.reading,
                            invalid: f.error.is_some(),
                            mono: true,
                            on_submit: move |_| a_enter.add(),
                        }
                    }
                    match help {
                        Some(Help::CopyRequest) => rsx! {
                            Button { kind: ButtonKind::Ghost, small: true,
                                onclick: move |_| a_copy.copy_provider_request(),
                                {t!("ui.servers.add.copyRequest")}
                            }
                        },
                        Some(Help::HwidRetry) => rsx! {
                            Button { kind: ButtonKind::Ghost, small: true,
                                onclick: move |_| {
                                    form.write().request.send_hwid = true;
                                    a_retry.add();
                                },
                                {t!("ui.servers.add.hwidRetry")}
                            }
                        },
                        None => rsx! {},
                    }
                    Field { label: t!("servers.add.selectGroup"),
                        Select {
                            options,
                            value: Some(f.target.clone()),
                            on_change: move |target| form.write().target = target,
                            disabled: f.busy,
                        }
                    }
                    div { class: "srv-add-device",
                        span { class: "w-field-label", {t!("ui.servers.add.device")} }
                        Segmented {
                            options: devices,
                            value: f.device,
                            on_change: move |device| form.write().device = device,
                            label: t!("ui.servers.add.device"),
                            disabled: f.busy,
                        }
                        p { class: "w-field-hint", {t!("ui.servers.add.deviceHint")} }
                    }
                    // A new subscription's request settings (a known one keeps its own).
                    Checkbox {
                        label: t!("ui.servers.request.hwid"),
                        hint: t!("ui.servers.add.hwidHint"),
                        checked: f.request.send_hwid,
                        on_change: move |on| form.write().request.send_hwid = on,
                        disabled: f.busy,
                    }
                    Field { label: t!("ui.servers.add.headers"), hint: t!("ui.servers.request.headersHint"),
                        TextArea {
                            value: f.request.headers.clone(),
                            oninput: move |text: String| form.write().request.headers = text,
                            rows: 2,
                            placeholder: t!("ui.servers.request.headersPlaceholder"),
                            disabled: f.busy,
                            mono: true,
                        }
                    }
                    if f.busy {
                        div { class: "srv-add-progress", role: "status", aria_live: "polite",
                            span { {t!("ui.servers.add.loading")} }
                            ProgressBar { value: None, label: t!("ui.servers.add.loading") }
                        }
                    }
                }
            }
        }
    }
}

/// What the add dialog offers under an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Help {
    /// An encrypted app link: the provider has the plain link; a request for it is copied.
    CopyRequest,
    /// The panel serves only devices with an HWID: turn the switch on and add again.
    HwidRetry,
}

/// Backend message keys of an encrypted app link's refusal (`profiles.deeplink.*`). Compared
/// only: the app registers their text.
pub(crate) const ENCRYPTED_LINK: [&str; 3] = [
    "profiles.deeplink.encryptedHapp",
    "profiles.deeplink.encryptedMantaray",
    "profiles.deeplink.encrypted",
];
/// Backend message keys of a panel that serves only devices with an HWID (`servers.fetch.*`),
/// its notices included (speed audit ops1: what HWID-bound panels send a device without one).
/// Compared only: the app registers their text.
pub(crate) const NEEDS_HWID: [&str; 4] = [
    "servers.fetch.hwidRequired",
    "servers.fetch.emptyListNoHwid",
    "servers.fetch.said",
    "servers.fetch.placeholder",
];

/// The help for the error `key`; the HWID retry only while the switch is off.
pub(crate) fn help_for(key: &str, send_hwid: bool) -> Option<Help> {
    if ENCRYPTED_LINK.contains(&key) {
        return Some(Help::CopyRequest);
    }
    (NEEDS_HWID.contains(&key) && !send_hwid).then_some(Help::HwidRetry)
}

/// What an import did: target group, counts, and the lines that were skipped (by number only:
/// a line may hold a key).
#[component]
fn Report(report: ImportReport) -> Element {
    let rows = [
        (t!("ui.servers.add.added"), report.added),
        (t!("ui.servers.add.updated"), report.updated),
        (t!("ui.servers.add.unchanged"), report.unchanged),
    ];
    rsx! {
        div { class: "srv-report", role: "status",
            p { class: "srv-report-head",
                {t!("ui.servers.add.reportTitle")}
                if report.subscription {
                    Badge { tone: Tone::Neutral, "SUB" }
                }
            }
            dl { class: "srv-report-grid",
                dt { class: "swiss-label", {t!("serverDetail.group")} }
                dd { "{report.group_name}" }
                for (label , count) in rows {
                    dt { class: "swiss-label", "{label}" }
                    dd { class: "swiss-mono", "{count}" }
                }
                dt { class: "swiss-label", {t!("ui.servers.add.skipped")} }
                dd { class: "swiss-mono", class: if !report.skipped.is_empty() { "is-alert" }, "{report.skipped.len()}" }
            }
            if !report.providers.is_empty() {
                p { class: "srv-report-head", {t!("ui.servers.add.providers")} }
                ul { class: "srv-report-skipped",
                    for provider in report.providers.iter() {
                        li { key: "{provider.name}",
                            span { class: "swiss-mono", "{provider.name}" }
                            " "
                            match provider.error {
                                Some(why) => fetch_error_text(why),
                                None => t!("ui.servers.add.providerServers", count = provider.servers),
                            }
                        }
                    }
                }
            }
            if !report.skipped.is_empty() {
                ul { class: "srv-report-skipped",
                    for line in report.skipped.iter() {
                        li { key: "{line.line}",
                            span { class: "swiss-mono", {t!("ui.servers.add.line", line = line.line)} }
                            " "
                            {tr(&line.reason)}
                        }
                    }
                }
            }
        }
    }
}
