//! The request dialog of a subscription (ru-2026 item 1): whether the app sends the device HWID,
//! and the extra request headers. Only header names are shown: the values may be tokens and never
//! come back from the backend; saving replaces every header.
use dioxus::prelude::*;

use super::actions::Actions;
use crate::lang::tr;
use crate::t;
use crate::widgets::{Button, ButtonKind, Field, Modal, ModalSize, Switch, TextArea};

#[component]
pub(crate) fn RequestDialog() -> Element {
    let actions = use_context::<Actions>();
    let store = actions.store;
    let mut request = store.request;
    let open = use_memo(move || request.read().is_some());
    let form = request();
    let group = form.as_ref().and_then(|f| {
        let view = store.view.read();
        view.groups.iter().find(|g| g.id == f.group).cloned()
    });
    let (Some(form), Some(group)) = (form, group) else {
        return rsx! {
            Modal { open, title: String::new(), on_close: move |_| request.set(None),
                close_label: t!("common.close") }
        };
    };
    let switching = store.busy.read().get(&group.id).is_some_and(|b| b.policy);
    let names = if group.header_names.is_empty() {
        t!("ui.servers.request.headersNone")
    } else {
        t!(
            "ui.servers.request.headersSet",
            names = group.header_names.join(", ")
        )
    };
    let error = form.error.as_ref().map(|e| tr(&e.msg));
    let (a_hwid, a_save, a_clear) = (actions.clone(), actions.clone(), actions.clone());
    let id = group.id.clone();
    let blank = form.headers.trim().is_empty();
    let footer = rsx! {
        Button {
            kind: ButtonKind::Ghost,
            disabled: form.busy || group.header_names.is_empty(),
            onclick: move |_| a_clear.save_headers(true),
            {t!("ui.servers.request.clear")}
        }
        Button { busy: form.busy, disabled: blank, onclick: move |_| a_save.save_headers(false),
            {t!("ui.servers.request.save")}
        }
    };
    rsx! {
        Modal {
            open,
            title: t!("ui.servers.request.title", name = form.name.clone()),
            description: t!("ui.servers.request.description"),
            on_close: move |_| request.set(None),
            close_label: t!("common.close"),
            size: ModalSize::Md,
            footer,
            div { class: "srv-add",
                Switch {
                    label: t!("ui.servers.request.hwid"),
                    hint: t!("ui.servers.request.hwidHint"),
                    checked: group.send_hwid,
                    busy: switching,
                    on_change: move |on| a_hwid.set_send_hwid(&id, on, false),
                }
                if let Some(device_id) = group.device_id.clone().filter(|_| group.send_hwid) {
                    DeviceId { group: group.id.clone(), device_id, own: group.own_device_id, busy: switching }
                }
                Field { label: t!("ui.servers.request.headers"), hint: names, error,
                    TextArea {
                        value: form.headers.clone(),
                        oninput: move |text: String| {
                            if let Some(f) = request.write().as_mut() {
                                f.headers = text;
                                f.error = None;
                            }
                        },
                        rows: 4,
                        placeholder: t!("ui.servers.request.headersPlaceholder"),
                        disabled: form.busy,
                        invalid: form.error.is_some(),
                        mono: true,
                    }
                }
                p { class: "w-field-hint", {t!("ui.servers.request.headersHint")} }
            }
        }
    }
}

/// The device ID the subscription sends (the user may name it to the provider's support), a new
/// one on request, and the way back to this PC's ID.
#[component]
fn DeviceId(group: String, device_id: String, own: bool, busy: bool) -> Element {
    let actions = use_context::<Actions>();
    let (a_new, a_back, g_new) = (actions.clone(), actions, group.clone());
    rsx! {
        div { class: "srv-add-device",
            span { class: "w-field-label", {t!("ui.servers.request.deviceId")} }
            span { class: "swiss-mono", "{device_id}" }
            Button { kind: ButtonKind::Link, small: true, disabled: busy,
                onclick: move |_| a_new.set_own_device_id(&g_new, true),
                {t!("ui.servers.request.newId")}
            }
            if own {
                Button { kind: ButtonKind::Link, small: true, disabled: busy,
                    onclick: move |_| a_back.set_own_device_id(&group, false),
                    {t!("ui.servers.request.pcId")}
                }
            }
            p { class: "w-field-hint",
                if own {
                    {t!("ui.servers.request.ownIdHint")}
                } else {
                    {t!("ui.servers.request.pcIdHint")}
                }
            }
        }
    }
}
