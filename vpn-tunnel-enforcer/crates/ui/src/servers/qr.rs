//! The key as a QR code for a phone, in the server detail (RU-2026 item 4). Fetched only on the
//! user's click and dropped with the detail; the backend refuses a key its provider hides (the
//! detail does not even offer it then).
use dioxus::prelude::*;
use vpnte_base::ErrorKind;

use super::api::use_servers_api;
use super::links_model::QrCode;
use crate::lang::tr;
use crate::t;
use crate::widgets::{Button, ButtonKind, Loading, UiError};

/// Modules of light margin around the code (the QR standard's quiet zone).
const QUIET: u32 = 4;

#[derive(Debug, Clone, PartialEq)]
enum Shown {
    Hidden,
    Loading,
    Ready(QrCode),
    Failed(UiError),
}

/// «QR-код» card of the server `id`.
#[component]
pub(crate) fn KeyQr(id: String) -> Element {
    let api = use_servers_api();
    let mut shown = use_signal(|| Shown::Hidden);
    let show = move |_| {
        if matches!(*shown.peek(), Shown::Loading) {
            return;
        }
        shown.set(Shown::Loading);
        let (api, id) = (api.clone(), id.clone());
        // Scoped to this card: closing the detail drops the request and the code.
        spawn(async move {
            match api.key_qr(&id).await {
                Ok(qr) => shown.set(Shown::Ready(qr)),
                Err(err) if err.kind == ErrorKind::Cancelled => shown.set(Shown::Hidden),
                Err(err) => shown.set(Shown::Failed(UiError::from(&err))),
            }
        });
    };
    let state = shown();
    rsx! {
        section { class: "srv-detail-card srv-qr",
            h3 { class: "swiss-label", {t!("ui.servers.phones.qr.title")} }
            match state {
                Shown::Hidden => rsx! {
                    p { class: "srv-detail-note", {t!("ui.servers.phones.qr.hint")} }
                    Button { kind: ButtonKind::Ghost, small: true, onclick: show,
                        {t!("ui.servers.phones.qr.show")}
                    }
                },
                Shown::Loading => rsx! {
                    Loading { label: t!("ui.servers.phones.qr.loading") }
                },
                Shown::Ready(qr) => rsx! {
                    QrSvg { qr }
                    p { class: "srv-detail-note", {t!("ui.servers.phones.qr.warning")} }
                    Button { kind: ButtonKind::Ghost, small: true,
                        onclick: move |_| shown.set(Shown::Hidden),
                        {t!("ui.servers.phones.qr.hide")}
                    }
                },
                Shown::Failed(err) => rsx! {
                    p { class: "srv-detail-note is-alert", role: "alert",
                        {t!("ui.servers.phones.qr.failed")}
                        " "
                        {tr(&err.msg)}
                    }
                },
            }
        }
    }
}

/// Dark modules on a light square with the quiet zone; crisp edges at any zoom.
#[component]
fn QrSvg(qr: QrCode) -> Element {
    let side = qr.size + 2 * QUIET;
    rsx! {
        svg {
            "xmlns": "http://www.w3.org/2000/svg",
            class: "srv-qr-code",
            role: "img",
            "aria-label": t!("ui.servers.phones.qr.title"),
            view_box: "-{QUIET} -{QUIET} {side} {side}",
            shape_rendering: "crispEdges",
            rect { x: "-{QUIET}", y: "-{QUIET}", width: "{side}", height: "{side}", fill: "#fff" }
            path { d: qr.path(), fill: "#000" }
        }
    }
}
