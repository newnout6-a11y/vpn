//! Links and QR codes from phones and messengers (RU-2026 item 4): the overlay that opens the
//! Servers page for a link Windows handed over, the page hook that puts it into the add dialog,
//! and the add dialog's sources (clipboard, key file, QR picture, QR on screen). Every source
//! only fills the dialog: the user confirms with «Добавить».
use std::time::Duration;

use dioxus::desktop::{DesktopContext, use_window};
use dioxus::prelude::*;
use tokio::sync::oneshot;
use vpnte_base::ErrorKind;

use super::actions::Actions;
use super::api::use_servers_api;
use crate::pages::{Page, use_nav};
use crate::t;
use crate::tray::show_window;
use crate::widgets::{Button, ButtonKind, UiError};

/// How long the hidden window needs to leave the screen before it is read (DWM animation).
const HIDE_SETTLE: Duration = Duration::from_millis(350);

/// Mount once under the shell (the root's overlays): each link Windows hands the app opens the
/// Servers page, whose add dialog takes it.
#[component]
pub fn LinkHandoff() -> Element {
    let api = use_servers_api();
    let nav = use_nav();
    use_future(move || {
        let mut arrivals = api.link_arrivals();
        async move {
            let mut seen = 0;
            loop {
                let seq = *arrivals.borrow_and_update();
                if seq != seen {
                    seen = seq;
                    nav.go(Page::Servers);
                }
                if arrivals.changed().await.is_err() {
                    return;
                }
            }
        }
    });
    rsx! {}
}

/// The page's side: each handed-over link opens the add dialog with it (once). While the dialog
/// imports or reads a source the link waits in the inbox (that work would overwrite it) and
/// opens as soon as the dialog is free: a clicked link is never lost.
pub(crate) fn use_link_intake(actions: &Actions) {
    let mut arrived = use_signal(|| 0u64);
    let api = actions.api.clone();
    use_future(move || {
        let mut arrivals = api.link_arrivals();
        async move {
            loop {
                arrived.set(*arrivals.borrow_and_update());
                if arrivals.changed().await.is_err() {
                    return;
                }
            }
        }
    });
    let actions = actions.clone();
    use_effect(move || {
        let _arrival = *arrived.read();
        let free = {
            let f = actions.store.add.read();
            !f.busy && !f.reading
        };
        if free && let Some(link) = actions.api.take_link() {
            offer_link(&actions, link);
        }
    });
}

/// Puts `link` into the free add dialog, with the new-group defaults, and opens it.
pub(super) fn offer_link(actions: &Actions, link: String) {
    let (mut form, mut open) = (actions.store.add, actions.store.add_open);
    form.write().linked(link);
    open.set(true);
}

/// Where the add dialog's text comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Clipboard,
    File,
    QrFile,
    QrScreen,
}

/// The source buttons above the key field.
#[component]
pub(crate) fn AddSources() -> Element {
    let actions = use_context::<Actions>();
    let desktop = use_window();
    let f = actions.store.add.read();
    let off = f.busy || f.reading;
    drop(f);
    let button = |source: Source, label: String, title: String| {
        let (actions, desktop) = (actions.clone(), desktop.clone());
        rsx! {
            Button {
                kind: ButtonKind::Ghost,
                small: true,
                disabled: off,
                title,
                onclick: move |_| fill(&actions, desktop.clone(), source),
                {label}
            }
        }
    };
    rsx! {
        div { class: "srv-add-sources", role: "group", aria_label: t!("ui.servers.phones.sources"),
            span { class: "w-field-label", {t!("ui.servers.phones.sources")} }
            {button(Source::Clipboard, t!("ui.servers.phones.clipboard"), t!("ui.servers.phones.clipboardTitle"))}
            {button(Source::File, t!("ui.servers.phones.file"), t!("ui.servers.phones.fileTitle"))}
            {button(Source::QrFile, t!("ui.servers.phones.qrFile"), t!("ui.servers.phones.qrFileTitle"))}
            {button(Source::QrScreen, t!("ui.servers.phones.qrScreen"), t!("ui.servers.phones.qrScreenTitle"))}
        }
    }
}

/// Reads `source` in the page's scope (the dialog may close meanwhile) and puts the text into the
/// draft; a dismissed dialog changes nothing, a failure shows under the field.
fn fill(actions: &Actions, desktop: DesktopContext, source: Source) {
    let mut form = actions.store.add;
    if form.peek().reading || form.peek().busy {
        return;
    }
    form.write().reading = true;
    let api = actions.api.clone();
    actions.spawn(async move {
        let result = match source {
            Source::Clipboard => api.read_clipboard().await.map(Some),
            Source::File => api.read_key_file().await,
            Source::QrFile => api.scan_qr_file().await,
            Source::QrScreen => {
                // Our own window would cover what the user wants read; it comes back as soon as
                // the screen is read, not after the slower decoding.
                desktop.window.set_visible(false);
                tokio::time::sleep(HIDE_SETTLE).await;
                let (captured, read) = oneshot::channel();
                let back = async {
                    let _ = read.await;
                    show_window(&desktop);
                };
                let (scan, ()) = tokio::join!(api.scan_qr_screen(captured), back);
                scan.map(Some)
            }
        };
        let mut f = form.write();
        f.reading = false;
        match result {
            Ok(Some(text)) => {
                f.input = text;
                f.error = None;
                f.from_link = false;
            }
            Ok(None) => {}
            Err(err) if err.kind == ErrorKind::Cancelled => {}
            Err(err) => f.error = Some(UiError::from(&err)),
        }
    });
}
