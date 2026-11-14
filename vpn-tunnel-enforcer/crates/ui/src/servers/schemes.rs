//! The link-scheme panel (RU-2026 item 4): which links (`vless://`, `hiddify://import/`, …)
//! Windows opens in this app. Free schemes were taken at install or the installed copy's first
//! start (a portable copy takes them only from here: «open links here»); one another program
//! answers is taken only here, on the user's click, and that program's registration comes back
//! when ours goes; one the user gave another program in Windows' settings is changed there.
//! Opened from the Servers page header: the Settings page belongs to another package.
use dioxus::prelude::*;
use vpnte_base::AppResult;

use super::actions::Actions;
use super::links_model::{LinkScheme, LinkSchemes, SchemeOwner};
use crate::lang::tr;
use crate::t;
use crate::widgets::{Button, ButtonKind, Checkbox, Loading, Modal, ModalSize, UiError};

/// Share-link schemes; the rest are other clients' subscription imports.
const KEY_SCHEMES: [&str; 8] = [
    "vless",
    "vmess",
    "trojan",
    "ss",
    "hysteria2",
    "hy2",
    "tuic",
    "anytls",
];

/// What the panel shows.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct SchemesPanel {
    pub loading: bool,
    pub list: Vec<LinkScheme>,
    /// A portable copy: it offers «open links here» instead of registering by itself.
    pub portable: bool,
    pub error: Option<UiError>,
    /// The scheme being changed, `*` for «open links here» (every toggle waits for it).
    pub changing: Option<String>,
}

impl SchemesPanel {
    /// The backend's answer to a read or a change.
    fn answered(&mut self, result: AppResult<LinkSchemes>) {
        match result {
            Ok(schemes) => {
                self.list = schemes.list;
                self.portable = schemes.portable;
                self.error = None;
            }
            Err(err) => self.error = Some(UiError::from(&err)),
        }
    }
}

impl Actions {
    /// Opens the panel and reads who answers each scheme now.
    pub fn open_schemes(&self) {
        let (store, api) = (self.store, self.api.clone());
        let (mut open, mut panel) = (store.schemes_open, store.schemes);
        open.set(true);
        panel.write().loading = true;
        self.spawn(async move {
            let result = api.link_schemes().await;
            let mut p = panel.write();
            p.loading = false;
            p.answered(result);
        });
    }

    /// A portable copy's «open links here».
    fn adopt_schemes(&self) {
        let (api, mut panel) = (self.api.clone(), self.store.schemes);
        if panel.peek().changing.is_some() {
            return;
        }
        panel.write().changing = Some("*".into());
        self.spawn(async move {
            let result = api.adopt_link_schemes().await;
            let mut p = panel.write();
            p.changing = None;
            p.answered(result);
        });
    }

    fn set_scheme(&self, scheme: String, on: bool) {
        let (api, mut panel) = (self.api.clone(), self.store.schemes);
        if panel.peek().changing.is_some() {
            return;
        }
        panel.write().changing = Some(scheme.clone());
        self.spawn(async move {
            let result = api.set_link_scheme(scheme, on).await;
            let mut p = panel.write();
            p.changing = None;
            p.answered(result);
        });
    }
}

/// «Ссылки из браузера и мессенджеров».
#[component]
pub(crate) fn LinkSchemesDialog() -> Element {
    let actions = use_context::<Actions>();
    let mut open = actions.store.schemes_open;
    let panel = actions.store.schemes.read().clone();
    let busy = panel.changing.is_some();
    let group = |keys: bool| -> Vec<LinkScheme> {
        panel
            .list
            .iter()
            .filter(|s| KEY_SCHEMES.contains(&s.scheme.as_str()) == keys)
            .cloned()
            .collect()
    };
    let (keys, imports) = (group(true), group(false));
    rsx! {
        Modal {
            open,
            title: t!("ui.servers.phones.schemesTitle"),
            description: t!("ui.servers.phones.schemesDescription"),
            on_close: move |_| open.set(false),
            close_label: t!("common.close"),
            size: ModalSize::Md,
            footer: rsx! {
                Button { kind: ButtonKind::Ghost, initial_focus: true, onclick: move |_| open.set(false),
                    {t!("common.close")}
                }
            },
            if panel.loading && panel.list.is_empty() {
                Loading { label: t!("ui.servers.phones.schemesLoading") }
            }
            if let Some(err) = &panel.error {
                p { class: "srv-strip is-fail", role: "alert", {tr(&err.msg)} }
            }
            if panel.portable {
                div { class: "srv-strip",
                    span { {t!("ui.servers.phones.portableNote")} }
                    Button { kind: ButtonKind::Ghost, small: true, disabled: busy,
                        onclick: {
                            let actions = actions.clone();
                            move |_| actions.adopt_schemes()
                        },
                        {t!("ui.servers.phones.adopt")}
                    }
                }
            }
            SchemeGroup { title: t!("ui.servers.phones.keysSection"), schemes: keys, busy }
            SchemeGroup { title: t!("ui.servers.phones.importSection"), schemes: imports, busy }
            p { class: "srv-detail-note", {t!("ui.servers.phones.cryptNote")} }
        }
    }
}

#[component]
fn SchemeGroup(title: String, schemes: Vec<LinkScheme>, busy: bool) -> Element {
    if schemes.is_empty() {
        return rsx! {};
    }
    rsx! {
        section { class: "srv-schemes",
            h3 { class: "swiss-label", "{title}" }
            for scheme in schemes {
                SchemeRow { key: "{scheme.scheme}", scheme, busy }
            }
        }
    }
}

#[component]
fn SchemeRow(scheme: LinkScheme, busy: bool) -> Element {
    let actions = use_context::<Actions>();
    let hint = match &scheme.owner {
        SchemeOwner::Free => t!("ui.servers.phones.free"),
        SchemeOwner::Ours => t!("ui.servers.phones.ours"),
        SchemeOwner::Other(Some(name)) => t!("ui.servers.phones.other", name = name),
        SchemeOwner::Other(None) => t!("ui.servers.phones.otherUnknown"),
        SchemeOwner::Chosen(name) => t!("ui.servers.phones.chosen", name = name),
    };
    // The user's Windows choice wins over any registration: a tick here could not change it.
    let chosen = matches!(scheme.owner, SchemeOwner::Chosen(_));
    let name = scheme.scheme.clone();
    rsx! {
        Checkbox {
            label: format!("{}://", scheme.scheme),
            checked: scheme.owner == SchemeOwner::Ours,
            hint,
            disabled: busy || chosen,
            on_change: move |on| actions.set_scheme(name.clone(), on),
        }
    }
}
