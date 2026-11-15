//! [`HelperLine`]: the one calm line of a privileged control; [`InstallService`]: its install.
use std::rc::Rc;

use dioxus::prelude::*;

use super::{Ability, Feature, HelperApi, use_capability};
use crate::lang::tr;
use crate::t;
use crate::widgets::{Button, ButtonKind, use_job};

/// The line where a privileged control lives: nothing while it works; «… работает через
/// службу-помощник.» with «Установить службу-помощник» while the service is missing;
/// «Служба-помощник запускается…» / «… остановлена…» while the installed one is down;
/// «Служба-помощник устарела.» with «Обновить службу-помощник» while it is too old to speak to;
/// «В этой версии недоступно.» for what no part of this version carries. Nothing without a helper
/// backend in context.
#[component]
pub fn HelperLine(feature: Feature) -> Element {
    let cap = use_capability();
    let Some(cap) = cap else {
        return rsx! {};
    };
    let ability = cap.ability(feature);
    let text = match ability {
        Ability::NeedsService => Some(t!(needs_key(feature))),
        Ability::NotInVersion => Some(t!("ui.helper.notInVersion")),
        // Installed but not running right now: say so instead of a silent offer.
        Ability::Service => cap.service.pause_key().map(|key| t!(key)),
        Ability::InProcess => None,
    };
    let Some(text) = text else {
        return rsx! {};
    };
    let offer = ability == Ability::NeedsService;
    let update = ability == Ability::Service && cap.service.needs_update();
    rsx! {
        div { class: "helper-line", "data-helper": feature.id(),
            p { class: "helper-line-text", "{text}" }
            if offer || update {
                InstallService { update }
            }
        }
    }
}

/// «Установить службу-помощник», or «Обновить службу-помощник» over a service too old to speak
/// to (`update`: the same install verb; Windows shows its one prompt, a declined prompt changes
/// nothing), and why a failed install failed. For a place where installing makes the control
/// beside it work; nothing without a helper backend in context.
#[component]
pub fn InstallService(#[props(default)] update: bool) -> Element {
    let api = try_use_context::<Rc<dyn HelperApi>>();
    let install = use_job::<bool>();
    let Some(api) = api else {
        return rsx! {};
    };
    let error = match install.last() {
        Some(Err(err)) => Some(tr(&err.msg)),
        _ => None,
    };
    rsx! {
        Button {
            kind: ButtonKind::Ghost,
            small: true,
            busy: install.running(),
            onclick: move |_| {
                let api = api.clone();
                install.start(move |_| async move { api.install_service().await });
            },
            {t!(install_key(update))}
        }
        if let Some(error) = error {
            p { class: "helper-line-error", role: "alert", "{error}" }
        }
    }
}

/// The line of a feature the missing service would carry: named where it helps to know which
/// controls of the panel it concerns.
fn needs_key(feature: Feature) -> &'static str {
    match feature {
        Feature::Tunnel => "ui.helper.tunnel",
        Feature::KillSwitch => "ui.helper.killSwitch",
        Feature::Policies | Feature::Capture => "ui.helper.viaService",
    }
}

/// The install button's label: an update over a service too old to speak to.
pub(super) const fn install_key(update: bool) -> &'static str {
    if update {
        "ui.helper.update"
    } else {
        "ui.helper.install"
    }
}
