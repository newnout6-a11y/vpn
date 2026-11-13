//! [`HelperLine`]: the one calm line of a privileged control; [`InstallService`]: its install.
use std::rc::Rc;

use dioxus::prelude::*;

use super::{Ability, Feature, HelperApi, Lack, use_capability};
use crate::lang::tr;
use crate::t;
use crate::widgets::{Button, ButtonKind, use_job};

/// The line where a privileged control lives: nothing while it works; «… работает через
/// службу-помощник.» with «Установить службу-помощник» while the service is missing; «В этой
/// версии недоступно.» for what no part of this version carries; under Tunnel mode, what an older
/// service does not do yet (it updates itself). Nothing without a helper backend in context.
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
        Ability::Service | Ability::InProcess => None,
    };
    // What an older service lacks concerns Tunnel mode only, and only while it carries it.
    let lacks = match (feature, ability) {
        (Feature::Tunnel, Ability::Service) => cap.lacks().to_vec(),
        _ => Vec::new(),
    };
    if text.is_none() && lacks.is_empty() {
        return rsx! {};
    }
    let offer = ability == Ability::NeedsService;
    rsx! {
        div { class: "helper-line", "data-helper": feature.id(),
            if let Some(text) = text {
                p { class: "helper-line-text", "{text}" }
            }
            for lack in lacks {
                p { class: "helper-line-text", "data-lack": lack.id(), {t!(lack_key(lack))} }
            }
            if offer {
                InstallService {}
            }
        }
    }
}

/// «Установить службу-помощник» (Windows shows its one prompt; a declined prompt changes
/// nothing) and why a failed install failed. For a place where installing makes the control
/// beside it work; nothing without a helper backend in context.
#[component]
pub fn InstallService() -> Element {
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
            {t!("ui.helper.install")}
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

fn lack_key(lack: Lack) -> &'static str {
    match lack {
        Lack::AppScope => "ui.helper.older.appScope",
    }
}
