//! «Ротация профилей» (instant; U-16: one server per call, U-17: Direct-only hint and distinct
//! outcome texts, U-32: the countdown follows the pushed config).
use std::time::Duration;

use dioxus::prelude::*;
use vpnte_base::Msg;

use super::fmt::{countdown, countdown_text};
use super::model::{
    ROTATION_INTERVAL_MIN, RotationOrder, RotationOutcome, RotationPatch, RotationServer,
    ServerStatus,
};
use super::{ActionError, Line, use_api, use_ctx};
use crate::lang::{LANG, Lang};
use crate::pages::use_page_active;
use crate::t;
use crate::widgets::{
    Badge, Button, ButtonKind, Checkbox, NumberInput, Panel, Row, Segmented, Switch, Tone, use_job,
};

/// Display name of a server id (the raw id when it is not in the list).
fn server_name(servers: &[RotationServer], id: &str) -> String {
    servers
        .iter()
        .find(|s| s.id == id)
        .map_or_else(|| id.to_owned(), |s| s.name.clone())
}

/// The message of a «Ротировать сейчас» outcome and whether it is a success (`lang` renders a
/// failure reason into it).
pub(super) fn outcome_msg(
    outcome: &RotationOutcome,
    direct_session: bool,
    servers: &[RotationServer],
    lang: Lang,
) -> (bool, Msg) {
    match outcome {
        RotationOutcome::Rotated { profile_id } => (
            true,
            Msg::new("ui.settings.rotation.rotated").arg("name", server_name(servers, profile_id)),
        ),
        RotationOutcome::NothingToRotate if !direct_session => {
            (false, Msg::new("ui.settings.rotation.directOnly"))
        }
        RotationOutcome::NothingToRotate => (false, Msg::new("ui.settings.rotation.noOther")),
        RotationOutcome::NoProfiles => (false, Msg::new("ui.settings.rotation.noProfiles")),
        RotationOutcome::NoneAvailable => (false, Msg::new("ui.settings.rotation.noneAvailable")),
        RotationOutcome::Failed {
            reason,
            restored_previous,
        } => {
            let key = if *restored_previous {
                "ui.settings.rotation.failedRestored"
            } else {
                "ui.settings.rotation.failedNotRestored"
            };
            (false, Msg::new(key).arg("reason", reason.render(lang)))
        }
    }
}

/// Re-renders the countdown once a second while the page is shown.
fn use_now() -> Signal<i64> {
    let active = use_page_active();
    let mut now = use_signal(vpnte_base::types::now_ms);
    use_future(move || async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if *active.peek() {
                now.set(vpnte_base::types::now_ms());
            }
        }
    });
    now
}

#[component]
pub(super) fn Rotation() -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let set_job = use_job::<()>();
    let rotate_job = use_job::<RotationOutcome>();
    let rot = ctx.rotation.read().clone();
    let direct = ctx.state.read().direct_session;
    let set = {
        let api = api.clone();
        move |patch: RotationPatch| {
            let api = api.clone();
            set_job.start(move |_| async move { api.set_rotation(patch).await });
        }
    };
    let set_enabled = set.clone();
    let set_interval = set.clone();
    let rotate_api = api.clone();
    let rotate = move |_| {
        let api = rotate_api.clone();
        rotate_job.start(move |_| async move { api.rotate_now().await });
    };
    let set_error = match set_job.last() {
        Some(Err(err)) => Some(err),
        _ => None,
    };
    let rotate_result = rotate_job.last();
    rsx! {
        Panel { title: t!("settings.rotation"), id: "set-rotation",
            Switch {
                label: t!("settings.rotationEnabled"),
                hint: t!("ui.settings.rotation.directOnlyHint"),
                checked: rot.enabled,
                busy: set_job.running(),
                on_change: move |on| set_enabled(RotationPatch { enabled: Some(on), ..RotationPatch::default() }),
            }
            if rot.enabled {
                RotationStatus { rotate_busy: rotate_job.running(), on_rotate: rotate }
            }
            match rotate_result {
                Some(Ok(outcome)) => {
                    let (ok, msg) = outcome_msg(&outcome, direct, &rot.servers, *LANG.read());
                    rsx! {
                        p { class: "set-result", class: if !ok { "is-warn" }, role: "status", {crate::lang::tr(&msg)} }
                    }
                }
                Some(Err(err)) => rsx! { ActionError { error: Some(err) } },
                None => rsx! {},
            }
            Row { label: t!("settings.rotationInterval"), hint: t!("settings.rotationIntervalHint"),
                NumberInput {
                    value: i64::from(rot.interval_minutes),
                    min: ROTATION_INTERVAL_MIN.0,
                    max: ROTATION_INTERVAL_MIN.1,
                    unit: t!("ui.settings.units.min"),
                    // one change at a time: a commit during a save would be dropped
                    disabled: !rot.enabled || set_job.running(),
                    on_commit: move |v: i64| {
                        let minutes = u32::try_from(v).unwrap_or(30);
                        set_interval(RotationPatch { interval_minutes: Some(minutes), ..RotationPatch::default() });
                    },
                }
            }
            Line { label: t!("settings.rotationOrder"),
                Segmented {
                    label: t!("settings.rotationOrder"),
                    options: vec![
                        (RotationOrder::Sequential, t!("settings.rotationSequential")),
                        (RotationOrder::Random, t!("settings.rotationRandom")),
                    ],
                    value: rot.order,
                    disabled: set_job.running(),
                    on_change: move |order| set(RotationPatch { order: Some(order), ..RotationPatch::default() }),
                }
            }
            ActionError { error: set_error }
            ProfileChecklist { enabled: rot.enabled }
        }
    }
}

/// Current server, the countdown and «Ротировать сейчас» (only while rotation is on).
#[component]
fn RotationStatus(rotate_busy: bool, on_rotate: EventHandler<MouseEvent>) -> Element {
    let ctx = use_ctx();
    let now = use_now();
    let rot = ctx.rotation.read().clone();
    let current = rot
        .current_profile_id
        .as_deref()
        .map_or_else(|| "—".to_owned(), |id| server_name(&rot.servers, id));
    let next = countdown_text(countdown(rot.next_rotation_at, now()));
    rsx! {
        dl { class: "set-facts",
            div {
                dt { {t!("settings.rotationCurrentProfile")} }
                dd { "{current}" }
            }
            div {
                dt { {t!("settings.rotationNextIn")} }
                dd { class: "swiss-mono", "{next}" }
            }
            Button {
                kind: ButtonKind::Ghost,
                small: true,
                busy: rotate_busy,
                disabled: rot.profile_ids.is_empty(),
                disabled_reason: t!("settings.rotationNoProfiles"),
                onclick: on_rotate,
                {t!("settings.rotationRotateNow")}
            }
        }
    }
}

/// One checkbox per server; each toggle adds or removes that server only (U-16).
#[component]
fn ProfileChecklist(enabled: bool) -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let job = use_job::<()>();
    let rot = ctx.rotation.read().clone();
    let error = match job.last() {
        Some(Err(err)) => Some(err),
        _ => None,
    };
    rsx! {
        div { class: "set-subgroup", role: "group", aria_label: t!("settings.rotationProfiles"),
            p { class: "set-subgroup-title", {t!("settings.rotationProfiles")} }
            if rot.servers.is_empty() {
                p { class: "set-empty", {t!("ui.settings.rotation.noServers")} }
            } else if rot.profile_ids.is_empty() {
                p { class: "set-hint", {t!("settings.rotationNoProfiles")} }
            }
            div { class: "set-checklist",
                for server in rot.servers.iter() {
                    div { key: "{server.id}", class: "set-check-line",
                        Checkbox {
                            label: server.name.clone(),
                            hint: match &server.country {
                                Some(country) => format!("{} · {country}", server.protocol),
                                None => server.protocol.clone(),
                            },
                            checked: rot.profile_ids.contains(&server.id),
                            // one change at a time: a click during the save would be dropped
                            disabled: !enabled || job.running(),
                            on_change: {
                                let api = api.clone();
                                let id = server.id.clone();
                                move |on: bool| {
                                    let (api, id) = (api.clone(), id.clone());
                                    job.start(move |_| async move { api.set_rotation_profile(id, on).await });
                                }
                            },
                        }
                        match server.status {
                            ServerStatus::Online => rsx! { Badge { tone: Tone::Ok, {t!("ui.settings.rotation.online")} } },
                            ServerStatus::Offline => rsx! { Badge { tone: Tone::Fail, {t!("ui.settings.rotation.offline")} } },
                            ServerStatus::Unknown => rsx! { Badge { tone: Tone::Unknown, {t!("ui.widgets.notChecked")} } },
                        }
                    }
                }
            }
            ActionError { error }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::widgets::{NumberCommit, commit_number};

    fn servers() -> Vec<RotationServer> {
        vec![RotationServer {
            id: "prof-2".into(),
            name: "Riga-2".into(),
            protocol: "vless".into(),
            country: Some("LV".into()),
            status: ServerStatus::Online,
        }]
    }

    /// ui-pages §7.11 `clampInterval`: NaN → 5 (here: not a number → the field keeps its value),
    /// 3 → 5, 2000 → 1440, 45 → 45; the field never sends a value outside 5..1440.
    #[test]
    fn interval_commits_inside_the_range() {
        let (min, max) = ROTATION_INTERVAL_MIN;
        assert_eq!(commit_number("abc", min, max), NumberCommit::Invalid);
        assert_eq!(
            commit_number("3", min, max),
            NumberCommit::Clamped { typed: 3, value: 5 }
        );
        assert_eq!(
            commit_number("2000", min, max),
            NumberCommit::Clamped {
                typed: 2000,
                value: 1440
            }
        );
        assert_eq!(commit_number("45", min, max), NumberCommit::Exact(45));
    }

    /// §7.11 'displays structured rotation failure' + the Rust outcome texts (U-17).
    #[test]
    fn outcomes_have_distinct_texts() {
        let s = servers();
        let (ok, msg) = outcome_msg(
            &RotationOutcome::Rotated {
                profile_id: "prof-2".into(),
            },
            true,
            &s,
            Lang::Ru,
        );
        assert!(ok);
        assert_eq!(
            msg,
            Msg::new("ui.settings.rotation.rotated").arg("name", "Riga-2")
        );
        let (ok, msg) = outcome_msg(&RotationOutcome::NothingToRotate, false, &s, Lang::Ru);
        assert!(!ok);
        assert_eq!(msg.key, "ui.settings.rotation.directOnly");
        let (_, msg) = outcome_msg(&RotationOutcome::NothingToRotate, true, &s, Lang::Ru);
        assert_eq!(msg.key, "ui.settings.rotation.noOther");
        let (_, msg) = outcome_msg(&RotationOutcome::NoneAvailable, true, &s, Lang::Ru);
        assert_eq!(msg.key, "ui.settings.rotation.noneAvailable");
        let failed = RotationOutcome::Failed {
            reason: Msg::new("errors.network"),
            restored_previous: true,
        };
        let (ok, msg) = outcome_msg(&failed, true, &s, Lang::Ru);
        assert!(!ok);
        assert_eq!(msg.key, "ui.settings.rotation.failedRestored");
        // an unknown id is shown raw
        assert_eq!(server_name(&s, "prof-9"), "prof-9");
    }
}
