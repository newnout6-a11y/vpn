//! «Подключаться при запуске» (instant): the last-used server, the lowest-delay one, or nothing.
//! The segments show the user's own choice only: while there is none, no segment is on and the
//! hint says what applies (off, or what the subscription's provider asks), so a click on «Нет»
//! always stores an explicit Off, which then wins over any provider's word.
use dioxus::prelude::*;

use super::model::{LaunchChoice, LaunchSource, LaunchView};
use super::{ActionError, Line, use_api, use_ctx};
use crate::t;
use crate::widgets::{Segmented, use_job};

/// The line's hint: what the choice does, then who decided it while the user did not.
pub(super) fn hint(view: LaunchView) -> String {
    if !view.server_mode {
        return t!("ui.settings.launch.hintProxy");
    }
    let note = match (view.source, view.effective) {
        (LaunchSource::User, _) => None,
        (LaunchSource::Default, _) => Some(t!("ui.settings.launch.notChosen")),
        (LaunchSource::Provider, LaunchChoice::Off) => Some(t!("ui.settings.launch.providerOff")),
        (LaunchSource::Provider, LaunchChoice::LastUsed) => {
            Some(t!("ui.settings.launch.providerLastUsed"))
        }
        (LaunchSource::Provider, LaunchChoice::LowestDelay) => {
            Some(t!("ui.settings.launch.providerLowestDelay"))
        }
        (LaunchSource::Provider, LaunchChoice::Random) => {
            Some(t!("ui.settings.launch.providerRandom"))
        }
    };
    let what = t!("ui.settings.launch.hint");
    match note {
        Some(note) => format!("{what} {note}"),
        None => what,
    }
}

/// The segment that is on: the user's own choice, none while they have not made one.
pub(super) fn chosen(view: LaunchView) -> Option<LaunchChoice> {
    (view.source == LaunchSource::User).then_some(view.effective)
}

#[component]
pub(super) fn Launch() -> Element {
    let api = use_api();
    let ctx = use_ctx();
    let launch = ctx.state.read().launch;
    let job = use_job::<()>();
    let set = move |choice: LaunchChoice| {
        let api = api.clone();
        job.start(move |_| async move { api.set_launch(choice).await });
    };
    let error = match job.last() {
        Some(Err(err)) => Some(err),
        _ => None,
    };
    rsx! {
        Line { label: t!("ui.settings.launch.label"), hint: hint(launch),
            Segmented {
                label: t!("ui.settings.launch.label"),
                options: vec![
                    (Some(LaunchChoice::Off), t!("ui.settings.launch.off")),
                    (Some(LaunchChoice::LastUsed), t!("ui.settings.launch.lastUsed")),
                    (Some(LaunchChoice::LowestDelay), t!("ui.settings.launch.lowestDelay")),
                ],
                value: chosen(launch),
                disabled: job.running() || !launch.server_mode,
                on_change: move |choice: Option<LaunchChoice>| {
                    if let Some(choice) = choice {
                        set(choice);
                    }
                },
            }
        }
        ActionError { error }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review fix a13: while the user has not chosen no segment is on, so a click on «Нет»
    /// always stores an explicit Off (it then wins over a provider's later word); the user's own
    /// choice shows as theirs.
    #[test]
    fn only_the_users_own_choice_is_on() {
        let view = |effective, source| LaunchView {
            effective,
            source,
            server_mode: true,
        };
        assert_eq!(chosen(view(LaunchChoice::Off, LaunchSource::Default)), None);
        let provider = view(LaunchChoice::LastUsed, LaunchSource::Provider);
        assert_eq!(chosen(provider), None);
        let own = view(LaunchChoice::Off, LaunchSource::User);
        assert_eq!(chosen(own), Some(LaunchChoice::Off));
    }
}
