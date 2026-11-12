//! «Подключаться при запуске» on the Settings page: the automatic server choice's rule as the
//! page shows it, and the user's choice stored in `autopick.json`.
use std::sync::Arc;

use vpnte_automation::autopick::{LaunchChoice, LaunchPick, LaunchSource};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::settings::{ConnectionMode, Settings};
use vpnte_ui::settings as ui;

use super::Shared;
use crate::support::blocking;
use crate::svc_auto::{AppPick, Automation, UserAct};

/// What a launch would do now and who decided; without the automatic choice (page tests) it
/// shows off by default.
pub fn launch_view(automation: Option<&Automation>, settings: &Settings) -> ui::LaunchView {
    let server_mode = settings.connection_mode == ConnectionMode::DirectVpn;
    let Some(pick) = automation.and_then(|a| a.autopick.get()) else {
        return ui::LaunchView {
            server_mode,
            ..ui::LaunchView::default()
        };
    };
    let (effective, source) = pick.launch_rule();
    ui::LaunchView {
        effective: match effective {
            None => ui::LaunchChoice::Off,
            Some(LaunchPick::LastUsed) => ui::LaunchChoice::LastUsed,
            Some(LaunchPick::LowestDelay) => ui::LaunchChoice::LowestDelay,
            Some(LaunchPick::Random) => ui::LaunchChoice::Random,
        },
        source: match source {
            LaunchSource::User => ui::LaunchSource::User,
            LaunchSource::Provider => ui::LaunchSource::Provider,
            LaunchSource::Default => ui::LaunchSource::Default,
        },
        server_mode,
    }
}

/// Stores the user's choice; the page's state follows through the document's generation.
pub async fn set_launch(shared: &Arc<Shared>, choice: ui::LaunchChoice) -> AppResult<()> {
    let choice = match choice {
        ui::LaunchChoice::Off => LaunchChoice::Off,
        ui::LaunchChoice::LastUsed => LaunchChoice::LastUsed,
        ui::LaunchChoice::LowestDelay => LaunchChoice::LowestDelay,
        // The provider's pick, never the user's.
        ui::LaunchChoice::Random => {
            return Err(AppError::msg(
                ErrorKind::Validation,
                Msg::new("errors.validation"),
            ));
        }
    };
    let pick = autopick(shared)?;
    blocking(move || pick.set_choice(choice)).await?;
    // A changed setting: an automatic path that began before gives up.
    if let Some(automation) = shared.automation.as_ref() {
        automation.coord.user_acted(UserAct::Change);
    }
    Ok(())
}

fn autopick(shared: &Shared) -> AppResult<Arc<AppPick>> {
    (shared.automation.as_ref())
        .and_then(|a| a.autopick.get().cloned())
        .ok_or_else(|| {
            AppError::msg(
                ErrorKind::Conflict,
                Msg::new("app.settings.automationUnavailable"),
            )
        })
}
