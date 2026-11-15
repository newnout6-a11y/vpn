//! The automation-backed parts of the Settings page: location privacy, browser hardening (an
//! elevated process only: otherwise its own `Permission` answer), the adaptive bypass status /
//! retry / reset, and profile rotation.
use std::sync::Arc;

use vpnte_automation::adaptive::{AdaptiveStatus, Phase};
use vpnte_automation::hardening::{BrowserReport, BrowserState};
use vpnte_automation::rotation::{
    RotationConfig, RotationOrder, RotationOutcome as Outcome, RotationPatch as Patch,
    RotationTrigger,
};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_servers::store::Servers;
use vpnte_ui::settings::{self as ui, LocationOutcome, RotationOutcome, RotationView};

use super::Shared;
use crate::support::{blocking, detached};
use crate::svc_auto::{Automation, Followed};

/// The automation of this process; `Conflict` where the page runs without one (tests).
fn automation(shared: &Shared) -> AppResult<Arc<Automation>> {
    shared.automation.clone().ok_or_else(|| {
        AppError::msg(
            ErrorKind::Conflict,
            Msg::new("app.settings.automationUnavailable"),
        )
    })
}

/// Stores the choice; with a session up the consent follows at once (`Applied`), refused by
/// Windows → `NotApplied`; without one it takes effect at the next connect (`Stored`). The
/// setting is the user's choice and is never rewritten from the outcome.
pub async fn set_location_privacy(shared: &Arc<Shared>, on: bool) -> AppResult<LocationOutcome> {
    let auto = automation(shared)?;
    let shared = shared.clone();
    detached(async move {
        {
            let _writes = shared.writes.lock().await;
            let settings = shared.backend.settings.clone();
            blocking(move || settings.update(|s| s.location_privacy = on)).await?;
        }
        // Judged by the lane's session under the forwarder's own lock, never by the page's
        // debounced "connected": a session that just ended must not get its consent denied.
        Ok(match auto.privacy.follow_setting().await {
            Followed::Applied => LocationOutcome::Applied,
            Followed::NotApplied => LocationOutcome::NotApplied,
            Followed::Stored => LocationOutcome::Stored,
        })
    })
    .await
}

/// Applies (`true`) or rolls back the browser policies; unelevated the automation answers
/// `Permission` («только от имени администратора») before writing anything.
pub async fn browsers(shared: &Arc<Shared>, apply: bool) -> AppResult<ui::BrowserView> {
    let auto = automation(shared)?;
    let shared = shared.clone();
    detached(async move {
        let report = auto.browser_policies(apply).await?;
        let view = browser_view(&report);
        shared.touch(|l| l.browser = Some(view.clone()));
        Ok(view)
    })
    .await
}

/// The browsers as the page shows them: installed ones only; «Не проверено» for the unverified
/// browsers and anything not read, never «защищён».
pub fn browser_view(report: &BrowserReport) -> ui::BrowserView {
    let browsers = report
        .browsers
        .iter()
        .filter(|e| e.state != BrowserState::NotInstalled)
        .map(|e| ui::BrowserState {
            name: e.browser.name().to_owned(),
            status: match &e.state {
                BrowserState::Protected => ui::BrowserStatus::Protected,
                BrowserState::Off | BrowserState::Drifted => ui::BrowserStatus::NotProtected,
                BrowserState::NotInstalled => ui::BrowserStatus::NotInstalled,
                BrowserState::NotVerified | BrowserState::Unknown => ui::BrowserStatus::NotChecked,
                BrowserState::Failed { reason } => ui::BrowserStatus::Failed(reason.clone()),
            },
        })
        .collect();
    ui::BrowserView {
        browsers,
        restart_required: report.restart_required,
    }
}

/// The adaptive bypass's status line.
pub fn adaptive_view(status: &AdaptiveStatus) -> ui::AdaptiveView {
    ui::AdaptiveView {
        phase: match status.phase {
            Phase::Idle => ui::AdaptivePhase::Idle,
            Phase::Connecting => ui::AdaptivePhase::Connecting,
            Phase::Verifying => ui::AdaptivePhase::Verifying,
            Phase::Adapting => ui::AdaptivePhase::Adapting,
            Phase::Connected => ui::AdaptivePhase::Connected,
            Phase::Failed => ui::AdaptivePhase::Failed,
        },
        mode: status.mode,
        message: Some(
            status
                .reason
                .clone()
                .unwrap_or_else(|| status.message.clone()),
        ),
    }
}

pub fn retry_adaptive(shared: &Shared) -> AppResult<bool> {
    Ok(automation(shared)?.adaptive.retry())
}

pub async fn reset_adaptive(shared: &Arc<Shared>) -> AppResult<()> {
    let auto = automation(shared)?;
    blocking(move || auto.adaptive.reset_learning()).await
}

/// Rotation as the page shows it: the stored config, the server at the current index, the
/// servers the list can hold (usable rows, with their last check).
pub fn rotation_view(cfg: &RotationConfig, servers: &Servers) -> RotationView {
    let rows = servers.read(|doc| {
        (doc.profiles.iter())
            .filter(|r| r.archived.is_none() && !r.is_locked())
            .map(|r| ui::RotationServer {
                id: r.id.0.clone(),
                name: r.name.clone(),
                protocol: r.protocol.clone(),
                country: r.display_country().map(|c| c.as_str().to_owned()),
                status: match &r.health {
                    Some(h) if h.online => ui::ServerStatus::Online,
                    Some(_) => ui::ServerStatus::Offline,
                    None => ui::ServerStatus::Unknown,
                },
            })
            .collect()
    });
    RotationView {
        enabled: cfg.enabled,
        interval_minutes: cfg.interval_minutes,
        order: match cfg.order {
            RotationOrder::Sequential => ui::RotationOrder::Sequential,
            RotationOrder::Random => ui::RotationOrder::Random,
        },
        profile_ids: cfg.profile_ids.clone(),
        current_profile_id: cfg.profile_ids.get(cfg.current_index).cloned(),
        next_rotation_at: cfg.next_rotation_at,
        servers: rows,
    }
}

pub async fn set_rotation(shared: &Arc<Shared>, patch: ui::RotationPatch) -> AppResult<()> {
    let auto = automation(shared)?;
    let patch = Patch {
        enabled: patch.enabled,
        interval_minutes: patch.interval_minutes.map(f64::from),
        order: patch.order.map(|o| match o {
            ui::RotationOrder::Sequential => RotationOrder::Sequential,
            ui::RotationOrder::Random => RotationOrder::Random,
        }),
        profile_ids: None,
    };
    blocking(move || auto.rotation.set_config(patch).map(drop)).await
}

/// Adds `id` to the rotation list (at the end) or removes it.
pub async fn set_rotation_profile(
    shared: &Arc<Shared>,
    id: String,
    included: bool,
) -> AppResult<()> {
    let auto = automation(shared)?;
    blocking(move || {
        let mut ids = auto.rotation.config().profile_ids;
        ids.retain(|p| *p != id);
        if included {
            ids.push(id);
        }
        let patch = Patch {
            profile_ids: Some(ids),
            ..Patch::default()
        };
        auto.rotation.set_config(patch).map(drop)
    })
    .await
}

/// «Ротировать сейчас»: the rotation's own outcome in the page's terms.
pub async fn rotate_now(shared: &Arc<Shared>) -> AppResult<RotationOutcome> {
    let auto = automation(shared)?;
    let outcome =
        detached(async move { Ok(auto.rotation.rotate(RotationTrigger::User).await) }).await?;
    page_outcome(outcome)
}

/// The page's outcome. Only a switch that ran says whether the previous server came back; an
/// attempt that never started (another rotation runs, refused) or was cancelled midway (the
/// list changed, the deadline) says just why, as the action's error: claiming the previous
/// server "restored" there would be a guess (the lifecycle's own notices tell what happened).
pub fn page_outcome(outcome: Outcome) -> AppResult<RotationOutcome> {
    Ok(match outcome {
        Outcome::Rotated { profile_id } => RotationOutcome::Rotated { profile_id },
        Outcome::NothingToRotate | Outcome::NotDirect => RotationOutcome::NothingToRotate,
        Outcome::NoProfiles => RotationOutcome::NoProfiles,
        Outcome::NoneAvailable => RotationOutcome::NoneAvailable,
        // Never `Cancelled`: the page hides that kind, and the user asked for this rotation.
        Outcome::NotStarted { reason } | Outcome::Aborted { reason } => {
            return Err(AppError::msg(ErrorKind::Conflict, reason));
        }
        Outcome::Failed {
            reason,
            restored_previous,
            ..
        } => RotationOutcome::Failed {
            reason,
            restored_previous,
        },
    })
}
