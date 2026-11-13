//! «Сохранить»: the sparse patch of the draft applied as one change. Everything that can be
//! refused (privileges, features outside this build, bad input) is checked before the first
//! write; then protection, Soft targets and settings are written and the tunnel gets the
//! change through `TunnelOps::apply_settings_change`.
use std::sync::Arc;

use vpnte_base::types::Level;
use vpnte_base::types::Notice;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::settings::{RuleSetChoice, RuleSetMode, SettingsPatch};
use vpnte_engine::routing::bypass;
use vpnte_tunnel::lifecycle::{ConnError, Done};
use vpnte_ui::settings as ui;

use super::Shared;
use super::project::{core_bootstrap_mode, core_connection_mode, core_routing_mode, settings_view};
use crate::services::Backend;
use crate::support::unavailable;

/// Update interval of the managed Smart RU lists the auto-update switch selects (hours).
const RULE_SET_HOURS: u32 = 24;

/// The live draft fields as the page shows them.
pub fn live_view(backend: &Backend) -> ui::SettingsView {
    let soft = backend.soft.read(|d| d.dev_targets);
    let leak = backend.protection.read(|d| d.settings.leak_protection);
    backend.settings.read(|s| settings_view(s, &soft, leak))
}

/// Saves the edited fields; see the module doc for the order.
pub async fn save(shared: Arc<Shared>, mut patch: ui::SettingsPatch) -> AppResult<ui::SaveReport> {
    let _writes = shared.writes.lock().await;
    let backend = &shared.backend;
    let tunnel = backend.tunnel()?.clone();
    let live = live_view(backend);
    patch.prune(&live);
    if patch.is_empty() {
        return Ok(ui::SaveReport {
            settings: live,
            restart: None,
            next_connect: false,
        });
    }
    tracing::info!(fields = ?patch.fields(), "saving settings");
    check(&patch, tunnel.tun_available())?;
    let core = core_patch(&patch)?;

    if let Some(on) = patch.leak_protection {
        let mut toggles = backend.protection.read(|d| d.settings.toggles());
        toggles.leak_protection = on;
        tunnel.set_protection_toggles(toggles).await?;
    }
    if patch.soft_git.is_some() || patch.soft_gradle.is_some() || patch.soft_studio.is_some() {
        backend.soft.update(|d| {
            let t = &mut d.dev_targets;
            t.git = patch.soft_git.unwrap_or(t.git);
            t.gradle = patch.soft_gradle.unwrap_or(t.gradle);
            t.android_studio = patch.soft_studio.unwrap_or(t.android_studio);
        })?;
    }
    let old = backend.settings.snapshot();
    backend.settings.update(|s| s.apply(core))?;
    let new = backend.settings.snapshot();
    if old.disable_geo_lookup != new.disable_geo_lookup {
        backend.geo.set_enabled(!new.disable_geo_lookup);
    }

    let generation = |t: &Arc<dyn crate::services::TunnelOps>| {
        t.session().borrow().as_ref().map(|s| s.generation)
    };
    let before = generation(&tunnel);
    let applied = tunnel.apply_settings_change(old, new).await;
    let restart = restart_outcome(backend, before, generation(&tunnel), applied);
    Ok(ui::SaveReport {
        settings: live_view(backend),
        restart,
        next_connect: next_connect(&patch),
    })
}

/// Refusals that must come before any write (NOADMIN §0 / §2: Hard needs the TUN, which needs
/// elevation in this phase; packet capture is not part of this build).
pub fn check(patch: &ui::SettingsPatch, tun_available: bool) -> AppResult<()> {
    if patch.routing_mode == Some(ui::RoutingMode::Hard) && !tun_available {
        return Err(hard_needs_admin());
    }
    if patch.deep_inspection == Some(true) || patch.capture_quota_mb.is_some() {
        return Err(unavailable("app.settings.captureUnavailable"));
    }
    Ok(())
}

/// Hard (TUN) chosen in a process that cannot capture with the TUN: `Permission`, and the
/// message offers Soft (never a silent fallback, NOADMIN §2).
pub fn hard_needs_admin() -> AppError {
    AppError::msg(
        ErrorKind::Permission,
        Msg::new("app.settings.hardNeedsAdmin"),
    )
}

/// The core settings part of a (pruned) page patch. The manual proxy is parsed here: a bad
/// address is a `Validation` error with the field message.
pub fn core_patch(p: &ui::SettingsPatch) -> AppResult<SettingsPatch> {
    let mut core = SettingsPatch {
        connection_mode: p.connection_mode.map(core_connection_mode),
        routing_mode: p.routing_mode.map(core_routing_mode),
        proxy_type: p.proxy_type,
        bootstrap_route_mode: p.bootstrap_route_mode.map(core_bootstrap_mode),
        check_interval_ms: p.check_interval_ms,
        disable_geo_lookup: p.disable_geo_lookup,
        autopilot: p.autopilot,
        minimize_to_tray: p.minimize_to_tray,
        domain_enrichment: p.domain_enrichment,
        advanced_mode: p.advanced_mode,
        auto_restart_on_crash: p.auto_restart_on_crash,
        public_wifi_compatibility: p.public_wifi_compatibility,
        deep_inspection: p.deep_inspection,
        deep_inspection_max_mb: p.deep_inspection_max_mb,
        stealth_mode: p.stealth_mode,
        adaptive_bypass: p.adaptive_bypass,
        adaptive_bypass_server_fallback: p.adaptive_bypass_server_fallback,
        smart_ru_split: p.smart_ru_split,
        smart_ru_maps_direct: p.smart_ru_maps_direct,
        proxy_engine: p.proxy_engine,
        proxy_bypass_auto: p.proxy_bypass_auto,
        ..SettingsPatch::default()
    };
    if let Some(text) = &p.proxy_bypass {
        // «Не через прокси» is the user's own rule (answer 4): every entry is checked, the first
        // bad one is named, and the list is stored in its canonical form.
        let entries = bypass::parse_list(text)?;
        core.proxy_bypass = Some(entries.iter().map(ToString::to_string).collect());
    }
    if let Some(on) = p.smart_ru_auto_update {
        core.smart_ru_rule_set_mode = Some(if on {
            RuleSetMode::Managed
        } else {
            RuleSetMode::Bundled
        });
        core.smart_ru_rule_set_auto_update = Some(on);
        // The user's own choice: the wizard never changes it again (psmart-b4).
        core.smart_ru_rule_set_choice = Some(RuleSetChoice::User);
        if on {
            core.smart_ru_rule_set_use_proxy = Some(true);
            core.smart_ru_rule_set_update_hours = Some(RULE_SET_HOURS);
        }
    }
    if let Some(input) = &p.proxy_override {
        // The page's proxy type wins over a scheme typed into the address.
        let chosen = core.proxy_type;
        core.set_proxy_override(input)?;
        core.proxy_type = chosen.or(core.proxy_type);
    }
    Ok(core)
}

/// Changes that a running tunnel takes only at the next connect (ui-pages §6.4). «Не через
/// прокси» is not one: a running proxy-mode session follows the list at once.
pub fn next_connect(p: &ui::SettingsPatch) -> bool {
    p.connection_mode.is_some()
        || p.routing_mode.is_some()
        || p.proxy_engine.is_some()
        || p.smart_ru_split.is_some()
        || p.smart_ru_maps_direct.is_some()
        || p.smart_ru_auto_update.is_some()
        || p.soft_git.is_some()
        || p.soft_gradle.is_some()
        || p.soft_studio.is_some()
}

/// What the save did to a running tunnel: a restart is reported only when it was observed (the
/// session's engine generation changed), a failure only when a session was open.
fn restart_outcome(
    backend: &Backend,
    before: Option<Option<u64>>,
    after: Option<Option<u64>>,
    applied: Result<Done, ConnError>,
) -> Option<Result<(), Msg>> {
    match applied {
        Ok(done) => {
            for warning in done.warnings {
                backend
                    .notifier
                    .notify(Notice::new(Level::Warn, warning), None);
            }
            (before.is_some() && after.is_some() && before != after).then_some(Ok(()))
        }
        Err(err) if err.kind() == ErrorKind::Cancelled => None,
        Err(err) => {
            tracing::warn!(error = %err, "settings change not applied");
            before.is_some().then(|| Err(err.user_msg()))
        }
    }
}
