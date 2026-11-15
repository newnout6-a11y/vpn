//! Rotation effects: the in-place upstream switch and the protected restarts (last start, adaptive).
use vpnte_base::types::UnixMs;

use super::*;

/// The engine run the status shows (`None`: nothing runs).
type Run = Option<(Option<u32>, Option<UnixMs>)>;

fn current_run(deps: &LifecycleDeps) -> Run {
    let status = deps.runtime.status();
    let s = status.borrow();
    s.running.then_some((s.pid, s.started_at))
}

/// Capture of the running session (a switch or restart keeps it).
fn running_capture(deps: &LifecycleDeps) -> CaptureKind {
    let capture = deps.runtime.status().borrow().capture;
    capture.unwrap_or(CaptureKind::Tun)
}

/// The session profile of `server` in the running mode.
fn server_profile(server: &VpnProfile, capture: CaptureKind) -> SessionProfile {
    match capture {
        CaptureKind::Tun => SessionProfile::direct(server),
        CaptureKind::Proxy => SessionProfile::soft_server(server),
    }
}

/// A restart put a new run in place: in Soft the tweaks follow its port (`port` = where they
/// point now; the port is kept across restarts, so normally nothing changes), then the actor
/// confirms. A failed re-point is `touched`: the recovery stop rolls back and stops.
async fn confirm_restart(ctx: &Ctx, up: Up, port: Option<u16>) -> Result<Up, Failure> {
    if running_capture(&ctx.deps) == CaptureKind::Proxy {
        point_tweaks(ctx, port).await?;
    }
    confirm(ctx, up).await
}

/// A failed restart that left its run untouched (the runtime refused before stopping it: no
/// last start, unreadable settings, cancelled at entry) keeps the previous state; any other
/// failure changed the tunnel.
fn failed_restart(mut failure: Failure, deps: &LifecycleDeps, before: Run) -> Failure {
    if before.is_some() && current_run(deps) == before {
        failure.kept_previous = true;
    } else {
        failure.touched = true;
    }
    failure
}

/// Moves the running tunnel to `profile_id`: in place when the runtime can swap the upstream
/// behind the TUN, otherwise a protected restart (which ends in a full stop on failure).
/// Nothing running → nothing to move (`Idle`; the caller commits the selection).
pub(in crate::lifecycle) async fn switch(
    ctx: Ctx,
    profile_id: String,
    kind: OutcomeKind,
    adaptive: AdaptiveMode,
) -> StartReport {
    let deps = &ctx.deps;
    let Some(choice) = deps.profiles.resolve(Some(&profile_id)) else {
        let msg = Msg::new(key::SERVER_UNAVAILABLE);
        return StartReport::done(Err(Failure::kept(ConnError::NoServer(msg))));
    };
    if !deps.runtime.status().borrow().running {
        return StartReport::done(Ok(Up::Idle));
    }
    let capture = running_capture(deps);
    let profile = server_profile(&choice.server, capture);
    let mode = Mode::DirectVpn {
        profile: choice.server.clone(),
    };
    let req = start_request(deps, mode, capture, adaptive, ctx.owner, ctx.guard.level);
    let token = ctx.token.clone();
    let is_owner: OwnerCheck = Arc::new(move || !token.is_cancelled());
    let in_place = deps
        .runtime
        .switch_upstream(req.clone(), ctx.token.clone(), is_owner)
        .await;
    if let Some(mut receipt) = in_place {
        let up = Up::Run {
            profile,
            key: Some(choice.server.profile.identity()),
            country: choice.country,
            generation: None,
            engine: receipt.engine,
            adaptive,
            warnings: std::mem::take(&mut receipt.warnings),
            guard: None,
        };
        return StartReport::done(switched_in_place(&ctx, receipt, up).await);
    }
    // The reason tells history what the restart was (`outcome::node_switch_kind`).
    let reason = match kind {
        OutcomeKind::Rotation => format!("profile rotation to {}", profile.name),
        _ => "server switch".to_owned(),
    };
    let opts = RestartOptions {
        cancel: ctx.token.clone(),
        ..RestartOptions::default()
    };
    let (before, port) = (current_run(deps), session_port(deps));
    let result = match deps.runtime.restart_protected(reason, req, opts).await {
        Ok(receipt) => {
            let up = Up::Run {
                profile,
                key: Some(choice.server.profile.identity()),
                country: choice.country,
                generation: Some(receipt.generation),
                engine: Some(receipt.engine),
                adaptive,
                warnings: receipt.warnings,
                guard: None,
            };
            confirm_restart(&ctx, up, port).await
        }
        Err(_) if ctx.token.is_cancelled() => Err(failed_restart(cancelled(), deps, before)),
        Err(e) => Err(failed_restart(
            Failure::new(ConnError::Failed(e)),
            deps,
            before,
        )),
    };
    StartReport::done(result)
}

/// Result of an in-place upstream switch: success, the preserved previous upstream (tunnel
/// unchanged), or a tunnel in an unproven state.
async fn switched_in_place(ctx: &Ctx, receipt: SwitchReceipt, up: Up) -> Result<Up, Failure> {
    if receipt.outcome == SwitchOutcome::Success && receipt.verified() {
        return confirm(ctx, up).await;
    }
    for f in &receipt.failures {
        tracing::warn!(phase = ?f.phase, message = %f.message, "upstream switch step failed");
    }
    if receipt.outcome == SwitchOutcome::Cancelled || ctx.token.is_cancelled() {
        let mut failure = cancelled();
        failure.kept_previous = receipt.verified();
        failure.touched = !receipt.verified();
        return Err(failure);
    }
    let mut failure = Failure::new(failed(ErrorKind::Network, key::SWITCH_FAILED));
    failure.kept_previous = receipt.verified();
    failure.touched = !receipt.verified();
    Err(failure)
}

/// Settings changed: the runtime re-applies its last start (a no-op when nothing runs).
pub(in crate::lifecycle) async fn restart_last(ctx: Ctx, reason: String) -> StartReport {
    let (before, port) = (current_run(&ctx.deps), session_port(&ctx.deps));
    let result = match ctx.deps.runtime.restart_with_last(reason).await {
        Ok(None) => Ok(Up::Idle),
        Ok(Some(receipt)) => {
            let up = Up::Restarted {
                generation: receipt.generation,
                engine: receipt.engine,
                adaptive: None,
                warnings: receipt.warnings,
            };
            confirm_restart(&ctx, up, port).await
        }
        Err(e) => Err(failed_restart(
            Failure::new(ConnError::Failed(e)),
            &ctx.deps,
            before,
        )),
    };
    StartReport::done(result)
}

/// Protected restart in another adaptive mode, optionally on a sibling server.
pub(in crate::lifecycle) async fn restart_adaptive(
    ctx: Ctx,
    mode: AdaptiveMode,
    sibling: Option<String>,
) -> StartReport {
    let deps = &ctx.deps;
    if !deps.runtime.status().borrow().running {
        let msg = Msg::new(key::NOT_RUNNING);
        return StartReport::done(Err(Failure::kept(ConnError::Refused(msg))));
    }
    let choice = match sibling {
        None => None,
        Some(id) => match deps.profiles.resolve(Some(&id)) {
            Some(choice) => Some(choice),
            None => {
                let msg = Msg::new(key::SERVER_UNAVAILABLE);
                return StartReport::done(Err(Failure::kept(ConnError::NoServer(msg))));
            }
        },
    };
    let reason = format!("adaptive restart: {mode:?}");
    let server = choice.as_ref().map(|c| c.server.clone());
    let (before, port) = (current_run(deps), session_port(deps));
    let result = match deps.runtime.restart_adaptive(mode, reason, server).await {
        Ok(receipt) => {
            let up = match choice {
                Some(choice) => Up::Run {
                    profile: server_profile(&choice.server, running_capture(deps)),
                    key: Some(choice.server.profile.identity()),
                    country: choice.country,
                    generation: Some(receipt.generation),
                    engine: Some(receipt.engine),
                    adaptive: mode,
                    warnings: receipt.warnings,
                    guard: None,
                },
                None => Up::Restarted {
                    generation: receipt.generation,
                    engine: receipt.engine,
                    adaptive: Some(mode),
                    warnings: receipt.warnings,
                },
            };
            confirm_restart(&ctx, up, port).await
        }
        Err(e) => Err(failed_restart(
            Failure::new(ConnError::Failed(e)),
            deps,
            before,
        )),
    };
    StartReport::done(result)
}
