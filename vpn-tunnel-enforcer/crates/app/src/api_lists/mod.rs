//! The Schedule, Apps (split tunnel) and Traffic history pages over the backend (work package
//! `app-lists`): [`ScheduleApi`], [`SplitTunnelApi`], [`TrafficHistoryApi`] and [`contexts`].
//!
//! Each page renders one pushed snapshot that a task of this package re-projects whenever its
//! source changes; actions run as backend tasks and publish before they answer, so leaving a
//! page mid-call never leaves a half-done change. Nothing here needs administrator rights
//! (NOADMIN). What this build cannot do is refused with its own sentence, never shown as working:
//! - the schedule list belongs to the process's one automation scheduler (built with the tunnel:
//!   `svc_tunnel::build`), whose reconcile task starts and stops the VPN; the page edits it
//!   and shows the next event that task reports (`schedule`);
//! - the domain history is the process's one `HistoryService` (opened with the tunnel,
//!   `svc_tunnel::DomainHistory`): the page lists it with the site names of the opt-in lookups
//!   (`traffic`).
mod schedule;
mod split;
mod traffic;

#[cfg(test)]
mod tests;

use std::any::Any;
use std::rc::Rc;
use std::sync::Arc;

use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_ui::schedule::ScheduleApi;
use vpnte_ui::split_tunnel::SplitTunnelApi;
use vpnte_ui::traffic_history::TrafficHistoryApi;

use crate::services::Backend;
use crate::svc_tunnel::scope::RunScope;
use crate::svc_tunnel::{Built, DomainHistory};
pub use schedule::ScheduleService;
pub use split::SplitService;
pub use traffic::TrafficService;

/// The UI contexts of this package for `vpnte_ui::launch`: `Rc<dyn ScheduleApi>`,
/// `Rc<dyn SplitTunnelApi>` and `Rc<dyn TrafficHistoryApi>`. Call it inside the tokio runtime
/// after `backend.tunnel` was set (the projection tasks start here and stop with
/// `backend.shutdown`).
pub fn contexts(backend: &Arc<Backend>, built: &Built) -> Vec<Box<dyn Any>> {
    let automation = &built.automation;
    let schedule: Rc<dyn ScheduleApi> = Rc::new(ScheduleService::start(
        backend.clone(),
        automation.schedules.clone(),
        automation.scheduler.clone(),
    ));
    with_schedule(
        backend,
        schedule,
        built.domains.clone(),
        built.run_scope.clone(),
    )
}

/// The contexts around the given Schedule page API.
fn with_schedule(
    backend: &Arc<Backend>,
    schedule: Rc<dyn ScheduleApi>,
    domains: Arc<DomainHistory>,
    run_scope: RunScope,
) -> Vec<Box<dyn Any>> {
    let split: Rc<dyn SplitTunnelApi> = Rc::new(SplitService::start(backend.clone(), run_scope));
    let traffic: Rc<dyn TrafficHistoryApi> =
        Rc::new(TrafficService::start(backend.clone(), domains));
    vec![Box::new(schedule), Box::new(split), Box::new(traffic)]
}

/// A refusal of these pages: `Conflict` with its own sentence (shown as a warning).
fn refused(key: &'static str) -> AppError {
    AppError::msg(ErrorKind::Conflict, Msg::new(key))
}
