//! The Schedule, Apps (split tunnel) and Traffic history pages over the backend (work package
//! `app-lists`): [`ScheduleApi`], [`SplitTunnelApi`], [`TrafficHistoryApi`] and [`contexts`].
//!
//! Each page renders one pushed snapshot that a task of this package re-projects whenever its
//! source changes; actions run as backend tasks and publish before they answer, so leaving a
//! page mid-call never leaves a half-done change. Nothing here needs administrator rights
//! (NOADMIN). What this build cannot do is refused with its own sentence, never shown as working:
//! - the scheduler's reconcile task needs an automation `Coordinator` over the tunnel lifecycle,
//!   which `svc_tunnel` does not expose: the list is edited, but enabling a schedule is refused
//!   and no next event is shown until that task runs (`schedule`);
//! - the domain history service lives inside `svc_tunnel` (not on `Backend`): the page reads the
//!   file that service persists and clears through `TunnelOps::clear_traffic_history`
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
pub use schedule::ScheduleService;
pub use split::SplitService;
pub use traffic::TrafficService;

/// The UI contexts of this package for `vpnte_ui::launch`: `Rc<dyn ScheduleApi>`,
/// `Rc<dyn SplitTunnelApi>` and `Rc<dyn TrafficHistoryApi>`. Call it inside the tokio runtime
/// after `backend.tunnel` was set (the projection tasks start here and stop with
/// `backend.shutdown`).
pub fn contexts(backend: &Arc<Backend>) -> Vec<Box<dyn Any>> {
    let schedule: Rc<dyn ScheduleApi> = Rc::new(ScheduleService::start(backend.clone()));
    let split: Rc<dyn SplitTunnelApi> = Rc::new(SplitService::start(backend.clone()));
    let traffic: Rc<dyn TrafficHistoryApi> = Rc::new(TrafficService::start(backend.clone()));
    vec![Box::new(schedule), Box::new(split), Box::new(traffic)]
}

/// The fragments of this package: `svc_core`'s list names only the packages wired before it.
const LOCALES: &[(&str, &str)] = &[(
    include_str!("../../locales/app-lists.ru.json"),
    include_str!("../../locales/app-lists.en.json"),
)];

/// Every locale layer of this build plus [`LOCALES`] (each once), for the one
/// `vpnte_ui::lang::init_locales` call at start. The first call wins and `root::run` makes this
/// one first, so the list starts from the Tools pages' list (which holds the Maintenance page's)
/// when those are built in. `api_tools` must therefore never build on this list (a cycle).
pub fn locale_layers() -> Vec<(&'static str, &'static str)> {
    #[cfg(feature = "app-tools")]
    let mut layers = crate::api_tools::locale_layers();
    #[cfg(all(not(feature = "app-tools"), feature = "app-maintenance"))]
    let mut layers = crate::api_maintenance::locale_layers();
    #[cfg(not(any(feature = "app-tools", feature = "app-maintenance")))]
    let mut layers = crate::svc_core::locale_layers();
    for pair in LOCALES {
        if !layers.contains(pair) {
            layers.push(*pair);
        }
    }
    layers
}

/// A refusal of these pages: `Conflict` with its own sentence (shown as a warning).
fn refused(key: &'static str) -> AppError {
    AppError::msg(ErrorKind::Conflict, Msg::new(key))
}
