//! The Schedule page («Расписание»): weekly time windows that connect and disconnect the VPN
//! automatically — the list with on/off switches, the next event, and a create / edit form
//! (ui-pages §3.11, U-25; the window rules themselves belong to the scheduler, automation §6.3).
//!
//! Data and actions come from a [`ScheduleApi`] in context (`Rc<dyn ScheduleApi>`); the app
//! implements it over the scheduler, [`demo::DemoSchedule`] fakes it. Register the page with
//! `registry.register(Page::Schedule, SchedulePage)`. The page stays mounted when hidden, so an
//! open form survives navigation, as before.
pub mod demo;
mod editor;
mod form;
mod model;
mod page;
#[cfg(test)]
pub(crate) mod tests;

use std::rc::Rc;

use crate::hooks::use_watch;
use crate::lang::tr_now;
use dioxus::prelude::*;

pub use form::{
    DISPLAY_ORDER, FormProblem, ScheduleForm, day_key, days_keys, local_hhmm, server_label,
    time_until, until_next_change, window_hint,
};
pub use model::{
    HhMm, NextAction, NextEvent, ScheduleApi, ScheduleEntry, ScheduleInput, ScheduleMode,
    ScheduleSnapshot, ServerChoice,
};
pub use page::SchedulePage;

/// The API from context.
fn use_api() -> Rc<dyn ScheduleApi> {
    use_context::<Rc<dyn ScheduleApi>>()
}
