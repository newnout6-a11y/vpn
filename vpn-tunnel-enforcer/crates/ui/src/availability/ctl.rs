//! The Availability page's state and actions, separate from its markup so the request-lifetime
//! rules (ui-pages §7.5) are tested on the code the page runs.
use std::rc::Rc;
use std::time::Duration;

use dioxus::prelude::*;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_base::{ErrorKind, Msg};

use super::AvailabilityApi;
use super::model::{RoutingReport, UrlCheck};
use crate::pages::use_page_active;
use crate::widgets::JobSlot;

/// How often relative ages («5 мин назад») are refreshed while the page is visible.
const AGE_TICK: Duration = Duration::from_secs(30);

/// Page-local state and the three jobs (Copy handles owned by the page root).
#[derive(Clone, Copy, PartialEq)]
pub(crate) struct Controller {
    api: CopyValue<Rc<dyn AvailabilityApi>>,
    pub url_job: JobSlot<UrlCheck>,
    pub route_job: JobSlot<RoutingReport>,
    pub clear_job: JobSlot<()>,
    /// The typed link.
    pub input: Signal<String>,
    blank: Signal<bool>,
    shown: Signal<Option<UrlCheck>>,
}

/// The controller of the calling component (its jobs die with it).
pub(crate) fn use_controller(api: Rc<dyn AvailabilityApi>) -> Controller {
    use_hook(move || Controller {
        api: CopyValue::new(api),
        url_job: JobSlot::new(),
        route_job: JobSlot::new(),
        clear_job: JobSlot::new(),
        input: Signal::new(String::new()),
        blank: Signal::new(false),
        shown: Signal::new(None),
    })
}

impl Controller {
    fn api(self) -> Rc<dyn AvailabilityApi> {
        self.api.read().clone()
    }

    /// Checks the typed link: a blank input is refused here; a running check is not restarted.
    pub fn check(self) {
        let (mut blank, mut shown) = (self.blank, self.shown);
        if self.url_job.running() {
            return;
        }
        self.url_job.clear();
        let url = self.input.peek().trim().to_owned();
        blank.set(url.is_empty());
        if url.is_empty() {
            return;
        }
        let api = self.api();
        self.url_job.start(move |token| async move {
            let result = api.check_url(url, token).await;
            if let Ok(check) = &result {
                // Host and URL stay out of the log (they are in the backend's own record).
                tracing::info!(target: "ui", verdict = ?check.verdict, "availability check finished");
                shown.set(Some(check.clone()));
            }
            result
        });
    }

    /// Runs the routing self-test (failures are shown and logged; cancellation is silent).
    pub fn run_routing(self) {
        let api = self.api();
        self.route_job.start(move |token| async move {
            let result = api.routing_test(token).await;
            match &result {
                Ok(report) => {
                    tracing::info!(target: "ui", verdict = ?report.verdict, "routing self-test finished");
                }
                Err(err) if err.kind != ErrorKind::Cancelled => {
                    tracing::warn!(target: "ui", error = %err, "routing self-test failed");
                }
                Err(_) => {}
            }
            result
        });
    }

    /// Forgets the saved checks (the backend pushes the empty list).
    pub fn clear_history(self) {
        let api = self.api();
        self.clear_job
            .start(move |_| async move { api.clear_history().await });
    }

    /// Puts a saved check back on screen.
    pub fn pick(self, check: UrlCheck) {
        let mut shown = self.shown;
        shown.set(Some(check));
    }

    /// The message under the link field: blank input, unusable link (validation) or the
    /// error of the last check (a cancelled check leaves none).
    pub fn check_error(self) -> Option<Msg> {
        if (self.blank)() {
            return Some(Msg::new("ui.availability.check.blank"));
        }
        match self.url_job.last() {
            Some(Err(err)) if err.kind == ErrorKind::Validation => {
                Some(Msg::new("ui.availability.check.invalid"))
            }
            Some(Err(err)) => Some(err.msg),
            _ => None,
        }
    }

    /// The check on screen: the one asked for in this session, else the newest saved one.
    pub fn result(self, history: &[UrlCheck]) -> Option<UrlCheck> {
        (self.shown)().or_else(|| history.first().cloned())
    }
}

/// The clock for relative ages: refreshed on every return to the page and every
/// [`AGE_TICK`] while it is visible (nothing ticks while it is hidden).
pub(crate) fn use_now() -> UnixMs {
    let active = use_page_active();
    let mut now = use_signal(now_ms);
    use_effect(move || {
        if active() {
            now.set(now_ms());
        }
    });
    use_future(move || async move {
        loop {
            tokio::time::sleep(AGE_TICK).await;
            if *active.peek() {
                now.set(now_ms());
            }
        }
    });
    now()
}

#[cfg(test)]
mod tests;
