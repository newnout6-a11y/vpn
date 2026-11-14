//! The Tools pages over the backend (work package `app-tools`): [`AvailabilityApi`]
//! («Доступность»: a link through the protected path and directly, the routing self-test, the
//! saved checks) and [`SpeedTestApi`] («Тест скорости»), handed to the UI by [`contexts`].
//!
//! Each page renders one pushed snapshot (`project`): whether a session runs and the saved
//! history, re-projected by a task on every tunnel status / history change and by the actions
//! before they answer. Measurements run as operations of the registry under the page's token
//! (cancelling it ends them with `Cancelled`); saving to the history is the operation's commit.
//! Nothing here needs elevation. The session kind decides the paths: a TUN session binds to the
//! TUN; a Soft session (NOADMIN §2) is measured through the loopback mixed inbound the system
//! proxy points at; what a kind cannot measure is refused or reported as not measured, never as
//! working.
mod availability;
mod project;
mod routing;
mod speed;
#[cfg(test)]
mod tests;

use std::any::Any;
use std::rc::Rc;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;
use vpnte_base::types::{Creds, Loopback};
use vpnte_core::store::Store;
use vpnte_probes::availability::UrlChecks;
use vpnte_probes::public_ip::IpReader;
use vpnte_probes::speedtest::SpeedTests;
use vpnte_tunnel::api::{CaptureKind, TunStatus};
use vpnte_ui::availability::{AvailabilityApi, AvailabilityState, RoutingReport, UrlCheck};
use vpnte_ui::speedtest::{SpeedProgress, SpeedResult, SpeedTestApi, SpeedTestState};

use crate::services::Backend;

/// The UI contexts of this package for `vpnte_ui::launch`: `Rc<dyn AvailabilityApi>` and
/// `Rc<dyn SpeedTestApi>`. Call it inside the tokio runtime after `backend.tunnel` was set (the
/// projection task starts here and stops with `backend.shutdown`).
pub fn contexts(backend: &Arc<Backend>) -> Vec<Box<dyn Any>> {
    let shared = Shared::start(backend.clone());
    vec![
        Box::new(Rc::new(Availability(shared.clone())) as Rc<dyn AvailabilityApi>),
        Box::new(Rc::new(SpeedTest(shared)) as Rc<dyn SpeedTestApi>),
    ]
}

/// State shared by both pages, their actions and the projection task.
pub(crate) struct Shared {
    pub backend: Arc<Backend>,
    /// `history/url-checks.json`: the only copy in the process (nobody else opens it).
    pub url_checks: Arc<Store<UrlChecks>>,
    /// `history/speed-tests.json`: the only copy in the process.
    pub speed_tests: Arc<Store<SpeedTests>>,
    /// Public-IP reads of the speed test's egress check. `svc_tunnel` keeps the monitor's reader
    /// private, so this one has a 429 back-off of its own (two reads per run).
    pub reader: Arc<IpReader>,
    pub availability: watch::Sender<AvailabilityState>,
    pub speed: watch::Sender<SpeedTestState>,
}

impl Shared {
    /// Opens the histories, starts the projection task and publishes the first snapshots (in
    /// this order: the task subscribes before the first projection).
    pub fn start(backend: Arc<Backend>) -> Arc<Self> {
        let shared = Arc::new(Self {
            url_checks: Arc::new(Store::open(&backend.dirs.root)),
            speed_tests: Arc::new(Store::open(&backend.dirs.root)),
            reader: Arc::new(IpReader::new()),
            availability: watch::Sender::new(AvailabilityState::default()),
            speed: watch::Sender::new(SpeedTestState::default()),
            backend,
        });
        project::spawn(&shared);
        shared.publish();
        shared
    }

    /// The running session now (a missing tunnel is `Internal` `app.base.tunnelMissing`).
    pub fn session(&self) -> AppResult<Session> {
        Ok(Session::of(
            &self.backend.tunnel()?.runtime_status().borrow(),
        ))
    }

    /// Re-projects both snapshots and sends the ones that changed.
    pub fn publish(&self) {
        let running = self.session().is_ok_and(|s| s.running());
        let availability = project::availability_state(running, &self.url_checks);
        self.availability
            .send_if_modified(|now| project::replace(now, availability));
        let speed = project::speed_state(running, &self.speed_tests);
        self.speed
            .send_if_modified(|now| project::replace(now, speed));
    }
}

/// How the running session takes traffic, as far as the measurements care.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Session {
    Off,
    /// Our TUN captures the machine; `direct` = the engine's authenticated `mixed-direct-in`.
    Tun {
        direct: Option<Loopback>,
        profile: Option<String>,
    },
    /// Soft: the per-user system proxy points at the unauthenticated mixed inbound `proxy`.
    Proxy {
        proxy: Option<u16>,
        direct: Option<Loopback>,
    },
}

impl Session {
    /// The session behind a runtime status (a run without a known capture counts as none).
    pub fn of(status: &TunStatus) -> Session {
        if !status.running {
            return Session::Off;
        }
        let direct = status.session.as_ref().map(|s| Loopback {
            port: s.direct.port,
            creds: Some(Creds {
                user: s.direct.user.clone(),
                pass: s.direct.pass.clone(),
            }),
        });
        match status.capture {
            Some(CaptureKind::Tun) => Session::Tun {
                direct,
                profile: status.profile_name.clone(),
            },
            Some(CaptureKind::Proxy) => Session::Proxy {
                proxy: status.session.as_ref().and_then(|s| s.proxy_port),
                direct,
            },
            None => Session::Off,
        }
    }

    /// A session of either kind is up.
    pub fn running(&self) -> bool {
        !matches!(self, Session::Off)
    }
}

/// [`AvailabilityApi`] over the backend.
pub struct Availability(Arc<Shared>);

#[async_trait(?Send)]
impl AvailabilityApi for Availability {
    fn state(&self) -> watch::Receiver<AvailabilityState> {
        self.0.availability.subscribe()
    }

    async fn check_url(&self, input: String, cancel: CancellationToken) -> AppResult<UrlCheck> {
        availability::check(&self.0, &input, cancel).await
    }

    async fn routing_test(&self, cancel: CancellationToken) -> AppResult<RoutingReport> {
        routing::run(&self.0, cancel).await
    }

    async fn clear_history(&self) -> AppResult<()> {
        availability::clear(self.0.clone()).await
    }
}

/// [`SpeedTestApi`] over the backend.
pub struct SpeedTest(Arc<Shared>);

#[async_trait(?Send)]
impl SpeedTestApi for SpeedTest {
    fn state(&self) -> watch::Receiver<SpeedTestState> {
        self.0.speed.subscribe()
    }

    async fn run(
        &self,
        progress: watch::Sender<SpeedProgress>,
        cancel: CancellationToken,
    ) -> AppResult<SpeedResult> {
        speed::run(&self.0, progress, cancel).await
    }
}
