//! The helper service's own update as the app sees it (p-svc-update): one calm line in Settings
//! from the service's answer, and the release's service taken before the release's installer
//! runs, so the installer finds the service current and Windows asks nothing. No service, an
//! older one (it refuses the request), a failure or a slow answer: the installer runs as before
//! and asks Windows as before.
use std::time::Duration;

use tokio::time::Instant;
use vpnte_service::pipe::client::{Client, ServerCheck};
use vpnte_service::proto::{Reply, Request, ServiceUpdateWire, UpdateAsk, UpdatePhase};
use vpnte_service::sddl;
use vpnte_ui::updates::{ServiceLine, ServiceState};
use vpnte_update::version::Version;

use super::Updates;
use crate::svc_journal::Tone;
use vpnte_base::Msg;

/// A state question: the pipe is local, the answer immediate.
const ASK: Duration = Duration::from_secs(5);
/// After a `Take` the service reads the feed and may download engines and its exe first.
const TAKE: Duration = Duration::from_secs(120);
/// The SCM starts the swapped-in service within seconds (its first restart waits 5 s).
const BACK: Duration = Duration::from_secs(45);
const POLL: Duration = Duration::from_secs(1);

/// The installed service's answer to `ask` within `wait`; `None` without a service that
/// answers it.
async fn ask(ask: UpdateAsk, wait: Duration) -> Option<ServiceUpdateWire> {
    let exe = crate::boot::service::installed_binary().ok()??;
    let check = ServerCheck::Image(exe);
    let answer = async {
        let mut client = Client::connect(sddl::PIPE_NAME, &check, ASK).await.ok()?;
        match client.call(Request::Update(ask)).await {
            Ok(Reply::Update(state)) => Some(state),
            _ => None,
        }
    };
    tokio::time::timeout(wait, answer).await.ok().flatten()
}

impl Updates {
    /// Reads the service's state into the Settings line.
    pub(super) async fn refresh_service(&self) {
        let state = ask(UpdateAsk::State, ASK).await;
        self.show_service(state);
    }

    /// Shows the service's answer and notes its version.
    pub(super) fn show_service(&self, state: Option<ServiceUpdateWire>) {
        let version = state.as_ref().map(|s| s.version.clone());
        self.inner.lock().service = state;
        if let Some(version) = version {
            self.service_seen(version);
        }
        self.refresh();
    }

    /// The service answered as `version`. Another version than at its last answer, in this run
    /// or an earlier one (the service may take a release, or the installer bring one, while the
    /// app is closed), is a release it took, or a lower one it went back to (its trial failed):
    /// one event of the journal. A version that could not be remembered is not written either:
    /// no repeat at every answer.
    fn service_seen(&self, version: String) {
        let before = self.doc.read(|d| d.service_version.clone());
        if before.as_deref() == Some(version.as_str()) {
            return;
        }
        if let Err(err) = self
            .doc
            .update(|d| d.service_version = Some(version.clone()))
        {
            tracing::warn!(%err, "helper service version not stored");
            return;
        }
        let Some(before) = before else {
            return;
        };
        let lower = matches!(
            (before.parse::<Version>(), version.parse::<Version>()),
            (Ok(before), Ok(now)) if now < before
        );
        let (key, tone) = if lower {
            ("app.journal.update.serviceBack", Tone::Warn)
        } else {
            ("app.journal.update.service", Tone::Ok)
        };
        self.journal(tone, Msg::new(key).arg("version", version), None);
    }

    /// Right before the installer of release `to` runs: the service takes `to` from the feed
    /// itself and restarts into it; this follows its state (it answers at once and checks on its
    /// own) until it answers as `to`, or gives up quietly: the installer then asks Windows.
    pub(super) async fn service_first(&self, to: Version) {
        let to = to.to_string();
        let take = UpdateAsk::Take {
            version: to.clone(),
        };
        let mut state = ask(take, ASK).await;
        let answered = state.is_some();
        let mut deadline = Instant::now() + TAKE;
        let mut restarting = false;
        loop {
            match state.take() {
                Some(now) => {
                    let step = step(&now, &to);
                    self.show_service(Some(now));
                    match step {
                        Step::Taken => {
                            tracing::info!(version = %to, "helper service took the release first");
                            return;
                        }
                        Step::Restarting if !restarting => {
                            restarting = true;
                            deadline = Instant::now() + BACK;
                        }
                        Step::Restarting | Step::Checking => {}
                        Step::Over => break,
                    }
                }
                // While the service restarts (or its old process ends) its pipe is not there for
                // a few seconds; no answer from the start = no service that takes releases.
                None if answered => {}
                None => break,
            }
            if Instant::now() > deadline {
                break;
            }
            tokio::time::sleep(POLL).await;
            state = ask(UpdateAsk::State, ASK).await;
        }
        tracing::info!(version = %to, "helper service did not take the release: the installer asks Windows");
    }
}

/// Where a `Take` of release `to` stands, by the service's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// The service runs `to`: the installer finds it current.
    Taken,
    /// It restarts into `to` now.
    Restarting,
    /// It still checks the feed or downloads.
    Checking,
    /// Anything else (not offered, waiting for another user's session, failed): the installer
    /// asks Windows as before.
    Over,
}

fn step(state: &ServiceUpdateWire, to: &str) -> Step {
    if state.version == to {
        return Step::Taken;
    }
    match state.phase {
        UpdatePhase::Restarting if state.target.as_deref() == Some(to) => Step::Restarting,
        UpdatePhase::Working => Step::Checking,
        _ => Step::Over,
    }
}

/// The Settings line of a service answer. «актуальна» only when the service runs `newest`, the
/// release the app's own last check confirmed as the newest: the service checks only when the
/// app asks, and its answer after a failed, outdated or refused check, or after a restart, says
/// nothing about being current (svcupd-a10 / b5). A failed take shows the version only: the
/// service does not retry by itself, the installer took over.
pub(super) fn line(state: &ServiceUpdateWire, newest: Option<&str>) -> ServiceLine {
    let target = state.target.clone();
    let state_now = match (state.phase, target) {
        (UpdatePhase::Working, _) => ServiceState::Working,
        (UpdatePhase::Waiting, Some(target)) => ServiceState::Waiting { target },
        (UpdatePhase::Restarting, Some(target)) => ServiceState::Restarting { target },
        _ if newest == Some(state.version.as_str()) => ServiceState::Current,
        _ => ServiceState::Unchecked,
    };
    ServiceLine {
        version: state.version.clone(),
        state: state_now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(phase: UpdatePhase, target: Option<&str>, checked: bool) -> ServiceUpdateWire {
        ServiceUpdateWire {
            version: "2.0.0".into(),
            phase,
            target: target.map(str::to_owned),
            checked_at: checked.then_some(1_794_480_000_000),
        }
    }

    /// Point 5: the app runs the installer once the service runs the release, keeps following
    /// while it checks or restarts into it, and stops waiting on anything else.
    #[test]
    fn a_take_is_followed_until_the_service_runs_the_release() {
        let to = "2.0.1";
        let at = |phase, target| step(&wire(phase, target, true), to);
        assert_eq!(at(UpdatePhase::Working, None), Step::Checking);
        assert_eq!(at(UpdatePhase::Restarting, Some(to)), Step::Restarting);
        assert_eq!(at(UpdatePhase::Restarting, Some("2.0.2")), Step::Over);
        assert_eq!(
            at(UpdatePhase::Waiting, Some(to)),
            Step::Over,
            "another user's session"
        );
        assert_eq!(at(UpdatePhase::Idle, None), Step::Over, "not offered");
        assert_eq!(at(UpdatePhase::Failed, None), Step::Over);
        let restarted = ServiceUpdateWire {
            version: to.into(),
            ..wire(UpdatePhase::Idle, None, false)
        };
        assert_eq!(step(&restarted, to), Step::Taken);
    }

    /// "Up to date" only when the service runs the release the app's own check found newest;
    /// never from the service's answer alone (a failed or outdated check, a restart: svcupd-a10,
    /// b5), and a failed take claims no retry.
    #[test]
    fn the_line_claims_only_what_was_seen() {
        let state = |w: ServiceUpdateWire| line(&w, None).state;
        let newest = |w: ServiceUpdateWire, v| line(&w, Some(v)).state;
        assert_eq!(
            newest(wire(UpdatePhase::Idle, None, true), "2.0.0"),
            ServiceState::Current
        );
        assert_eq!(
            newest(wire(UpdatePhase::Off, None, false), "2.0.0"),
            ServiceState::Current,
            "no keys: the app's check still knows"
        );
        assert_eq!(
            newest(wire(UpdatePhase::Idle, None, true), "2.0.1"),
            ServiceState::Unchecked,
            "a newer release exists"
        );
        assert_eq!(
            state(wire(UpdatePhase::Idle, None, true)),
            ServiceState::Unchecked,
            "the service's own word is not enough"
        );
        assert_eq!(
            state(wire(UpdatePhase::Off, None, false)),
            ServiceState::Unchecked
        );
        assert_eq!(
            state(wire(UpdatePhase::Working, None, true)),
            ServiceState::Working
        );
        assert_eq!(
            state(wire(UpdatePhase::Waiting, Some("2.0.1"), true)),
            ServiceState::Waiting {
                target: "2.0.1".into()
            }
        );
        assert_eq!(
            state(wire(UpdatePhase::Restarting, Some("2.0.1"), true)),
            ServiceState::Restarting {
                target: "2.0.1".into()
            }
        );
        assert_eq!(
            state(wire(UpdatePhase::Failed, None, true)),
            ServiceState::Unchecked
        );
        assert_eq!(
            line(&wire(UpdatePhase::Idle, None, true), None).version,
            "2.0.0"
        );
    }
}
