//! Tunnel mode's failover (speed audit conn2). The helper service's runtime has none of its own
//! (the server list lives here), so a crash with an outbound fault left Tunnel mode waiting out
//! the server's 130 s quiet time under the kill switch while Proxy mode moved to a sibling in a
//! second. When the service schedules a restart later than any backoff, this process starts the
//! next live sibling through the service (a start the service checks like any other) and tells
//! the lifecycle what the in-process runtime's own failover tells it: `FailedOver` right after
//! the run began, `PostTrialFailover` after it finished well. One try per outage; a sibling that
//! does not start leaves the service's own schedule for the first server.
use std::time::Duration;

use vpnte_tunnel::api::{FailoverCause, TunStatusKind, TunnelEvent};

/// A scheduled restart this much later is a quiet time, not a backoff (the backoffs are 2, 5
/// and 10 s).
pub(super) const QUIET_WAIT: Duration = Duration::from_secs(15);

/// Where one outage's failover stands.
#[derive(Debug, Default)]
pub(super) struct ServiceFailover {
    /// The sibling being started: its id and name.
    pending: Option<(String, String)>,
    /// This outage had its try.
    tried: bool,
}

/// What the forwarder does after one of the service's events.
#[derive(Debug, Default, PartialEq)]
pub(super) struct Step {
    /// Events to pass on after the service's own one.
    pub then: Vec<TunnelEvent>,
    /// Start the failover now.
    pub start: bool,
    /// The sibling started: make it the active server.
    pub commit: Option<String>,
}

impl ServiceFailover {
    /// The service sent `event` (generations already the lifecycle's); `direct` = its session
    /// runs a server of the list (a local proxy's server is no one's to replace).
    pub fn on_event(&mut self, event: &TunnelEvent, direct: bool) -> Step {
        let mut step = Step::default();
        match event {
            TunnelEvent::RestartScheduled { delay }
                if *delay > QUIET_WAIT && direct && !self.tried && self.pending.is_none() =>
            {
                self.tried = true;
                step.start = true;
            }
            TunnelEvent::StartBegan { generation } => {
                if let Some((id, _)) = &self.pending {
                    step.then.push(TunnelEvent::FailedOver {
                        generation: *generation,
                        profile_id: id.clone(),
                        cause: FailoverCause::ServerFault,
                    });
                }
            }
            TunnelEvent::StartFinished { ok, .. } => {
                if let Some((id, name)) = self.pending.take().filter(|_| *ok) {
                    step.then
                        .push(TunnelEvent::Status(TunStatusKind::PostTrialFailover {
                            name,
                        }));
                    step.commit = Some(id);
                }
                if *ok {
                    // A run that came up ends the outage: the next one may try again.
                    self.tried = false;
                }
            }
            _ => {}
        }
        step
    }

    /// The failover start of sibling `id` (`name`) is about to be sent.
    pub fn begin(&mut self, id: String, name: String) {
        self.pending = Some((id, name));
    }

    /// No sibling, or its start was refused before it began.
    pub fn abandon(&mut self) {
        self.pending = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scheduled(secs: u64) -> TunnelEvent {
        TunnelEvent::RestartScheduled {
            delay: Duration::from_secs(secs),
        }
    }

    /// A quiet time (not a backoff) of a list server's session starts one failover per outage;
    /// its run is named `FailedOver` right after it began and announced after it finished well.
    #[test]
    fn a_quiet_time_fails_over_once_and_names_the_run() {
        let mut f = ServiceFailover::default();
        assert!(!f.on_event(&scheduled(5), true).start, "a backoff");
        assert!(!f.on_event(&scheduled(130), false).start, "a local proxy");
        assert!(f.on_event(&scheduled(130), true).start);
        assert!(!f.on_event(&scheduled(130), true).start, "one try");
        f.begin("b".into(), "Fake B".into());
        let began = f.on_event(&TunnelEvent::StartBegan { generation: 7 }, true);
        assert_eq!(
            began.then,
            [TunnelEvent::FailedOver {
                generation: 7,
                profile_id: "b".into(),
                cause: FailoverCause::ServerFault,
            }]
        );
        let done = TunnelEvent::StartFinished {
            generation: 7,
            ok: true,
        };
        let finished = f.on_event(&done, true);
        assert_eq!(finished.commit.as_deref(), Some("b"));
        let announced = TunnelEvent::Status(TunStatusKind::PostTrialFailover {
            name: "Fake B".into(),
        });
        assert_eq!(finished.then, [announced]);
        assert!(f.on_event(&scheduled(130), true).start, "a new outage");
    }

    /// A sibling that does not start is not announced and keeps the outage's one try spent.
    #[test]
    fn a_failed_sibling_is_never_announced() {
        let mut f = ServiceFailover::default();
        assert!(f.on_event(&scheduled(130), true).start);
        f.begin("b".into(), "Fake B".into());
        let _ = f.on_event(&TunnelEvent::StartBegan { generation: 3 }, true);
        let failed = TunnelEvent::StartFinished {
            generation: 3,
            ok: false,
        };
        assert_eq!(f.on_event(&failed, true), Step::default());
        assert!(!f.on_event(&scheduled(130), true).start);
    }
}
