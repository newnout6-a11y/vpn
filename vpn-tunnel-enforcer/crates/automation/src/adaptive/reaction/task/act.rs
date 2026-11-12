//! One report: learn, decide, act, tell.
use vpnte_base::Msg;
use vpnte_base::types::{Level, Notice, Owner};

use super::super::decide::Cause;
use super::*;
use crate::coordinator::{NoticeCategory, OpError, SwitchError};

/// How a fingerprint retry ended.
enum Retry {
    Done,
    /// A higher-priority operation took over (or the session moved): not a failure.
    Preempted,
    /// Give up on the server.
    Failed,
}

impl<C: Coordinator, H: ReactionHost> Reactions<C, H> {
    pub(in crate::adaptive::reaction) async fn handle(
        &self,
        report: Report,
        cancel: &CancellationToken,
    ) {
        let Some(server) = self.host.server(&report.profile_id) else {
            tracing::debug!("reactions: report about an unknown profile ignored");
            return;
        };
        let servers = self.host.servers();
        self.verdicts.with(|m| m.learn(&report, &server, &servers));
        // At most twice: a failed fingerprint retry is marked as tried, so the table then
        // answers with a switch away from the server (or nothing, if the session moved).
        loop {
            match self.decide(&report, &server, &servers) {
                Decision::Fingerprint(fingerprint) => {
                    match self.retry_fingerprint(&server, fingerprint, cancel).await {
                        Retry::Failed => continue,
                        Retry::Done | Retry::Preempted => return,
                    }
                }
                Decision::Nothing(why) => tracing::debug!(why, "reactions: nothing to do"),
                Decision::Manual(cause) => {
                    self.mark(&server, Attempt::Switch, true);
                    self.tell(Level::Warn, cause, &server, Msg::new(AUTO_OFF));
                }
                Decision::Paused(_) => {
                    self.mark(&server, Attempt::Switch, true);
                    if self
                        .verdicts
                        .with(|m| !std::mem::replace(&mut m.paused_told, true))
                    {
                        let notice =
                            Notice::new(Level::Warn, PAUSED_TITLE).body(Msg::new(PAUSED_BODY));
                        self.coord.notify(NoticeCategory::ConnectionError, notice);
                    }
                }
                Decision::Switch { cause, candidates } => {
                    self.mark(&server, Attempt::Switch, true);
                    self.switch(cause, &server, candidates, cancel).await;
                }
            }
            return;
        }
    }

    fn decide(&self, report: &Report, server: &ServerFacts, servers: &[ServerFacts]) -> Decision {
        let allowed = self.settings.read(|s| Allowed {
            fingerprint: s.adaptive_bypass,
            switch: s.adaptive_bypass && s.adaptive_bypass_server_fallback,
        });
        let active = self.still_on(server);
        self.verdicts
            .with(|m| decide::decide(report, server, active, m, servers, allowed))
    }

    /// The running Direct session is on `server`.
    fn still_on(&self, server: &ServerFacts) -> bool {
        self.coord.session().is_some_and(|s| {
            s.kind == SessionKind::Direct && s.profile_id.as_deref() == Some(server.id.as_str())
        })
    }

    /// Records (`on`) or withdraws a reaction for this network session.
    fn mark(&self, server: &ServerFacts, attempt: Attempt, on: bool) {
        let key = (server.id.clone(), attempt);
        self.verdicts.with(|m| {
            if on {
                m.tried.insert(key);
            } else {
                m.tried.remove(&key);
            }
        });
    }

    fn count_restart(&self) {
        self.verdicts
            .with(|m| m.restarts = m.restarts.saturating_add(1));
    }

    fn tell(&self, level: Level, cause: Cause, server: &ServerFacts, body: Msg) {
        let title = Msg::new(cause_key(cause)).arg("name", &server.name);
        let notice = Notice::new(level, title).body(body);
        self.coord.notify(NoticeCategory::ConnectionError, notice);
    }
}

impl<C: Coordinator, H: ReactionHost> Reactions<C, H> {
    /// One protected restart of the running REALITY server with `fingerprint` (session-only
    /// override). Success means the coordinator proved fresh egress through it.
    async fn retry_fingerprint(
        &self,
        server: &ServerFacts,
        fingerprint: &'static str,
        cancel: &CancellationToken,
    ) -> Retry {
        self.mark(server, Attempt::Fingerprint, true);
        if self.coord.busy() {
            // A lifecycle operation runs; it would refuse the restart anyway.
            self.mark(server, Attempt::Fingerprint, false);
            return Retry::Preempted;
        }
        let slot = self
            .host
            .handshake_slot(&server.id, RETRY_SLOT_WAIT, cancel.clone());
        if !slot.await {
            tracing::info!("reactions: handshake budget refused the fingerprint retry");
            return Retry::Failed;
        }
        let Some(mode) = self
            .coord
            .session()
            .filter(|_| self.still_on(server))
            .map(|s| s.mode)
        else {
            self.mark(server, Attempt::Fingerprint, false);
            return Retry::Preempted;
        };
        let guard = Override::set(&*self.host, &server.id, fingerprint);
        self.count_restart();
        match self
            .coord
            .adaptive_restart(Owner::AdaptiveRetry, mode, None)
            .await
        {
            Ok(_) => {
                guard.keep();
                self.verdicts.with(|m| m.avoid.remove(&server.id));
                tracing::info!(
                    fingerprint,
                    "reactions: REALITY retry with another fingerprint held"
                );
                let body = Msg::new(FINGERPRINT).arg("fingerprint", fingerprint);
                self.tell(Level::Warn, Cause::HandshakeFailed, server, body);
                Retry::Done
            }
            Err(OpError::Conflict | OpError::Cancelled) => {
                self.mark(server, Attempt::Fingerprint, false);
                Retry::Preempted
            }
            Err(err) => {
                tracing::warn!(error = %err, "reactions: fingerprint retry failed");
                Retry::Failed
            }
        }
    }

    /// Moves the session to the first candidate that takes a budget slot and passes the
    /// coordinator's protected switch; tells the outcome once.
    async fn switch(
        &self,
        cause: Cause,
        from: &ServerFacts,
        candidates: Vec<ServerFacts>,
        cancel: &CancellationToken,
    ) {
        let mut failure: Option<Msg> = None;
        let mut deferred = false;
        for to in candidates {
            if self.coord.busy() || !self.still_on(from) {
                // A higher operation runs or already moved the session: not ours to touch.
                self.mark(from, Attempt::Switch, false);
                return;
            }
            let slot = self
                .host
                .handshake_slot(&to.id, SWITCH_SLOT_WAIT, cancel.clone());
            if !slot.await {
                tracing::info!("reactions: handshake budget deferred a candidate");
                deferred = true;
                continue;
            }
            self.count_restart();
            match self
                .coord
                .switch_profile(Owner::AdaptiveRetry, &to.id)
                .await
            {
                Ok(()) => {
                    tracing::info!(?cause, "reactions: session moved to another server");
                    let key = if cause == Cause::UdpBlocked {
                        SWITCHED_TCP
                    } else {
                        SWITCHED
                    };
                    self.tell(
                        Level::Warn,
                        cause,
                        from,
                        Msg::new(key).arg("name", &to.name),
                    );
                    return;
                }
                Err(SwitchError::NotStarted(OpError::Conflict | OpError::Cancelled)) => {
                    tracing::info!("reactions: switch pre-empted by a higher-priority operation");
                    self.mark(from, Attempt::Switch, false);
                    return;
                }
                Err(
                    SwitchError::NotStarted(reason)
                    | SwitchError::Failed {
                        reason,
                        restored_previous: true,
                    },
                ) => {
                    tracing::warn!(error = %reason, "reactions: switch to a candidate failed");
                    self.avoid_failed(&to);
                    failure = Some(reason.reason());
                }
                Err(SwitchError::Failed {
                    reason,
                    restored_previous: false,
                }) => {
                    tracing::warn!(error = %reason, "reactions: switch failed, session stopped");
                    self.tell(Level::Error, cause, from, reason.reason());
                    return;
                }
            }
        }
        match failure {
            Some(reason) => self.tell(Level::Warn, cause, from, reason),
            // Every candidate is busy in the budget for now: not a failure, the next check
            // of this server may react again.
            None if deferred => self.mark(from, Attempt::Switch, false),
            None => self.tell(Level::Warn, cause, from, Msg::new(NO_ALTERNATIVE)),
        }
    }

    /// A candidate whose protected start failed here is as good as offline for later picks.
    fn avoid_failed(&self, to: &ServerFacts) {
        let report = Report {
            profile_id: to.id.clone(),
            verdict: super::super::CheckVerdict::Offline,
            reaction: super::super::CheckReaction::SwitchServer,
        };
        self.verdicts.with(|m| m.learn(&report, to, &[]));
    }
}

/// The session-only fingerprint override; removed again unless the retry held.
struct Override<'a, H: ReactionHost> {
    host: &'a H,
    id: &'a str,
    keep: bool,
}

impl<'a, H: ReactionHost> Override<'a, H> {
    fn set(host: &'a H, id: &'a str, fingerprint: &'static str) -> Self {
        host.override_fingerprint(id, Some(fingerprint));
        Self {
            host,
            id,
            keep: false,
        }
    }

    fn keep(mut self) {
        self.keep = true;
    }
}

impl<H: ReactionHost> Drop for Override<'_, H> {
    fn drop(&mut self) {
        // Also on an abandoned reaction (network change, shutdown): never leave a failed guess.
        if !self.keep {
            self.host.override_fingerprint(self.id, None);
        }
    }
}

const AUTO_OFF: &str = "automation.adaptive.reaction.action.autoOff";
const FINGERPRINT: &str = "automation.adaptive.reaction.action.fingerprint";
const NO_ALTERNATIVE: &str = "automation.adaptive.reaction.action.noAlternative";
const SWITCHED: &str = "automation.adaptive.reaction.action.switched";
const SWITCHED_TCP: &str = "automation.adaptive.reaction.action.switchedTcp";
const PAUSED_TITLE: &str = "automation.adaptive.reaction.paused.title";
const PAUSED_BODY: &str = "automation.adaptive.reaction.paused.body";

/// The notice title: what happened to the server (`{{name}}`).
fn cause_key(cause: Cause) -> &'static str {
    match cause {
        Cause::IpBanned => "automation.adaptive.reaction.cause.ipBanned",
        Cause::Frozen => "automation.adaptive.reaction.cause.frozen",
        Cause::Offline => "automation.adaptive.reaction.cause.offline",
        Cause::KeyRejected => "automation.adaptive.reaction.cause.keyRejected",
        Cause::HandshakeFailed => "automation.adaptive.reaction.cause.handshakeFailed",
        Cause::UdpBlocked => "automation.adaptive.reaction.cause.udpBlocked",
    }
}
