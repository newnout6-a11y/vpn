//! Outages of a live session (ks-a, research killswitch §5.2): the session stays open while the
//! runtime recovers it. With a kill switch that holds it is the paused state the start page and
//! the tray show with «Подключить» / «Продолжить без VPN»; with the kill switch off programs go
//! direct meanwhile. Either way one calm notice, only after the outage lasted a while.
use vpnte_base::types::OutboundFault;

use super::*;

/// Shorter outages stay silent (engine restarts take 2-10 s); tests wait a fraction of it.
pub(super) const PAUSE_NOTICE_AFTER: Duration = if cfg!(test) {
    Duration::from_millis(300)
} else {
    Duration::from_secs(10)
};

/// The actor's side of an outage.
pub(super) struct Paused {
    view: Pause,
    /// The kill switch holds: the internet is paused (otherwise programs go direct).
    held: bool,
    /// The one notice of this outage was shown (a later `restored` closes it).
    told: bool,
    /// The notice for a rejected key was shown (the second one: the user must act).
    told_key: bool,
}

impl Actor {
    /// The runtime's recovery owns the live session's tunnel (its last status was a crash
    /// restart or the held block), e.g. after a planned reconnect failed under the kill switch.
    pub(super) fn runtime_recovers(&self) -> bool {
        self.session.is_some()
            && !self.runtime_running()
            && matches!(
                self.last_kind,
                Some(TunStatusKind::Restarting { .. } | TunStatusKind::KillSwitchActive)
            )
    }

    /// The runtime lost the session's tunnel (a crash restart, the held block after the budget,
    /// a failed planned reconnect). `held`: the kill switch keeps the internet paused (the state
    /// machine says so); otherwise the caller already fed the runtime status to it.
    pub(super) fn enter_pause(&mut self, e: Option<Evidence>, held: bool) {
        if held && self.fsm.paused(e).is_err() {
            tracing::debug!("pause not applied to the state machine (operation in flight)");
        }
        let key_rejected =
            self.deps.runtime.recent_fault() == Some(OutboundFault::RealityKeyMismatch);
        let begun = self.paused.is_none();
        let p = self.paused.get_or_insert_with(|| Paused {
            view: Pause {
                since: now_ms(),
                next_attempt: None,
                key_rejected: false,
            },
            held,
            told: false,
            told_key: false,
        });
        p.held |= held;
        p.view.key_rejected |= key_rejected;
        let tell_key = p.told && p.view.key_rejected && !p.told_key;
        let since = p.view.since;
        if begun {
            tracing::info!(held, "session lost its tunnel: recovering");
            let tx = self.tx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(PAUSE_NOTICE_AFTER).await;
                let _ = tx.send(Cmd::PauseNotice { since });
            });
        }
        if tell_key {
            self.tell_pause();
        }
        self.push_kill_switch();
    }

    /// The outage that began at `since` still lasts: its one notice.
    pub(super) fn pause_notice(&mut self, since: UnixMs) {
        if self
            .paused
            .as_ref()
            .is_some_and(|p| p.view.since == since && !p.told)
        {
            self.tell_pause();
        }
    }

    /// One notice per outage; a second one only when the user must act (the key was rejected).
    fn tell_pause(&mut self) {
        let Some(p) = self.paused.as_mut() else {
            return;
        };
        let name = match (p.view.key_rejected, p.held) {
            (true, _) => "keyRejected",
            (false, true) => "paused",
            (false, false) => "reconnecting",
        };
        p.told = true;
        p.told_key |= p.view.key_rejected;
        self.notify(Level::Warn, name, NoticeKind::ConnectionError, None);
    }

    /// The next automatic attempt (`None`: one runs now, or none is scheduled).
    pub(super) fn pause_next(&mut self, at: Option<UnixMs>) {
        if let Some(p) = self.paused.as_mut() {
            p.view.next_attempt = at;
            self.push_kill_switch();
        }
    }

    /// The pause is over (reconnected, or the session ended); `true` when the user had been told
    /// about it (then a reconnect is worth a `restored` notice).
    pub(super) fn end_pause(&mut self) -> bool {
        let told = self.paused.take().is_some_and(|p| p.told);
        self.push_kill_switch();
        told
    }

    /// Publishes what the start page and the tray show.
    pub(super) fn push_kill_switch(&self) {
        let view = KillSwitchView {
            pause: self
                .paused
                .as_ref()
                .filter(|p| p.held)
                .map(|p| p.view.clone()),
            foreign_vpn: self.session.as_ref().and(self.guard.foreign_vpn.clone()),
        };
        self.kill_switch.send_if_modified(|v| {
            let changed = *v != view;
            *v = view;
            changed
        });
    }
}
