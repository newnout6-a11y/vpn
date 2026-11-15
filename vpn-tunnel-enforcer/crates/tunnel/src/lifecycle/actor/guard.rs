//! The live session's kill switch kept current (fix-ks a1, b1): the level the user picks now,
//! and for a proxy session whether another full-tunnel VPN carries the default route now. Read
//! at connect, on a level change, when an outage begins, and while another VPN is in the way.
use super::*;

/// How often a proxy session next to another VPN looks again whether that VPN is still up: the
/// «Другой VPN» line and the session's pause follow it.
pub(super) const FOREIGN_RECHECK: Duration = if cfg!(test) {
    Duration::from_millis(200)
} else {
    Duration::from_secs(30)
};

impl Actor {
    /// Re-reads the session's kill switch; a change reaches the runtime's crash policy, the
    /// system proxy of an outage that now pauses, and what the start page shows.
    pub(super) async fn refresh_guard(&mut self) {
        let Some(soft) = self.session.as_ref().map(LiveSession::is_soft) else {
            return;
        };
        let guard = effects::session_guard(&self.deps, soft).await;
        if guard != self.guard {
            tracing::info!(level = ?guard.level, foreign = guard.foreign_vpn.is_some(),
                "the session's kill switch changed");
            self.guard = guard;
            self.deps.runtime.set_kill_switch(self.guard.level).await;
            if self.guard.pauses() && self.paused.is_some() {
                // The outage turns into a pause: a proxy session points programs at the dead
                // port again instead of letting them go direct.
                self.resume_soft().await;
                let e = self.evidence();
                self.enter_pause(e, true);
            }
        }
        self.push_kill_switch();
        self.watch_foreign();
    }

    /// While another VPN keeps this session from pausing, look again later.
    pub(super) fn watch_foreign(&mut self) {
        if self.foreign_watch || self.guard.foreign_vpn.is_none() || self.session.is_none() {
            return;
        }
        self.foreign_watch = true;
        let tx = self.tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(FOREIGN_RECHECK).await;
            let _ = tx.send(Cmd::GuardCheck);
        });
    }

    /// The timer of [`Actor::watch_foreign`] fired.
    pub(super) async fn guard_check(&mut self) {
        self.foreign_watch = false;
        if self.lane_idle() {
            self.refresh_guard().await;
        } else {
            // The operation in flight decides the session; look again after it.
            self.watch_foreign();
        }
    }
}
