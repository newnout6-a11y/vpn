//! The [`Protection`] handle (firewall-recovery §6.5). One mutex serialises every change; a
//! change is one BFE transaction per session (dynamic / persistent), so it is all or nothing
//! and the previous filters stay intact when it fails.
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::broadcast;
use vpnte_base::types::{KillSwitchLevel, Level, Notice};
use vpnte_base::{AppResult, Msg};

use super::backend::{Backend, RemoveReport, WfpBackend, remove_all_objects};
use super::desired::Installed;
use super::model::{Conn, EnginePaths, ProtectionError, ProtectionSettings};
use super::spec::FilterSpec;

mod apply;
mod config;
mod health;

/// How often [`Protection::run_watchdog`] re-checks our filters (a BFE restart drops them).
pub const WATCHDOG_PERIOD: std::time::Duration = std::time::Duration::from_secs(30);

/// Saves the settings; called by [`Protection::set_level`] / [`Protection::set_exceptions`]
/// at the point the persistence order requires, with the protection lock held (so it must
/// not call back into [`Protection`]).
pub type Persist<'a> = &'a dyn Fn(&ProtectionSettings) -> AppResult<()>;

/// Deletes every object of ours (uninstall, `--cleanup`). Run it while no instance holds
/// dynamic filters, or the sublayer delete fails with `FWP_E_IN_USE`.
pub fn remove_all() -> Result<RemoveReport, ProtectionError> {
    remove_all_objects().map_err(ProtectionError::from)
}

/// Kill switch and leak protection for the whole app; share it behind an `Arc`.
pub struct Protection {
    inner: Mutex<Inner>,
    notices: broadcast::Sender<Notice>,
}

/// The state a change is computed for before it is committed.
#[derive(Debug, Clone)]
struct Target {
    settings: ProtectionSettings,
    conn: Conn,
    tun_luid: Option<u64>,
    session: Vec<PathBuf>,
    tun_addrs: Vec<IpAddr>,
}

struct Inner {
    settings: ProtectionSettings,
    engines: EnginePaths,
    self_exe: PathBuf,
    conn: Conn,
    tun_luid: Option<u64>,
    session: Vec<PathBuf>,
    tun_addrs: Vec<IpAddr>,
    /// Our filters in the dynamic session.
    dynamic: Installed,
    /// The last dynamic change failed or the read-back differed: `dynamic` is in doubt.
    dynamic_dirty: bool,
    /// Our persistent filters; `None` = unknown (not reconciled yet, or failed).
    persistent: Option<Installed>,
    sublayer_weight: Option<u16>,
    bfe_running: Option<bool>,
    last_error: Option<ProtectionError>,
    last_verified: Option<i64>,
    skipped: Vec<String>,
    watchdog_failed: bool,
    backend: Box<dyn Backend>,
}

/// The read-back `seen` holds exactly the filters of `installed`.
fn same_ids(seen: &[u64], installed: &[(FilterSpec, u64)]) -> bool {
    let mut seen = seen.to_vec();
    let mut ours: Vec<u64> = installed.iter().map(|(_, id)| *id).collect();
    seen.sort_unstable();
    ours.sort_unstable();
    seen == ours
}

fn blocked(body: &'static str) -> Notice {
    Notice::new(Level::Warn, "winnet.wfp.notice.blockedTitle").body(body)
}

fn persist_failed(e: vpnte_base::AppError) -> ProtectionError {
    tracing::warn!(error = %e, "protection settings not saved");
    ProtectionError::Persist(Arc::new(e))
}

impl Protection {
    /// A handle over the real WFP backend; nothing is applied before [`Protection::startup`].
    /// `engines` and `self_exe` are the canonical paths the processes run from.
    pub fn new(engines: EnginePaths, self_exe: PathBuf, settings: ProtectionSettings) -> Self {
        Self::with_backend(engines, self_exe, settings, Box::new(WfpBackend::default()))
    }

    fn with_backend(
        engines: EnginePaths,
        self_exe: PathBuf,
        settings: ProtectionSettings,
        backend: Box<dyn Backend>,
    ) -> Self {
        let inner = Inner {
            settings,
            engines,
            self_exe,
            conn: Conn::Disconnected,
            tun_luid: None,
            session: Vec::new(),
            tun_addrs: Vec::new(),
            dynamic: Vec::new(),
            dynamic_dirty: false,
            persistent: None,
            sublayer_weight: None,
            bfe_running: None,
            last_error: None,
            last_verified: None,
            skipped: Vec::new(),
            watchdog_failed: false,
            backend,
        };
        Self {
            inner: Mutex::new(inner),
            notices: broadcast::channel(16).0,
        }
    }

    /// Notices for the user; all of them belong to the `connectionError` preference category.
    pub fn notices(&self) -> broadcast::Receiver<Notice> {
        self.notices.subscribe()
    }

    /// The settings in force.
    pub fn settings(&self) -> ProtectionSettings {
        self.inner.lock().settings.clone()
    }

    /// Whether a TUN session under the current settings has IPv6 and DNS outside the TUN
    /// blocked by our filters (kill switch standard / strict, or leak protection). The tunnel
    /// builds a dual-stack TUN with `dns_mode: native` exactly then, otherwise an IPv4-only TUN
    /// with `hijack` (review D1 / D2); read it at connect, a change applies from the next one.
    pub fn session_guarded(&self) -> bool {
        let g = self.inner.lock();
        g.settings.level != KillSwitchLevel::Off || g.settings.leak_protection
    }

    fn notify(&self, notice: Notice) {
        // No receiver yet is fine: the notice is advisory.
        let _ = self.notices.send(notice);
    }

    /// Records which app exceptions were skipped; each newly skipped one is announced once.
    fn note_skipped(&self, g: &mut Inner, skipped: Vec<String>) {
        for id in skipped.iter().filter(|id| !g.skipped.contains(id)) {
            if let Some(e) = g.settings.exceptions.iter().find(|e| &e.id == id) {
                tracing::warn!(id = %e.id, "app exception skipped: file not found");
                let body = Msg::new("winnet.wfp.notice.exceptionSkipped").arg("label", &e.label);
                self.notify(
                    Notice::new(Level::Warn, "winnet.wfp.notice.exceptionSkippedTitle").body(body),
                );
            }
        }
        g.skipped = skipped;
    }

    /// At app start, after the settings import and the legacy cleanup: installs the strict set,
    /// or removes persistent leftovers when the level is not strict.
    pub fn startup(&self) -> Result<(), ProtectionError> {
        let mut g = self.inner.lock();
        let mut t = g.target();
        t.conn = Conn::Disconnected;
        t.tun_luid = None;
        t.session.clear();
        t.tun_addrs.clear();
        let skipped = g.transition(t, true)?;
        self.note_skipped(&mut g, skipped);
        if g.settings.level == KillSwitchLevel::Strict {
            self.notify(blocked("winnet.wfp.notice.blockedStrict"));
        }
        Ok(())
    }

    /// Before any engine is spawned (TUN sessions only; Soft mode never calls it): engages the
    /// kill switch or leak protection (DNS outside the TUN blocked from here on), permits the
    /// per-session programs (canonical paths of the local-proxy owner executables) and the TUN's
    /// fixed local addresses (`adapters::TUN_V4`, plus `TUN_V6` when dual-stack), so traffic
    /// routed into the TUN before [`Protection::tun_up`] is not refused. An error means the
    /// connect must be refused.
    pub fn connect_begin(
        &self,
        session_programs: &[PathBuf],
        tun_addresses: &[IpAddr],
    ) -> Result<(), ProtectionError> {
        let mut g = self.inner.lock();
        let mut t = g.target();
        t.conn = Conn::Connecting;
        t.tun_luid = None;
        t.session = session_programs.to_vec();
        t.tun_addrs = tun_addresses.to_vec();
        let skipped = g.transition(t, false)?;
        self.note_skipped(&mut g, skipped);
        Ok(())
    }

    /// The TUN is up (`luid` = `adapters::OwnedTun::luid` from `wait_owned_tun`); a new
    /// LUID after an engine restart replaces the old permit. An error means the connect must be
    /// aborted.
    pub fn tun_up(&self, luid: u64) -> Result<(), ProtectionError> {
        let mut g = self.inner.lock();
        let mut t = g.target();
        t.conn = Conn::Up;
        t.tun_luid = Some(luid);
        let skipped = g.transition(t, false)?;
        self.note_skipped(&mut g, skipped);
        Ok(())
    }

    /// The TUN went away unexpectedly: the blocks stay until the user disconnects.
    pub fn tun_lost(&self) -> Result<(), ProtectionError> {
        let mut g = self.inner.lock();
        if !g.conn.in_session() {
            return Ok(());
        }
        let mut t = g.target();
        t.conn = Conn::Dropped;
        t.tun_luid = None;
        let result = g.transition(t, true);
        if g.settings.level == KillSwitchLevel::Standard {
            self.notify(blocked("winnet.wfp.notice.blockedStandard"));
        }
        let skipped = result?;
        self.note_skipped(&mut g, skipped);
        Ok(())
    }

    /// The session ended (user stop, failed start, or "Disable protection" after a drop): the
    /// dynamic set goes; a strict set stays and says so.
    pub fn disconnected(&self) -> Result<(), ProtectionError> {
        let mut g = self.inner.lock();
        let mut t = g.target();
        t.conn = Conn::Disconnected;
        t.tun_luid = None;
        t.session.clear();
        t.tun_addrs.clear();
        let result = g.transition(t, true);
        let strict_on = g.persistent.as_ref().is_some_and(|p| !p.is_empty());
        if g.settings.level == KillSwitchLevel::Strict && strict_on {
            self.notify(blocked("winnet.wfp.notice.blockedStrict"));
        }
        let skipped = result?;
        self.note_skipped(&mut g, skipped);
        Ok(())
    }

    /// App exit: closes the dynamic session, so BFE removes its filters; strict stays.
    pub fn shutdown(&self) {
        let mut g = self.inner.lock();
        g.drop_dynamic();
        g.conn = Conn::Disconnected;
        g.tun_luid = None;
        g.session.clear();
        g.tun_addrs.clear();
    }
}

#[cfg(test)]
mod tests;
