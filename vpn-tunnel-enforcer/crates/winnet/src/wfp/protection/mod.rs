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
    /// The session's TUN was up once: "If the VPN drops" blocks from here until `disconnected()`.
    armed: bool,
}

struct Inner {
    settings: ProtectionSettings,
    engines: EnginePaths,
    self_exe: PathBuf,
    conn: Conn,
    tun_luid: Option<u64>,
    session: Vec<PathBuf>,
    tun_addrs: Vec<IpAddr>,
    armed: bool,
    /// "Always" can be kept safe (the helper service owns the filters); otherwise a stored
    /// `strict` works as `standard` and nothing persistent is installed.
    always_available: bool,
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
            armed: false,
            always_available: false,
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
    /// blocked by our filters (kill switch on, or leak protection). The tunnel builds a
    /// dual-stack TUN with `dns_mode: native` exactly then, otherwise an IPv4-only TUN with
    /// `hijack` (review D1 / D2); read it at connect, a change applies from the next one.
    pub fn session_guarded(&self) -> bool {
        let g = self.inner.lock();
        g.level_in_force() != KillSwitchLevel::Off || g.settings.leak_protection
    }

    /// The level the filters enforce: a stored `strict` works as `standard` until
    /// [`Protection::set_always_available`] says "Always" can be kept safe.
    pub fn level_in_force(&self) -> KillSwitchLevel {
        self.inner.lock().level_in_force()
    }

    /// Set by the helper-service wiring: "Always" (persistent filters) is enforced only while
    /// something owns them across exit and reboot. Off by default: an app run as administrator
    /// creates no persistent filters, and leftovers of an earlier strict run are removed.
    pub fn set_always_available(&self, available: bool) -> Result<(), ProtectionError> {
        let mut g = self.inner.lock();
        if g.always_available == available {
            return Ok(());
        }
        g.always_available = available;
        let t = g.target();
        let persistent_first = g.level_in_force() == KillSwitchLevel::Strict;
        let (d, skipped) = g.plan(&t)?;
        g.sync(&d, persistent_first)?;
        self.note_skipped(&mut g, skipped);
        Ok(())
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

    /// At app start, after the settings import and the legacy cleanup: installs the "Always"
    /// set where it is in force, otherwise removes persistent leftovers (an earlier strict run,
    /// a crash). Quiet: the start page shows what the kill switch does.
    pub fn startup(&self) -> Result<(), ProtectionError> {
        let mut g = self.inner.lock();
        let mut t = g.target();
        t.conn = Conn::Disconnected;
        t.tun_luid = None;
        t.session.clear();
        t.tun_addrs.clear();
        t.armed = false;
        let skipped = g.transition(t, true)?;
        self.note_skipped(&mut g, skipped);
        Ok(())
    }

    /// Before any engine is spawned (TUN sessions only; Soft mode never calls it): engages leak
    /// protection (DNS outside the TUN blocked from here on), permits the per-session programs
    /// (canonical paths of the local-proxy owner executables) and the TUN's fixed local
    /// addresses (`adapters::TUN_V4`, plus `TUN_V6` when dual-stack), so traffic routed into the
    /// TUN before [`Protection::tun_up`] is not refused. "If the VPN drops" blocks everything
    /// only once a TUN of this session was up: a first connect that never comes up leaves the
    /// internet alone, a reconnect (planned or after a drop) keeps the block with no gap. An
    /// error means the connect must be refused.
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
    /// LUID after an engine restart replaces the old permit. Arms "If the VPN drops". An error
    /// means the connect must be aborted.
    pub fn tun_up(&self, luid: u64) -> Result<(), ProtectionError> {
        let mut g = self.inner.lock();
        let mut t = g.target();
        t.conn = Conn::Up;
        t.tun_luid = Some(luid);
        t.armed = true;
        let skipped = g.transition(t, false)?;
        self.note_skipped(&mut g, skipped);
        Ok(())
    }

    /// The TUN went away unexpectedly: an armed block stays until the user disconnects (the
    /// tunnel's paused state tells the user; no notice from here).
    pub fn tun_lost(&self) -> Result<(), ProtectionError> {
        let mut g = self.inner.lock();
        if !g.conn.in_session() {
            return Ok(());
        }
        let mut t = g.target();
        t.conn = Conn::Dropped;
        t.tun_luid = None;
        let skipped = g.transition(t, true)?;
        self.note_skipped(&mut g, skipped);
        Ok(())
    }

    /// The session ended (user stop, failed start, or "Continue without VPN" after a drop): the
    /// dynamic set goes; an "Always" set stays.
    pub fn disconnected(&self) -> Result<(), ProtectionError> {
        let mut g = self.inner.lock();
        let mut t = g.target();
        t.conn = Conn::Disconnected;
        t.tun_luid = None;
        t.session.clear();
        t.tun_addrs.clear();
        t.armed = false;
        let skipped = g.transition(t, true)?;
        self.note_skipped(&mut g, skipped);
        Ok(())
    }

    /// App exit: closes the dynamic session, so BFE removes its filters; "Always" stays.
    pub fn shutdown(&self) {
        let mut g = self.inner.lock();
        g.drop_dynamic();
        g.conn = Conn::Disconnected;
        g.tun_luid = None;
        g.session.clear();
        g.tun_addrs.clear();
        g.armed = false;
    }
}

#[cfg(test)]
mod tests;
