//! The owner's start: the "Always" set where it is in force, leftovers removed — and in the
//! helper service, the block of a crashed run taken over (research killswitch §5.3 "Helper
//! service crash": paused until Windows restarts the service and it reconnects).
use vpnte_base::types::KillSwitchLevel;

use super::{Inner, Protection};
use crate::wfp::engine::Lifetime;
use crate::wfp::model::{Conn, ProtectionError};

impl Protection {
    /// At start, after the settings import and the legacy cleanup: installs the "Always" set
    /// where it is in force, otherwise removes persistent leftovers (an earlier strict run, a
    /// crash). In the helper service a provider registered without its name is re-created first,
    /// and the static filters of a crashed run are taken over: an armed "If the VPN drops" block
    /// keeps holding ([`Protection::paused`]: the service resumes its session, or calls
    /// `disconnected()`), everything else of it goes. Quiet: the start page shows what the kill
    /// switch does.
    pub fn startup(&self) -> Result<(), ProtectionError> {
        let mut g = self.inner.lock();
        let held = match g.owner.session_lifetime() {
            Lifetime::Static => g.take_over()?,
            Lifetime::Dynamic | Lifetime::Persistent => false,
        };
        let mut t = g.target();
        t.conn = if held {
            Conn::Dropped
        } else {
            Conn::Disconnected
        };
        t.armed = held;
        t.tun_luid = None;
        t.session.clear();
        t.tun_addrs.clear();
        let skipped = g.transition(t, true)?;
        self.note_skipped(&mut g, skipped);
        Ok(())
    }
}

impl Inner {
    /// The helper service starts: our provider must carry its name (otherwise it is re-created
    /// with all our objects: one an app run as administrator or an older build created), and our
    /// non-persistent filters are a crashed run's static set, in doubt from here on (the next
    /// sync replaces them whole, in one transaction). `true` = it held an armed "If the VPN
    /// drops" block, which keeps holding.
    fn take_over(&mut self) -> Result<bool, ProtectionError> {
        let name = self.owner.service_name().map(str::to_owned);
        let provider = self.backend.provider().map_err(|e| self.wfp_failed(e))?;
        if provider.is_some_and(|p| p.service_name != name) {
            tracing::info!("WFP provider re-created for the helper service");
            self.backend.remove_all().map_err(|e| self.wfp_failed(e))?;
            self.persistent = None;
            self.sublayer_weight = None;
            return Ok(false);
        }
        let census = self.backend.census().map_err(|e| self.wfp_failed(e))?;
        if census.dynamic.is_empty() {
            return Ok(false);
        }
        self.dynamic_dirty = true;
        let held = census.session_block && self.level_in_force() == KillSwitchLevel::Standard;
        tracing::info!(
            filters = census.dynamic.len(),
            held,
            "static filters of a crashed run found"
        );
        Ok(held)
    }
}
