//! Servers whose exit proof failed in this app session (p-follow3): their start's exit check got
//! nothing back through the server, or a transfer through their new session carried nothing.
//! The rescue rounds never dial them again, even when nothing else is left: a dead server
//! dialled over and over only delays the honest end. The user's own start on one, a new key
//! from its subscription or a network change gives it back.
use std::collections::HashSet;

use crate::coordinator::OpError;

/// The runtime's error of a start whose exit check got nothing back through the server (the
/// app's coordinator passes it on unchanged).
const EXIT_SILENT: &str = "tunnel.runtime.exitSilent";

/// The servers that failed their exit proof.
#[derive(Debug, Default)]
pub(super) struct Unproven(parking_lot::Mutex<HashSet<String>>);

impl Unproven {
    pub(super) fn contains(&self, id: &str) -> bool {
        self.0.lock().contains(id)
    }

    /// Server `id` failed its exit proof.
    pub(super) fn add(&self, id: &str) {
        self.0.lock().insert(id.to_owned());
    }

    /// A dial of `id` failed with `e`: only a silent exit counts (a refused or timed-out start
    /// may be a freeze that lifts; the quiet window handles those).
    pub(super) fn add_if_silent(&self, id: &str, e: &OpError) {
        if matches!(e, OpError::Failed(err) if err.user_msg().key == EXIT_SILENT) {
            self.add(id);
        }
    }

    /// The servers `ids` get another chance (the user started one, or it has a new key).
    pub(super) fn forgive<'a>(&self, ids: impl IntoIterator<Item = &'a str>) {
        let mut held = self.0.lock();
        for id in ids {
            held.remove(id);
        }
    }

    /// A new network: what failed on the old one proves nothing here.
    pub(super) fn clear(&self) {
        self.0.lock().clear();
    }
}
