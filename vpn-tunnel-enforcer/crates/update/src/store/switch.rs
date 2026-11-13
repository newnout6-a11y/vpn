//! Switching between versions by hand («Вернуть предыдущую», «Вернуть встроенную»), the trial
//! of a fresh install, and keeping at most two downloaded versions per engine.
use super::state::{self, Choice, TRIAL_FAILURES};
use super::{EngineStore, RolledBack};

impl EngineStore {
    /// «Вернуть предыдущую»: active and previous swap. `Ok(false)` = nothing to go back to.
    pub fn revert_previous(&self, id: &str) -> std::io::Result<bool> {
        let mut state = self.state();
        let record = state.engine_mut(id);
        let Some(previous) = record.previous else {
            return Ok(false);
        };
        if let Choice::Downloaded(v) = previous
            && self.usable(id, v).is_none()
        {
            return Ok(false);
        }
        record.previous = Some(record.active);
        record.active = previous;
        // The user chose it: no automatic return.
        record.trial = None;
        state::write(&self.root, &state)?;
        tracing::info!(engine = id, active = %previous, "engine switched back by the user");
        Ok(true)
    }

    /// «Вернуть встроенную»: the bundled engine runs again; the downloaded one stays as previous.
    pub fn revert_bundled(&self, id: &str) -> std::io::Result<()> {
        let mut state = self.state();
        let record = state.engine_mut(id);
        if record.active != Choice::Bundled {
            record.previous = Some(record.active);
            record.active = Choice::Bundled;
        }
        record.trial = None;
        state::write(&self.root, &state)?;
        tracing::info!(engine = id, "bundled engine restored by the user");
        Ok(())
    }

    /// A start with engine `id` ended: `ok` = it ran, `false` = it failed to start or refused
    /// the config. The third failure in a row of a fresh install switches back by itself.
    pub fn record_start(&self, id: &str, ok: bool) -> std::io::Result<Option<RolledBack>> {
        let mut state = self.state();
        let Some(record) = state.engines.get_mut(id) else {
            return Ok(None);
        };
        let (Some(failures), Choice::Downloaded(from)) = (record.trial, record.active) else {
            return Ok(None);
        };
        let rolled = if ok {
            record.trial = None;
            None
        } else if failures + 1 >= TRIAL_FAILURES {
            let to = record.previous.take().unwrap_or(Choice::Bundled);
            record.active = to;
            record.previous = Some(Choice::Downloaded(from));
            record.trial = None;
            tracing::warn!(engine = id, %from, %to, "new engine failed its trial, switched back");
            Some(RolledBack {
                id: id.to_owned(),
                from,
                to,
            })
        } else {
            record.trial = Some(failures + 1);
            None
        };
        state::write(&self.root, &state)?;
        Ok(rolled)
    }

    /// At start: versions this build no longer allows (older than the bundled one after an app
    /// update, outside the compiled range, a feed that no longer verifies) are dropped from the
    /// record and from disk; the bundled engine takes their place.
    pub fn tidy(&self, id: &str) {
        let mut state = self.state();
        if let Some(record) = state.engines.get_mut(id) {
            let usable = |c: Option<Choice>| match c {
                Some(Choice::Downloaded(v)) => self.usable(id, v).map(|_| Choice::Downloaded(v)),
                other => other,
            };
            let (active, previous) = (usable(Some(record.active)), usable(record.previous));
            if active != Some(record.active) || previous != record.previous {
                tracing::info!(
                    engine = id,
                    "downloaded engine no longer usable, bundled restored"
                );
                record.active = active.unwrap_or(Choice::Bundled);
                record.previous = previous.filter(|p| *p != record.active);
                if active.is_none() {
                    record.trial = None;
                }
                if let Err(err) = state::write(&self.root, &state) {
                    tracing::warn!(%err, "engine state not written");
                }
            }
        }
        self.prune(id);
    }

    /// Removes downloaded versions of `id` that are neither active nor previous (and any other
    /// leftover folder). A folder still in use (an engine running from it) stays for next time.
    pub fn prune(&self, id: &str) {
        let state = self.state();
        let keep: Vec<String> = state
            .engine(id)
            .map(|r| [Some(r.active), r.previous])
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|c| match c {
                Choice::Downloaded(v) => Some(v.to_string()),
                Choice::Bundled => None,
            })
            .collect();
        let Ok(entries) = std::fs::read_dir(self.root.join(id)) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.path().is_dir()
                && !keep.contains(&name)
                && let Err(err) = std::fs::remove_dir_all(entry.path())
            {
                tracing::debug!(engine = id, %err, "old engine folder kept for now");
            }
        }
    }
}
