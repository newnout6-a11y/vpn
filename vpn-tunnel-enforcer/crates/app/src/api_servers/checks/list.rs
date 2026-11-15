//! The list check's results stored as they land (psmall-a2): a run of up to 20 minutes neither
//! holds them back until its end nor writes them then over fresher records (the list keeps the
//! newer one of each key, `Servers::record_health`).
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use vpnte_base::AppResult;
use vpnte_probes::key_health::KeyCheck;
use vpnte_servers::store::Servers;

use super::{Key, updates};
use crate::api_servers::verdict;

/// Results go to the list in batches at most this often (each write rewrites the list file).
const SAVE_EVERY: Duration = Duration::from_secs(10);

/// The results of one list check not stored yet.
pub(super) struct Saver {
    servers: Arc<Servers>,
    pending: Mutex<(Vec<(Key, KeyCheck)>, Instant)>,
}

impl Saver {
    pub(super) fn new(servers: Arc<Servers>) -> Self {
        Self {
            servers,
            pending: Mutex::new((Vec::new(), Instant::now())),
        }
    }

    /// One result; the batch is stored once [`SAVE_EVERY`] passed since the last write. A
    /// failed write keeps the batch for the next one.
    pub(super) fn add(&self, key: &Key, check: &KeyCheck) {
        let batch = {
            let mut pending = self.pending.lock();
            pending.0.push((key.clone(), check.clone()));
            if pending.1.elapsed() < SAVE_EVERY {
                return;
            }
            pending.1 = Instant::now();
            std::mem::take(&mut pending.0)
        };
        if let Err(err) = self.save(&batch) {
            tracing::warn!(error = %err, "list check results not stored yet");
            self.pending.lock().0.extend(batch);
        }
    }

    /// Stores what is left (the run's end).
    pub(super) fn finish(&self) -> AppResult<()> {
        let batch = std::mem::take(&mut self.pending.lock().0);
        self.save(&batch)
    }

    fn save(&self, batch: &[(Key, KeyCheck)]) -> AppResult<()> {
        if batch.is_empty() {
            return Ok(());
        }
        self.servers.record_health(updates(batch))?;
        self.servers.record_verdicts(verdict::updates(batch))?;
        Ok(())
    }
}
