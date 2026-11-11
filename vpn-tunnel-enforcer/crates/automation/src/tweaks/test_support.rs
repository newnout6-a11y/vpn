//! An in-memory backend with fault injection for the journal tests. Nothing here touches the
//! user's real settings.
use std::collections::{HashMap, HashSet};
use std::io;

use parking_lot::Mutex;

use super::journal::{Backend, Target, Val};

/// In-memory system values with injected faults.
#[derive(Default)]
pub struct Fake {
    pub values: Mutex<HashMap<Target, Val>>,
    pub fail_read: Mutex<HashSet<Target>>,
    pub fail_write: Mutex<HashSet<Target>>,
    /// Writes to these store something else (read-back mismatch).
    pub garble: Mutex<HashSet<Target>>,
    pub writes: Mutex<Vec<(Target, Val)>>,
    pub pruned: Mutex<Vec<Target>>,
    pub broadcasts: Mutex<usize>,
}

impl Fake {
    pub fn with(values: &[(Target, Val)]) -> Self {
        let fake = Fake::default();
        fake.values.lock().extend(values.iter().cloned());
        fake
    }

    pub fn get(&self, t: &Target) -> Val {
        self.values.lock().get(t).cloned().unwrap_or(Val::Absent)
    }

    pub fn set(&self, t: &Target, v: Val) {
        self.values.lock().insert(t.clone(), v);
    }

    pub fn write_count(&self) -> usize {
        self.writes.lock().len()
    }
}

impl Backend for Fake {
    fn read(&self, target: &Target) -> io::Result<Val> {
        if self.fail_read.lock().contains(target) {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(self.get(target))
    }

    fn write(&self, target: &Target, value: &Val) -> io::Result<bool> {
        if self.fail_write.lock().contains(target) {
            return Err(io::Error::other("injected write failure"));
        }
        self.writes.lock().push((target.clone(), value.clone()));
        let stored = if self.garble.lock().contains(target) {
            Val::Text("garbled".into())
        } else {
            value.clone()
        };
        let created = self.values.lock().insert(target.clone(), stored).is_none();
        Ok(created)
    }

    fn prune(&self, target: &Target) -> io::Result<()> {
        self.pruned.lock().push(target.clone());
        Ok(())
    }

    fn changed(&self, _targets: &[Target]) {
        *self.broadcasts.lock() += 1;
    }
}
