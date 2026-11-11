//! The effects [`super::protection::Protection`] needs, behind a small trait so its state
//! machine is unit-tested with a fake; [`WfpBackend`] is the real one over [`Engine`].
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::engine::{Engine, WfpError};
use super::filters::{app_id_of, canonical};
use super::spec::{AppId, FilterSpec};
use super::{PROVIDER_KEY, SUBLAYER_KEY};

/// Our filters as a fresh enumeration sees them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Census {
    /// Runtime IDs of our non-persistent filters.
    pub dynamic: Vec<u64>,
    /// Runtime IDs of our intact persistent filters.
    pub persistent: Vec<u64>,
}

/// What [`super::remove_all`] deleted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RemoveReport {
    /// Filters of our provider that were deleted (dynamic ones of any session included).
    pub filters: usize,
    /// Our sublayer is gone (deleted or already absent).
    pub sublayer: bool,
    /// Our provider is gone (deleted or already absent).
    pub provider: bool,
}

pub(crate) trait Backend: Send {
    /// App ID of an existing executable (missing file = error).
    fn app_id(&mut self, exe: &Path) -> Result<Arc<AppId>, WfpError>;
    /// Creates provider + sublayer when missing; returns the actual sublayer weight.
    fn ensure(&mut self) -> Result<u16, WfpError>;
    /// One dynamic transaction: delete `delete`, add `add`; returns the IDs of `add`.
    fn change_dynamic(&mut self, delete: &[u64], add: &[FilterSpec]) -> Result<Vec<u64>, WfpError>;
    /// One persistent transaction: delete `delete` (`None` = every persistent filter of ours),
    /// add `add`; returns the IDs of `add`.
    fn change_persistent(
        &mut self,
        delete: Option<&[u64]>,
        add: &[FilterSpec],
    ) -> Result<Vec<u64>, WfpError>;
    /// Fresh enumeration of our filters.
    fn census(&mut self) -> Result<Census, WfpError>;
    /// Closes the dynamic session; BFE deletes everything it added.
    fn close_dynamic(&mut self);
    /// Deletes every object of ours: filters of all sessions, sublayer, provider.
    fn remove_all(&mut self) -> Result<RemoveReport, WfpError>;
}

/// The real backend: one dynamic session kept for the process lifetime, persistent sessions
/// opened per operation, app IDs cached per path.
#[derive(Default)]
pub(crate) struct WfpBackend {
    dynamic: Option<Engine>,
    ids: HashMap<PathBuf, Arc<AppId>>,
}

impl Backend for WfpBackend {
    fn app_id(&mut self, exe: &Path) -> Result<Arc<AppId>, WfpError> {
        // Keyed by the canonical path: every spelling of a file shares one ID, and a file that
        // vanished fails here even while its ID is cached.
        let path = canonical(exe)?;
        if let Some(id) = self.ids.get(&path) {
            return Ok(id.clone());
        }
        let id = Arc::new(app_id_of(&path)?);
        self.ids.insert(path, id.clone());
        Ok(id)
    }

    fn ensure(&mut self) -> Result<u16, WfpError> {
        Engine::open_persistent()?.ensure_provider_and_sublayer()
    }

    fn change_dynamic(&mut self, delete: &[u64], add: &[FilterSpec]) -> Result<Vec<u64>, WfpError> {
        if self.dynamic.is_none() {
            if add.is_empty() {
                // No session means none of its filters exist any more.
                return Ok(Vec::new());
            }
            self.dynamic = Some(Engine::open_dynamic()?);
        }
        let Some(engine) = &self.dynamic else {
            return Ok(Vec::new());
        };
        change(engine, delete, add)
    }

    fn change_persistent(
        &mut self,
        delete: Option<&[u64]>,
        add: &[FilterSpec],
    ) -> Result<Vec<u64>, WfpError> {
        let engine = Engine::open_persistent()?;
        let all: Vec<u64>;
        let delete = match delete {
            Some(ids) => ids,
            None => {
                all = engine
                    .owned_filters()?
                    .into_iter()
                    .filter(|f| f.is_persistent())
                    .map(|f| f.id)
                    .collect();
                &all
            }
        };
        match delete.is_empty() && add.is_empty() {
            true => Ok(Vec::new()),
            false => change(&engine, delete, add),
        }
    }

    fn census(&mut self) -> Result<Census, WfpError> {
        let filters = match &self.dynamic {
            Some(engine) => engine.owned_filters()?,
            None => Engine::open_persistent()?.owned_filters()?,
        };
        let (persistent, dynamic): (Vec<_>, Vec<_>) =
            filters.into_iter().partition(|f| f.is_persistent());
        Ok(Census {
            dynamic: dynamic.into_iter().map(|f| f.id).collect(),
            // A disabled or otherwise altered persistent filter protects nothing: left out, so
            // the read-back mismatches and the set is rewritten.
            persistent: persistent
                .into_iter()
                .filter(|f| f.flags_valid(false))
                .map(|f| f.id)
                .collect(),
        })
    }

    fn close_dynamic(&mut self) {
        self.dynamic = None;
    }

    fn remove_all(&mut self) -> Result<RemoveReport, WfpError> {
        self.dynamic = None;
        remove_all_objects()
    }
}

/// One transaction: delete `delete`, add `add`, all or nothing; returns the IDs of `add`.
fn change(engine: &Engine, delete: &[u64], add: &[FilterSpec]) -> Result<Vec<u64>, WfpError> {
    engine.transaction(|e| {
        for &id in delete {
            e.delete(id)?;
        }
        add.iter().map(|s| e.add(s)).collect()
    })
}

/// Deletes every filter of our provider on our layers (persistent, disabled and other
/// sessions' dynamic ones) in one transaction, then the sublayer, then the provider; each step
/// is attempted and the first failure is returned.
pub(crate) fn remove_all_objects() -> Result<RemoveReport, WfpError> {
    let engine = Engine::open_persistent()?;
    let ids: Vec<u64> = engine.owned_filters()?.into_iter().map(|f| f.id).collect();
    let filters = match ids.is_empty() {
        true => Ok(()),
        false => engine.transaction(|e| ids.iter().try_for_each(|&id| e.delete(id))),
    };
    let sublayer = engine.delete_sublayer(&SUBLAYER_KEY);
    let provider = engine.delete_provider(&PROVIDER_KEY);
    let report = RemoveReport {
        filters: if filters.is_ok() { ids.len() } else { 0 },
        sublayer: sublayer.is_ok(),
        provider: provider.is_ok(),
    };
    filters.and(sublayer).and(provider).map(|()| report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use crate::wfp::filters::tests::{Objects, harmless, short_name};

    /// Review D6 (unelevated): an 8.3 spelling and the long path share one canonical path, one
    /// app ID and one cache entry; a vanished file fails although its ID is cached.
    #[test]
    fn app_ids_are_keyed_by_the_canonical_path() {
        let dir = TempDir::new("appid");
        let long = dir.file("a long program name.exe");
        let mut b = WfpBackend::default();
        let id = b.app_id(&long).unwrap();
        if let Some(short) = short_name(&long) {
            assert_eq!(b.app_id(&short).unwrap(), id);
        }
        assert_eq!(b.ids.len(), 1);
        std::fs::remove_file(&long).unwrap();
        assert!(b.app_id(&long).is_err());
        assert!(b.app_id(dir.path()).is_err(), "a directory is no program");
    }

    /// The real backend: replace / census / close on both sessions, harmless filters only.
    #[test]
    #[ignore = "needs elevation"]
    fn elevated_real_backend_round_trip() {
        let objects = Objects::before();
        if objects.existed() {
            // replace_persistent would rewrite a real installation's strict set.
            eprintln!("skipped: VPNTE WFP objects already exist on this machine");
            return;
        }
        let mut b = WfpBackend::default();
        assert!(b.ensure().unwrap() > 0);
        let start = b.census().unwrap();
        let ids = b
            .change_dynamic(&[], &[harmless("test-a"), harmless("test-b")])
            .unwrap();
        let census = b.census().unwrap();
        assert!(ids.iter().all(|id| census.dynamic.contains(id)));
        let ids = b.change_dynamic(&ids, &[harmless("test-c")]).unwrap();
        assert_eq!(b.census().unwrap().dynamic.len(), start.dynamic.len() + 1);
        let kept = b.change_persistent(None, &[harmless("test-p")]).unwrap();
        assert_eq!(b.census().unwrap().persistent, kept);
        b.change_persistent(Some(&kept), &[]).unwrap();
        assert!(b.census().unwrap().persistent.is_empty());
        b.close_dynamic();
        let census = b.census().unwrap();
        assert!(
            ids.iter().all(|id| !census.dynamic.contains(id)),
            "closing the session removes its filters"
        );
        objects.restore();
    }

    /// `remove_all` on a machine without a real installation (it deletes every object of ours).
    #[test]
    #[ignore = "needs elevation"]
    fn elevated_remove_all_objects_clears_everything() {
        let objects = Objects::before();
        if objects.existed() {
            eprintln!("skipped: VPNTE WFP objects already exist on this machine");
            return;
        }
        let mut b = WfpBackend::default();
        b.ensure().unwrap();
        b.change_dynamic(&[], &[harmless("test-d")]).unwrap();
        b.change_persistent(None, &[harmless("test-p")]).unwrap();
        let report = b.remove_all().unwrap();
        assert!(report.filters >= 1 && report.sublayer && report.provider);
        let e = Engine::open_persistent().unwrap();
        assert!(e.sublayer(&SUBLAYER_KEY).unwrap().is_none());
        assert!(!e.provider_exists(&PROVIDER_KEY).unwrap());
    }
}
